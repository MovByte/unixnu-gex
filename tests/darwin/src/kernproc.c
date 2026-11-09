// kern.proc: this process's record and what it holds, another's, the
// kernel's own, the lists by group and by user, the room a size query
// leaves, and a read too short for what it asks.

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

static int bad(const char *what, long got, long want) {
    printf("kernproc: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

static int get(int cmd, int arg, struct kinfo_proc *k, size_t *len) {
    int mib[4] = {CTL_KERN, KERN_PROC, cmd, arg};
    return sysctl(mib, 4, k, len, NULL, 0);
}

int main(int argc, char **argv) {
    (void)argc;
    struct kinfo_proc k;
    size_t len = sizeof k;
    if (get(KERN_PROC_PID, getpid(), &k, &len) != 0) return bad("kern.proc.pid", errno, 0);
    if (len != sizeof k) return bad("the record's size", (long)len, (long)sizeof k);
    if (k.kp_proc.p_pid != getpid()) return bad("p_pid", k.kp_proc.p_pid, getpid());
    if (k.kp_eproc.e_ppid != getppid()) return bad("e_ppid", k.kp_eproc.e_ppid, getppid());
    if (k.kp_eproc.e_pgid != getpgrp()) return bad("e_pgid", k.kp_eproc.e_pgid, getpgrp());
    if (k.kp_eproc.e_ucred.cr_uid != geteuid()) return bad("cr_uid", k.kp_eproc.e_ucred.cr_uid, geteuid());
    if (k.kp_eproc.e_pcred.p_ruid != getuid()) return bad("p_ruid", k.kp_eproc.e_pcred.p_ruid, getuid());
    if (!(k.kp_proc.p_flag & P_LP64)) return bad("P_LP64", k.kp_proc.p_flag, P_LP64);
    if (k.kp_proc.p_flag & P_TRACED) return bad("P_TRACED", 1, 0);
    if (k.kp_proc.p_stat != SRUN) return bad("p_stat", k.kp_proc.p_stat, SRUN);
    if (k.kp_eproc.e_tdev != (dev_t)-1) return bad("e_tdev", k.kp_eproc.e_tdev, -1);
    const char *base = strrchr(argv[0], '/');
    base = base ? base + 1 : argv[0];
    if (strncmp(k.kp_proc.p_comm, base, MAXCOMLEN) != 0) return bad("p_comm", 1, 0);
    struct timeval now;
    gettimeofday(&now, NULL);
    long age = now.tv_sec - k.kp_proc.p_starttime.tv_sec;
    if (age < 0 || age > 120) return bad("the process's age", age, 0);

    // Its dispositions and timer, as they change.
    signal(SIGUSR1, SIG_IGN);
    struct itimerval it = {{3, 0}, {50, 0}};
    setitimer(ITIMER_REAL, &it, NULL);
    len = sizeof k;
    get(KERN_PROC_PID, getpid(), &k, &len);
    if (!(k.kp_proc.p_sigignore & (1u << (SIGUSR1 - 1)))) return bad("p_sigignore", k.kp_proc.p_sigignore, 1);
    if (k.kp_proc.p_realtimer.it_value.tv_sec != 50 || k.kp_proc.p_realtimer.it_interval.tv_sec != 3) return bad("p_realtimer", k.kp_proc.p_realtimer.it_value.tv_sec, 50);
    memset(&it, 0, sizeof it);
    setitimer(ITIMER_REAL, &it, NULL);

    // A child's, read from its parent: forked and not exec'd.
    int p[2];
    pipe(p);
    pid_t pid = fork();
    if (pid == 0) {
        char c;
        close(p[1]);
        read(p[0], &c, 1);
        _exit(0);
    }
    close(p[0]);
    len = sizeof k;
    if (get(KERN_PROC_PID, pid, &k, &len) != 0 || len != sizeof k) return bad("a child's record", (long)len, (long)sizeof k);
    if (k.kp_proc.p_pid != pid || k.kp_eproc.e_ppid != getpid()) return bad("a child's ids", k.kp_proc.p_pid, pid);
    if (!(k.kp_proc.p_acflag & 1)) return bad("AFORK", k.kp_proc.p_acflag, 1);
    if (!(k.kp_proc.p_sigignore & (1u << (SIGUSR1 - 1)))) return bad("a child's inherited p_sigignore", k.kp_proc.p_sigignore, 1);
    write(p[1], "x", 1);
    close(p[1]);
    int st;
    waitpid(pid, &st, 0);

    // The kernel's own process.
    len = sizeof k;
    if (get(KERN_PROC_PID, 0, &k, &len) != 0 || len != sizeof k) return bad("pid 0's record", (long)len, (long)sizeof k);
    if (strcmp(k.kp_proc.p_comm, "kernel_task") != 0) return bad("pid 0's name", 1, 0);
    if (!(k.kp_proc.p_flag & P_SYSTEM)) return bad("P_SYSTEM", k.kp_proc.p_flag, P_SYSTEM);

    // No such process: an empty answer.
    len = sizeof k;
    if (get(KERN_PROC_PID, 99999, &k, &len) != 0 || len != 0) return bad("a pid with no process", (long)len, 0);

    // A list, sized first.
    int all[3] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL};
    len = 0;
    if (sysctl(all, 3, NULL, &len, NULL, 0) != 0) return bad("sizing the list", errno, 0);
    if (len < 7 * sizeof k || len % sizeof k != 0) return bad("the list's size", (long)len, (long)(7 * sizeof k));
    size_t room = len;
    struct kinfo_proc *list = malloc(room);
    if (sysctl(all, 3, list, &len, NULL, 0) != 0) return bad("the list", errno, 0);
    int self = 0, kern = 0;
    for (size_t i = 0; i < len / sizeof k; i++) {
        self += list[i].kp_proc.p_pid == getpid();
        kern += list[i].kp_proc.p_pid == 0;
    }
    if (self != 1 || kern != 1) return bad("this process in the list", self * 10 + kern, 11);

    // Too short: what fits is written, ENOMEM, and no size comes back.
    size_t one = sizeof k;
    errno = 0;
    list[0].kp_proc.p_pid = -1;
    if (sysctl(all, 3, list, &one, NULL, 0) != -1 || errno != ENOMEM) return bad("a short list", errno, ENOMEM);
    if (one != 0) return bad("a short list's size", (long)one, 0);
    if (list[0].kp_proc.p_pid == -1) return bad("what fits of a short list", -1, 0);

    // By group and by user.
    len = room;
    if (get(KERN_PROC_PGRP, getpgrp(), list, &len) != 0 || len < sizeof k) return bad("by group", errno, 0);
    len = room;
    if (get(KERN_PROC_UID, (int)geteuid(), list, &len) != 0 || len < sizeof k) return bad("by user", errno, 0);
    for (size_t i = 0; i < len / sizeof k; i++) {
        if (list[i].kp_eproc.e_ucred.cr_uid != geteuid()) return bad("another user's in the list", list[i].kp_eproc.e_ucred.cr_uid, geteuid());
    }

    // Numbers: the wrong count, and a command that is not one.
    int two[3] = {CTL_KERN, KERN_PROC, KERN_PROC_PID};
    len = sizeof k;
    errno = 0;
    if (sysctl(two, 3, &k, &len, NULL, 0) != -1 || errno != EINVAL) return bad("no pid given", errno, EINVAL);
    // Its arguments: argc, the executable's path, then argv and the rest.
    int pa[3] = {CTL_KERN, KERN_PROCARGS2, getpid()};
    size_t asize = 0;
    if (sysctl(pa, 3, NULL, &asize, NULL, 0) != 0 || asize < 8) return bad("sizing procargs2", errno, 0);
    char *abuf = malloc(asize);
    size_t got = asize;
    if (sysctl(pa, 3, abuf, &got, NULL, 0) != 0) return bad("procargs2", errno, 0);
    if (*(int *)abuf != 1) return bad("argc", *(int *)abuf, 1);
    char *path = abuf + 4;
    size_t plen = strlen(path);
    if (strcmp(path + plen - strlen(base), base) != 0) return bad("the executable's path", (long)plen, 0);
    char *a = path + plen;
    while (*a == 0) a++;
    if (strcmp(a, argv[0]) != 0) return bad("argv[0]", 1, 0);
    int found_env = 0;
    extern char **environ;
    for (char *e = a + strlen(a) + 1; e < abuf + got && *e; e += strlen(e) + 1) {
        found_env |= environ[0] && strcmp(e, environ[0]) == 0;
    }
    if (!found_env) return bad("its environment", 0, 1);

    // A short buffer gets the end of it.
    got = 64;
    if (sysctl(pa, 3, abuf, &got, NULL, 0) != 0 || got != 64) return bad("a short procargs2", (long)got, 64);

    // A forked child's: the same strings, read from the other process.
    pipe(p);
    pid = fork();
    if (pid == 0) {
        char c;
        close(p[1]);
        read(p[0], &c, 1);
        _exit(0);
    }
    close(p[0]);
    int pc[3] = {CTL_KERN, KERN_PROCARGS2, pid};
    got = asize;
    if (sysctl(pc, 3, abuf, &got, NULL, 0) != 0 || *(int *)abuf != 1) return bad("a child's procargs2", errno, 0);
    write(p[1], "x", 1);
    close(p[1]);
    waitpid(pid, &st, 0);

    // The kernel's process, no process at all, no room for the word.
    int pz[3] = {CTL_KERN, KERN_PROCARGS2, 0};
    got = asize;
    errno = 0;
    if (sysctl(pz, 3, abuf, &got, NULL, 0) != -1 || errno != EINVAL) return bad("pid 0's procargs2", errno, EINVAL);
    pz[2] = 99999;
    got = asize;
    errno = 0;
    if (sysctl(pz, 3, abuf, &got, NULL, 0) != -1 || errno != EINVAL) return bad("no process's procargs2", errno, EINVAL);
    got = 2;
    errno = 0;
    if (sysctl(pa, 3, abuf, &got, NULL, 0) != -1 || errno != EINVAL) return bad("procargs2 with no room", errno, EINVAL);
    printf("kernproc ok\n");
    return 0;
}
