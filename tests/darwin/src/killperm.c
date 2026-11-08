// Who may signal whom, by kern_sig.c's cansignal: a process of another
// user (a child spawned into a persona as the next uid) refuses kill (EPERM,
// for signal 0 too), killpg of its group (EPERM: none signalled) and
// proc_terminate, but takes SIGCONT from its session; a broadcast finds
// the caller itself; init never takes SIGKILL; a zombie is signalled
// successfully. Its exit status is its parent's to watch for, not a
// sibling's of another user (EACCES), though the sibling may watch for
// the exit itself. Needs the persona manager's entitlement and a caller
// that is not root.

#include <errno.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;
int posix_spawnattr_set_persona_np(const posix_spawnattr_t *attr, uid_t persona_id, uint32_t flags);
int posix_spawnattr_set_persona_uid_np(const posix_spawnattr_t *attr, uid_t uid);
int posix_spawnattr_set_persona_gid_np(const posix_spawnattr_t *attr, gid_t gid);
int proc_terminate(pid_t pid, int *sig);

struct kpersona_info {
    uint32_t version;
    uid_t id;
    int type;
    gid_t gid;
    uint32_t ngroups;
    gid_t groups[16];
    uid_t gmuid;
    char name[256];
    uid_t uid;
} __attribute__((packed));

static int bad(const char *what, long got, long want) {
    printf("killperm: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

static int watch(pid_t pid, unsigned fflags) {
    int kq = kqueue();
    struct kevent ev;
    EV_SET(&ev, pid, EVFILT_PROC, EV_ADD | EV_RECEIPT, fflags, 0, 0);
    if (kevent(kq, &ev, 1, &ev, 1, NULL) != 1) return -1;
    close(kq);
    return ev.flags & EV_ERROR ? (int)ev.data : 0;
}

// The sibling, of the caller's user: another user's process is not its
// to signal nor to collect the exit status of.
static int sibling(pid_t other) {
    if (kill(other, 0) != -1 || errno != EPERM) return 20;
    if (watch(other, NOTE_EXIT | NOTE_EXITSTATUS) != EACCES) return 21;
    if (watch(other, NOTE_EXIT) != 0) return 22;
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 2) return sibling(atoi(argv[2]));
    if (argc > 1) {
        // The other user's process: until its standard input ends.
        char c;
        while (read(0, &c, 1) > 0) {
        }
        return 0;
    }
    if (geteuid() == 0) return bad("run as root", 0, 1);
    struct kpersona_info k;
    memset(&k, 0, sizeof k);
    k.version = 2;
    k.id = (uid_t)-1;
    k.type = 4;
    strcpy(k.name, "gex-killperm");
    uid_t id = 0;
    if (syscall(494, 1, 0, &k, &id, NULL, NULL) != 0) return bad("a persona", errno, 0);

    posix_spawnattr_t sa;
    posix_spawnattr_init(&sa);
    posix_spawnattr_set_persona_np(&sa, id, 1);
    posix_spawnattr_set_persona_uid_np(&sa, getuid() + 1);
    posix_spawnattr_set_persona_gid_np(&sa, getgid() + 1);
    posix_spawnattr_setflags(&sa, POSIX_SPAWN_SETPGROUP);
    posix_spawnattr_setpgroup(&sa, 0);
    int p[2];
    pipe(p);
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, p[0], 0);
    posix_spawn_file_actions_addclose(&fa, p[1]);
    char *args[] = {argv[0], "other", NULL};
    pid_t other;
    int e = posix_spawn(&other, argv[0], &fa, &sa, args, environ);
    if (e) return bad("spawning the other user's process", e, 0);
    close(p[0]);

    if (kill(other, SIGUSR1) != -1 || errno != EPERM) return bad("kill", errno, EPERM);
    if (kill(other, 0) != -1 || errno != EPERM) return bad("kill with signal 0", errno, EPERM);
    if (kill(-other, SIGUSR1) != -1 || errno != EPERM) return bad("killpg of its group", errno, EPERM);
    if (kill(other, SIGCONT) != 0) return bad("SIGCONT in the session", errno, 0);
    int sig = 0;
    if ((e = proc_terminate(other, &sig)) != EPERM) return bad("proc_terminate", e, EPERM);
    if (kill(-1, 0) != 0) return bad("a broadcast finding itself", errno, 0);
    if (kill(1, SIGKILL) != -1 || errno != EPERM) return bad("SIGKILL to init", errno, EPERM);
    if (watch(other, NOTE_EXIT | NOTE_EXITSTATUS) != 0) return bad("its parent watching its exit status", errno, 0);

    char num[16];
    snprintf(num, sizeof num, "%d", other);
    char *sargs[] = {argv[0], "sibling", num, NULL};
    pid_t sib;
    if ((e = posix_spawn(&sib, argv[0], NULL, NULL, sargs, environ))) return bad("spawning the sibling", e, 0);
    int st;
    if (waitpid(sib, &st, 0) != sib || !WIFEXITED(st) || WEXITSTATUS(st) != 0) return bad("the sibling", WIFEXITED(st) ? WEXITSTATUS(st) : -1, 0);

    close(p[1]);
    siginfo_t si;
    if (waitid(P_PID, other, &si, WEXITED | WNOWAIT) != 0) return bad("its end", errno, 0);
    if (kill(other, SIGUSR1) != 0) return bad("kill of a zombie", errno, 0);
    if (waitpid(other, &st, 0) != other || !WIFEXITED(st) || WEXITSTATUS(st) != 0) return bad("its status", st, 0);
    if (syscall(494, 3, 0, NULL, &id, NULL, NULL) != 0) return bad("dealloc", errno, 0);
    printf("killperm ok\n");
    return 0;
}
