// proc_pidinfo of this process and of a child: the BSD info (its ids,
// parent, name, status, flags, descriptor table size), the short form,
// the path, architecture and platform. A spawned child's descriptor table
// starts at NDFILE (25) slots and grows to NDEXTENT (50) for descriptor 30
// (xnu-10063's sizing; later kernels size it otherwise);
// once it has exited and before it is reaped, its BSD info is found only
// when zombies are asked for (SZOMB), and is ESRCH otherwise.
// proc_listpids lists every process, the zombie too, and by parent, group
// and user. PROC_PIDLISTFDS lists the open descriptors and their types;
// PROC_PIDLISTTHREADIDS and PROC_PIDLISTTHREADS the threads, in the order
// made, by thread id (thread_selfid's, from 101 up) and by TSD base, which
// thread_info(THREAD_IDENTIFIER_INFO) reports too.

#include <errno.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach/mach.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;
int proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int buffersize);
int proc_pidpath(int pid, void *buffer, uint32_t buffersize);
int proc_listpids(uint32_t type, uint32_t typeinfo, void *buffer, int buffersize);

static int gate[2];

// A second thread: there until the gate is written.
static void *waiter(void *arg) {
    char c;
    (void)arg;
    read(gate[0], &c, 1);
    return NULL;
}

// Whether `pid` is among the pids proc_listpids(type, info) lists, and how
// many it lists.
static int listed(uint32_t type, uint32_t info, pid_t pid, int *count) {
    static pid_t pids[4096];
    int n = proc_listpids(type, info, pids, sizeof pids) / (int)sizeof(pid_t);
    *count = n;
    for (int i = 0; i < n; i++)
        if (pids[i] == pid) return 1;
    return 0;
}

struct bsdinfo {
    uint32_t flags, status, xstatus, pid, ppid, uid, gid, ruid, rgid, svuid, svgid, rfu;
    char comm[16];
    char name[32];
    uint32_t nfiles, pgid, pjobc, tdev, tpgid;
    int32_t nice;
    uint64_t start_sec, start_usec;
};

struct shortinfo {
    uint32_t pid, ppid, pgid, status;
    char comm[16];
    uint32_t flags, uid, gid, ruid, rgid, svuid, svgid, rfu;
};

static int bad(const char *what, long got, long want) {
    printf("procinfo: %s: %#lx, want %#lx\n", what, got, want);
    return 1;
}

int main(int argc, char **argv) {
    if (argc > 1) {
        // The child: descriptor 30, then wait for the parent.
        int in = atoi(argv[1]), out = atoi(argv[2]);
        dup2(0, 30);
        char c = 1;
        write(out, &c, 1);
        read(in, &c, 1);
        return 7;
    }
    struct bsdinfo b;
    if (proc_pidinfo(getpid(), 3, 0, &b, sizeof b) != sizeof b) return bad("PROC_PIDTBSDINFO", errno, 0);
    if (b.pid != (uint32_t)getpid() || b.ppid != (uint32_t)getppid() || b.status != 2) return bad("its pid, parent, status", b.status, 2);
    if (b.uid != geteuid() || b.ruid != getuid() || b.gid != getegid() || b.rgid != getgid() || b.svuid != geteuid()) return bad("its ids", b.uid, geteuid());
    if ((b.flags & 0x10) == 0 || (b.flags & 0x4000) == 0) return bad("its flags (LP64, EXEC)", b.flags, 0x4010);
    const char *base = strrchr(argv[0], '/') ? strrchr(argv[0], '/') + 1 : argv[0];
    if (strncmp(b.comm, base, 15) || b.comm[15]) return bad("its name", 0, 1);
    if (b.pgid != (uint32_t)getpgrp() || b.start_sec == 0 || b.nfiles < 25) return bad("its group, start, table", b.nfiles, 25);
    struct shortinfo s;
    if (proc_pidinfo(getpid(), 13, 0, &s, sizeof s) != sizeof s || s.pid != b.pid || s.ppid != b.ppid || s.flags != b.flags || strcmp(s.comm, b.comm)) return bad("PROC_PIDT_SHORTBSDINFO", s.flags, b.flags);
    if (proc_pidinfo(getpid(), 3, 0, &b, sizeof b - 1) != 0 || errno != ENOMEM) return bad("a short buffer", errno, ENOMEM);
    char path[1024];
    if (proc_pidpath(getpid(), path, sizeof path) <= 0 || !strstr(path, base)) return bad("its path", errno, 0);
    uint32_t arch[2];
    if (proc_pidinfo(getpid(), 19, 0, arch, sizeof arch) != sizeof arch || arch[0] != 0x100000c) return bad("its architecture", arch[0], 0x100000c);
    // Its platform: its LC_BUILD_VERSION's.
    uint32_t want = 0, plat = 0;
    const struct mach_header_64 *mh = (const struct mach_header_64 *)_dyld_get_image_header(0);
    const struct load_command *lc = (const struct load_command *)(mh + 1);
    for (uint32_t i = 0; i < mh->ncmds; i++, lc = (const struct load_command *)((const char *)lc + lc->cmdsize))
        if (lc->cmd == LC_BUILD_VERSION) want = ((const struct build_version_command *)lc)->platform;
    if (proc_pidinfo(getpid(), 30, 0, &plat, sizeof plat) != sizeof plat || plat != want) return bad("its platform", plat, want);
    if (proc_pidinfo(99999, 3, 0, &b, sizeof b) != 0 || errno != ESRCH) return bad("no such process", errno, ESRCH);
    // Its descriptors: 0-2, and a pipe's two ends of type PIPE.
    int pp[2];
    pipe(pp);
    struct { int32_t fd; uint32_t type; } fds[256];
    int nf = proc_pidinfo(getpid(), 1, 0, fds, sizeof fds) / 8, pipes = 0;
    for (int i = 0; i < nf; i++)
        if ((fds[i].fd == pp[0] || fds[i].fd == pp[1]) && fds[i].type == 6) pipes++;
    if (nf < 5 || fds[0].fd != 0 || pipes != 2) return bad("its descriptors", nf, 5);
    if (proc_pidinfo(getpid(), 1, 0, NULL, 0) < (int)(8 * (b.nfiles + 20))) return bad("the descriptors' room", 0, 1);
    close(pp[0]);
    close(pp[1]);
    // Its threads: this one, then a second.
    uint64_t me, other, tsd, ids[64], tsds[64];
    pthread_threadid_np(NULL, &me);
    __asm__ volatile("mrs %0, tpidrro_el0" : "=r"(tsd));
    pipe(gate);
    pthread_t th;
    pthread_create(&th, NULL, waiter, NULL);
    pthread_threadid_np(th, &other);
    int ni = proc_pidinfo(getpid(), 28, 0, ids, sizeof ids) / 8;
    int nt = proc_pidinfo(getpid(), 6, 0, tsds, sizeof tsds) / 8;
    int at_me = -1, at_other = -1;
    for (int i = 0; i < ni; i++) {
        if (ids[i] == me) at_me = i;
        if (ids[i] == other) at_other = i;
    }
    if (me <= 100 || ni < 2 || at_me < 0 || at_other <= at_me) return bad("its thread ids", ni, 2);
    if (nt != ni || tsds[at_me] != tsd || tsds[at_other] == 0 || tsds[at_other] == tsd) return bad("its TSD bases", nt, ni);
    if (proc_pidinfo(getpid(), 28, 0, ids, 8) != 8 || ids[0] != me) return bad("one thread id", 0, 1);
    struct thread_identifier_info ti;
    mach_msg_type_number_t cnt = THREAD_IDENTIFIER_INFO_COUNT;
    mach_port_t self = mach_thread_self();
    kern_return_t kr = thread_info(self, THREAD_IDENTIFIER_INFO, (thread_info_t)&ti, &cnt);
    mach_port_deallocate(mach_task_self(), self);
    if (kr != KERN_SUCCESS || cnt != THREAD_IDENTIFIER_INFO_COUNT || ti.thread_id != me || ti.thread_handle != tsd || ti.dispatch_qaddr <= tsd) return bad("its identifier info", kr, 0);
    if (proc_pidinfo(getpid(), 28, 0, ids, 7) != 0 || errno != ENOMEM) return bad("no room", errno, ENOMEM);
    write(gate[1], "", 1);
    pthread_join(th, NULL);

    // A child.
    int p1[2], p2[2];
    pipe(p1);
    pipe(p2);
    char a1[16], a2[16];
    snprintf(a1, sizeof a1, "%d", p1[0]);
    snprintf(a2, sizeof a2, "%d", p2[1]);
    char *args[] = {argv[0], a1, a2, NULL};
    pid_t pid;
    if (posix_spawn(&pid, argv[0], NULL, NULL, args, environ)) return bad("spawn", errno, 0);
    char c;
    read(p2[0], &c, 1);
    struct bsdinfo cb;
    if (proc_pidinfo(pid, 3, 0, &cb, sizeof cb) != sizeof cb) return bad("the child's info", errno, 0);
    if (cb.ppid != (uint32_t)getpid() || cb.nfiles != 50 || cb.status != 2) return bad("the child's parent and table", cb.nfiles, 50);
    struct shortinfo cs;
    if (proc_pidinfo(pid, 13, 0, &cs, sizeof cs) != sizeof cs || cs.ppid != (uint32_t)getpid()) return bad("the child's short info", cs.ppid, getpid());
    int n;
    if (proc_listpids(1, 0, NULL, 0) <= 0) return bad("the list's room", 0, 1);
    if (!listed(1, 0, getpid(), &n) || !listed(1, 0, pid, &n)) return bad("all pids", n, 0);
    if (!listed(6, getpid(), pid, &n) || n != 1) return bad("its children", n, 1);
    if (!listed(2, getpgrp(), getpid(), &n) || !listed(4, geteuid(), getpid(), &n) || !listed(5, getuid(), pid, &n)) return bad("by group and user", n, 0);
    write(p1[1], &c, 1);
    siginfo_t si;
    if (waitid(P_PID, pid, &si, WEXITED | WNOWAIT)) return bad("waitid", errno, 0);
    if (proc_pidinfo(pid, 3, 0, &cb, sizeof cb) != 0 || errno != ESRCH) return bad("a zombie without asking", errno, ESRCH);
    if (proc_pidinfo(pid, 3, 1, &cb, sizeof cb) != sizeof cb || cb.status != 5) return bad("the zombie", cb.status, 5);
    if (!listed(1, 0, pid, &n)) return bad("the zombie listed", n, 0);
    int st;
    waitpid(pid, &st, 0);
    printf("procinfo ok\n");
    return 0;
}
