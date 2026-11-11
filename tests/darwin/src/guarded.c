// Guarded file descriptors (kern_guarded.c): each call's checks, the guard
// and close-on flags change_fdguard_np moves, guarded writes and kqueues; a
// guard that goes with its descriptor and is not a fork's child's; and each
// call a guard refuses ending the process by SIGKILL for an OS_REASON_GUARD
// reason whose code names the guard broken and the descriptor.

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#define SYS_guarded_open_np 441
#define SYS_guarded_close_np 442
#define SYS_guarded_kqueue_np 443
#define SYS_change_fdguard_np 444
#define SYS_guarded_open_dprotected_np 484
#define SYS_guarded_write_np 485
#define SYS_guarded_pwrite_np 486
#define SYS_guarded_writev_np 487
#define SYS_open_dprotected_np 216

#define GUARD_CLOSE 1u
#define GUARD_DUP 2u
#define GUARD_SOCKET_IPC 4u
#define GUARD_FILEPORT 8u
#define GUARD_WRITE 16u

#define EXC_CLOSE 1ull
#define EXC_DUP 2ull
#define EXC_NOCLOEXEC 4ull
#define EXC_SOCKET_IPC 8ull
#define EXC_FILEPORT 16ull
#define EXC_WRITE 64ull

#define FD_CLOFORK 2
#define O_CLOFORK_ 0x08000000
#define PROC_PIDEXITREASONBASICINFO 25
#define OS_REASON_GUARD 23
#define FLAG_GENERATE_CRASH_REPORT 0x2
#define POSIX_SPAWN_SETEXEC_ 0x40

extern char **environ;
int syscall(int, ...);
int proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int buffersize);
int fileport_makeport(int fd, unsigned *port);
int posix_spawn_file_actions_addinherit_np(posix_spawn_file_actions_t *, int);

struct basic {
    uint32_t ns;
    uint64_t code;
    uint64_t flags;
    uint32_t size;
} __attribute__((packed));

static const uint64_t G = 0x1122334455667788ull, H = 0xfeedfacecafebeefull, Z = 0, B = 0xbadull;
static char file[256];
static char self[1024];

static int bad(const char *what, long got, long want) {
    printf("guarded: %s: %#lx, want %#lx\n", what, got, want);
    return 1;
}

static int expect(const char *what, long r, int e) {
    if (r != -1 || errno != e) return bad(what, r == -1 ? errno : r, e);
    return 0;
}

static int gopen(const uint64_t *g, unsigned gf, int flags) {
    return syscall(SYS_guarded_open_np, file, g, gf, flags, 0644);
}

static int gclose(int fd, const uint64_t *g) {
    return syscall(SYS_guarded_close_np, fd, g);
}

static int change(int fd, const uint64_t *g, unsigned gf, const uint64_t *n, unsigned nf, int *fl) {
    return syscall(SYS_change_fdguard_np, fd, g, gf, n, nf, fl);
}

// Each breaks one guard on the descriptor it reports as its exit status
// were it to go on: the process ends in the call.
static int violate(const char *mode) {
    int fd = -1, sv[2], other;
    unsigned port;
    int fl = 0;
    if (!strcmp(mode, "close")) {
        fd = gopen(&G, GUARD_CLOSE | GUARD_DUP, O_RDWR | O_CREAT | O_CLOEXEC);
        close(fd);
    } else if (!strcmp(mode, "dup")) {
        fd = gopen(&G, GUARD_DUP, O_RDWR | O_CREAT | O_CLOEXEC);
        dup(fd);
    } else if (!strcmp(mode, "dup2-old")) {
        fd = gopen(&G, GUARD_DUP, O_RDWR | O_CREAT | O_CLOEXEC);
        dup2(fd, 30);
    } else if (!strcmp(mode, "dup2-new")) {
        fd = gopen(&G, GUARD_CLOSE | GUARD_DUP, O_RDWR | O_CREAT | O_CLOEXEC);
        other = open(file, O_RDONLY);
        dup2(other, fd);
    } else if (!strcmp(mode, "dupfd")) {
        fd = gopen(&G, GUARD_DUP, O_RDWR | O_CREAT | O_CLOEXEC);
        fcntl(fd, F_DUPFD, 40);
    } else if (!strcmp(mode, "dupfd-cloexec")) {
        fd = gopen(&G, GUARD_DUP, O_RDWR | O_CREAT | O_CLOEXEC);
        fcntl(fd, F_DUPFD_CLOEXEC, 40);
    } else if (!strcmp(mode, "setfd")) {
        fd = gopen(&G, GUARD_DUP, O_RDWR | O_CREAT | O_CLOEXEC);
        fcntl(fd, F_SETFD, 0);
    } else if (!strcmp(mode, "fileport")) {
        fd = gopen(&G, GUARD_DUP | GUARD_FILEPORT, O_RDWR | O_CREAT | O_CLOEXEC);
        fileport_makeport(fd, &port);
    } else if (!strcmp(mode, "write")) {
        fd = gopen(&G, GUARD_DUP | GUARD_WRITE, O_RDWR | O_CREAT | O_CLOEXEC);
        write(fd, "x", 1);
    } else if (!strcmp(mode, "scm")) {
        fd = gopen(&G, GUARD_DUP | GUARD_SOCKET_IPC, O_RDWR | O_CREAT | O_CLOEXEC);
        socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
        char byte = 'x';
        struct iovec iov = {&byte, 1};
        char ctl[CMSG_SPACE(sizeof(int))];
        struct msghdr msg = {0};
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = ctl;
        msg.msg_controllen = CMSG_LEN(sizeof(int));
        struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
        c->cmsg_len = CMSG_LEN(sizeof(int));
        c->cmsg_level = SOL_SOCKET;
        c->cmsg_type = SCM_RIGHTS;
        memcpy(CMSG_DATA(c), &fd, sizeof fd);
        sendmsg(sv[0], &msg, 0);
    } else if (!strcmp(mode, "inherit")) {
        // FIONCLEX, which no guard refuses, is how a guarded descriptor
        // reaches an exec's copy of the table.
        fd = gopen(&G, GUARD_DUP, O_RDWR | O_CREAT | O_CLOEXEC);
        ioctl(fd, FIONCLEX, &fl);
        posix_spawn_file_actions_t fa;
        posix_spawnattr_t at;
        posix_spawn_file_actions_init(&fa);
        posix_spawn_file_actions_addinherit_np(&fa, fd);
        posix_spawnattr_init(&at);
        posix_spawnattr_setflags(&at, POSIX_SPAWN_SETEXEC_);
        char *args[] = {self, NULL};
        posix_spawn(NULL, self, &fa, &at, args, environ);
    }
    // The call fails with EPERM before the thread's way back ends it.
    return errno == EPERM ? 10 + fd : 9;
}

static const struct {
    const char *mode;
    unsigned long long flavor;
} kinds[] = {
    {"close", EXC_CLOSE},
    {"dup", EXC_DUP},
    {"dup2-old", EXC_DUP},
    {"dup2-new", EXC_CLOSE},
    {"dupfd", EXC_DUP},
    {"dupfd-cloexec", EXC_DUP},
    {"setfd", EXC_NOCLOEXEC},
    {"fileport", EXC_FILEPORT},
    {"write", EXC_WRITE},
    {"scm", EXC_SOCKET_IPC},
    {"inherit", EXC_NOCLOEXEC},
};

// The child ends by SIGKILL, for a reason whose code is its guard's.
static int expect_kill(const char *mode, unsigned long long flavor) {
    char *args[] = {self, (char *)mode, file, NULL};
    pid_t pid;
    if (posix_spawn(&pid, self, NULL, NULL, args, environ)) return bad(mode, errno, 0);
    siginfo_t si;
    if (waitid(P_PID, pid, &si, WEXITED | WNOWAIT) != 0) return bad("waitid", errno, 0);
    if (si.si_code == CLD_EXITED || si.si_status != SIGKILL) {
        printf("guarded: %s: ended %d status %d\n", mode, si.si_code, si.si_status);
        return 1;
    }
    struct basic b;
    if (proc_pidinfo(pid, PROC_PIDEXITREASONBASICINFO, 0, &b, sizeof b) != sizeof b) return bad("its reason", errno, 0);
    if (b.ns != OS_REASON_GUARD) return bad("the reason's namespace", b.ns, OS_REASON_GUARD);
    if (b.flags != FLAG_GENERATE_CRASH_REPORT) return bad("the reason's flags", (long)b.flags, FLAG_GENERATE_CRASH_REPORT);
    if (b.code >> 61 != 2) return bad("the code's type", (long)(b.code >> 61), 2);
    if (((b.code >> 32) & 0x1fffffff) != flavor) return bad(mode, (long)((b.code >> 32) & 0x1fffffff), (long)flavor);
    if ((b.code & 0xffffffff) >= 256) return bad("the code's descriptor", (long)(b.code & 0xffffffff), 0);
    int st;
    waitpid(pid, &st, 0);
    return 0;
}

int main(int argc, char **argv) {
    strcpy(self, argv[0]);
    if (argc > 2) {
        strcpy(file, argv[2]);
        return violate(argv[1]);
    }
    if (argc > 1) return 0;
    snprintf(file, sizeof file, "/tmp/guarded-%d", getpid());

    // guarded_open_np's checks, in order.
    int fd, st, fl;
    if (expect("no O_CLOEXEC", gopen(&G, GUARD_DUP, O_RDWR | O_CREAT), EINVAL)) return 1;
    if (expect("no GUARD_DUP", gopen(&G, GUARD_CLOSE, O_RDWR | O_CREAT | O_CLOEXEC), EINVAL)) return 1;
    if (expect("unknown attribute", gopen(&G, GUARD_DUP | 0x100, O_RDWR | O_CREAT | O_CLOEXEC), EINVAL)) return 1;
    if (expect("a zero guard", gopen(&Z, GUARD_DUP, O_RDWR | O_CREAT | O_CLOEXEC), EINVAL)) return 1;
    if (expect("a bad address", syscall(SYS_guarded_open_np, file, (void *)8, GUARD_DUP, O_RDWR | O_CREAT | O_CLOEXEC, 0644), EFAULT)) return 1;

    // A guarded open is close-on-exec and close-on-fork.
    if ((fd = gopen(&G, GUARD_CLOSE | GUARD_DUP, O_RDWR | O_CREAT | O_CLOEXEC)) < 0) return bad("guarded_open_np", errno, 0);
    if ((st = fcntl(fd, F_GETFD)) != FD_CLOEXEC) return bad("F_GETFD", st, FD_CLOEXEC);
    fl = 0;
    if (change(fd, &G, GUARD_CLOSE | GUARD_DUP, &G, GUARD_CLOSE | GUARD_DUP, &fl) != 0) return bad("the same guard again", errno, 0);
    if (fl != (FD_CLOEXEC | FD_CLOFORK)) return bad("its flags", fl, FD_CLOEXEC | FD_CLOFORK);

    // guarded_close_np.
    if (expect("the wrong guard", gclose(fd, &H), EPERM)) return 1;
    if (gclose(fd, &G) != 0) return bad("guarded_close_np", errno, 0);
    if (expect("a closed descriptor", gclose(fd, &G), EBADF)) return 1;
    int plain = open(file, O_RDWR);
    if (expect("an unguarded descriptor", gclose(plain, &G), EINVAL)) return 1;

    // A descriptor number that goes to another file has no guard: fd was
    // the lowest free number, and is plain's.
    if (plain != fd) return bad("the number reused", plain, fd);
    if (close(plain) != 0) return bad("close of a reused number", errno, 0);

    // change_fdguard_np's cases.
    plain = open(file, O_RDWR | O_CLOFORK_);
    if (expect("a guard given for none", change(plain, &G, GUARD_DUP, &H, GUARD_DUP, NULL), EINVAL)) return 1;
    if (expect("nothing to remove", change(plain, NULL, 0, NULL, 0, NULL), EINVAL)) return 1;
    if (expect("a zero new guard", change(plain, NULL, 0, &Z, GUARD_DUP, NULL), EINVAL)) return 1;
    if (expect("no GUARD_DUP in a new guard", change(plain, NULL, 0, &G, GUARD_CLOSE, NULL), EINVAL)) return 1;
    fl = 0;
    if (change(plain, NULL, 0, &G, GUARD_DUP, &fl) != 0) return bad("adding a guard", errno, 0);
    if (fl != FD_CLOFORK) return bad("the flags before", fl, FD_CLOFORK);
    if ((st = fcntl(plain, F_GETFD)) != FD_CLOEXEC) return bad("a guard's close-on-exec", st, FD_CLOEXEC);
    if (expect("a guard missing", change(plain, NULL, 0, &H, GUARD_DUP, NULL), EINVAL)) return 1;
    if (expect("a zero old guard", change(plain, &Z, GUARD_DUP, &H, GUARD_DUP, NULL), EPERM)) return 1;
    if (expect("the wrong old guard", change(plain, &B, GUARD_DUP, &H, GUARD_DUP, NULL), EPERM)) return 1;
    if (expect("the wrong old flags", change(plain, &G, GUARD_DUP | GUARD_CLOSE, &H, GUARD_DUP, NULL), EPERM)) return 1;
    if (change(plain, &G, GUARD_DUP, &H, GUARD_DUP | GUARD_CLOSE, NULL) != 0) return bad("swapping a guard", errno, 0);
    fl = 0;
    if (change(plain, &H, GUARD_DUP | GUARD_CLOSE, &G, GUARD_DUP, &fl) != 0) return bad("swapping back", errno, 0);
    if (fl != (FD_CLOEXEC | FD_CLOFORK)) return bad("GUARD_CLOSE's close-on-fork", fl, FD_CLOEXEC | FD_CLOFORK);
    fl = 0;
    if (change(plain, &G, GUARD_DUP, &H, GUARD_DUP, &fl) != 0) return bad("a swap", errno, 0);
    if (fl != FD_CLOEXEC) return bad("close-on-fork gone with GUARD_CLOSE", fl, FD_CLOEXEC);
    if (expect("removal with new flags", change(plain, &H, GUARD_DUP, NULL, GUARD_DUP, NULL), EINVAL)) return 1;
    fl = FD_CLOFORK;
    if (change(plain, &H, GUARD_DUP, NULL, 0, &fl) != 0) return bad("removing a guard", errno, 0);
    if ((st = fcntl(plain, F_GETFD)) != 0) return bad("the flags restored", st, 0);
    if (close(plain) != 0) return bad("close after removal", errno, 0);
    if (expect("a bad descriptor", change(987, NULL, 0, &G, GUARD_DUP, NULL), EBADF)) return 1;

    // A guarded write; the plain call is refused only when GUARD_WRITE is
    // on (violations below).
    if ((fd = gopen(&G, GUARD_DUP | GUARD_WRITE, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC)) < 0) return bad("open", errno, 0);
    if (syscall(SYS_guarded_write_np, fd, &G, "ab", 2) != 2) return bad("guarded_write_np", errno, 0);
    if (syscall(SYS_guarded_pwrite_np, fd, &G, "cd", 2, 8) != 2) return bad("guarded_pwrite_np", errno, 0);
    struct iovec iov = {"ef", 2};
    if (syscall(SYS_guarded_writev_np, fd, &G, &iov, 1) != 2) return bad("guarded_writev_np", errno, 0);
    if (expect("a write with the wrong guard", syscall(SYS_guarded_write_np, fd, &H, "x", 1), EPERM)) return 1;
    char got[10] = {0};
    if (pread(fd, got, 10, 0) != 10 || memcmp(got, "abef\0\0\0\0cd", 10)) return bad("the file written", got[0], 'a');
    if (gclose(fd, &G) != 0) return bad("close", errno, 0);
    plain = open(file, O_RDONLY);
    if (expect("a guarded write unguarded", syscall(SYS_guarded_write_np, plain, &G, "x", 1), EINVAL)) return 1;
    close(plain);
    if ((fd = gopen(&G, GUARD_DUP | GUARD_WRITE, O_RDONLY | O_CLOEXEC)) < 0) return bad("open", errno, 0);
    if (expect("a guarded write read-only", syscall(SYS_guarded_write_np, fd, &G, "x", 1), EBADF)) return 1;
    if (expect("a plain write read-only", write(fd, "x", 1), EBADF)) return 1;
    gclose(fd, &G);

    // A guarded kqueue.
    if (expect("a kqueue without GUARD_DUP", syscall(SYS_guarded_kqueue_np, &G, GUARD_CLOSE), EINVAL)) return 1;
    if ((fd = syscall(SYS_guarded_kqueue_np, &G, GUARD_DUP | GUARD_CLOSE)) < 0) return bad("guarded_kqueue_np", errno, 0);
    struct kevent ev;
    struct timespec zero = {0, 0};
    if (kevent(fd, NULL, 0, &ev, 1, &zero) != 0) return bad("kevent on it", errno, 0);
    if ((st = fcntl(fd, F_GETFD)) != FD_CLOEXEC) return bad("kqueue F_GETFD", st, FD_CLOEXEC);
    if (expect("a kqueue's wrong guard", gclose(fd, &H), EPERM)) return 1;
    if (gclose(fd, &G) != 0) return bad("a kqueue's close", errno, 0);

    // The protected opens: a class with O_CREAT for a file that exists,
    // which keeps its own, and flags that need no contents read raw.
    if ((fd = syscall(SYS_guarded_open_dprotected_np, file, &G, GUARD_DUP, O_RDWR | O_CREAT | O_CLOEXEC, 3, 0, 0644)) < 0) return bad("guarded_open_dprotected_np", errno, 0);
    if (gclose(fd, &G) != 0) return bad("its close", errno, 0);
    if ((fd = syscall(SYS_open_dprotected_np, file, O_RDWR | O_CREAT, 3, 0, 0644)) < 0) return bad("open_dprotected_np", errno, 0);
    close(fd);
    if (expect("O_DP_AUTHENTICATE", syscall(SYS_open_dprotected_np, file, O_RDONLY, 3, 4, 0), EINVAL)) return 1;
    if (expect("raw contents written", syscall(SYS_open_dprotected_np, file, O_RDWR, 3, 1, 0), EINVAL)) return 1;

    // A fork's child: an FP_CLOFORK descriptor is gone, another stays
    // without its guard.
    int gone = gopen(&G, GUARD_CLOSE | GUARD_DUP, O_RDWR | O_CREAT | O_CLOEXEC);
    plain = open(file, O_RDWR);
    if (change(plain, NULL, 0, &H, GUARD_DUP, NULL) != 0) return bad("guarding", errno, 0);
    pid_t pid = fork();
    if (pid == 0) {
        if (fcntl(gone, F_GETFD) != -1 || errno != EBADF) _exit(21);
        if (gclose(plain, &H) != -1 || errno != EINVAL) _exit(22);
        if (dup(plain) < 0) _exit(23);
        _exit(close(plain) == 0 ? 0 : 24);
    }
    if (waitpid(pid, &st, 0) != pid || st != 0) return bad("the fork's child", st, 0);
    gclose(gone, &G);
    gclose(plain, &H);

    // An exec's copy has no close-on-exec descriptors for file actions.
    int cx = open(file, O_RDONLY | O_CLOEXEC);
    posix_spawn_file_actions_t fa;
    posix_spawnattr_t at;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, cx, 25);
    posix_spawnattr_init(&at);
    posix_spawnattr_setflags(&at, POSIX_SPAWN_SETEXEC_);
    char *args[] = {self, "exec-test", NULL};
    if ((st = posix_spawn(NULL, self, &fa, &at, args, environ)) != EBADF) return bad("dup2 of a close-on-exec descriptor in place", st, EBADF);
    close(cx);

    // FIONCLEX is not refused.
    fd = gopen(&G, GUARD_DUP, O_RDWR | O_CREAT | O_CLOEXEC);
    if (ioctl(fd, FIONCLEX, &st) != 0) return bad("FIONCLEX", errno, 0);
    if ((st = fcntl(fd, F_GETFD)) != 0) return bad("its result", st, 0);
    gclose(fd, &G);

    for (unsigned i = 0; i < sizeof kinds / sizeof kinds[0]; i++) {
        if (expect_kill(kinds[i].mode, kinds[i].flavor)) return 1;
    }
    unlink(file);
    puts("guarded ok");
    return 0;
}
