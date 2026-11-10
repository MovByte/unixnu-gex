// File lock importance: an adaptive daemon holding a POSIX lock is boosted
// while a donor waits for the lock (a file lock assertion), not while a
// process that is no donor does, and not once it has unlocked.

#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

int posix_spawnattr_setprocesstype_np(posix_spawnattr_t *, int);
int proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int buffersize);

#define POSIX_SPAWN_PROC_TYPE_DAEMON_ADAPTIVE 0x600
#define PROC_PIDTBSDINFO 3
#define PROC_FLAG_ADAPTIVE_IMPORTANT 0x200000

extern char **environ;

// struct proc_bsdinfo.
struct bsdinfo {
    uint32_t flags, status, xstatus, pid, ppid, uid, gid, ruid, rgid, svuid, svgid, rfu;
    char comm[16];
    char name[32];
    uint32_t nfiles, pgid, pjobc, tdev, tpgid;
    int32_t nice;
    uint64_t start_sec, start_usec;
};

// process_policy(2), which libsystem has no wrapper for.
static long process_policy(long scope, long action, long policy, long subtype, void *attr, long pid, uint64_t tid) {
    register long x0 __asm__("x0") = scope;
    register long x1 __asm__("x1") = action;
    register long x2 __asm__("x2") = policy;
    register long x3 __asm__("x3") = subtype;
    register void *x4 __asm__("x4") = attr;
    register long x5 __asm__("x5") = pid;
    register uint64_t x6 __asm__("x6") = tid;
    register long x16 __asm__("x16") = 323;
    long carry;
    __asm__ volatile("svc #0x80\n\tcset %1, cs" : "+r"(x0), "=r"(carry) : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x6), "r"(x16) : "memory", "cc");
    if (carry) {
        errno = (int)x0;
        return -1;
    }
    return x0;
}

static int bad(const char *who, const char *what, long got, long want) {
    printf("lockimp: %s: %s: %ld, want %ld\n", who, what, got, want);
    fflush(stdout);
    return 1;
}

static int boosted(pid_t pid) {
    struct bsdinfo bi;
    if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bi, sizeof bi) != sizeof bi) return -1;
    return (bi.flags & PROC_FLAG_ADAPTIVE_IMPORTANT) != 0;
}

static pid_t spawn_as(const char *path, char *role, char *file, char *fd1, char *fd2) {
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_setprocesstype_np(&attr, POSIX_SPAWN_PROC_TYPE_DAEMON_ADAPTIVE);
    char *args[] = {(char *)path, role, file, fd1, fd2, NULL};
    pid_t c;
    int err = posix_spawn(&c, path, NULL, &attr, args, environ);
    posix_spawnattr_destroy(&attr);
    return err ? -err : c;
}

static int lock(int fd, short type, int wait) {
    struct flock fl = {.l_type = type, .l_whence = SEEK_SET};
    return fcntl(fd, wait ? F_SETLKW : F_SETLK, &fl);
}

// A boost seen within about two seconds (or its absence over half one).
static int settles(pid_t pid, int want) {
    for (int i = 0; i < (want ? 200 : 50); i++) {
        if (boosted(pid) == want && want) return 1;
        if (boosted(pid) != 0 && !want) return 0;
        usleep(10000);
    }
    return boosted(pid) == want;
}

int main(int argc, char **argv) {
    if (argc == 5) {
        int fd = open(argv[2], O_RDWR), out = atoi(argv[3]), in = atoi(argv[4]);
        char c;
        if (!strcmp(argv[1], "holder")) {
            if (lock(fd, F_WRLCK, 0)) return bad("holder", "lock", errno, 0);
            write(out, "L", 1);
            read(in, &c, 1);
            if (lock(fd, F_UNLCK, 0)) return bad("holder", "unlock", errno, 0);
            // The boost goes with the lock.
            int f = boosted(getpid()) != 0 ? bad("holder", "boosted unlocked", boosted(getpid()), 0) : 0;
            read(in, &c, 1);
            return f;
        }
        // A waiter, a donor if asked (proc_donate_importance_boost).
        if (!strcmp(argv[1], "donor") && process_policy(1, 10, 7, 3, NULL, getpid(), 0)) return bad("donor", "donation", errno, 0);
        write(out, "W", 1);
        if (lock(fd, F_WRLCK, 1)) return bad(argv[1], "wait", errno, 0);
        lock(fd, F_UNLCK, 0);
        return 0;
    }
    int fail = 0;
    char path[64], a[16], b[16], c;
    snprintf(path, sizeof path, "/private/var/tmp/lockimp-%d", getpid());
    close(open(path, O_CREAT | O_RDWR, 0644));
    int up[2], down[2];
    pipe(up);
    pipe(down);
    snprintf(a, sizeof a, "%d", up[1]);
    snprintf(b, sizeof b, "%d", down[0]);
    pid_t h = spawn_as(argv[0], "holder", path, a, b);
    if (h < 0) return bad("main", "spawn holder", -h, 0);
    if (read(up[0], &c, 1) != 1 || c != 'L') return bad("main", "holder's lock", c, 'L');
    fail |= boosted(h) != 0 ? bad("main", "holder at start", boosted(h), 0) : 0;
    // One that is no donor waits: no boost.
    pid_t n = spawn_as(argv[0], "plain", path, a, b);
    if (read(up[0], &c, 1) != 1 || c != 'W') return bad("main", "plain waiter", c, 'W');
    fail |= !settles(h, 0) ? bad("main", "boost by no donor", boosted(h), 0) : 0;
    // A donor waits: the holder is boosted.
    pid_t d = spawn_as(argv[0], "donor", path, a, b);
    if (read(up[0], &c, 1) != 1 || c != 'W') return bad("main", "donor waiter", c, 'W');
    fail |= !settles(h, 1) ? bad("main", "boost by a donor", boosted(h), 1) : 0;
    // Unlocked: no boost (the holder checks).
    write(down[1], "g", 1);
    int st;
    waitpid(d, &st, 0);
    fail |= !WIFEXITED(st) || WEXITSTATUS(st) ? bad("main", "donor", st, 0) : 0;
    waitpid(n, &st, 0);
    fail |= !WIFEXITED(st) || WEXITSTATUS(st) ? bad("main", "plain", st, 0) : 0;
    write(down[1], "g", 1);
    waitpid(h, &st, 0);
    fail |= !WIFEXITED(st) || WEXITSTATUS(st) ? bad("main", "holder", st, 0) : 0;
    unlink(path);
    if (!fail) printf("lockimp ok\n");
    return fail;
}
