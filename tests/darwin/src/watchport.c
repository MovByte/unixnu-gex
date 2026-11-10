// Importance watch ports: a port that takes donations and is a temporary
// owner, given to a spawned adaptive daemon to watch, sends its boosts to
// that daemon though another task receives from it: a donor's message
// waiting on it before the spawn boosts the daemon once it starts, the
// message's receipt takes the boost away, and the next one boosts it again.

#include <errno.h>
#include <mach/mach.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

int posix_spawnattr_setprocesstype_np(posix_spawnattr_t *, int);
int posix_spawnattr_set_importancewatch_port_np(posix_spawnattr_t *, int, mach_port_t *);
int proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int buffersize);

#define POSIX_SPAWN_PROC_TYPE_DAEMON_ADAPTIVE 0x600
#define PROC_FLAG_ADAPTIVE_IMPORTANT 0x200000

extern char **environ;

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

static int bad(const char *what, long got, long want) {
    printf("watchport: %s: %ld, want %ld\n", what, got, want);
    fflush(stdout);
    return 1;
}

static int boosted(pid_t pid) {
    struct bsdinfo bi;
    if (proc_pidinfo(pid, 3, 0, &bi, sizeof bi) != sizeof bi) return -1;
    return (bi.flags & PROC_FLAG_ADAPTIVE_IMPORTANT) != 0;
}

// The boost seen within about two seconds.
static int becomes(pid_t pid, int want) {
    for (int i = 0; i < 200; i++) {
        if (boosted(pid) == want) return 1;
        usleep(10000);
    }
    return 0;
}

static kern_return_t send0(mach_port_t to) {
    mach_msg_header_t h = {0};
    h.msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND, 0, 0, 0);
    h.msgh_remote_port = to;
    h.msgh_size = sizeof h;
    return mach_msg(&h, MACH_SEND_MSG, sizeof h, 0, 0, 0, 0);
}

static kern_return_t recv0(mach_port_t on) {
    struct {
        mach_msg_header_t h;
        mach_msg_trailer_t t;
    } m;
    return mach_msg(&m.h, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof m, on, 1000, 0);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        // The watching daemon: it waits to be told to go.
        char c;
        read(0, &c, 1);
        return 0;
    }
    int fail = 0;
    // A donor (proc_donate_importance_boost).
    if (process_policy(1, 10, 7, 3, NULL, getpid(), 0)) return bad("donor", errno, 0);
    mach_port_t w;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &w);
    mach_port_insert_right(mach_task_self(), w, w, MACH_MSG_TYPE_MAKE_SEND);
    int info = 0;
    if (mach_port_set_attributes(mach_task_self(), w, MACH_PORT_TEMPOWNER, &info, 0)) return bad("tempowner", 1, 0);
    // A boost waiting before the daemon starts.
    fail |= send0(w) ? bad("first send", 1, 0) : 0;

    int fds[2];
    pipe(fds);
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, fds[0], 0);
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_setprocesstype_np(&attr, POSIX_SPAWN_PROC_TYPE_DAEMON_ADAPTIVE);
    posix_spawnattr_set_importancewatch_port_np(&attr, 1, &w);
    char *args[] = {argv[0], "watch", NULL};
    pid_t c;
    int e = posix_spawn(&c, argv[0], &fa, &attr, args, environ);
    if (e) return bad("spawn", e, 0);
    close(fds[0]);
    fail |= !becomes(c, 1) ? bad("boosted by the waiting message", boosted(c), 1) : 0;
    // Received here: the daemon's boost goes.
    fail |= recv0(w) ? bad("receive", 1, 0) : 0;
    fail |= !becomes(c, 0) ? bad("unboosted", boosted(c), 0) : 0;
    // The next message boosts it again, until received.
    fail |= send0(w) ? bad("second send", 1, 0) : 0;
    fail |= !becomes(c, 1) ? bad("boosted again", boosted(c), 1) : 0;
    fail |= recv0(w) ? bad("receive again", 1, 0) : 0;
    fail |= !becomes(c, 0) ? bad("unboosted again", boosted(c), 0) : 0;
    write(fds[1], "x", 1);
    int st;
    waitpid(c, &st, 0);
    fail |= !WIFEXITED(st) || WEXITSTATUS(st) ? bad("daemon", st, 0) : 0;
    if (!fail) printf("watchport ok\n");
    return fail;
}
