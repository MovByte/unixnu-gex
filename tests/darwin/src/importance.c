// IPC importance: an adaptive daemon (an importance receiver) is boosted
// while a donor's message waits on its port that takes donations, and the
// port counts the boost; received without a voucher the message says so
// (MACH_MSGH_BITS_RAISEIMP) and leaves the boost as a legacy assertion the
// receiver drops; received with one, the voucher holds it, as an inherit
// that names both processes, until the voucher goes. A sender that is no
// donor (an adaptive daemon not boosted, until it marks itself a donor)
// boosts nothing.

#include <errno.h>
#include <mach/mach.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

int posix_spawnattr_setprocesstype_np(posix_spawnattr_t *, int);
int proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int buffersize);
kern_return_t mach_voucher_extract_attr_content(mach_port_t, uint32_t, uint8_t *, mach_msg_type_number_t *);

#define POSIX_SPAWN_PROC_TYPE_DAEMON_ADAPTIVE 0x600
#define PROC_POLICY_SCOPE_PROCESS 1
#define PROC_POLICY_ACTION_SET 10
#define PROC_POLICY_ACTION_HOLD 14
#define PROC_POLICY_ACTION_DROP 15
#define PROC_POLICY_BOOST 7
#define PROC_POLICY_IMP_IMPORTANT 1
#define PROC_POLICY_IMP_DONATION 3
#define PROC_FLAG_ADAPTIVE_IMPORTANT 0x200000
#define MACH_PORT_IMPORTANCE_RECEIVER 5
#define PROC_PIDTBSDINFO 3

// struct proc_bsdinfo.
struct bsdinfo {
    uint32_t flags, status, xstatus, pid, ppid, uid, gid, ruid, rgid, svuid, svgid, rfu;
    char comm[16];
    char name[32];
    uint32_t nfiles, pgid, pjobc, tdev, tpgid;
    int32_t nice;
    uint64_t start_sec, start_usec;
};

extern char **environ;

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
    printf("importance: %s: %s: %ld, want %ld\n", who, what, got, want);
    fflush(stdout);
    return 1;
}

typedef struct {
    mach_msg_header_t h;
    mach_msg_body_t b;
    mach_msg_port_descriptor_t p;
} pmsg;

typedef struct {
    pmsg m;
    char pad[64];
    mach_msg_trailer_t t;
} rmsg;

static kern_return_t msend(mach_port_t to, mach_port_t carried, int id) {
    pmsg m;
    memset(&m, 0, sizeof m);
    m.h.msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND, 0, 0, carried ? MACH_MSGH_BITS_COMPLEX : 0);
    m.h.msgh_remote_port = to;
    m.h.msgh_size = carried ? sizeof m : sizeof m.h;
    m.h.msgh_id = id;
    if (carried) {
        m.b.msgh_descriptor_count = 1;
        m.p.name = carried;
        m.p.disposition = MACH_MSG_TYPE_MAKE_SEND;
        m.p.type = MACH_MSG_PORT_DESCRIPTOR;
    }
    return mach_msg(&m.h, MACH_SEND_MSG, m.h.msgh_size, 0, 0, 0, 0);
}

static kern_return_t mrecv(mach_port_t on, rmsg *r, int voucher) {
    return mach_msg(&r->m.h, MACH_RCV_MSG | (voucher ? MACH_RCV_VOUCHER : 0), 0, sizeof *r, on, 0, 0);
}

static int boosted(void) {
    struct bsdinfo bi;
    if (proc_pidinfo(getpid(), PROC_PIDTBSDINFO, 0, &bi, sizeof bi) != sizeof bi) return -1;
    return (bi.flags & PROC_FLAG_ADAPTIVE_IMPORTANT) != 0;
}

static unsigned boost_count(mach_port_t p) {
    mach_port_info_ext_t info;
    mach_msg_type_number_t n = MACH_PORT_INFO_EXT_COUNT;
    if (mach_port_get_attributes(mach_task_self(), p, MACH_PORT_INFO_EXT, (mach_port_info_t)&info, &n) != KERN_SUCCESS) return 999;
    return info.mpie_boost_cnt;
}

static int legacy(int action) {
    return process_policy(PROC_POLICY_SCOPE_PROCESS, action, PROC_POLICY_BOOST, PROC_POLICY_IMP_IMPORTANT, NULL, getpid(), 0) ? errno : 0;
}

static int child(void) {
    int fail = 0;
    int parent = getppid();
    mach_port_t bp, x, y;
    task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &bp);
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &x);
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &y);
    int info = 0;
    fail |= mach_port_set_attributes(mach_task_self(), x, MACH_PORT_IMPORTANCE_RECEIVER, &info, 0) != KERN_SUCCESS ? bad("child", "receiver attribute", 1, 0) : 0;
    fail |= boosted() != 0 ? bad("child", "boosted at start", boosted(), 0) : 0;
    // x to the parent, then y.
    if (msend(bp, x, 1) || msend(bp, y, 2)) return bad("child", "send ports", 1, 0);
    rmsg r;

    // From no donor: no boost.
    if (mrecv(y, &r, 0)) return bad("child", "go 0", 1, 0);
    fail |= boost_count(x) != 0 || boosted() != 0 ? bad("child", "no donor's boost", boost_count(x), 0) : 0;
    if (mrecv(x, &r, 0)) return bad("child", "m0", 1, 0);
    fail |= r.m.h.msgh_bits & MACH_MSGH_BITS_RAISEIMP ? bad("child", "m0 raised", r.m.h.msgh_bits, 0) : 0;
    msend(bp, 0, 3);

    // A donor's: boosted while it waits; received, a legacy boost.
    if (mrecv(y, &r, 0)) return bad("child", "go 1", 1, 0);
    fail |= boost_count(x) != 1 ? bad("child", "boost count", boost_count(x), 1) : 0;
    fail |= boosted() != 1 ? bad("child", "boosted by m1", boosted(), 1) : 0;
    if (mrecv(x, &r, 0)) return bad("child", "m1", 1, 0);
    fail |= !(r.m.h.msgh_bits & MACH_MSGH_BITS_RAISEIMP) ? bad("child", "m1 raised", r.m.h.msgh_bits, MACH_MSGH_BITS_RAISEIMP) : 0;
    fail |= boost_count(x) != 0 ? bad("child", "boost count received", boost_count(x), 0) : 0;
    fail |= boosted() != 1 ? bad("child", "legacy boost", boosted(), 1) : 0;
    // One more taken on the one held, and both dropped; then none to drop
    // and none to take another on.
    fail |= legacy(PROC_POLICY_ACTION_HOLD) ? bad("child", "hold another", legacy(PROC_POLICY_ACTION_HOLD), 0) : 0;
    fail |= legacy(PROC_POLICY_ACTION_DROP) || legacy(PROC_POLICY_ACTION_DROP) ? bad("child", "drop both", 1, 0) : 0;
    fail |= boosted() != 0 ? bad("child", "dropped", boosted(), 0) : 0;
    int e;
    fail |= (e = legacy(PROC_POLICY_ACTION_DROP)) != EOVERFLOW ? bad("child", "over-drop", e, EOVERFLOW) : 0;
    fail |= (e = legacy(PROC_POLICY_ACTION_HOLD)) != ENOTSUP ? bad("child", "hold without one", e, ENOTSUP) : 0;
    msend(bp, 0, 4);

    // Received with a voucher: the voucher keeps the boost.
    if (mrecv(y, &r, 0)) return bad("child", "go 2", 1, 0);
    fail |= boosted() != 1 ? bad("child", "boosted by m2", boosted(), 1) : 0;
    if (mrecv(x, &r, 1)) return bad("child", "m2", 1, 0);
    mach_port_t v = r.m.h.msgh_voucher_port;
    fail |= MACH_MSGH_BITS_VOUCHER(r.m.h.msgh_bits) != MACH_MSG_TYPE_MOVE_SEND || !MACH_PORT_VALID(v) ? bad("child", "voucher", v, 1) : 0;
    fail |= !(r.m.h.msgh_bits & MACH_MSGH_BITS_RAISEIMP) ? bad("child", "m2 raised", r.m.h.msgh_bits, MACH_MSGH_BITS_RAISEIMP) : 0;
    char buf[256], want[256];
    mach_msg_type_number_t n = sizeof buf;
    memset(buf, 0, sizeof buf);
    kern_return_t kr = mach_voucher_extract_attr_content(v, MACH_VOUCHER_ATTR_KEY_IMPORTANCE, (uint8_t *)buf, &n);
    snprintf(want, sizeof want, "Importance for pid %d (1 of 1 boosts) donated from pid %d", getpid(), parent);
    if (kr || strcmp(buf, want) || n != strlen(want) + 1) {
        printf("importance: child: content (%d, %u) \"%s\"\n", kr, n, buf);
        fail = 1;
    }
    fail |= boosted() != 1 ? bad("child", "voucher's boost", boosted(), 1) : 0;
    mach_port_deallocate(mach_task_self(), v);
    fail |= boosted() != 0 ? bad("child", "voucher gone", boosted(), 0) : 0;
    msend(bp, 0, 5);
    return fail;
}

static pid_t spawn_as(const char *path, const char *role, int proctype) {
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_setprocesstype_np(&attr, proctype);
    char *args[] = {(char *)path, (char *)role, NULL};
    pid_t c;
    int err = posix_spawn(&c, path, NULL, &attr, args, environ);
    posix_spawnattr_destroy(&attr);
    return err ? -err : c;
}

static int parent(const char *path) {
    int fail = 0;
    mach_port_t b, saved;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &b);
    mach_port_insert_right(mach_task_self(), b, b, MACH_MSG_TYPE_MAKE_SEND);
    task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &saved);
    task_set_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, b);
    pid_t c = spawn_as(path, "child", POSIX_SPAWN_PROC_TYPE_DAEMON_ADAPTIVE);
    task_set_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, saved);
    if (c < 0) return bad("parent", "spawn", -c, 0);
    rmsg r;
    if (mrecv(b, &r, 0) || r.m.h.msgh_id != 1) return bad("parent", "x", 1, 0);
    mach_port_t x = r.m.p.name;
    if (mrecv(b, &r, 0) || r.m.h.msgh_id != 2) return bad("parent", "y", 1, 0);
    mach_port_t y = r.m.p.name;

    // Not yet a donor.
    fail |= msend(x, 0, 10) || msend(y, 0, 20) ? bad("parent", "m0", 1, 0) : 0;
    if (mrecv(b, &r, 0) || r.m.h.msgh_id != 3) return bad("parent", "done 0", r.m.h.msgh_id, 3);
    // A donor (proc_donate_importance_boost).
    fail |= process_policy(PROC_POLICY_SCOPE_PROCESS, PROC_POLICY_ACTION_SET, PROC_POLICY_BOOST, PROC_POLICY_IMP_DONATION, NULL, getpid(), 0) ? bad("parent", "donor", errno, 0) : 0;
    fail |= msend(x, 0, 11) || msend(y, 0, 21) ? bad("parent", "m1", 1, 0) : 0;
    if (mrecv(b, &r, 0) || r.m.h.msgh_id != 4) return bad("parent", "done 1", r.m.h.msgh_id, 4);
    fail |= msend(x, 0, 12) || msend(y, 0, 22) ? bad("parent", "m2", 1, 0) : 0;
    if (mrecv(b, &r, 0) || r.m.h.msgh_id != 5) return bad("parent", "done 2", r.m.h.msgh_id, 5);
    int st;
    waitpid(c, &st, 0);
    fail |= !WIFEXITED(st) || WEXITSTATUS(st) ? bad("parent", "child", st, 0) : 0;
    return fail;
}

int main(int argc, char **argv) {
    int f;
    if (argc > 1 && !strcmp(argv[1], "child")) {
        f = child();
    } else if (argc > 1 && !strcmp(argv[1], "parent")) {
        f = parent(argv[0]);
    } else {
        // The sender: an adaptive daemon, which is no donor unboosted.
        pid_t p = spawn_as(argv[0], "parent", POSIX_SPAWN_PROC_TYPE_DAEMON_ADAPTIVE);
        if (p < 0) return bad("main", "spawn", -p, 0);
        int st;
        waitpid(p, &st, 0);
        f = !WIFEXITED(st) || WEXITSTATUS(st);
        if (!f) printf("importance ok\n");
    }
    fflush(stdout);
    return f;
}
