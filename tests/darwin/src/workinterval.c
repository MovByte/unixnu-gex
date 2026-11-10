// work_interval_ctl: creating, joining, leaving and notifying work
// intervals, a joinable one's port, the deferred group of one that waits for
// a workload ID, a Core Audio one's realtime requirement, and the errors.

#include <errno.h>
#include <mach/mach.h>
#include <mach/thread_policy.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define SYS_WORK_INTERVAL_CTL 499
#define OP_CREATE 1
#define OP_DESTROY 2
#define OP_NOTIFY 3
#define OP_CREATE2 4
#define OP_JOIN 5
#define OP_GET_FLAGS 9
#define OP_SET_NAME 10
#define OP_SET_WORKLOAD_ID 11
#define F_JOINABLE 0x1
#define F_GROUP 0x2
#define F_HAS_WORKLOAD_ID 0x80
#define T_COREAUDIO (1u << 28)
#define T_CA_CLIENT (3u << 28)
#define T_HID (4u << 28)

static long wi(uint32_t op, uint64_t id, void *arg, size_t len) {
    register long x0 __asm__("x0") = op, x1 __asm__("x1") = (long)id, x2 __asm__("x2") = (long)arg, x3 __asm__("x3") = (long)len;
    register long x16 __asm__("x16") = SYS_WORK_INTERVAL_CTL, cs __asm__("x9");
    __asm__ volatile("svc #0x80\n cset x9, cs" : "+r"(x0), "+r"(x1), "=r"(cs) : "r"(x2), "r"(x3), "r"(x16) : "x4", "x5", "x6", "x7", "x8", "x10", "x11", "x12", "x13", "x14", "x15", "x17", "memory", "cc");
    if (cs) {
        errno = (int)x0;
        return -1;
    }
    return x0;
}

struct create_params {
    uint64_t id;
    uint32_t port;
    uint32_t flags;
};

struct notification {
    uint64_t start, finish, deadline, next_start;
    uint32_t notify_flags, create_flags;
};

struct workload_id_params {
    uint32_t flags;
    uint32_t wicreate_flags;
    uint64_t name;
    uint64_t syscall_mask[2];
};

static int bad(const char *what, long got, long want) {
    printf("workinterval: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

static int expect(const char *what, long r, int e) {
    if (r != -1 || errno != e) return bad(what, r == -1 ? errno : r, e);
    return 0;
}

static int create(uint32_t flags, struct create_params *p) {
    memset(p, 0, sizeof *p);
    p->flags = flags;
    return (int)wi(OP_CREATE2, 0, p, sizeof *p);
}

static struct notification note;

static void *joiner(void *port) {
    long r = wi(OP_JOIN, (uint32_t)(uintptr_t)port, NULL, 0);
    return (void *)(r == 0 ? 0 : (long)errno);
}

int main(void) {
    int fail = 0;
    struct create_params p;

    // The old create and an operation there is none of.
    fail |= expect("CREATE", wi(OP_CREATE, 0, &p, sizeof p), ENOTSUP);
    fail |= expect("operation 99", wi(99, 0, NULL, 0), ENOTSUP);
    fail |= expect("CREATE2 of nothing", wi(OP_CREATE2, 0, NULL, sizeof p), EINVAL);
    fail |= expect("CREATE2 with an id", wi(OP_CREATE2, 5, &p, sizeof p), EINVAL);
    fail |= expect("CREATE2 short", wi(OP_CREATE2, 0, &p, sizeof p - 1), EINVAL);

    // One the thread joins: no port, ids from 2 on.
    if (create(0, &p) != 0) return bad("CREATE2", errno, 0);
    uint64_t id = p.id;
    if (id < 2 || p.port != 0 || p.flags != 0) return bad("its params", (long)id, 2);
    fail |= expect("a second, joined", create(0, &p), EALREADY);
    fail |= wi(OP_NOTIFY, id, &note, sizeof note) != 0 ? bad("NOTIFY", errno, 0) : 0;
    fail |= expect("NOTIFY another id", wi(OP_NOTIFY, id + 1000, &note, sizeof note), EINVAL);
    fail |= expect("NOTIFY short", wi(OP_NOTIFY, id, &note, sizeof note - 1), EINVAL);
    fail |= expect("NOTIFY of nothing", wi(OP_NOTIFY, id, NULL, sizeof note), EINVAL);
    fail |= expect("DESTROY with an arg", wi(OP_DESTROY, id, &p, 0), EINVAL);
    fail |= expect("DESTROY another id", wi(OP_DESTROY, id + 1000, NULL, 0), EINVAL);
    fail |= wi(OP_DESTROY, id, NULL, 0) != 0 ? bad("DESTROY", errno, 0) : 0;
    fail |= expect("DESTROY again", wi(OP_DESTROY, id, NULL, 0), EINVAL);
    fail |= expect("NOTIFY after", wi(OP_NOTIFY, id, &note, sizeof note), EINVAL);

    // A joinable one: its port, which threads join by.
    if (create(F_JOINABLE | F_GROUP, &p) != 0) return bad("joinable", errno, 0);
    uint32_t port = p.port;
    uint64_t jid = p.id;
    if (!MACH_PORT_VALID(port) || jid <= id) return bad("joinable params", port, 1);
    struct create_params g = {0};
    if (wi(OP_GET_FLAGS, port, &g, sizeof g) != 0 || g.flags != (F_JOINABLE | F_GROUP) || g.port != port || g.id != 0) return bad("GET_FLAGS", errno, 0);
    fail |= expect("GET_FLAGS of no port", wi(OP_GET_FLAGS, 0, &g, sizeof g), EINVAL);
    fail |= expect("GET_FLAGS of the task's", wi(OP_GET_FLAGS, mach_task_self(), &g, sizeof g), EINVAL);
    char name[32] = "renderer";
    fail |= wi(OP_SET_NAME, port, name, sizeof name) != 0 ? bad("SET_NAME", errno, 0) : 0;
    fail |= expect("SET_NAME short", wi(OP_SET_NAME, port, name, 31), EINVAL);
    fail |= expect("NOTIFY before joining", wi(OP_NOTIFY, jid, &note, sizeof note), EINVAL);
    fail |= expect("JOIN with an arg", wi(OP_JOIN, port, &p, 0), EINVAL);
    fail |= wi(OP_JOIN, port, NULL, 0) != 0 ? bad("JOIN", errno, 0) : 0;
    fail |= wi(OP_NOTIFY, jid, &note, sizeof note) != 0 ? bad("NOTIFY joined", errno, 0) : 0;
    fail |= expect("SET_NAME after a join", wi(OP_SET_NAME, port, name, sizeof name), EINVAL);
    // A joinable one may be made while in another.
    struct create_params p2;
    if (create(F_JOINABLE, &p2) != 0) return bad("joinable while joined", errno, 0);
    fail |= expect("a joined one while joined", create(0, &p), EALREADY);
    pthread_t t;
    void *res;
    pthread_create(&t, NULL, joiner, (void *)(uintptr_t)port);
    pthread_join(t, &res);
    if (res) fail |= bad("another thread's JOIN", (long)res, 0);
    fail |= wi(OP_JOIN, 0, NULL, 0) != 0 ? bad("leaving", errno, 0) : 0;
    fail |= wi(OP_JOIN, 0, NULL, 0) != 0 ? bad("leaving none", errno, 0) : 0;
    fail |= expect("NOTIFY after leaving", wi(OP_NOTIFY, jid, &note, sizeof note), EINVAL);
    // The port's last right takes the interval; the name is gone.
    fail |= wi(OP_JOIN, port, NULL, 0) != 0 ? bad("JOIN again", errno, 0) : 0;
    mach_port_deallocate(mach_task_self(), port);
    fail |= expect("JOIN by a dead name", wi(OP_JOIN, port, NULL, 0), EINVAL);
    fail |= wi(OP_NOTIFY, jid, &note, sizeof note) != 0 ? bad("NOTIFY still in it", errno, 0) : 0;
    fail |= wi(OP_JOIN, 0, NULL, 0) != 0 ? bad("leaving it", errno, 0) : 0;
    mach_port_deallocate(mach_task_self(), p2.port);

    // A group that waits for its workload ID: none to join or name.
    if (create(F_JOINABLE | F_GROUP | F_HAS_WORKLOAD_ID | T_HID, &p) != 0) return bad("with a workload ID", errno, 0);
    port = p.port;
    fail |= expect("JOIN before the ID", wi(OP_JOIN, port, NULL, 0), EINVAL);
    fail |= expect("SET_NAME before the ID", wi(OP_SET_NAME, port, name, sizeof name), EINVAL);
    char wl[64] = "com.example.hid";
    struct workload_id_params w = {.flags = 0x10, .wicreate_flags = T_COREAUDIO, .name = (uint64_t)(uintptr_t)wl};
    fail |= expect("SET_WORKLOAD_ID of another type", wi(OP_SET_WORKLOAD_ID, port, &w, sizeof w), EINVAL);
    w = (struct workload_id_params){.wicreate_flags = T_HID, .name = 0};
    fail |= expect("SET_WORKLOAD_ID with no name", wi(OP_SET_WORKLOAD_ID, port, &w, sizeof w), EINVAL);
    w = (struct workload_id_params){.flags = 0x10, .wicreate_flags = T_HID, .name = (uint64_t)(uintptr_t)wl, .syscall_mask = {7, 7}};
    fail |= expect("SET_WORKLOAD_ID short", wi(OP_SET_WORKLOAD_ID, port, &w, sizeof w - 1), EINVAL);
    if (wi(OP_SET_WORKLOAD_ID, port, &w, sizeof w) != 0) return bad("SET_WORKLOAD_ID", errno, 0);
    uint32_t pflags = F_JOINABLE | F_GROUP | F_HAS_WORKLOAD_ID | T_HID;
    if (w.flags != 0x10 || w.wicreate_flags != pflags || w.name != 0 || w.syscall_mask[0] || w.syscall_mask[1]) return bad("its answer", w.flags, 0x10);
    w = (struct workload_id_params){.wicreate_flags = T_HID, .name = (uint64_t)(uintptr_t)wl};
    if (wi(OP_SET_WORKLOAD_ID, port, &w, sizeof w) != 0 || w.flags != 3) return bad("SET_WORKLOAD_ID again", w.flags, 3);
    fail |= wi(OP_JOIN, port, NULL, 0) != 0 ? bad("JOIN after the ID", errno, 0) : 0;
    fail |= wi(OP_JOIN, 0, NULL, 0) != 0 ? bad("leaving that", errno, 0) : 0;
    mach_port_deallocate(mach_task_self(), port);

    // A workloop may be made with a joinable interval's port, not another.
    if (create(F_JOINABLE | F_GROUP, &p) != 0) return bad("for a workloop", errno, 0);
    struct __attribute__((packed)) {
        int32_t version, flags;
        uint64_t id;
        int32_t sched_pri, sched_pol, cpu_percent, cpu_refillms;
        uint32_t wi_port;
    } loop = {.version = 36, .flags = 0x08, .id = 0x5157, .wi_port = p.port};
    _Static_assert(sizeof loop == 36, "kqueue_workloop_params");
    fail |= syscall(530, 1, 0, &loop, sizeof loop) != 0 ? bad("workloop with an interval", errno, 0) : 0;
    // The interval's class brings no policy: the loop has no parameters for
    // a destroy to release.
    fail |= expect("its destroy", syscall(530, 2, 0, &loop, sizeof loop), EINVAL);
    // What the loop asks for itself stays.
    loop.flags = 0x08 | 0x01;
    loop.sched_pri = 31;
    loop.id = 0x5159;
    fail |= syscall(530, 1, 0, &loop, sizeof loop) != 0 ? bad("workloop with an interval and a priority", errno, 0) : 0;
    fail |= syscall(530, 2, 0, &loop, sizeof loop) != 0 ? bad("that one's destroy", errno, 0) : 0;
    loop.flags = 0x08;
    loop.wi_port = mach_task_self();
    loop.id = 0x5158;
    fail |= expect("workloop with the task's port", syscall(530, 1, 0, &loop, sizeof loop), EINVAL);
    mach_port_deallocate(mach_task_self(), p.port);

    // Core Audio's: only a realtime thread joins, unless its ID allows it.
    if (create(F_JOINABLE | F_GROUP | T_COREAUDIO, &p) != 0) return bad("Core Audio", errno, 0);
    port = p.port;
    fail |= expect("JOIN not realtime", wi(OP_JOIN, port, NULL, 0), EINVAL);
    struct thread_time_constraint_policy tc = {.period = 0, .computation = 50000, .constraint = 100000, .preemptible = 1};
    if (thread_policy_set(mach_thread_self(), THREAD_TIME_CONSTRAINT_POLICY, (thread_policy_t)&tc, THREAD_TIME_CONSTRAINT_POLICY_COUNT) != KERN_SUCCESS) return bad("realtime", 1, 0);
    fail |= wi(OP_JOIN, port, NULL, 0) != 0 ? bad("JOIN realtime", errno, 0) : 0;
    fail |= wi(OP_JOIN, 0, NULL, 0) != 0 ? bad("leaving Core Audio", errno, 0) : 0;
    mach_port_deallocate(mach_task_self(), port);

    // A Core Animation client's: no group of its own, and only an app's.
    fail |= expect("CA client with a group", create(F_JOINABLE | F_GROUP | T_CA_CLIENT, &p), EALREADY);
    fail |= expect("CA client of no app", create(F_JOINABLE | T_CA_CLIENT, &p), EINVAL);

    if (!fail) printf("workinterval ok\n");
    return fail;
}
