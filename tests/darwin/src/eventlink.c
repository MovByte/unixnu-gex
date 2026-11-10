// Mach eventlinks: creating a pair, associating threads, signalling the
// other end and waiting for a count, with a deadline, without waiting, cut
// short by a signal, a disassociate or a destroy; an end any thread may
// wait on; and the ends' ports' lives.

#include <errno.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

kern_return_t mach_eventlink_create(task_t, uint32_t, mach_port_t[2]);
kern_return_t mach_eventlink_destroy(mach_port_t);
kern_return_t mach_eventlink_associate(mach_port_t, thread_t, mach_vm_address_t, uint64_t, mach_vm_address_t, uint64_t, uint32_t);
kern_return_t mach_eventlink_disassociate(mach_port_t, uint32_t);
kern_return_t mach_eventlink_signal(mach_port_t, uint64_t);
kern_return_t mach_eventlink_wait_until(mach_port_t, uint64_t *, uint32_t, uint32_t, uint64_t);
kern_return_t mach_eventlink_signal_wait_until(mach_port_t, uint64_t *, uint64_t, uint32_t, uint32_t, uint64_t);

#define NO_COPYIN 1
#define ON_WAIT 1
#define NO_WAIT 1
#define ABSTIME 1

static int bad(const char *what, long got, long want) {
    printf("eventlink: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

static mach_port_t el[2];
static volatile int stage;

static uint64_t in_ms(int ms) {
    mach_timebase_info_data_t tb;
    mach_timebase_info(&tb);
    return mach_absolute_time() + (uint64_t)ms * 1000000 * tb.denom / tb.numer;
}

// The other side: associated with end 1, it signals end 0 and waits.
static void *peer(void *arg) {
    (void)arg;
    if (mach_eventlink_associate(el[1], mach_thread_self(), 0, 0, 0, 0, 0) != KERN_SUCCESS) return (void *)1;
    stage = 1;
    usleep(50000);
    // Wakes the main thread, which waits on end 0 for a count past 1.
    if (mach_eventlink_signal(el[1], 0) != KERN_SUCCESS) return (void *)2;
    // Ping-pong: wait for the main thread's signal_wait.
    uint64_t c = 0;
    kern_return_t kr = mach_eventlink_wait_until(el[1], &c, 0, ABSTIME, 0);
    if (kr != KERN_SUCCESS || c != 1) return (void *)3;
    // Answer it, and wait again until it disassociates this end.
    kr = mach_eventlink_signal_wait_until(el[1], &c, 0, 0, ABSTIME, 0);
    if (kr != KERN_TERMINATED || c != 1) return (void *)(uintptr_t)(100 + kr);
    return NULL;
}

static void on_usr1(int s) { (void)s; }

static void *interrupter(void *t) {
    usleep(50000);
    pthread_kill(*(pthread_t *)t, SIGUSR1);
    return NULL;
}

static void *destroyer(void *arg) {
    usleep(50000);
    mach_eventlink_destroy(*(mach_port_t *)arg);
    return NULL;
}

int main(void) {
    int fail = 0;
    kern_return_t kr;
    uint64_t c;

    fail |= mach_eventlink_create(mach_task_self(), 0, el) != KERN_INVALID_ARGUMENT ? bad("create with no option", 1, 4) : 0;
    if ((kr = mach_eventlink_create(mach_task_self(), NO_COPYIN, el)) != KERN_SUCCESS) return bad("create", kr, 0);
    if (!MACH_PORT_VALID(el[0]) || !MACH_PORT_VALID(el[1]) || el[0] == el[1]) return bad("its ports", el[0], 1);

    // Not associated: no wait.
    c = 5;
    fail |= (kr = mach_eventlink_wait_until(el[0], &c, NO_WAIT, ABSTIME, 0)) != KERN_INVALID_ARGUMENT || c != 5 ? bad("waiting unassociated", kr, 4) : 0;
    // Association's checks.
    fail |= (kr = mach_eventlink_associate(el[0], mach_thread_self(), 8, 0, 0, 0, 0)) != KERN_INVALID_ARGUMENT ? bad("associate with copyin", kr, 4) : 0;
    fail |= (kr = mach_eventlink_associate(el[0], MACH_PORT_NULL, 0, 0, 0, 0, 0)) != KERN_INVALID_ARGUMENT ? bad("associate no thread", kr, 4) : 0;
    fail |= (kr = mach_eventlink_associate(el[0], mach_thread_self(), 0, 0, 0, 0, ON_WAIT)) != KERN_INVALID_ARGUMENT ? bad("associate a thread on wait", kr, 4) : 0;
    if ((kr = mach_eventlink_associate(el[0], mach_thread_self(), 0, 0, 0, 0, 0)) != KERN_SUCCESS) return bad("associate", kr, 0);
    fail |= (kr = mach_eventlink_associate(el[0], mach_thread_self(), 0, 0, 0, 0, 0)) != KERN_NAME_EXISTS ? bad("associate again", kr, 13) : 0;

    // The other end's signal counts here; a count already past returns at
    // once, one not reached times out.
    c = 0;
    fail |= (kr = mach_eventlink_wait_until(el[0], &c, NO_WAIT, ABSTIME, 0)) != KERN_OPERATION_TIMED_OUT || c != 0 ? bad("no wait", kr, 49) : 0;
    fail |= (kr = mach_eventlink_signal(el[1], 0)) != KERN_SUCCESS ? bad("signal", kr, 0) : 0;
    c = 0;
    fail |= (kr = mach_eventlink_wait_until(el[0], &c, 0, ABSTIME, 0)) != KERN_SUCCESS || c != 1 ? bad("count already past", (long)c, 1) : 0;
    c = 1;
    fail |= (kr = mach_eventlink_wait_until(el[0], &c, 0, ABSTIME, in_ms(20))) != KERN_OPERATION_TIMED_OUT || c != 1 ? bad("deadline", kr, 49) : 0;
    c = 1;
    fail |= (kr = mach_eventlink_wait_until(el[0], &c, 0, 2, 0)) != KERN_INVALID_ARGUMENT || c != 1 ? bad("another clock", kr, 4) : 0;

    // A wait the other side's thread ends, and a signal_wait it answers.
    pthread_t t;
    pthread_create(&t, NULL, peer, NULL);
    while (!stage) usleep(1000);
    c = 1;
    fail |= (kr = mach_eventlink_wait_until(el[0], &c, 0, ABSTIME, 0)) != KERN_SUCCESS || c != 2 ? bad("woken", (long)c, 2) : 0;
    c = 2;
    fail |= (kr = mach_eventlink_signal_wait_until(el[0], &c, 0, 0, ABSTIME, 0)) != KERN_SUCCESS || c != 3 ? bad("signal_wait", (long)c, 3) : 0;
    // The peer waits again; disassociating its end ends that.
    usleep(50000);
    fail |= (kr = mach_eventlink_disassociate(el[1], 1)) != KERN_INVALID_ARGUMENT ? bad("disassociate option", kr, 4) : 0;
    fail |= (kr = mach_eventlink_disassociate(el[1], 0)) != KERN_SUCCESS ? bad("disassociate", kr, 0) : 0;
    void *res;
    pthread_join(t, &res);
    if (res) fail |= bad("the peer", (long)res, 0);
    fail |= (kr = mach_eventlink_disassociate(el[1], 0)) != KERN_INVALID_ARGUMENT ? bad("disassociate none", kr, 4) : 0;

    // A signal's handler ends a wait: KERN_ABORTED, the count found.
    struct sigaction sa = {.sa_handler = on_usr1};
    sigaction(SIGUSR1, &sa, NULL);
    pthread_t self = pthread_self(), it;
    pthread_create(&it, NULL, interrupter, &self);
    c = 3;
    fail |= (kr = mach_eventlink_wait_until(el[0], &c, 0, ABSTIME, 0)) != KERN_ABORTED || c != 3 ? bad("interrupted", kr, 14) : 0;
    pthread_join(it, NULL);

    // An end any thread may wait on, one at a time: a wait that timed out
    // leaves its count set until the next signal.
    fail |= mach_eventlink_disassociate(el[0], 0) != KERN_SUCCESS ? bad("disassociate end 0", 1, 0) : 0;
    fail |= (kr = mach_eventlink_associate(el[0], MACH_PORT_NULL, 0, 0, 0, 0, ON_WAIT)) != KERN_SUCCESS ? bad("associate on wait", kr, 0) : 0;
    c = 3;
    fail |= (kr = mach_eventlink_wait_until(el[0], &c, 0, ABSTIME, in_ms(10))) != KERN_OPERATION_TIMED_OUT || c != 3 ? bad("wild deadline", kr, 49) : 0;
    c = 3;
    fail |= (kr = mach_eventlink_wait_until(el[0], &c, NO_WAIT, ABSTIME, 0)) != KERN_INVALID_ARGUMENT ? bad("wild after a timeout", kr, 4) : 0;
    fail |= mach_eventlink_signal(el[1], 0) != KERN_SUCCESS ? bad("signal again", 1, 0) : 0;
    c = 3;
    fail |= (kr = mach_eventlink_wait_until(el[0], &c, NO_WAIT, ABSTIME, 0)) != KERN_SUCCESS || c != 4 ? bad("wild after a signal", (long)c, 4) : 0;

    // A destroy wakes the waiter; the destroyed end's port dies (the call
    // consumes the right it is made with: a second one is left as a dead
    // name), the other stays with no eventlink behind it.
    fail |= mach_port_mod_refs(mach_task_self(), el[1], MACH_PORT_RIGHT_SEND, 1) != KERN_SUCCESS ? bad("a second right", 1, 0) : 0;
    pthread_t d;
    pthread_create(&d, NULL, destroyer, &el[1]);
    c = 4;
    fail |= (kr = mach_eventlink_wait_until(el[0], &c, 0, ABSTIME, 0)) != KERN_TERMINATED || c != 4 ? bad("destroyed while waiting", kr, 37) : 0;
    pthread_join(d, NULL);
    mach_port_type_t type = 0;
    mach_port_type(mach_task_self(), el[1], &type);
    fail |= type != MACH_PORT_TYPE_DEAD_NAME ? bad("the destroyed end", (long)type, MACH_PORT_TYPE_DEAD_NAME) : 0;
    mach_port_type(mach_task_self(), el[0], &type);
    fail |= type != MACH_PORT_TYPE_SEND ? bad("the other end", (long)type, MACH_PORT_TYPE_SEND) : 0;
    fail |= (kr = mach_eventlink_signal(el[0], 0)) != KERN_TERMINATED ? bad("signal after destroy", kr, 37) : 0;
    fail |= (kr = mach_eventlink_destroy(el[0])) != KERN_SUCCESS ? bad("destroy again", kr, 0) : 0;

    // The last send right to an end destroys the eventlink.
    mach_port_t e2[2];
    if (mach_eventlink_create(mach_task_self(), NO_COPYIN, e2) != KERN_SUCCESS) return bad("create 2", 1, 0);
    mach_port_deallocate(mach_task_self(), e2[0]);
    fail |= (kr = mach_eventlink_signal(e2[1], 0)) != KERN_TERMINATED ? bad("signal after no senders", kr, 37) : 0;

    // What is no eventlink.
    fail |= (kr = mach_eventlink_signal(mach_task_self(), 0)) != KERN_INVALID_CAPABILITY ? bad("signal the task", kr, 20) : 0;
    fail |= (kr = mach_eventlink_signal(0x1234567, 0)) != KERN_INVALID_NAME ? bad("signal no name", kr, 15) : 0;

    if (!fail) printf("eventlink ok\n");
    return fail;
}
