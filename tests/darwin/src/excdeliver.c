// Exceptions sent to their handlers (exception.c): an invalid Mach trap
// raises EXC_SYSCALL with the call's number; a task handler of behavior
// EXCEPTION_STATE | MACH_EXCEPTION_CODES gets mach_exception_raise_state
// with the thread's state, and the state it replies with is the thread's
// (x0 here); a handler that fails passes it on to the host's, which makes
// it SIGSYS, as it does with no handler.

#include <mach/mach.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

static int bad(const char *what, long got, long want) {
    printf("excdeliver: %s: %#lx, want %#lx\n", what, got, want);
    return 1;
}

static long trap(long n) {
    register long x16 __asm__("x16") = n;
    register long x0 __asm__("x0") = 0x55;
    __asm__ volatile("svc #0x80" : "+r"(x0) : "r"(x16) : "memory", "cc");
    return x0;
}

static mach_port_t port;
static int fail_next;
static volatile long seen_exc, seen_code, seen_flavor, seen_count, seen_id;

#pragma pack(4)
typedef struct {
    mach_msg_header_t head;
    NDR_record_t ndr;
    int exc;
    mach_msg_type_number_t code_count;
    int64_t code[2];
    int flavor;
    mach_msg_type_number_t state_count;
    natural_t state[ARM_THREAD_STATE64_COUNT];
    mach_msg_trailer_t trailer;
} request_t;

typedef struct {
    mach_msg_header_t head;
    NDR_record_t ndr;
    kern_return_t ret;
    int flavor;
    mach_msg_type_number_t state_count;
    natural_t state[ARM_THREAD_STATE64_COUNT];
} reply_t;
#pragma pack()

static void *handler(void *arg) {
    (void)arg;
    for (;;) {
        request_t req;
        if (mach_msg(&req.head, MACH_RCV_MSG, 0, sizeof req, port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL)) return NULL;
        seen_id = req.head.msgh_id;
        seen_exc = req.exc;
        seen_code = req.code[0];
        // The fields after the codes follow the ones sent (MIG packs them).
        char *after = (char *)req.code + req.code_count * sizeof(int64_t);
        int flavor;
        mach_msg_type_number_t count;
        memcpy(&flavor, after, 4);
        memcpy(&count, after + 4, 4);
        seen_flavor = flavor;
        seen_count = count;
        reply_t rep;
        memset(&rep, 0, sizeof rep);
        rep.head.msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(req.head.msgh_bits), 0);
        rep.head.msgh_remote_port = req.head.msgh_remote_port;
        rep.head.msgh_id = req.head.msgh_id + 100;
        rep.ndr = NDR_record;
        rep.ret = fail_next ? KERN_FAILURE : KERN_SUCCESS;
        rep.flavor = flavor;
        rep.state_count = count;
        memcpy(rep.state, after + 8, count * sizeof(natural_t));
        ((arm_thread_state64_t *)rep.state)->__x[0] = 0x1234;
        rep.head.msgh_size = fail_next ? offsetof(reply_t, flavor) : sizeof rep;
        if (mach_msg(&rep.head, MACH_SEND_MSG, rep.head.msgh_size, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL)) return NULL;
    }
}

static volatile sig_atomic_t sigsys;
static void on_sigsys(int s) {
    (void)s;
    sigsys++;
}

int main(void) {
    signal(SIGSYS, on_sigsys);
    // No handler of the task's: the host's makes it SIGSYS, x0 untouched.
    if (trap(-1) != 0x55 || sigsys != 1) return bad("an invalid trap with no handler", sigsys, 1);

    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
    kern_return_t kr = task_set_exception_ports(mach_task_self(), EXC_MASK_SYSCALL, port, EXCEPTION_STATE | MACH_EXCEPTION_CODES, ARM_THREAD_STATE64);
    if (kr) return bad("setting the handler", kr, 0);
    pthread_t t;
    pthread_create(&t, NULL, handler, NULL);

    long r = trap(-200);
    if (seen_id != 2406 || seen_exc != EXC_SYSCALL || seen_code != 200) return bad("the request", seen_id, 2406);
    if (seen_flavor != ARM_THREAD_STATE64 || seen_count != ARM_THREAD_STATE64_COUNT) return bad("its state", seen_count, ARM_THREAD_STATE64_COUNT);
    if (r != 0x1234 || sigsys != 1) return bad("the state the handler gave", r, 0x1234);

    // A handler that fails: on to the host's.
    fail_next = 1;
    if (trap(-2) != 0x55 || sigsys != 2 || seen_code != 2) return bad("a failed handler", sigsys, 2);
    printf("excdeliver ok\n");
    return 0;
}
