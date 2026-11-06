// Task ports by flavor (ipc_tt.c): the inspect port answers what an
// inspect port may (task_info but not TASK_DYLD_INFO, its inspect and name
// ports from task_get_special_port, KERN_INVALID_CAPABILITY for more) and
// is refused by routines that want the control port; asked for again it
// is the same port. An exception handler of behavior EXCEPTION_DEFAULT
// gets the thread's and task's ports, in the task's own space its self
// ports.

#include <mach/mach.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

static int bad(const char *what, long got, long want) {
    printf("readports: %s: %#lx, want %#lx\n", what, got, want);
    return 1;
}

static long trap(long n) {
    register long x16 __asm__("x16") = n;
    register long x0 __asm__("x0") = 0x55;
    __asm__ volatile("svc #0x80" : "+r"(x0) : "r"(x16) : "memory", "cc");
    return x0;
}

#pragma pack(4)
typedef struct {
    mach_msg_header_t head;
    mach_msg_body_t body;
    mach_msg_port_descriptor_t thread;
    mach_msg_port_descriptor_t task;
    NDR_record_t ndr;
    int exc;
    mach_msg_type_number_t code_count;
    int64_t code[2];
    mach_msg_trailer_t trailer;
} request_t;

typedef struct {
    mach_msg_header_t head;
    NDR_record_t ndr;
    kern_return_t ret;
} reply_t;
#pragma pack()

static mach_port_t port;
static volatile long seen_id, seen_thread, seen_task, seen_code;

static void *handler(void *arg) {
    (void)arg;
    request_t req;
    if (mach_msg(&req.head, MACH_RCV_MSG, 0, sizeof req, port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL)) return NULL;
    seen_id = req.head.msgh_id;
    seen_thread = req.thread.name;
    seen_task = req.task.name;
    seen_code = req.code[0];
    reply_t rep;
    memset(&rep, 0, sizeof rep);
    rep.head.msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(req.head.msgh_bits), 0);
    rep.head.msgh_remote_port = req.head.msgh_remote_port;
    rep.head.msgh_id = req.head.msgh_id + 100;
    rep.head.msgh_size = sizeof rep;
    rep.ndr = NDR_record;
    rep.ret = KERN_SUCCESS;
    mach_msg(&rep.head, MACH_SEND_MSG, sizeof rep, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    return NULL;
}

int main(void) {
    mach_port_t self = mach_task_self(), insp = MACH_PORT_NULL, again = MACH_PORT_NULL, p = MACH_PORT_NULL;
    kern_return_t kr;
    if ((kr = task_get_special_port(self, TASK_INSPECT_PORT, &insp)) || !MACH_PORT_VALID(insp) || insp == self) return bad("the inspect port", kr ? kr : (long)insp, 0);
    if ((kr = task_get_special_port(self, TASK_INSPECT_PORT, &again)) || again != insp) return bad("the inspect port again", kr ? kr : (long)again, insp);
    if ((kr = task_get_special_port(insp, TASK_INSPECT_PORT, &p)) || p != insp) return bad("its own inspect port", kr ? kr : (long)p, insp);
    if ((kr = task_get_special_port(insp, TASK_NAME_PORT, &p)) || !MACH_PORT_VALID(p)) return bad("its name port", kr, 0);
    if ((kr = task_get_special_port(insp, TASK_READ_PORT, &p)) != KERN_INVALID_CAPABILITY) return bad("a read port from it", kr, KERN_INVALID_CAPABILITY);
    if ((kr = task_get_special_port(insp, TASK_BOOTSTRAP_PORT, &p)) != KERN_INVALID_CAPABILITY) return bad("the bootstrap port from it", kr, KERN_INVALID_CAPABILITY);
    audit_token_t tok;
    mach_msg_type_number_t n = TASK_AUDIT_TOKEN_COUNT;
    if ((kr = task_info(insp, TASK_AUDIT_TOKEN, (task_info_t)&tok, &n))) return bad("task_info by it", kr, 0);
    struct task_dyld_info dyld;
    n = TASK_DYLD_INFO_COUNT;
    if ((kr = task_info(insp, TASK_DYLD_INFO, (task_info_t)&dyld, &n)) != KERN_INVALID_ARGUMENT) return bad("TASK_DYLD_INFO by it", kr, KERN_INVALID_ARGUMENT);
    if ((kr = task_set_special_port(insp, TASK_BOOTSTRAP_PORT, MACH_PORT_NULL)) != KERN_INVALID_ARGUMENT) return bad("a control routine by it", kr, KERN_INVALID_ARGUMENT);

    // EXCEPTION_DEFAULT: the thread's and task's ports come with it.
    mach_port_allocate(self, MACH_PORT_RIGHT_RECEIVE, &port);
    mach_port_insert_right(self, port, port, MACH_MSG_TYPE_MAKE_SEND);
    if ((kr = task_set_exception_ports(self, EXC_MASK_SYSCALL, port, EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES, THREAD_STATE_NONE))) return bad("setting the handler", kr, 0);
    pthread_t t;
    pthread_create(&t, NULL, handler, NULL);
    mach_port_t me = mach_thread_self();
    long r = trap(-200);
    pthread_join(t, NULL);
    if (seen_id != 2405 || seen_code != 200 || r != 0x55) return bad("the request", seen_id, 2405);
    if (seen_thread != (long)me || seen_task != (long)self) return bad("its ports", seen_thread, me);
    printf("readports ok\n");
    return 0;
}
