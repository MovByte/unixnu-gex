// A receive right leaving a name that keeps a send right, by ipc_right.c:
// moved out in a message (the name is left a send right) and received back
// into the same space; and given up with a port-destroyed request armed (the
// notification carries the receive right back). Each time the name ends as a
// send and receive right that still works.

#include <mach/mach.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void *sleeper(void *arg) {
    (void)arg;
    pause();
    return NULL;
}

static int bad(const char *what, long got, long want) {
    printf("portrefs: %s: %#lx, want %#lx\n", what, got, want);
    return 1;
}

typedef struct {
    mach_msg_header_t h;
    mach_msg_body_t b;
    mach_msg_port_descriptor_t d;
} carry_t;

typedef struct {
    carry_t m;
    mach_msg_trailer_t t;
} carry_rcv_t;

// The name works: a message sent to it with a copied send right is
// received on it.
static int works(mach_port_t p, const char *what) {
    mach_msg_header_t h = {.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0), .msgh_size = sizeof h, .msgh_remote_port = p, .msgh_id = 7};
    kern_return_t kr = mach_msg(&h, MACH_SEND_MSG, sizeof h, 0, MACH_PORT_NULL, 0, MACH_PORT_NULL);
    if (kr) return bad(what, kr, 0);
    struct {
        mach_msg_header_t h;
        mach_msg_trailer_t t;
    } r;
    kr = mach_msg(&r.h, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof r, p, 0, MACH_PORT_NULL);
    if (kr || r.h.msgh_id != 7) return bad(what, kr, 0);
    mach_port_urefs_t refs;
    if ((kr = mach_port_get_refs(mach_task_self(), p, MACH_PORT_RIGHT_SEND, &refs)) || refs != 1) return bad(what, kr ? kr : refs, 1);
    return 0;
}

int main(void) {
    mach_port_t task = mach_task_self(), p, q, n;
    mach_port_type_t t;
    kern_return_t kr;

    // Moved out in a message and received back.
    mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &p);
    mach_port_insert_right(task, p, p, MACH_MSG_TYPE_MAKE_SEND);
    mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &q);
    carry_t m;
    memset(&m, 0, sizeof m);
    m.h.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0) | MACH_MSGH_BITS_COMPLEX;
    m.h.msgh_size = sizeof m;
    m.h.msgh_remote_port = q;
    m.b.msgh_descriptor_count = 1;
    m.d.name = p;
    m.d.disposition = MACH_MSG_TYPE_MOVE_RECEIVE;
    m.d.type = MACH_MSG_PORT_DESCRIPTOR;
    if ((kr = mach_msg(&m.h, MACH_SEND_MSG, sizeof m, 0, MACH_PORT_NULL, 0, MACH_PORT_NULL))) return bad("sending the receive right", kr, 0);
    if ((kr = mach_port_type(task, p, &t)) || t != MACH_PORT_TYPE_SEND) return bad("the name it left", kr ? kr : t, MACH_PORT_TYPE_SEND);
    carry_rcv_t r;
    if ((kr = mach_msg(&r.m.h, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof r, q, 0, MACH_PORT_NULL))) return bad("receiving it", kr, 0);
    if (r.m.d.name != p || (kr = mach_port_type(task, p, &t)) || t != MACH_PORT_TYPE_SEND_RECEIVE) return bad("the right back under its name", kr ? kr : t, MACH_PORT_TYPE_SEND_RECEIVE);
    if (works(p, "the name after the move")) return 1;

    // Given up with a port-destroyed request: the notification brings the
    // receive right back to the name's send right.
    mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &n);
    mach_port_t prev;
    if ((kr = mach_port_request_notification(task, p, MACH_NOTIFY_PORT_DESTROYED, 0, n, MACH_MSG_TYPE_MAKE_SEND_ONCE, &prev))) return bad("arming port-destroyed", kr, 0);
    if ((kr = mach_port_mod_refs(task, p, MACH_PORT_RIGHT_RECEIVE, -1))) return bad("giving up the receive right", kr, 0);
    if ((kr = mach_port_type(task, p, &t)) || t != MACH_PORT_TYPE_SEND) return bad("the name it left", kr ? kr : t, MACH_PORT_TYPE_SEND);
    if ((kr = mach_msg(&r.m.h, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof r, n, 0, MACH_PORT_NULL)) || r.m.h.msgh_id != MACH_NOTIFY_PORT_DESTROYED) return bad("the notification", kr ? kr : r.m.h.msgh_id, MACH_NOTIFY_PORT_DESTROYED);
    if (r.m.d.name != p || (kr = mach_port_type(task, p, &t)) || t != MACH_PORT_TYPE_SEND_RECEIVE) return bad("the right back from it", kr ? kr : t, MACH_PORT_TYPE_SEND_RECEIVE);
    if (works(p, "the name after the notification")) return 1;
    // A service port is launchd's to make; a connection port needs one.
    mach_port_options_t sp_opts = {.flags = MPO_SERVICE_PORT};
    mach_port_t made = MACH_PORT_NULL;
    if ((kr = mach_port_construct(mach_task_self(), &sp_opts, 0, &made)) != KERN_DENIED) {
        printf("portrefs: a service port by anyone else: %d\n", kr);
        return 1;
    }
    mach_port_options_t conn_opts = {.flags = MPO_CONNECTION_PORT};
    if ((kr = mach_port_construct(mach_task_self(), &conn_opts, 0, &made)) != KERN_INVALID_ARGUMENT) {
        printf("portrefs: a connection port of nothing: %d\n", kr);
        return 1;
    }
    mach_port_options_t both_opts = {.flags = MPO_SERVICE_PORT | MPO_CONNECTION_PORT};
    if ((kr = mach_port_construct(mach_task_self(), &both_opts, 0, &made)) != KERN_INVALID_ARGUMENT) {
        printf("portrefs: both kinds at once: %d\n", kr);
        return 1;
    }
    // A kernel routine that fails leaves the rights its request carried to
    // the server to destroy: thread_set_mach_voucher of another, running
    // thread takes nothing from the port it is given, whose sender still
    // holds it (no no-senders notification yet).
    mach_port_t v;
    mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &v);
    mach_port_insert_right(task, v, v, MACH_MSG_TYPE_MAKE_SEND);
    if ((kr = mach_port_request_notification(task, v, MACH_NOTIFY_NO_SENDERS, 0, v, MACH_MSG_TYPE_MAKE_SEND_ONCE, &prev))) return bad("arming no-senders", kr, 0);
    pthread_t other;
    pthread_create(&other, NULL, sleeper, NULL);
    usleep(20000);
    if ((kr = thread_set_mach_voucher(pthread_mach_thread_np(other), v)) != KERN_INVALID_ARGUMENT) return bad("another thread's voucher", kr, KERN_INVALID_ARGUMENT);
    if ((kr = mach_msg(&r.m.h, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof r, v, 0, MACH_PORT_NULL)) != MACH_RCV_TIMED_OUT) return bad("no-senders while a right is held", kr ? kr : r.m.h.msgh_id, MACH_RCV_TIMED_OUT);
    mach_port_deallocate(task, v);
    if ((kr = mach_msg(&r.m.h, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof r, v, 1000, MACH_PORT_NULL)) || r.m.h.msgh_id != MACH_NOTIFY_NO_SENDERS) return bad("no-senders once it went", kr ? kr : r.m.h.msgh_id, MACH_NOTIFY_NO_SENDERS);
    printf("portrefs ok\n");
    return 0;
}
