// Receive rights in transit: a message that would put a port in transit to
// itself, directly or through a chain of ports in transit, is destroyed and
// its send succeeds; one that would not carries its port to the receiver,
// which gets it back working.

#include <mach/mach.h>
#include <stdio.h>
#include <string.h>

static int bad(const char *what, long got, long want) {
    printf("circular: %s: %lx, want %lx\n", what, got, want);
    return 1;
}

typedef struct {
    mach_msg_header_t h;
    mach_msg_body_t b;
    mach_msg_port_descriptor_t p;
} pmsg;

typedef struct {
    pmsg m;
    mach_msg_trailer_t t;
} rmsg;

static mach_port_t port(void) {
    mach_port_t p;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &p);
    mach_port_insert_right(mach_task_self(), p, p, MACH_MSG_TYPE_MAKE_SEND);
    return p;
}

// Send `carried`'s receive right to `to`.
static kern_return_t carry(mach_port_t to, mach_port_t carried) {
    pmsg m;
    memset(&m, 0, sizeof m);
    m.h.msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND, 0, 0, MACH_MSGH_BITS_COMPLEX);
    m.h.msgh_remote_port = to;
    m.h.msgh_size = sizeof m;
    m.h.msgh_id = 77;
    m.b.msgh_descriptor_count = 1;
    m.p.name = carried;
    m.p.disposition = MACH_MSG_TYPE_MOVE_RECEIVE;
    m.p.type = MACH_MSG_PORT_DESCRIPTOR;
    return mach_msg(&m.h, MACH_SEND_MSG, sizeof m, 0, 0, 0, 0);
}

static mach_port_type_t type_of(mach_port_t p) {
    mach_port_type_t t = 0;
    if (mach_port_type(mach_task_self(), p, &t) != KERN_SUCCESS) return 0;
    return t;
}

int main(void) {
    int fail = 0;
    kern_return_t kr;

    // To itself: the message, and the port with it, are destroyed; the
    // send right left is a dead name.
    mach_port_t a = port();
    fail |= (kr = carry(a, a)) != KERN_SUCCESS ? bad("send to itself", kr, 0) : 0;
    fail |= type_of(a) != MACH_PORT_TYPE_DEAD_NAME ? bad("itself after", type_of(a), MACH_PORT_TYPE_DEAD_NAME) : 0;

    // A cycle of two: a in transit to b, then b sent to a.
    a = port();
    mach_port_t b = port();
    fail |= (kr = carry(b, a)) != KERN_SUCCESS ? bad("a to b", kr, 0) : 0;
    fail |= type_of(a) != MACH_PORT_TYPE_SEND ? bad("a in transit", type_of(a), MACH_PORT_TYPE_SEND) : 0;
    fail |= (kr = carry(a, b)) != KERN_SUCCESS ? bad("b to a", kr, 0) : 0;
    // b's receive right went with the message, and a's with b's queue.
    fail |= type_of(b) != MACH_PORT_TYPE_DEAD_NAME ? bad("b after", type_of(b), MACH_PORT_TYPE_DEAD_NAME) : 0;
    fail |= type_of(a) != MACH_PORT_TYPE_DEAD_NAME ? bad("a after", type_of(a), MACH_PORT_TYPE_DEAD_NAME) : 0;

    // A chain of three closed by the last: c to d, d to e, e to c.
    mach_port_t c = port(), d = port(), e = port();
    fail |= carry(d, c) || carry(e, d) ? bad("chain", 1, 0) : 0;
    fail |= (kr = carry(c, e)) != KERN_SUCCESS ? bad("e to c", kr, 0) : 0;
    fail |= type_of(c) != MACH_PORT_TYPE_DEAD_NAME || type_of(d) != MACH_PORT_TYPE_DEAD_NAME || type_of(e) != MACH_PORT_TYPE_DEAD_NAME ? bad("chain after", type_of(e), MACH_PORT_TYPE_DEAD_NAME) : 0;

    // No cycle: f in transit to g, and back from g's queue, working.
    mach_port_t f = port(), g = port();
    fail |= carry(g, f) ? bad("f to g", 1, 0) : 0;
    rmsg r;
    kr = mach_msg(&r.m.h, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof r, g, 0, 0);
    if (kr != KERN_SUCCESS || r.m.p.disposition != MACH_MSG_TYPE_MOVE_RECEIVE) return bad("receive f", kr, 0);
    mach_port_t f2 = r.m.p.name;
    // Its name is the one its send right has here.
    fail |= f2 != f ? bad("f's name", f2, f) : 0;
    fail |= type_of(f2) != (MACH_PORT_TYPE_SEND | MACH_PORT_TYPE_RECEIVE) ? bad("f back", type_of(f2), MACH_PORT_TYPE_SEND | MACH_PORT_TYPE_RECEIVE) : 0;
    // f can go to g again, and g into f's queue now: no cycle remains.
    fail |= (kr = carry(f2, g)) != KERN_SUCCESS ? bad("g to f", kr, 0) : 0;
    kr = mach_msg(&r.m.h, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof r, f2, 0, 0);
    fail |= kr != KERN_SUCCESS || r.m.p.name != g ? bad("receive g", kr, 0) : 0;
    fail |= type_of(g) != (MACH_PORT_TYPE_SEND | MACH_PORT_TYPE_RECEIVE) ? bad("g back", type_of(g), MACH_PORT_TYPE_SEND | MACH_PORT_TYPE_RECEIVE) : 0;

    if (!fail) printf("circular ok\n");
    return fail;
}
