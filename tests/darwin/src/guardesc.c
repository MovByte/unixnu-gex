// A guarded port descriptor received without MACH_RCV_GUARDED_DESC: the
// right it carried is destroyed and the descriptor, still guarded, names
// nothing; with the option the receiver gets the right.

#include <mach/mach.h>
#include <stdio.h>
#include <string.h>

static int bad(const char *what, long got, long want) {
    printf("guardesc: %s: %#lx, want %#lx\n", what, got, want);
    fflush(stdout);
    return 1;
}

typedef struct {
    mach_msg_header_t head;
    mach_msg_body_t body;
    mach_msg_guarded_port_descriptor_t port;
} Msg;

typedef struct {
    Msg m;
    mach_msg_max_trailer_t trailer;
} Rcv;

// Send the receive right `p` guarded to `q`, then receive it there.
static kern_return_t round_trip(mach_port_t q, mach_port_t p, mach_msg_option_t rcv_opts, Rcv *r) {
    Msg s;
    memset(&s, 0, sizeof s);
    s.head.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND_ONCE, 0) | MACH_MSGH_BITS_COMPLEX;
    s.head.msgh_size = sizeof s;
    s.head.msgh_remote_port = q;
    s.head.msgh_id = 7;
    s.body.msgh_descriptor_count = 1;
    s.port.name = p;
    s.port.disposition = MACH_MSG_TYPE_MOVE_RECEIVE;
    s.port.type = MACH_MSG_GUARDED_PORT_DESCRIPTOR;
    // An unguarded port, sent with no context.
    s.port.flags = MACH_MSG_GUARD_FLAGS_UNGUARDED_ON_SEND;
    kern_return_t kr = mach_msg(&s.head, MACH_SEND_MSG, sizeof s, 0, MACH_PORT_NULL, 0, MACH_PORT_NULL);
    if (kr) return kr;
    memset(r, 0, sizeof *r);
    return mach_msg(&r->m.head, MACH_RCV_MSG | rcv_opts, 0, sizeof *r, q, 0, MACH_PORT_NULL);
}

int main(void) {
    mach_port_t q, p;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &q);
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &p);
    // A send right kept, to see the port die.
    mach_port_insert_right(mach_task_self(), p, p, MACH_MSG_TYPE_MAKE_SEND);
    Rcv r;
    kern_return_t kr = round_trip(q, p, 0, &r);
    if (kr) return bad("a round trip without the option", kr, 0);
    if (r.m.port.type != MACH_MSG_GUARDED_PORT_DESCRIPTOR) return bad("the descriptor's type", r.m.port.type, MACH_MSG_GUARDED_PORT_DESCRIPTOR);
    if (r.m.port.name != MACH_PORT_NULL) return bad("the descriptor's name", r.m.port.name, 0);
    mach_port_type_t t;
    if ((kr = mach_port_type(mach_task_self(), p, &t)) || t != MACH_PORT_TYPE_DEAD_NAME) return bad("the port after", kr ? kr : t, MACH_PORT_TYPE_DEAD_NAME);

    mach_port_t p2;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &p2);
    kr = round_trip(q, p2, MACH_RCV_GUARDED_DESC, &r);
    if (kr) return bad("a round trip with the option", kr, 0);
    if (r.m.port.type != MACH_MSG_GUARDED_PORT_DESCRIPTOR || r.m.port.name == MACH_PORT_NULL) return bad("the right received", r.m.port.name, 1);
    if ((kr = mach_port_type(mach_task_self(), r.m.port.name, &t)) || !(t & MACH_PORT_TYPE_RECEIVE)) return bad("its type", kr ? kr : t, MACH_PORT_TYPE_RECEIVE);
    printf("guardesc ok\n");
    return 0;
}
