// A message too large for the receive buffer, without MACH_RCV_LARGE:
// MACH_RCV_TOO_LARGE with the message made a bare header (its size the
// header's, its id and ports kept) and a trailer, the message gone.

#include <mach/mach.h>
#include <stdio.h>
#include <string.h>

static int bad(const char *what, long got, long want) {
    printf("rcvlarge: %s: %#lx, want %#lx\n", what, got, want);
    fflush(stdout);
    return 1;
}

static kern_return_t send_body(mach_port_t q, int id, size_t body) {
    struct {
        mach_msg_header_t head;
        char body[256];
    } s;
    memset(&s, 0x5a, sizeof s);
    s.head.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    s.head.msgh_size = (mach_msg_size_t)(sizeof s.head + body);
    s.head.msgh_remote_port = q;
    s.head.msgh_local_port = MACH_PORT_NULL;
    s.head.msgh_voucher_port = MACH_PORT_NULL;
    s.head.msgh_id = id;
    return mach_msg(&s.head, MACH_SEND_MSG, s.head.msgh_size, 0, MACH_PORT_NULL, 0, MACH_PORT_NULL);
}

int main(void) {
    mach_port_t q;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &q);
    mach_port_insert_right(mach_task_self(), q, q, MACH_MSG_TYPE_MAKE_SEND);
    union {
        mach_msg_header_t head;
        unsigned char b[64];
    } r;
    // The body overflows, and then only the trailer does.
    size_t bodies[2] = {76, 36};
    for (int i = 0; i < 2; i++) {
        if (send_body(q, 40 + i, bodies[i])) return bad("a send", i, 0);
        memset(&r, 0xee, sizeof r);
        kern_return_t kr = mach_msg(&r.head, MACH_RCV_MSG, 0, sizeof r, q, 0, MACH_PORT_NULL);
        if (kr != MACH_RCV_TOO_LARGE) return bad("receiving it", kr, MACH_RCV_TOO_LARGE);
        if (r.head.msgh_size != sizeof(mach_msg_header_t)) return bad("the bare header's size", r.head.msgh_size, sizeof(mach_msg_header_t));
        if (r.head.msgh_id != 40 + i) return bad("its id", r.head.msgh_id, 40 + i);
        if (r.head.msgh_local_port != q) return bad("its port", r.head.msgh_local_port, q);
        mach_msg_trailer_t *t = (mach_msg_trailer_t *)(r.b + sizeof(mach_msg_header_t));
        if (t->msgh_trailer_type != 0 || t->msgh_trailer_size != sizeof(mach_msg_trailer_t)) return bad("its trailer", t->msgh_trailer_size, sizeof(mach_msg_trailer_t));
        kr = mach_msg(&r.head, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof r, q, 0, MACH_PORT_NULL);
        if (kr != MACH_RCV_TIMED_OUT) return bad("the message afterwards", kr, MACH_RCV_TIMED_OUT);
    }

    printf("rcvlarge ok\n");
    return 0;
}
