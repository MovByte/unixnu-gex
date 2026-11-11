// A send-once right destroyed unused carries its own MACH_NOTIFY_SEND_ONCE
// to its port (the right is the notification's destination, consumed by
// it): each one destroyed brings one notification, and the port, its
// counts kept, lives on until its receive right goes.

#include <mach/mach.h>
#include <mach/notify.h>
#include <stdio.h>

static int bad(const char *what, long got, long want) {
    printf("sonce: %s: %#lx, want %#lx\n", what, got, want);
    fflush(stdout);
    return 1;
}

int main(void) {
    mach_port_t q;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &q);
    for (int i = 0; i < 3; i++) {
        mach_port_t so;
        mach_msg_type_name_t t;
        kern_return_t kr = mach_port_extract_right(mach_task_self(), q, MACH_MSG_TYPE_MAKE_SEND_ONCE, &so, &t);
        if (kr || t != MACH_MSG_TYPE_PORT_SEND_ONCE) return bad("a send-once right", kr ? kr : t, MACH_MSG_TYPE_PORT_SEND_ONCE);
        // Destroying it unused sends the notification.
        if ((kr = mach_port_deallocate(mach_task_self(), so))) return bad("deallocating it", kr, 0);
        struct {
            mach_msg_header_t head;
            mach_msg_trailer_t trailer;
        } n;
        kr = mach_msg(&n.head, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof n, q, 100, MACH_PORT_NULL);
        if (kr || n.head.msgh_id != MACH_NOTIFY_SEND_ONCE) return bad("the notification", kr ? kr : n.head.msgh_id, MACH_NOTIFY_SEND_ONCE);
    }
    mach_port_urefs_t refs;
    kern_return_t kr = mach_port_get_refs(mach_task_self(), q, MACH_PORT_RIGHT_RECEIVE, &refs);
    if (kr || refs != 1) return bad("the receive right afterwards", kr ? kr : refs, 1);
    mach_port_status_t st;
    mach_msg_type_number_t cnt = MACH_PORT_RECEIVE_STATUS_COUNT;
    if ((kr = mach_port_get_attributes(mach_task_self(), q, MACH_PORT_RECEIVE_STATUS, (mach_port_info_t)&st, &cnt)) || st.mps_sorights != 0) return bad("its send-once rights", kr ? kr : st.mps_sorights, 0);
    if ((kr = mach_port_mod_refs(mach_task_self(), q, MACH_PORT_RIGHT_RECEIVE, -1))) return bad("destroying it", kr, 0);
    printf("sonce ok\n");
    return 0;
}
