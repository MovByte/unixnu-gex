// mach_port_extract_right: a right taken from the task's space as if the
// space had sent it, its type the one the disposition carries; a type
// that is not a port right is KERN_INVALID_VALUE, a null name
// KERN_INVALID_RIGHT, a name with no right KERN_INVALID_NAME, and a right
// the name does not hold KERN_INVALID_RIGHT.

#include <mach/mach.h>
#include <stdio.h>

static int bad(const char *what, long got, long want) {
    printf("extractright: %s: %#lx, want %#lx\n", what, got, want);
    fflush(stdout);
    return 1;
}

int main(void) {
    mach_port_t me = mach_task_self(), q, r;
    mach_msg_type_name_t t;
    mach_port_allocate(me, MACH_PORT_RIGHT_RECEIVE, &q);
    kern_return_t kr = mach_port_extract_right(me, q, 0, &r, &t);
    if (kr != KERN_INVALID_VALUE) return bad("a type that is no right", kr, KERN_INVALID_VALUE);
    kr = mach_port_extract_right(me, MACH_PORT_NULL, MACH_MSG_TYPE_MAKE_SEND, &r, &t);
    if (kr != KERN_INVALID_RIGHT) return bad("a null name", kr, KERN_INVALID_RIGHT);
    kr = mach_port_extract_right(me, 0x7f03, MACH_MSG_TYPE_MAKE_SEND, &r, &t);
    if (kr != KERN_INVALID_NAME) return bad("a name with no right", kr, KERN_INVALID_NAME);
    kr = mach_port_extract_right(me, q, MACH_MSG_TYPE_COPY_SEND, &r, &t);
    if (kr != KERN_INVALID_RIGHT) return bad("a send right the name lacks", kr, KERN_INVALID_RIGHT);
    // A send right made: it comes back under the receive right's name.
    kr = mach_port_extract_right(me, q, MACH_MSG_TYPE_MAKE_SEND, &r, &t);
    if (kr || t != MACH_MSG_TYPE_PORT_SEND || r != q) return bad("a send right made", kr ? kr : t, MACH_MSG_TYPE_PORT_SEND);
    mach_port_urefs_t refs;
    if ((kr = mach_port_get_refs(me, q, MACH_PORT_RIGHT_SEND, &refs)) || refs != 1) return bad("its send references", kr ? kr : refs, 1);
    // The receive right moved out and back.
    kr = mach_port_extract_right(me, q, MACH_MSG_TYPE_MOVE_RECEIVE, &r, &t);
    if (kr || t != MACH_MSG_TYPE_PORT_RECEIVE) return bad("the receive right", kr ? kr : t, MACH_MSG_TYPE_PORT_RECEIVE);
    mach_port_type_t ty;
    if ((kr = mach_port_type(me, r, &ty)) || !(ty & MACH_PORT_TYPE_RECEIVE)) return bad("its type", kr ? kr : ty, MACH_PORT_TYPE_RECEIVE);
    printf("extractright ok\n");
    return 0;
}
