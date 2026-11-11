// A workloop's knotes need a priority with a QoS: a new one's is the
// priority it is added with (ERANGE without a QoS), while EV_ADD on one
// that is there checks the knote's own, whatever priority comes with it.

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/event.h>

// sys/event_private.h.
#define KEVENT_FLAG_WORKLOOP 0x000400
struct kevent_qos_s {
    uint64_t ident;
    int16_t filter;
    uint16_t flags;
    int32_t qos;
    uint64_t udata;
    uint32_t fflags;
    uint32_t xflags;
    int64_t data;
    uint64_t ext[4];
};
// _pthread_priority of QOS_CLASS_UTILITY (thread QoS 3 at bit 8+2).
#define PRIORITY_UTILITY 0x00000400
extern int kevent_id(uint64_t id, const struct kevent_qos_s *changelist, int nchanges,
    struct kevent_qos_s *eventlist, int nevents, void *data_out, size_t *data_available, unsigned int flags);

static int bad(const char *what, long got, long want) {
    printf("wlqos: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

// One change on workloop `id`: its error, from the EV_ERROR event.
static long change(uint64_t id, uint16_t flags, int32_t qos) {
    struct kevent_qos_s kev, out;
    memset(&kev, 0, sizeof kev);
    memset(&out, 0, sizeof out);
    kev.ident = 1;
    kev.filter = EVFILT_USER;
    kev.flags = flags;
    kev.qos = qos;
    int n = kevent_id(id, &kev, 1, &out, 1, NULL, NULL, KEVENT_FLAG_WORKLOOP | KEVENT_FLAG_ERROR_EVENTS | KEVENT_FLAG_IMMEDIATE);
    if (n < 0) return -errno;
    if (n == 1 && (out.flags & EV_ERROR)) return out.data;
    return 0;
}

int main(void) {
    uint64_t id = 0x67657877;
    long e = change(id, EV_ADD, 0x1);
    if (e != ERANGE) return bad("a new knote with no QoS", e, ERANGE);
    e = change(id, EV_ADD, PRIORITY_UTILITY);
    if (e != 0) return bad("a new knote at utility", e, 0);
    e = change(id, EV_ADD, 0x1);
    if (e != 0) return bad("EV_ADD on it with no QoS", e, 0);
    e = change(id, EV_DELETE, 0);
    if (e != 0) return bad("deleting it", e, 0);
    printf("wlqos ok\n");
    return 0;
}
