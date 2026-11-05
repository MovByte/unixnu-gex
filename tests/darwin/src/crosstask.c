// Mach IPC between tasks: a spawned child inherits its parent's bootstrap
// port (ipc_task_init) and sends it a request carrying a send-once reply
// right and a send right to a port of its own; the parent, waiting to
// receive, is woken, answers on the reply right and sends to the child's
// port; a second request is seen through an EVFILT_MACHPORT knote; and once
// the child has ended, its port is dead in the parent's space and the
// dead-name notification the parent asked for arrives.

#include <errno.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <sys/event.h>
#include <sys/wait.h>
#include <unistd.h>

typedef struct {
    mach_msg_header_t h;
    mach_msg_body_t b;
    mach_msg_port_descriptor_t d;
    int value;
} request_t;

typedef struct {
    mach_msg_header_t h;
    int value;
} simple_t;

typedef struct {
    union {
        request_t r;
        simple_t s;
        mach_dead_name_notification_t n;
    };
    mach_msg_trailer_t t;
} rcv_t;

static int bad(const char *who, const char *what, long got, long want) {
    printf("crosstask: %s: %s: %#lx, want %#lx\n", who, what, got, want);
    return 1;
}

// A receive that gives up after a minute, so that a child gone wrong
// fails the test instead of hanging it.
static kern_return_t receive(mach_port_t p, rcv_t *r) {
    memset(r, 0, sizeof *r);
    return mach_msg(&r->r.h, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof *r, p, 60000, MACH_PORT_NULL);
}

static kern_return_t send_simple(mach_port_t to, mach_msg_type_name_t disp, int id, int value) {
    simple_t s = {.h = {.msgh_bits = MACH_MSGH_BITS(disp, 0), .msgh_size = sizeof s, .msgh_remote_port = to, .msgh_id = id}, .value = value};
    return mach_msg(&s.h, MACH_SEND_MSG, sizeof s, 0, MACH_PORT_NULL, 0, MACH_PORT_NULL);
}

static int child(void) {
    mach_port_t task = mach_task_self(), b, r, c;
    kern_return_t kr;
    rcv_t m;
    if ((kr = task_get_bootstrap_port(task, &b)) || !MACH_PORT_VALID(b)) return bad("child", "the inherited bootstrap port", kr ? kr : b, 1);
    mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &r);
    mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &c);
    request_t q;
    memset(&q, 0, sizeof q);
    q.h.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE) | MACH_MSGH_BITS_COMPLEX;
    q.h.msgh_size = sizeof q;
    q.h.msgh_remote_port = b;
    q.h.msgh_local_port = r;
    q.h.msgh_id = 100;
    q.b.msgh_descriptor_count = 1;
    q.d.name = c;
    q.d.disposition = MACH_MSG_TYPE_MAKE_SEND;
    q.d.type = MACH_MSG_PORT_DESCRIPTOR;
    q.value = 41;
    if ((kr = mach_msg(&q.h, MACH_SEND_MSG, sizeof q, 0, MACH_PORT_NULL, 0, MACH_PORT_NULL))) return bad("child", "the request", kr, 0);
    if ((kr = receive(r, &m)) || m.s.h.msgh_id != 200 || m.s.value != 42) return bad("child", "the reply", kr ? kr : m.s.h.msgh_id, 200);
    if ((kr = receive(c, &m)) || m.s.h.msgh_id != 300) return bad("child", "the parent's message on its port", kr ? kr : m.s.h.msgh_id, 300);
    if ((kr = send_simple(b, MACH_MSG_TYPE_COPY_SEND, 101, 0))) return bad("child", "the second request", kr, 0);
    if ((kr = receive(c, &m)) || m.s.h.msgh_id != 301) return bad("child", "the parent's leave to end", kr ? kr : m.s.h.msgh_id, 301);
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1) return child();
    mach_port_t task = mach_task_self(), p, n, prev;
    kern_return_t kr;
    rcv_t m;
    mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &p);
    mach_port_insert_right(task, p, p, MACH_MSG_TYPE_MAKE_SEND);
    if ((kr = task_set_special_port(task, TASK_BOOTSTRAP_PORT, p))) return bad("parent", "setting the bootstrap port", kr, 0);

    char self[PATH_MAX];
    uint32_t len = sizeof self;
    _NSGetExecutablePath(self, &len);
    char *args[] = {self, "child", NULL};
    char *env[] = {"MallocNanoZone=0", NULL};
    pid_t pid;
    if (posix_spawn(&pid, self, NULL, NULL, args, env)) return bad("parent", "spawning", errno, 0);

    // Waiting to receive when the child sends.
    if ((kr = receive(p, &m)) || m.r.h.msgh_id != 100 || m.r.value != 41) return bad("parent", "the request", kr ? kr : m.r.h.msgh_id, 100);
    mach_port_t reply = m.r.h.msgh_remote_port, c = m.r.d.name;
    mach_port_type_t t;
    if (MACH_MSGH_BITS_REMOTE(m.r.h.msgh_bits) != MACH_MSG_TYPE_PORT_SEND_ONCE || (kr = mach_port_type(task, reply, &t)) || t != MACH_PORT_TYPE_SEND_ONCE) return bad("parent", "the reply right", kr ? kr : t, MACH_PORT_TYPE_SEND_ONCE);
    if (m.r.d.disposition != MACH_MSG_TYPE_PORT_SEND || (kr = mach_port_type(task, c, &t)) || t != MACH_PORT_TYPE_SEND) return bad("parent", "the carried right", kr ? kr : t, MACH_PORT_TYPE_SEND);
    if ((kr = send_simple(reply, MACH_MSG_TYPE_MOVE_SEND_ONCE, 200, 42))) return bad("parent", "the reply", kr, 0);
    if ((kr = send_simple(c, MACH_MSG_TYPE_COPY_SEND, 300, 0))) return bad("parent", "a message on the child's port", kr, 0);

    // The second request, through a knote on the port.
    int kq = kqueue();
    struct kevent64_s ev, out;
    EV_SET64(&ev, p, EVFILT_MACHPORT, EV_ADD, 0, 0, 0, 0, 0);
    if (kevent64(kq, &ev, 1, NULL, 0, 0, NULL)) return bad("parent", "the knote", errno, 0);
    struct timespec minute = {60, 0};
    int got = kevent64(kq, NULL, 0, &out, 1, 0, &minute);
    if (got != 1 || out.ident != p) return bad("parent", "the knote's event", got, 1);
    if ((kr = receive(p, &m)) || m.s.h.msgh_id != 101) return bad("parent", "the second request", kr ? kr : m.s.h.msgh_id, 101);

    // Its port, once it has ended.
    mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &n);
    if ((kr = mach_port_request_notification(task, c, MACH_NOTIFY_DEAD_NAME, 0, n, MACH_MSG_TYPE_MAKE_SEND_ONCE, &prev))) return bad("parent", "asking for the dead name", kr, 0);
    if ((kr = send_simple(c, MACH_MSG_TYPE_COPY_SEND, 301, 0))) return bad("parent", "the leave to end", kr, 0);
    int st;
    if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st) || WEXITSTATUS(st)) return bad("parent", "the child's status", st, 0);
    if ((kr = receive(n, &m)) || m.n.not_header.msgh_id != MACH_NOTIFY_DEAD_NAME || m.n.not_port != c) return bad("parent", "the dead-name notification", kr ? kr : m.n.not_header.msgh_id, MACH_NOTIFY_DEAD_NAME);
    if ((kr = mach_port_type(task, c, &t)) || t != MACH_PORT_TYPE_DEAD_NAME) return bad("parent", "the child's port after it ended", kr ? kr : t, MACH_PORT_TYPE_DEAD_NAME);
    printf("crosstask ok\n");
    return 0;
}
