// posix_spawn's port actions by kern_exec.c (exec_handle_port_actions): a
// special port action gives the child a bootstrap port other than the one
// it would inherit, a registered port action its registered ports
// (mach_ports_lookup); the child sends to each. Setting its kernel port
// (task_set_special_port: KERN_NO_ACCESS) or naming a right this task does
// not hold fails the spawn with EINVAL.

#include <errno.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>

extern int posix_spawnattr_set_registered_ports_np(posix_spawnattr_t *, mach_port_t[], uint32_t);

typedef struct {
    mach_msg_header_t h;
    mach_msg_trailer_t t;
} rcv_t;

static int bad(const char *who, const char *what, long got, long want) {
    printf("spawnports: %s: %s: %#lx, want %#lx\n", who, what, got, want);
    return 1;
}

static kern_return_t send_id(mach_port_t to, int id) {
    mach_msg_header_t h = {.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0), .msgh_size = sizeof h, .msgh_remote_port = to, .msgh_id = id};
    return mach_msg(&h, MACH_SEND_MSG, sizeof h, 0, MACH_PORT_NULL, 0, MACH_PORT_NULL);
}

static int child(void) {
    mach_port_t b;
    kern_return_t kr;
    if ((kr = task_get_bootstrap_port(mach_task_self(), &b)) || (kr = send_id(b, 1))) return bad("child", "sending to its bootstrap port", kr, 0);
    mach_port_array_t ports;
    mach_msg_type_number_t n;
    if ((kr = mach_ports_lookup(mach_task_self(), &ports, &n)) || n != 3 || !MACH_PORT_VALID(ports[0]) || ports[1] != MACH_PORT_NULL) return bad("child", "its registered ports", kr ? kr : n, 3);
    if ((kr = send_id(ports[0], 2))) return bad("child", "sending to its registered port", kr, 0);
    return 0;
}

static mach_port_t new_port(void) {
    mach_port_t p;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &p);
    mach_port_insert_right(mach_task_self(), p, p, MACH_MSG_TYPE_MAKE_SEND);
    return p;
}

int main(int argc, char **argv) {
    if (argc > 1) return child();
    char self[PATH_MAX];
    uint32_t len = sizeof self;
    _NSGetExecutablePath(self, &len);
    char *args[] = {self, "child", NULL};
    char *env[] = {"MallocNanoZone=0", NULL};
    mach_port_t inherited = new_port(), b = new_port(), r = new_port();
    task_set_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, inherited);

    posix_spawnattr_t at;
    posix_spawnattr_init(&at);
    posix_spawnattr_setspecialport_np(&at, b, TASK_BOOTSTRAP_PORT);
    mach_port_t reg[1] = {r};
    posix_spawnattr_set_registered_ports_np(&at, reg, 1);
    pid_t pid;
    int e;
    if ((e = posix_spawn(&pid, self, NULL, &at, args, env))) return bad("parent", "spawning", e, 0);
    posix_spawnattr_destroy(&at);
    rcv_t m;
    kern_return_t kr;
    if ((kr = mach_msg(&m.h, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof m, b, 60000, MACH_PORT_NULL)) || m.h.msgh_id != 1) return bad("parent", "the message on the child's bootstrap port", kr ? kr : m.h.msgh_id, 1);
    if ((kr = mach_msg(&m.h, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof m, r, 60000, MACH_PORT_NULL)) || m.h.msgh_id != 2) return bad("parent", "the message on the child's registered port", kr ? kr : m.h.msgh_id, 2);
    int st;
    if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st) || WEXITSTATUS(st)) return bad("parent", "the child's status", st, 0);
    if ((kr = mach_msg(&m.h, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof m, inherited, 0, MACH_PORT_NULL)) != MACH_RCV_TIMED_OUT) return bad("parent", "the bootstrap port it would have inherited", kr, MACH_RCV_TIMED_OUT);

    posix_spawnattr_init(&at);
    posix_spawnattr_setspecialport_np(&at, b, TASK_KERNEL_PORT);
    if ((e = posix_spawn(&pid, self, NULL, &at, args, env)) != EINVAL) return bad("parent", "setting the child's kernel port", e, EINVAL);
    posix_spawnattr_destroy(&at);
    posix_spawnattr_init(&at);
    posix_spawnattr_setspecialport_np(&at, 0x7f03, TASK_BOOTSTRAP_PORT);
    if ((e = posix_spawn(&pid, self, NULL, &at, args, env)) != EINVAL) return bad("parent", "a right it does not hold", e, EINVAL);
    posix_spawnattr_destroy(&at);
    printf("spawnports ok\n");
    return 0;
}
