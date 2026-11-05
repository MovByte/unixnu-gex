// Exception ports by ipc_tt.c: a task's and a thread's handlers set, read
// back (types with alike actions merged into one entry) and swapped; masks,
// behaviors and flavors outside what is valid refused; the host port is not
// the privileged one; a forked child inherits its parent's handlers, and a
// posix_spawn exception port action gives a spawned one its own.

#include <errno.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <spawn.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

static int bad(const char *what, long got, long want) {
    printf("excports: %s: %#lx, want %#lx\n", what, got, want);
    return 1;
}

typedef struct {
    exception_mask_t masks[EXC_TYPES_COUNT];
    mach_port_t ports[EXC_TYPES_COUNT];
    exception_behavior_t behaviors[EXC_TYPES_COUNT];
    thread_state_flavor_t flavors[EXC_TYPES_COUNT];
    mach_msg_type_number_t n;
} got_t;

static kern_return_t get(exception_mask_t mask, got_t *g) {
    g->n = EXC_TYPES_COUNT;
    return task_get_exception_ports(mach_task_self(), mask, g->masks, &g->n, g->ports, g->behaviors, g->flavors);
}

static mach_port_t new_port(void) {
    mach_port_t p;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &p);
    mach_port_insert_right(mach_task_self(), p, p, MACH_MSG_TYPE_MAKE_SEND);
    return p;
}

int main(int argc, char **argv) {
    mach_port_t task = mach_task_self();
    kern_return_t kr;
    got_t g;
    const exception_behavior_t codes_default = EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES;
    if (argc > 1) {
        // Spawned with an exception port action for EXC_GUARD.
        if ((kr = get(EXC_MASK_GUARD, &g)) || g.n != 1 || !MACH_PORT_VALID(g.ports[0]) || g.behaviors[0] != codes_default) return bad("the spawned child's guard handler", kr ? kr : g.n, 1);
        return 0;
    }
    mach_port_t p = new_port(), q = new_port();

    if ((kr = task_set_exception_ports(task, EXC_MASK_BAD_ACCESS | EXC_MASK_CRASH, p, codes_default, THREAD_STATE_NONE))) return bad("setting a task handler", kr, 0);
    if ((kr = get(EXC_MASK_BAD_ACCESS | EXC_MASK_CRASH | EXC_MASK_SOFTWARE, &g)) || g.n != 2) return bad("reading them back", kr ? kr : g.n, 2);
    if (g.masks[0] != (EXC_MASK_BAD_ACCESS | EXC_MASK_CRASH) || g.ports[0] != p || g.behaviors[0] != codes_default || g.flavors[0] != THREAD_STATE_NONE) return bad("the handler's entry", g.masks[0], EXC_MASK_BAD_ACCESS | EXC_MASK_CRASH);
    if (g.masks[1] != EXC_MASK_SOFTWARE || g.ports[1] != MACH_PORT_NULL) return bad("the unset type's entry", g.masks[1], EXC_MASK_SOFTWARE);

    if ((kr = task_set_exception_ports(task, 1, p, codes_default, 0)) != KERN_INVALID_ARGUMENT) return bad("exception type 0", kr, KERN_INVALID_ARGUMENT);
    if ((kr = task_set_exception_ports(task, 1 << 14, p, codes_default, 0)) != KERN_INVALID_ARGUMENT) return bad("a type past the last", kr, KERN_INVALID_ARGUMENT);
    if ((kr = task_set_exception_ports(task, EXC_MASK_BAD_ACCESS, p, 7, 0)) != KERN_INVALID_ARGUMENT) return bad("an unknown behavior", kr, KERN_INVALID_ARGUMENT);
    if ((kr = task_set_exception_ports(task, EXC_MASK_BAD_ACCESS, p, codes_default, 8)) != KERN_INVALID_ARGUMENT) return bad("an invalid flavor", kr, KERN_INVALID_ARGUMENT);
    if ((kr = task_set_exception_ports(task, EXC_MASK_BAD_ACCESS, p, EXCEPTION_IDENTITY_PROTECTED, 0)) != KERN_INVALID_ARGUMENT) return bad("identity protected without codes", kr, KERN_INVALID_ARGUMENT);

    // Swapped: the old handler back, the new one in.
    got_t o;
    o.n = EXC_TYPES_COUNT;
    if ((kr = task_swap_exception_ports(task, EXC_MASK_BAD_ACCESS, q, EXCEPTION_STATE | MACH_EXCEPTION_CODES, ARM_THREAD_STATE64, o.masks, &o.n, o.ports, o.behaviors, o.flavors)) || o.n != 1) return bad("swapping", kr ? kr : o.n, 1);
    if (o.masks[0] != EXC_MASK_BAD_ACCESS || o.ports[0] != p || o.behaviors[0] != codes_default) return bad("the swapped-out handler", o.masks[0], EXC_MASK_BAD_ACCESS);
    if ((kr = get(EXC_MASK_BAD_ACCESS, &g)) || g.ports[0] != q || g.flavors[0] != ARM_THREAD_STATE64) return bad("the swapped-in handler", kr ? kr : (long)g.ports[0], q);

    // A thread's own.
    exception_mask_t tm[EXC_TYPES_COUNT];
    mach_port_t tp[EXC_TYPES_COUNT];
    exception_behavior_t tb[EXC_TYPES_COUNT];
    thread_state_flavor_t tf[EXC_TYPES_COUNT];
    mach_msg_type_number_t tn = EXC_TYPES_COUNT;
    mach_port_t th = mach_thread_self();
    if ((kr = thread_get_exception_ports(th, EXC_MASK_BREAKPOINT, tm, &tn, tp, tb, tf)) || tn != 1 || tp[0] != MACH_PORT_NULL) return bad("a thread with no handler", kr ? kr : tn, 1);
    if ((kr = thread_set_exception_ports(th, EXC_MASK_BREAKPOINT, p, codes_default, 0))) return bad("setting a thread handler", kr, 0);
    tn = EXC_TYPES_COUNT;
    if ((kr = thread_get_exception_ports(th, EXC_MASK_BREAKPOINT, tm, &tn, tp, tb, tf)) || tn != 1 || tp[0] != p) return bad("the thread's handler", kr ? kr : tn, 1);

    // The host port is not the host privilege port.
    if ((kr = host_set_exception_ports(mach_host_self(), EXC_MASK_BAD_ACCESS, p, codes_default, 0)) != KERN_INVALID_ARGUMENT) return bad("the host port", kr, KERN_INVALID_ARGUMENT);

    // Inherited by a forked child.
    pid_t pid = fork();
    if (pid == 0) {
        got_t c;
        if (get(EXC_MASK_BAD_ACCESS | EXC_MASK_CRASH, &c) || c.n != 2 || c.masks[0] != EXC_MASK_BAD_ACCESS || !MACH_PORT_VALID(c.ports[0]) || c.flavors[0] != ARM_THREAD_STATE64) _exit(3);
        if (c.masks[1] != EXC_MASK_CRASH || !MACH_PORT_VALID(c.ports[1])) _exit(4);
        _exit(0);
    }
    int st;
    if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st) || WEXITSTATUS(st)) return bad("the forked child's handlers", st, 0);

    // A spawn's exception port action.
    char self[PATH_MAX];
    uint32_t len = sizeof self;
    _NSGetExecutablePath(self, &len);
    char *args[] = {self, "spawned", NULL};
    char *env[] = {"MallocNanoZone=0", NULL};
    posix_spawnattr_t at;
    posix_spawnattr_init(&at);
    posix_spawnattr_setexceptionports_np(&at, EXC_MASK_GUARD, p, codes_default, 0);
    int e;
    if ((e = posix_spawn(&pid, self, NULL, &at, args, env))) return bad("spawning", e, 0);
    if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st) || WEXITSTATUS(st)) return bad("the spawned child's handler", st, 0);
    posix_spawnattr_destroy(&at);
    printf("excports ok\n");
    return 0;
}
