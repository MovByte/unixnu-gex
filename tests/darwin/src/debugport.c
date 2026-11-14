// debug_control_port_for_pid (vm_unix.c) for a caller entitled to
// com.apple.private.debug_port, which skips the policies' check of the
// control port: a copy of the debug control port its own task set
// (TASK_DEBUG_CONTROL_PORT), under the name the right already has, as
// task_get_special_port gives it; null with KERN_SUCCESS when none is set,
// and dead once its port has died. pid 0, a target that is no task port, a
// pid that names nothing and a zombie's give null and KERN_FAILURE.

#include <mach/mach.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int bad(const char *what, long got, long want) {
    printf("debugport: %s: %#lx, want %#lx\n", what, got, want);
    return 1;
}

static kern_return_t lookup(mach_port_name_t target, pid_t pid, mach_port_t *out) {
    *out = 0x1234;
    return debug_control_port_for_pid(target, pid, out);
}

int main(void) {
    mach_port_t n, g = MACH_PORT_NULL;
    // What the task's start left set (its libraries may set one).
    kern_return_t kr = task_get_special_port(mach_task_self(), TASK_DEBUG_CONTROL_PORT, &g);
    if (kr) return bad("task_get_special_port", kr, 0);
    kr = lookup(mach_task_self(), getpid(), &n);
    if (kr != KERN_SUCCESS || n != g) return bad("what is set", kr ? kr : n, g);
    if ((kr = task_set_special_port(mach_task_self(), TASK_DEBUG_CONTROL_PORT, MACH_PORT_NULL))) return bad("setting none", kr, 0);
    kr = lookup(mach_task_self(), getpid(), &n);
    if (kr != KERN_SUCCESS || n != MACH_PORT_NULL) return bad("none set", kr ? kr : n, 0);
    mach_port_t p;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &p);
    mach_port_insert_right(mach_task_self(), p, p, MACH_MSG_TYPE_MAKE_SEND);
    if ((kr = task_set_special_port(mach_task_self(), TASK_DEBUG_CONTROL_PORT, p))) return bad("setting it", kr, 0);
    mach_port_urefs_t before = 0, after = 0;
    mach_port_get_refs(mach_task_self(), p, MACH_PORT_RIGHT_SEND, &before);
    kr = lookup(mach_task_self(), getpid(), &n);
    if (kr != KERN_SUCCESS || n != p) return bad("the port set", kr ? kr : n, p);
    mach_port_get_refs(mach_task_self(), p, MACH_PORT_RIGHT_SEND, &after);
    if (after != before + 1) return bad("a copy of its send right", after, before + 1);
    if (lookup(mach_task_self(), 0, &n) != KERN_FAILURE || n) return bad("pid 0", n, 0);
    if (lookup(MACH_PORT_NULL, getpid(), &n) != KERN_FAILURE || n) return bad("no task port", n, 0);
    if (lookup(mach_task_self(), 99999, &n) != KERN_FAILURE || n) return bad("no such process", n, 0);
    pid_t c = fork();
    if (c == 0) _exit(0);
    siginfo_t si;
    memset(&si, 0, sizeof si);
    if (waitid(P_PID, c, &si, WEXITED | WNOWAIT) || si.si_pid != c) return bad("the zombie", c, 0);
    if (lookup(mach_task_self(), c, &n) != KERN_FAILURE || n) return bad("a zombie", n, 0);
    waitpid(c, NULL, 0);
    // Its port dies: what is set is dead.
    mach_port_mod_refs(mach_task_self(), p, MACH_PORT_RIGHT_RECEIVE, -1);
    kr = lookup(mach_task_self(), getpid(), &n);
    if (kr != KERN_SUCCESS || n != MACH_PORT_DEAD) return bad("a port that died", kr ? kr : n, MACH_PORT_DEAD);
    printf("debugport ok\n");
    return 0;
}
