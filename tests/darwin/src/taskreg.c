// A new task is reachable by its pid once the call that made it returns:
// fork and posix_spawn enable its IPC before they return to the parent
// (kern_fork.c's fork, kern_exec.c's posix_spawn: ipc_task_enable), whether
// or not the child has run since. A child forked with the trap itself runs
// nothing of libSystem's and so never makes a Mach call; a child spawned
// POSIX_SPAWN_START_SUSPENDED is stopped (SSTOP, its task suspended) before
// posix_spawn returns. For each, task_name_for_pid gives a name port that
// pid_for_task takes back to the pid and whose kernel answers task_info
// (TASK_AUDIT_TOKEN), and task_for_pid gives no control port (AMFI, without
// Developer Mode): KERN_FAILURE and null. An exec keeps the pid with a new
// task: the old name port names no task and task_name_for_pid gives a new
// one. Once a child is a zombie, and once it is reaped, its pid gives null
// and KERN_FAILURE, and its name port is dead.

#include <errno.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int bad(const char *what, long got, long want) {
    printf("taskreg: %s: %#lx, want %#lx\n", what, got, want);
    return 1;
}

// fork(2) by its trap, x1 telling the child (1) from the parent (0). The
// child closes `wr`, reads `rd` until it ends and exits 0 (2 if a call
// fails), with system calls of its own: no libSystem code, no Mach call.
// The parent gets the child's pid, or -errno.
static pid_t fork_reader(int rd, int wr) {
    register long x0 __asm__("x0");
    __asm__ volatile(
        "mov x9, %1\n"
        "mov x10, %2\n"
        "mov x16, #2\n" // SYS_fork
        "svc #0x80\n"
        "b.cs 3f\n"
        "cbz x1, 4f\n"
        "mov x0, x10\n"
        "mov x16, #6\n" // SYS_close
        "svc #0x80\n"
        "b.cs 2f\n"
        "sub sp, sp, #16\n"
        "1:\n"
        "mov x0, x9\n"
        "mov x1, sp\n"
        "mov x2, #1\n"
        "mov x16, #3\n" // SYS_read
        "svc #0x80\n"
        "b.cs 2f\n"
        "cbnz x0, 1b\n"
        "mov x0, #0\n"
        "mov x16, #1\n" // SYS_exit
        "svc #0x80\n"
        "2:\n"
        "mov x0, #2\n"
        "mov x16, #1\n"
        "svc #0x80\n"
        "brk #1\n"
        "3:\n"
        "neg x0, x0\n"
        "4:\n"
        : "=r"(x0)
        : "r"((long)rd), "r"((long)wr)
        : "x1", "x2", "x9", "x10", "x16", "memory", "cc");
    return (pid_t)x0;
}

// The child's task by its pid, before it has run: its name port (returned
// in *out), the pid it names, its audit token, and no control port.
static int reach(const char *who, pid_t pid, mach_port_t *out) {
    char what[96];
    mach_port_t n = MACH_PORT_NULL;
    kern_return_t kr = task_name_for_pid(mach_task_self(), pid, &n);
    snprintf(what, sizeof what, "%s: task_name_for_pid", who);
    if (kr != KERN_SUCCESS || !MACH_PORT_VALID(n)) return bad(what, kr ? kr : n, 1);
    int got = -1;
    kr = pid_for_task(n, &got);
    snprintf(what, sizeof what, "%s: pid_for_task on its name port", who);
    if (kr != KERN_SUCCESS || got != pid) return bad(what, kr ? kr : got, pid);
    audit_token_t tok;
    mach_msg_type_number_t cnt = TASK_AUDIT_TOKEN_COUNT;
    kr = task_info(n, TASK_AUDIT_TOKEN, (task_info_t)&tok, &cnt);
    snprintf(what, sizeof what, "%s: its audit token's pid", who);
    if (kr != KERN_SUCCESS || (pid_t)tok.val[5] != pid) return bad(what, kr ? kr : (long)tok.val[5], pid);
    mach_port_t t = 0x1234;
    kr = task_for_pid(mach_task_self(), pid, &t);
    snprintf(what, sizeof what, "%s: task_for_pid", who);
    if (kr != KERN_FAILURE || t != MACH_PORT_NULL) return bad(what, kr, KERN_FAILURE);
    *out = n;
    return 0;
}

// The pid of a zombie or of no process: null and KERN_FAILURE.
static int unreachable(const char *who, pid_t pid) {
    mach_port_t n = 0x1234;
    kern_return_t kr = task_name_for_pid(mach_task_self(), pid, &n);
    if (kr != KERN_FAILURE || n != MACH_PORT_NULL) return bad(who, kr ? kr : n, KERN_FAILURE);
    return 0;
}

// A name port whose task is gone: pid_for_task fails with -1.
static int nameless(const char *who, mach_port_t n) {
    int got = 0;
    kern_return_t kr = pid_for_task(n, &got);
    if (kr != KERN_FAILURE || got != -1) return bad(who, kr ? kr : got, KERN_FAILURE);
    return 0;
}

static int dead(const char *who, mach_port_t n) {
    mach_port_type_t t = 0;
    kern_return_t kr = mach_port_type(mach_task_self(), n, &t);
    if (kr != KERN_SUCCESS || t != MACH_PORT_TYPE_DEAD_NAME) return bad(who, kr ? kr : t, MACH_PORT_TYPE_DEAD_NAME);
    return 0;
}

int main(int argc, char **argv) {
    char self[PATH_MAX];
    uint32_t len = sizeof self;
    _NSGetExecutablePath(self, &len);
    char *env[] = {"MallocNanoZone=0", NULL};
    if (argc > 1 && !strcmp(argv[1], "exec")) {
        // The suspended child, let go: the same pid with a new image.
        char *args[] = {self, "child", NULL};
        execve(self, args, env);
        return 3;
    }
    if (argc > 1) {
        // The new image says it runs, then waits for its stdin to end.
        char c = 'x';
        if (write(1, &c, 1) != 1) return 4;
        while (read(0, &c, 1) > 0) {}
        return 0;
    }
    int r, st;

    // A forked child that never makes a Mach call.
    int p[2];
    if (pipe(p)) return bad("pipe", errno, 0);
    pid_t fk = fork_reader(p[0], p[1]);
    if (fk <= 0) return bad("the trap's fork", fk, 1);
    close(p[0]);
    mach_port_t fn;
    if ((r = reach("the forked child", fk, &fn))) return r;
    close(p[1]);
    if (waitpid(fk, &st, 0) != fk || !WIFEXITED(st) || WEXITSTATUS(st)) return bad("the forked child's status", st, 0);
    if ((r = dead("the forked child's name port once reaped", fn))) return r;
    if ((r = unreachable("the forked child's pid once reaped", fk))) return r;

    // A child spawned suspended, reached before it runs.
    int in[2], out[2];
    if (pipe(in) || pipe(out)) return bad("pipe", errno, 0);
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, in[0], 0);
    posix_spawn_file_actions_adddup2(&fa, out[1], 1);
    posix_spawn_file_actions_addclose(&fa, in[1]);
    posix_spawn_file_actions_addclose(&fa, out[0]);
    posix_spawnattr_t at;
    posix_spawnattr_init(&at);
    posix_spawnattr_setflags(&at, POSIX_SPAWN_START_SUSPENDED);
    char *args[] = {self, "exec", NULL};
    pid_t sp;
    int e;
    if ((e = posix_spawn(&sp, self, &fa, &at, args, env))) return bad("spawning", e, 0);
    close(in[0]);
    close(out[1]);
    mach_port_t sn;
    if ((r = reach("the suspended child", sp, &sn))) return r;
    // Stopped before posix_spawn returned.
    st = -1;
    if (waitpid(sp, &st, WUNTRACED | WNOHANG) != sp || !WIFSTOPPED(st) || WSTOPSIG(st) != 0) return bad("the suspended child's stop", st, 0x7f);

    // Let go, it execs: the old task's name port names no task, and the
    // pid's new task has a name port of its own.
    kill(sp, SIGCONT);
    char c = 0;
    if (read(out[0], &c, 1) != 1 || c != 'x') return bad("the exec'd image's word", c, 'x');
    if ((r = nameless("the name port of the task the exec left", sn))) return r;
    mach_port_t xn;
    if ((r = reach("the exec'd child", sp, &xn))) return r;
    if (xn == sn) return bad("the exec'd task's name port", xn, 0);

    // A zombie, then reaped.
    close(in[1]);
    siginfo_t si;
    memset(&si, 0, sizeof si);
    if (waitid(P_PID, sp, &si, WEXITED | WNOWAIT) || si.si_pid != sp) return bad("the zombie", errno, 0);
    if ((r = unreachable("a zombie's pid", sp))) return r;
    if ((r = nameless("a zombie's name port", xn))) return r;
    if (waitpid(sp, &st, 0) != sp || !WIFEXITED(st) || WEXITSTATUS(st)) return bad("the exec'd child's status", st, 0);
    if ((r = dead("the exec'd child's name port once reaped", xn))) return r;
    if ((r = unreachable("the exec'd child's pid once reaped", sp))) return r;
    printf("taskreg ok\n");
    return 0;
}
