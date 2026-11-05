// task_name_for_pid (vm_unix.c) and requests on another task's name port:
// the child's name port names it (pid_for_task) and its kernel answers
// task_info for it (its audit token); a name port is not enough for
// TASK_DYLD_INFO; a pid with no process gives null and KERN_FAILURE; and
// once the child has ended its name port is dead.

#include <errno.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <spawn.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

static int bad(const char *what, long got, long want) {
    printf("taskname: %s: %#lx, want %#lx\n", what, got, want);
    return 1;
}

int main(int argc, char **argv) {
    if (argc > 1) {
        // Until the parent closes the pipe.
        char c;
        while (read(0, &c, 1) > 0) {}
        return 0;
    }
    char self[PATH_MAX];
    uint32_t len = sizeof self;
    _NSGetExecutablePath(self, &len);
    char *args[] = {self, "child", NULL};
    char *env[] = {"MallocNanoZone=0", NULL};
    int p[2];
    pipe(p);
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, p[0], 0);
    posix_spawn_file_actions_addclose(&fa, p[1]);
    pid_t pid;
    int e;
    if ((e = posix_spawn(&pid, self, &fa, NULL, args, env))) return bad("spawning", e, 0);
    close(p[0]);

    mach_port_t n = 0, mine = 0;
    kern_return_t kr;
    int got;
    if ((kr = task_name_for_pid(mach_task_self(), pid, &n)) || !MACH_PORT_VALID(n)) return bad("the child's name port", kr ? kr : n, 1);
    if ((kr = pid_for_task(n, &got)) || got != pid) return bad("pid_for_task on it", kr ? kr : got, pid);
    if ((kr = task_name_for_pid(mach_task_self(), getpid(), &mine)) || (kr = pid_for_task(mine, &got)) || got != getpid()) return bad("its own name port", kr ? kr : got, getpid());

    audit_token_t tok;
    mach_msg_type_number_t cnt = TASK_AUDIT_TOKEN_COUNT;
    // The audit token's pid (audit_token_to_pid's word).
    if ((kr = task_info(n, TASK_AUDIT_TOKEN, (task_info_t)&tok, &cnt)) || (pid_t)tok.val[5] != pid) return bad("the child's audit token", kr ? kr : (long)tok.val[5], pid);
    struct task_dyld_info di;
    cnt = TASK_DYLD_INFO_COUNT;
    if ((kr = task_info(n, TASK_DYLD_INFO, (task_info_t)&di, &cnt)) != KERN_INVALID_ARGUMENT) return bad("TASK_DYLD_INFO on a name port", kr, KERN_INVALID_ARGUMENT);

    mach_port_t none = 0x1234;
    if ((kr = task_name_for_pid(mach_task_self(), 99999, &none)) != KERN_FAILURE || none != MACH_PORT_NULL) return bad("a pid with no process", kr, KERN_FAILURE);

    close(p[1]);
    int st;
    if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st) || WEXITSTATUS(st)) return bad("the child's status", st, 0);
    mach_port_type_t t;
    if ((kr = mach_port_type(mach_task_self(), n, &t)) || t != MACH_PORT_TYPE_DEAD_NAME) return bad("its name port after it ended", kr ? kr : t, MACH_PORT_TYPE_DEAD_NAME);
    printf("taskname ok\n");
    return 0;
}
