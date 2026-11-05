// wait4 by kern_exit.c's rules: ECHILD with no child to wait for, EINVAL
// for INT_MIN, an exit's status, a death by signal with Darwin's number,
// WNOHANG's zero while the child runs, and the children a process group
// names (zero for the caller's own, which a child in a group of its own is
// not in). waitid: EINVAL for no options and for a negative pid, the
// siginfo of an exit (CLD_EXITED and the code) and of a death by signal
// (CLD_KILLED and the signal), WNOWAIT leaving the child to be waited for
// again.

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int bad(const char *what, long v) {
    printf("wait: %s (%ld)\n", what, v);
    return 1;
}

static char self[PATH_MAX];
static char *env[] = {"MallocNanoZone=0", NULL};

static pid_t run(const char *mode, posix_spawn_file_actions_t *fa, posix_spawnattr_t *at) {
    char *args[] = {self, (char *)mode, NULL};
    pid_t pid = -1;
    int r = posix_spawn(&pid, self, fa, at, args, env);
    return r ? -r : pid;
}

int main(int argc, char **argv) {
    if (argc > 1) {
        if (!strcmp(argv[1], "exit7")) return 7;
        if (!strcmp(argv[1], "usr1")) {
            signal(SIGUSR1, SIG_DFL);
            raise(SIGUSR1);
            return 0;
        }
        if (!strcmp(argv[1], "block")) {
            char c;
            while (read(0, &c, 1) > 0) {
            }
            return 0;
        }
        return 99;
    }
    uint32_t n = sizeof self;
    _NSGetExecutablePath(self, &n);
    int st;

    if (waitpid(-1, &st, WNOHANG) != -1 || errno != ECHILD) return bad("ECHILD with no children", errno);
    if (waitpid(INT_MIN, &st, 0) != -1 || errno != EINVAL) return bad("EINVAL for INT_MIN", errno);

    pid_t pid = run("exit7", NULL, NULL);
    if (pid <= 0) return bad("spawning", pid);
    if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st) || WEXITSTATUS(st) != 7) return bad("an exit's status", st);
    if (waitpid(pid, &st, WNOHANG) != -1 || errno != ECHILD) return bad("a reaped child", errno);

    pid = run("usr1", NULL, NULL);
    if (waitpid(pid, &st, 0) != pid || !WIFSIGNALED(st) || WTERMSIG(st) != SIGUSR1) return bad("a death by SIGUSR1", st);

    int p[2];
    pipe(p);
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, p[0], 0);
    posix_spawn_file_actions_addclose(&fa, p[1]);
    pid = run("block", &fa, NULL);
    close(p[0]);
    if (waitpid(pid, &st, WNOHANG) != 0) return bad("WNOHANG while it runs", 0);
    close(p[1]);
    if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st) || WEXITSTATUS(st) != 0) return bad("the blocked child's end", st);

    // In a group of its own first: wait4 makes zero minus the caller's
    // group, which for group 1 is WAIT_ANY.
    if (setpgid(0, 0)) return bad("setpgid", errno);
    posix_spawnattr_t at;
    posix_spawnattr_init(&at);
    posix_spawnattr_setpgroup(&at, 0);
    posix_spawnattr_setflags(&at, POSIX_SPAWN_SETPGROUP);
    pid = run("exit7", NULL, &at);
    if (waitpid(0, &st, WNOHANG) != -1 || errno != ECHILD) return bad("waitpid(0) for a child in another group", errno);
    if (waitpid(-pid, &st, 0) != pid || WEXITSTATUS(st) != 7) return bad("waitpid(-pgid)", st);
    siginfo_t si;
    if (waitid(P_ALL, 0, &si, 0) != -1 || errno != EINVAL) return bad("waitid with no options", errno);
    if (waitid(P_PID, (id_t)-1, &si, WEXITED) != -1 || errno != EINVAL) return bad("waitid of a negative pid", errno);
    pid = run("exit7", NULL, NULL);
    memset(&si, 0, sizeof si);
    if (waitid(P_PID, pid, &si, WEXITED | WNOWAIT) || si.si_signo != SIGCHLD || si.si_pid != pid || si.si_code != CLD_EXITED || si.si_status != 7) return bad("waitid's siginfo of an exit", si.si_code);
    memset(&si, 0, sizeof si);
    if (waitid(P_PID, pid, &si, WEXITED) || si.si_pid != pid) return bad("the child WNOWAIT left", si.si_pid);
    if (waitpid(pid, &st, WNOHANG) != -1 || errno != ECHILD) return bad("the child waitid reaped", errno);
    pid = run("usr1", NULL, NULL);
    if (waitid(P_ALL, 0, &si, WEXITED) || si.si_code != CLD_KILLED || si.si_status != SIGUSR1) return bad("waitid's siginfo of a death by signal", si.si_status);
    printf("wait ok\n");
    return 0;
}
