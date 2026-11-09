// pid_suspend and pid_resume on a child, each only once, what a task_resume
// cannot undo; ptrace(PT_DENY_ATTACH) and a debugger's request refused;
// memorystatus_available_memory.

#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define PT_DENY_ATTACH 31
int ptrace(int, pid_t, char *, int);
int pid_suspend(int);
int pid_resume(int);
int syscall(int, ...);

extern char **environ;

static int bad(const char *what, long got, long want) {
    printf("pidhold: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

int main(int argc, char **argv) {
    if (argc > 1) {
        // Says so each time it has run, until its pipe ends.
        for (;;) {
            if (write(1, "t", 1) != 1) return 0;
            usleep(10000);
        }
    }
    int p[2];
    pipe(p);
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, p[1], 1);
    posix_spawn_file_actions_addclose(&fa, p[0]);
    char *args[] = {argv[0], "tick", NULL};
    pid_t c;
    if (posix_spawn(&c, argv[0], &fa, NULL, args, environ)) return bad("spawn", errno, 0);
    close(p[1]);
    char b[256];
    if (read(p[0], b, 1) != 1) return bad("it runs", errno, 0);

    if (pid_suspend(c) != 0) return bad("pid_suspend", errno, 0);
    if (pid_suspend(c) != -1 || errno != EPERM) return bad("suspended twice", errno, EPERM);
    usleep(300000);
    // What it wrote before the hold took: drained, then silence.
    fcntl(p[0], F_SETFL, O_NONBLOCK);
    while (read(p[0], b, sizeof b) > 0) {
    }
    usleep(200000);
    errno = 0;
    if (read(p[0], b, sizeof b) != -1 || errno != EAGAIN) return bad("it still ran", errno, EAGAIN);

    if (pid_resume(c) != 0) return bad("pid_resume", errno, 0);
    if (pid_resume(c) != -1 || errno != EPERM) return bad("resumed twice", errno, EPERM);
    fcntl(p[0], F_SETFL, 0);
    if (read(p[0], b, 1) != 1) return bad("it runs again", errno, 0);

    if (pid_suspend(0) != -1 || errno != EPERM) return bad("pid 0", errno, EPERM);
    if (pid_suspend(99999) != -1 || errno != ESRCH) return bad("no such process", errno, ESRCH);
    kill(c, SIGKILL);
    int st;
    waitpid(c, &st, 0);
    close(p[0]);

    if (ptrace(PT_DENY_ATTACH, 0, 0, 0) != 0) return bad("PT_DENY_ATTACH", errno, 0);

    // An app (no dirty tracking) has what its limit leaves.
    uint64_t left = (uint64_t)syscall(534);
    if (left == 0) return bad("available memory", (long)left, 1);
    // No audit in an arm64 kernel.
    for (int n = 350; n <= 359; n++) {
        if (n == 352 || n == 355 || n == 356) continue;
        errno = 0;
        if (syscall(n, 0, 0) != -1 || errno != ENOSYS) return bad("an audit call", n, errno);
    }
    if (syscall(428) != -1 || errno != ENOSYS) return bad("audit_session_self", errno, ENOSYS);
    puts("pidhold ok");
    return 0;
}
