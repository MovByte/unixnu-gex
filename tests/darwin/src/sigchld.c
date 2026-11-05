// SIGCHLD's siginfo by proc_exit and sendsig: a child's end is CLD_EXITED
// with its pid, real uid and exit code, the top byte of the value it exited
// with above it (moved from the child to the parent's record, so waitid no
// longer sees it), and a death by signal is CLD_KILLED with the signal. A
// signal posted by kill has code 0, the sender and the signal.

#include <errno.h>
#include <mach-o/dyld.h>
#include <limits.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile siginfo_t got;
static volatile int count;

static void on(int s, siginfo_t *si, void *uc) {
    (void)s;
    (void)uc;
    got = *si;
    count++;
}

static int bad(const char *what, long v) {
    printf("sigchld: %s (%lx)\n", what, v);
    return 1;
}

static char self[PATH_MAX];

static pid_t run(const char *mode) {
    char *args[] = {self, (char *)mode, NULL};
    char *env[] = {"MallocNanoZone=0", NULL};
    pid_t pid = -1;
    return posix_spawn(&pid, self, NULL, NULL, args, env) ? -1 : pid;
}

// Wait for the handler to have run `n` times, SIGCHLD let through only in
// sigsuspend.
static void await_count(int n) {
    sigset_t none;
    sigemptyset(&none);
    while (count < n) sigsuspend(&none);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        if (!strcmp(argv[1], "high")) _exit(0x2a000005);
        signal(SIGUSR1, SIG_DFL);
        raise(SIGUSR1);
        return 0;
    }
    uint32_t n = sizeof self;
    _NSGetExecutablePath(self, &n);
    struct sigaction sa = {.sa_sigaction = on, .sa_flags = SA_SIGINFO};
    sigaction(SIGCHLD, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);
    sigset_t m;
    sigemptyset(&m);
    sigaddset(&m, SIGCHLD);
    sigaddset(&m, SIGUSR2);
    sigprocmask(SIG_BLOCK, &m, NULL);

    pid_t pid = run("high");
    await_count(1);
    if (got.si_signo != SIGCHLD || got.si_code != CLD_EXITED || got.si_pid != pid || got.si_uid != getuid()) return bad("an exit's siginfo", got.si_code);
    if ((unsigned)got.si_status != 0x2a000005u) return bad("an exit's status with its top byte", got.si_status);
    siginfo_t si;
    memset(&si, 0, sizeof si);
    if (waitid(P_PID, pid, &si, WEXITED | WNOWAIT) || si.si_status != 5) return bad("waitid without the byte its parent took", si.si_status);
    int st;
    if (waitpid(pid, &st, 0) != pid || WEXITSTATUS(st) != 5) return bad("wait4's status", st);

    pid = run("usr1");
    await_count(2);
    if (got.si_code != CLD_KILLED || got.si_pid != pid || got.si_status != SIGUSR1) return bad("a death by signal's siginfo", got.si_status);
    waitpid(pid, &st, 0);

    kill(getpid(), SIGUSR2);
    await_count(3);
    if (got.si_signo != SIGUSR2 || got.si_code != 0 || got.si_pid != getpid() || got.si_status != SIGUSR2) return bad("a kill's siginfo", got.si_code);
    printf("sigchld ok\n");
    return 0;
}
