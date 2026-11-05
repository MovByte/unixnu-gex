// Signal handlers on Darwin's frame: a SA_SIGINFO handler's siginfo and
// mask and exception state, the old action sigaction reports, SA_RESETHAND,
// an alternate stack, and the interrupted code's registers back after
// sigreturn.

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile int hits, bad;
static volatile pid_t from;
static char altstack[64 * 1024];

static void with_info(int sig, siginfo_t *si, void *uc) {
    ucontext_t *u = uc;
    sigset_t now;
    sigprocmask(SIG_BLOCK, NULL, &now);
    if (sig != SIGUSR1 || si->si_signo != SIGUSR1 || !sigismember(&now, SIGUSR1) || !sigismember(&now, SIGUSR2) || sigismember(&u->uc_sigmask, SIGUSR1)) {
        bad = 1;
    }
    // Taken on kill's way back: the frame's exception state is that
    // call's svc #0x80, with no fault address.
    if (u->uc_mcontext->__es.__esr != 0x56000080 || u->uc_mcontext->__es.__far) {
        bad = 3;
    }
    from = si->si_pid;
    hits++;
}

static void once(int sig) {
    (void)sig;
    hits++;
}

static void on_alt(int sig) {
    char here;
    (void)sig;
    if (&here < altstack || &here >= altstack + sizeof altstack) {
        bad = 2;
    }
    hits++;
}

int main(void) {
    struct sigaction sa, old;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = with_info;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGUSR2);
    if (sigaction(SIGUSR1, &sa, NULL) || sigaction(SIGUSR1, NULL, &old) || old.sa_sigaction != with_info || !(old.sa_flags & SA_SIGINFO) || !sigismember(&old.sa_mask, SIGUSR2)) {
        printf("sighandler: sigaction reports the wrong action\n");
        return 1;
    }
    double d = 1.5;
    kill(getpid(), SIGUSR1);
    d *= 2;
    if (hits != 1 || bad || from != getpid() || d != 3.0) {
        printf("sighandler: SA_SIGINFO hits %d bad %d from %d\n", hits, bad, (int)from);
        return 1;
    }

    signal(SIGUSR2, SIG_DFL);
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = once;
    sa.sa_flags = SA_RESETHAND;
    sigaction(SIGUSR2, &sa, NULL);
    kill(getpid(), SIGUSR2);
    sigaction(SIGUSR2, NULL, &old);
    if (hits != 2 || old.sa_handler != SIG_DFL) {
        printf("sighandler: SA_RESETHAND hits %d\n", hits);
        return 1;
    }

    stack_t ss = {.ss_sp = altstack, .ss_size = sizeof altstack, .ss_flags = 0};
    if (sigaltstack(&ss, NULL)) {
        printf("sighandler: sigaltstack failed\n");
        return 1;
    }
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_alt;
    sa.sa_flags = SA_ONSTACK;
    sigaction(SIGALRM, &sa, NULL);
    kill(getpid(), SIGALRM);
    if (hits != 3 || bad) {
        printf("sighandler: SA_ONSTACK hits %d bad %d\n", hits, bad);
        return 1;
    }
    printf("sighandler %d\n", hits);
    return 0;
}
