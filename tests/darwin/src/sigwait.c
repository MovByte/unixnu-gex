// sigwait by kern_sig.c's __sigwait: a signal of the set already on a
// thread's list is taken from it at once, the lowest; with none, the thread
// waits for one (a signal that kills by default is taken, not acted on),
// its mask as it was after; a set of nothing, or of only SIGKILL and
// SIGSTOP, is EINVAL.

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int __sigwait(const sigset_t *set, int *sig);

static int bad(const char *what, long got, long want) {
    printf("sigwait: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

static int waited;
static sigset_t after;

static void *waiter(void *arg) {
    sigset_t *set = arg;
    int sig = 0;
    if (sigwait(set, &sig) != 0) return (void *)1;
    waited = sig;
    pthread_sigmask(SIG_BLOCK, NULL, &after);
    return NULL;
}

int main(void) {
    sigset_t set, none, pending;
    int sig = 0;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    sigaddset(&set, SIGUSR2);
    sigaddset(&set, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &set, NULL);

    // Already pending on this thread: taken at once, the lowest first.
    pthread_kill(pthread_self(), SIGUSR2);
    pthread_kill(pthread_self(), SIGUSR1);
    if (sigwait(&set, &sig) != 0 || sig != SIGUSR1) return bad("the lowest pending", sig, SIGUSR1);
    if (sigwait(&set, &sig) != 0 || sig != SIGUSR2) return bad("the next", sig, SIGUSR2);
    sigpending(&pending);
    if (sigismember(&pending, SIGUSR1) || sigismember(&pending, SIGUSR2)) return bad("taken off the list", 1, 0);

    // Nothing to wait for.
    sigemptyset(&none);
    if (__sigwait(&none, &sig) != -1 || errno != EINVAL) return bad("an empty set", errno, EINVAL);
    sigaddset(&none, SIGKILL);
    sigaddset(&none, SIGSTOP);
    if (__sigwait(&none, &sig) != -1 || errno != EINVAL) return bad("only SIGKILL and SIGSTOP", errno, EINVAL);

    // Another thread waits; this process is sent the signal.
    sigset_t one;
    sigemptyset(&one);
    sigaddset(&one, SIGUSR2);
    pthread_t t;
    pthread_create(&t, NULL, waiter, &one);
    usleep(100000);
    kill(getpid(), SIGUSR2);
    void *r;
    pthread_join(t, &r);
    if (r != NULL || waited != SIGUSR2) return bad("a waiting thread", waited, SIGUSR2);
    if (!sigismember(&after, SIGUSR2) || !sigismember(&after, SIGTERM)) return bad("its mask after", 0, 1);

    // A signal whose default kills is taken by the wait.
    kill(getpid(), SIGTERM);
    if (sigwait(&set, &sig) != 0 || sig != SIGTERM) return bad("SIGTERM", sig, SIGTERM);
    printf("sigwait ok\n");
    return 0;
}
