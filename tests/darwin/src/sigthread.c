// psignal's choice of thread and record of the sender: a process-directed
// signal goes to the first thread that does not block it; one every thread
// blocks waits on the first thread's list (sigpending there, not in
// another); a signal held when it was posted reaches its handler with no
// sender, and one taken at once with the sender's pid.

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static pthread_t taker;
static volatile int on_taker, hits;
static volatile pid_t from;
static volatile int stop, ready;
static sigset_t other_pending;

static void handler(int s, siginfo_t *si, void *uc) {
    (void)s;
    (void)uc;
    on_taker = pthread_equal(pthread_self(), taker);
    from = si->si_pid;
    hits++;
}

static void *run(void *arg) {
    (void)arg;
    sigset_t none;
    sigemptyset(&none);
    pthread_sigmask(SIG_SETMASK, &none, NULL);
    ready = 1;
    while (!stop) usleep(1000);
    return NULL;
}

static void *peek(void *arg) {
    (void)arg;
    sigpending(&other_pending);
    return NULL;
}

static int bad(const char *what, long v) {
    printf("sigthread: %s (%ld)\n", what, v);
    return 1;
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);

    sigset_t s1;
    sigemptyset(&s1);
    sigaddset(&s1, SIGUSR1);
    sigaddset(&s1, SIGUSR2);
    pthread_sigmask(SIG_BLOCK, &s1, NULL);
    pthread_create(&taker, NULL, run, NULL);
    while (!ready) usleep(1000);
    // The main thread blocks it: the other thread takes it, from us.
    kill(getpid(), SIGUSR1);
    for (int i = 0; i < 5000 && !hits; i++) usleep(1000);
    if (hits != 1 || !on_taker || from != getpid()) return bad("the signal went to the wrong thread", hits * 10 + on_taker);
    stop = 1;
    pthread_join(taker, NULL);

    // Every thread blocks it: it waits on the first thread's list.
    kill(getpid(), SIGUSR2);
    sigset_t mine;
    sigpending(&mine);
    pthread_t p;
    pthread_create(&p, NULL, peek, NULL);
    pthread_join(p, NULL);
    if (!sigismember(&mine, SIGUSR2) || sigismember(&other_pending, SIGUSR2)) return bad("sigpending", sigismember(&mine, SIGUSR2) * 10 + sigismember(&other_pending, SIGUSR2));
    // Held when posted, so no record of who sent it.
    hits = 0;
    from = -1;
    taker = pthread_self();
    pthread_sigmask(SIG_UNBLOCK, &s1, NULL);
    if (hits != 1 || from != 0) return bad("the held signal's sender", from);
    printf("sigthread ok\n");
    return 0;
}
