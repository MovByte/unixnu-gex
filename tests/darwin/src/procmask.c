// sigprocmask is the process's mask: blocking a signal in one thread
// blocks it in every thread (block_procsigmask), so a signal sent to the
// process stays pending until it is unblocked; pthread_sigmask is the
// calling thread's alone.

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

static volatile sig_atomic_t caught;
static void on_usr1(int s) { caught++; }

static int bad(const char *what, long got, long want) {
    printf("procmask: %s: %ld, want %ld\n", what, got, want);
    fflush(stdout);
    return 1;
}

static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static int step, seen_usr1, seen_usr2;

// The other thread: reports its mask at each step it is asked for.
static void *other(void *arg) {
    for (int want = 1; want <= 2; want++) {
        pthread_mutex_lock(&mu);
        while (step != want) pthread_cond_wait(&cv, &mu);
        sigset_t m;
        pthread_sigmask(SIG_BLOCK, NULL, &m);
        if (want == 1) seen_usr1 = sigismember(&m, SIGUSR1);
        else seen_usr2 = sigismember(&m, SIGUSR2);
        step = want * 10;
        pthread_cond_broadcast(&cv);
        pthread_mutex_unlock(&mu);
    }
    return NULL;
}

static void ask(int s) {
    pthread_mutex_lock(&mu);
    step = s;
    pthread_cond_broadcast(&cv);
    while (step != s * 10) pthread_cond_wait(&cv, &mu);
    pthread_mutex_unlock(&mu);
}

int main(void) {
    signal(SIGUSR1, on_usr1);
    pthread_t t;
    pthread_create(&t, NULL, other, NULL);
    sigset_t s;
    sigemptyset(&s);
    sigaddset(&s, SIGUSR1);
    sigprocmask(SIG_BLOCK, &s, NULL);
    ask(1);
    if (!seen_usr1) return bad("the other thread's mask after sigprocmask", seen_usr1, 1);
    // pthread_sigmask: this thread's alone.
    sigemptyset(&s);
    sigaddset(&s, SIGUSR2);
    pthread_sigmask(SIG_BLOCK, &s, NULL);
    ask(2);
    if (seen_usr2) return bad("the other thread's mask after pthread_sigmask", seen_usr2, 0);
    pthread_join(t, NULL);

    // Blocked everywhere: sent to the process, it waits.
    kill(getpid(), SIGUSR1);
    usleep(100000);
    if (caught) return bad("caught while blocked", caught, 0);
    sigset_t p;
    sigpending(&p);
    if (!sigismember(&p, SIGUSR1)) return bad("pending while blocked", 0, 1);
    sigemptyset(&s);
    sigaddset(&s, SIGUSR1);
    sigprocmask(SIG_UNBLOCK, &s, NULL);
    for (int i = 0; i < 100 && !caught; i++) usleep(10000);
    if (caught != 1) return bad("caught once unblocked", caught, 1);
    printf("procmask ok\n");
    return 0;
}
