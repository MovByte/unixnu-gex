// Process-shared synchronization in a task's own memory: a
// PTHREAD_PROCESS_SHARED mutex and condition variable, which reach psynch
// once contended, and a shared ulock (UL_COMPARE_AND_WAIT_SHARED), each
// waited on by one thread and woken by another.

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define UL_COMPARE_AND_WAIT_SHARED 3
#define ULF_NO_ERRNO 0x01000000

int __ulock_wait(uint32_t operation, void *addr, uint64_t value, uint32_t timeout);
int __ulock_wake(uint32_t operation, void *addr, uint64_t wake_value);

struct shared {
    pthread_mutex_t m;
    pthread_cond_t c;
    int ready;
    _Atomic uint32_t word;
};

static int bad(const char *what, long got, long want) {
    printf("pshared: %s: %ld, want %ld\n", what, got, want);
    fflush(stdout);
    return 1;
}

static void *signaller(void *arg) {
    struct shared *s = arg;
    usleep(20000);
    pthread_mutex_lock(&s->m);
    s->ready = 1;
    pthread_cond_signal(&s->c);
    pthread_mutex_unlock(&s->m);
    return NULL;
}

static void *waker(void *arg) {
    struct shared *s = arg;
    usleep(20000);
    s->word = 1;
    __ulock_wake(UL_COMPARE_AND_WAIT_SHARED | ULF_NO_ERRNO, (void *)&s->word, 0);
    return NULL;
}

int main(void) {
    struct shared *s = calloc(1, sizeof *s);
    pthread_mutexattr_t ma;
    pthread_mutexattr_init(&ma);
    if (pthread_mutexattr_setpshared(&ma, PTHREAD_PROCESS_SHARED)) return bad("mutex pshared", errno, 0);
    pthread_mutex_init(&s->m, &ma);
    pthread_condattr_t ca;
    pthread_condattr_init(&ca);
    if (pthread_condattr_setpshared(&ca, PTHREAD_PROCESS_SHARED)) return bad("cond pshared", errno, 0);
    pthread_cond_init(&s->c, &ca);

    pthread_t t;
    pthread_create(&t, NULL, signaller, s);
    pthread_mutex_lock(&s->m);
    while (!s->ready) {
        int r = pthread_cond_wait(&s->c, &s->m);
        if (r) return bad("cond wait", r, 0);
    }
    pthread_mutex_unlock(&s->m);
    pthread_join(t, NULL);

    pthread_create(&t, NULL, waker, s);
    while (s->word == 0) {
        int r = __ulock_wait(UL_COMPARE_AND_WAIT_SHARED | ULF_NO_ERRNO, (void *)&s->word, 0, 2000000);
        if (r < 0 && r != -EINTR && r != -ETIMEDOUT) return bad("ulock wait", r, 0);
    }
    pthread_join(t, NULL);
    printf("pshared ok\n");
    return 0;
}
