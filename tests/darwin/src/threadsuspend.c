// thread_suspend and thread_resume by thread_act.c: a running thread is
// held at its next return to user space, and thread_suspend returns once
// it is off its CPU (thread_wait); a thread waiting in a call is off its
// CPU already, finishes its call, and is held before user space; the
// counts nest, and a resume of a thread not suspended is KERN_FAILURE; a
// thread may suspend itself until another resumes it.

#include <mach/mach.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

static volatile unsigned long spins;
static volatile int stop, after_read, after_self;
static int p[2];

static int bad(const char *what, long got, long want) {
    printf("threadsuspend: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

static void *spin(void *a) {
    (void)a;
    while (!stop) spins++;
    return NULL;
}

static void *reader(void *a) {
    (void)a;
    char c;
    read(p[0], &c, 1);
    after_read = 1;
    return NULL;
}

static void *self_suspender(void *a) {
    (void)a;
    thread_suspend(mach_thread_self());
    after_self = 1;
    return NULL;
}

int main(void) {
    kern_return_t kr;
    pthread_t t;
    pthread_create(&t, NULL, spin, NULL);
    while (spins < 1000) usleep(1000);
    thread_act_t th = pthread_mach_thread_np(t);
    if ((kr = thread_suspend(th))) return bad("suspending a running thread", kr, 0);
    unsigned long c1 = spins;
    usleep(100000);
    if (spins != c1) return bad("a suspended thread spinning", (long)(spins - c1), 0);
    // Nested: two suspends, two resumes.
    thread_suspend(th);
    thread_resume(th);
    usleep(50000);
    if (spins != c1) return bad("still suspended once", (long)(spins - c1), 0);
    if ((kr = thread_resume(th))) return bad("resuming", kr, 0);
    while (spins == c1) usleep(1000);
    if ((kr = thread_resume(th)) != KERN_FAILURE) return bad("a resume too many", kr, KERN_FAILURE);
    stop = 1;
    pthread_join(t, NULL);

    // Waiting in a call: suspended at once, held after its call.
    pipe(p);
    pthread_create(&t, NULL, reader, NULL);
    usleep(100000);
    th = pthread_mach_thread_np(t);
    if ((kr = thread_suspend(th))) return bad("suspending a waiting thread", kr, 0);
    write(p[1], "x", 1);
    usleep(100000);
    if (after_read) return bad("a suspended thread past its call", after_read, 0);
    thread_resume(th);
    pthread_join(t, NULL);
    if (!after_read) return bad("the thread once resumed", after_read, 1);

    // Itself, until another resumes it.
    pthread_create(&t, NULL, self_suspender, NULL);
    usleep(200000);
    if (after_self) return bad("a thread that suspended itself", after_self, 0);
    thread_resume(pthread_mach_thread_np(t));
    pthread_join(t, NULL);
    if (!after_self) return bad("it, resumed", after_self, 1);
    printf("threadsuspend ok\n");
    return 0;
}
