// Processor time: a thread's clock (CLOCK_THREAD_CPUTIME_ID, from
// thread_selfusage) runs while it computes and not while it sleeps; the
// process's (getrusage RUSAGE_SELF) holds the same time; a child's, reaped,
// is its parent's RUSAGE_CHILDREN, a child killed as it computes too.

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int bad(const char *what, long got, long want) {
    printf("cputime: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

static uint64_t thread_ns(void) {
    return clock_gettime_nsec_np(CLOCK_THREAD_CPUTIME_ID);
}

static uint64_t tv_ns(struct timeval tv) {
    return (uint64_t)tv.tv_sec * 1000000000u + (uint64_t)tv.tv_usec * 1000u;
}

static uint64_t usage_ns(int who) {
    struct rusage ru;
    getrusage(who, &ru);
    return tv_ns(ru.ru_utime) + tv_ns(ru.ru_stime);
}

static volatile uint64_t sink;

// Compute until this thread has used `ns` more.
static void spin(uint64_t ns) {
    uint64_t until = thread_ns() + ns;
    while (thread_ns() < until) {
        for (int i = 0; i < 100000; i++) sink += (uint64_t)i * i;
    }
}

int main(void) {
    const uint64_t ms = 1000000;
    uint64_t t0 = thread_ns(), u0 = usage_ns(RUSAGE_SELF);
    spin(100 * ms);
    uint64_t t1 = thread_ns(), u1 = usage_ns(RUSAGE_SELF);
    if (t1 - t0 < 100 * ms) return bad("the thread's clock", (long)((t1 - t0) / ms), 100);
    if (u1 - u0 < 90 * ms) return bad("the process's time", (long)((u1 - u0) / ms), 100);
    usleep(200000);
    uint64_t t2 = thread_ns();
    if (t2 - t1 > 50 * ms) return bad("time asleep", (long)((t2 - t1) / ms), 0);

    // A child computing, then exiting; then one killed as it computes.
    int st;
    pid_t pid = fork();
    if (pid == 0) {
        spin(100 * ms);
        _exit(0);
    }
    waitpid(pid, &st, 0);
    uint64_t c1 = usage_ns(RUSAGE_CHILDREN);
    if (c1 < 90 * ms) return bad("a child's time", (long)(c1 / ms), 100);
    int p[2];
    pipe(p);
    pid = fork();
    if (pid == 0) {
        spin(100 * ms);
        write(p[1], "x", 1);
        for (;;) sink++;
    }
    char c;
    read(p[0], &c, 1);
    kill(pid, SIGKILL);
    waitpid(pid, &st, 0);
    uint64_t c2 = usage_ns(RUSAGE_CHILDREN);
    if (c2 - c1 < 90 * ms) return bad("a killed child's time", (long)((c2 - c1) / ms), 100);
    printf("cputime ok\n");
    return 0;
}
