// The virtual and profiling timers and RLIMIT_CPU, counted in processor
// time (bsd_ast): ITIMER_VIRTUAL ends after the user time it was set to,
// not while the process sleeps; ITIMER_PROF runs again by its interval; a
// timer set before an exec runs on in the new image; RLIMIT_CPU ends a
// process that computes past it by SIGXCPU, one already past it at once,
// and a forked child's own time is counted against the limit from nothing.

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int bad(const char *what, long got, long want) {
    printf("vtimer: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

static uint64_t thread_ns(void) {
    return clock_gettime_nsec_np(CLOCK_THREAD_CPUTIME_ID);
}

static volatile uint64_t sink;
static volatile sig_atomic_t vtalrm, prof, xcpu;

static void on_vtalrm(int s) {
    (void)s;
    vtalrm++;
}

static void on_prof(int s) {
    (void)s;
    prof++;
}

static void on_xcpu(int s) {
    (void)s;
    xcpu++;
}

// Compute until `*flag` reaches `n`, or until this thread has used `limit`
// nanoseconds more; what it used.
static uint64_t spin_until(volatile sig_atomic_t *flag, int n, uint64_t limit) {
    uint64_t t0 = thread_ns();
    while (*flag < n && thread_ns() - t0 < limit) {
        for (int i = 0; i < 10000; i++) sink += (uint64_t)i * i;
    }
    return thread_ns() - t0;
}

static void forever(void) {
    for (;;) sink++;
}

static int status_of(pid_t pid) {
    int st;
    if (waitpid(pid, &st, 0) != pid) return -1;
    return WIFSIGNALED(st) ? WTERMSIG(st) : 0x1000 | WEXITSTATUS(st);
}

int main(int argc, char **argv) {
    const uint64_t ms = 1000000;
    if (argc > 1 && !strcmp(argv[1], "spin")) forever();

    // ITIMER_VIRTUAL: after 100 ms of user time, not of sleep.
    signal(SIGVTALRM, on_vtalrm);
    struct itimerval it = {{0, 0}, {0, 100000}}, got;
    if (setitimer(ITIMER_VIRTUAL, &it, NULL) != 0) return bad("setitimer(ITIMER_VIRTUAL)", -1, 0);
    usleep(300000);
    if (vtalrm) return bad("SIGVTALRM while asleep", vtalrm, 0);
    getitimer(ITIMER_VIRTUAL, &got);
    if (got.it_value.tv_sec != 0 || got.it_value.tv_usec < 90000) return bad("its value after a sleep", got.it_value.tv_usec, 100000);
    uint64_t used = spin_until(&vtalrm, 1, 2000 * ms);
    if (!vtalrm) return bad("SIGVTALRM", 0, 1);
    if (used < 80 * ms || used > 400 * ms) return bad("its time", (long)(used / ms), 100);
    getitimer(ITIMER_VIRTUAL, &got);
    if (got.it_value.tv_sec || got.it_value.tv_usec) return bad("ended", got.it_value.tv_usec, 0);

    // ITIMER_PROF every 50 ms, three times.
    signal(SIGPROF, on_prof);
    it = (struct itimerval){{0, 50000}, {0, 50000}};
    setitimer(ITIMER_PROF, &it, NULL);
    used = spin_until(&prof, 3, 3000 * ms);
    it = (struct itimerval){{0, 0}, {0, 0}};
    setitimer(ITIMER_PROF, &it, NULL);
    if (prof < 3) return bad("SIGPROFs", prof, 3);
    if (used < 120 * ms) return bad("their time", (long)(used / ms), 150);

    // A virtual timer set before an exec ends the new image (its handler
    // gone with the old one).
    pid_t pid = fork();
    if (pid == 0) {
        it = (struct itimerval){{0, 0}, {0, 100000}};
        setitimer(ITIMER_VIRTUAL, &it, NULL);
        char *args[] = {argv[0], "spin", NULL};
        execv(argv[0], args);
        _exit(9);
    }
    int st = status_of(pid);
    if (st != SIGVTALRM) return bad("the exec'd image's end", st, SIGVTALRM);

    // RLIMIT_CPU of a second: SIGXCPU once the process has used it.
    pid = fork();
    if (pid == 0) {
        struct rlimit rl = {1, RLIM_INFINITY};
        if (setrlimit(RLIMIT_CPU, &rl) != 0) _exit(8);
        signal(SIGXCPU, on_xcpu);
        uint64_t t = spin_until(&xcpu, 1, 5000 * ms);
        _exit(xcpu == 1 && t >= 800 * ms && t < 2500 * ms ? 0 : 7);
    }
    if ((st = status_of(pid)) != 0x1000) return bad("the CPU limit", st, 0x1000);

    // A limit the process is already past: SIGXCPU at once.
    pid = fork();
    if (pid == 0) {
        spin_until(&xcpu, 1, 50 * ms);
        signal(SIGXCPU, on_xcpu);
        struct rlimit rl = {0, RLIM_INFINITY};
        setrlimit(RLIMIT_CPU, &rl);
        _exit(xcpu == 1 ? 0 : 6);
    }
    if ((st = status_of(pid)) != 0x1000) return bad("a limit already passed", st, 0x1000);

    // A forked child computes against the limit from nothing, and dies of
    // SIGXCPU by default.
    pid = fork();
    if (pid == 0) {
        spin_until(&xcpu, 1, 600 * ms);
        struct rlimit rl = {1, RLIM_INFINITY};
        setrlimit(RLIMIT_CPU, &rl);
        pid_t c = fork();
        if (c == 0) {
            uint64_t t0 = thread_ns();
            signal(SIGXCPU, on_xcpu);
            spin_until(&xcpu, 1, 5000 * ms);
            _exit(thread_ns() - t0 >= 800 * ms ? 0 : 5);
        }
        int s = status_of(c);
        if (s != 0x1000) _exit(4);
        signal(SIGXCPU, SIG_DFL);
        forever();
    }
    if ((st = status_of(pid)) != SIGXCPU) return bad("the default action", st, SIGXCPU);
    printf("vtimer ok\n");
    return 0;
}
