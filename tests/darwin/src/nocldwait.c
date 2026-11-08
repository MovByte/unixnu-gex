// P_NOCLDWAIT (SIGCHLD ignored, or SA_NOCLDWAIT): a child's end is reaped
// by the system, so the parent's wait finds no child (ECHILD) once it has
// ended, no SIGCHLD comes, and its time is not the parent's children's
// (RUSAGE_CHILDREN). A child reaped by its parent brings its own reaped
// children's time with it: the grandparent's RUSAGE_CHILDREN has the
// grandchild's.

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int bad(const char *what, long got, long want) {
    printf("nocldwait: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

static volatile uint64_t sink;
static volatile sig_atomic_t chld;

static void on_chld(int s) {
    (void)s;
    chld++;
}

static void spin(uint64_t ns) {
    uint64_t until = clock_gettime_nsec_np(CLOCK_THREAD_CPUTIME_ID) + ns;
    while (clock_gettime_nsec_np(CLOCK_THREAD_CPUTIME_ID) < until) {
        for (int i = 0; i < 100000; i++) sink += (uint64_t)i * i;
    }
}

static uint64_t children_ns(void) {
    struct rusage ru;
    getrusage(RUSAGE_CHILDREN, &ru);
    return (uint64_t)ru.ru_utime.tv_sec * 1000000000u + (uint64_t)ru.ru_utime.tv_usec * 1000u + (uint64_t)ru.ru_stime.tv_sec * 1000000000u + (uint64_t)ru.ru_stime.tv_usec * 1000u;
}

int main(void) {
    const uint64_t ms = 1000000;
    // SIGCHLD ignored: the wait finds none once the child has ended.
    signal(SIGCHLD, SIG_IGN);
    pid_t pid = fork();
    if (pid == 0) {
        spin(100 * ms);
        _exit(0);
    }
    int st;
    errno = 0;
    if (waitpid(-1, &st, 0) != -1 || errno != ECHILD) return bad("waiting under SIG_IGN", errno, ECHILD);
    if (children_ns() > 50 * ms) return bad("an ignored child's time", (long)(children_ns() / ms), 0);

    // SA_NOCLDWAIT with a handler: no SIGCHLD either.
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_chld;
    sa.sa_flags = SA_NOCLDWAIT;
    sigaction(SIGCHLD, &sa, NULL);
    pid = fork();
    if (pid == 0) _exit(0);
    errno = 0;
    if (waitpid(pid, &st, 0) != -1 || errno != ECHILD) return bad("waiting under SA_NOCLDWAIT", errno, ECHILD);
    usleep(100000);
    if (chld != 0) return bad("SIGCHLDs", chld, 0);

    // Reaped by its parent: its own reaped children's time comes with it.
    signal(SIGCHLD, SIG_DFL);
    uint64_t before = children_ns();
    pid = fork();
    if (pid == 0) {
        pid_t g = fork();
        if (g == 0) {
            spin(150 * ms);
            _exit(0);
        }
        waitpid(g, &st, 0);
        _exit(0);
    }
    waitpid(pid, &st, 0);
    if (children_ns() - before < 130 * ms) return bad("a grandchild's time", (long)((children_ns() - before) / ms), 150);
    printf("nocldwait ok\n");
    return 0;
}
