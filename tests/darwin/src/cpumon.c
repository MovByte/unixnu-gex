// The CPU usage monitor a spawn turns on (posix_spawnattr_setcpumonitor):
// the new process's per-thread limit, as process_policy reads it back (its
// action NOTIFY_EXC, its percentage, its interval in seconds), a spawn's
// taken as entitled past the system's caps, the defaults its 0xFE asks for
// (50% over three minutes); a thread that computes past it (its start-up,
// or what it does after) is reported and the monitor suspended, so it
// reads back as none.

#include <errno.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;
int posix_spawnattr_setcpumonitor(posix_spawnattr_t *attr, uint64_t percent, uint64_t interval);

struct cpuattr {
    uint32_t attr;
    uint32_t percentage;
    uint64_t interval;
    uint64_t deadline;
};

static long pp(long scope, long action, long policy, long subtype, void *attr, long pid, uint64_t tid) {
    register long x0 __asm__("x0") = scope;
    register long x1 __asm__("x1") = action;
    register long x2 __asm__("x2") = policy;
    register long x3 __asm__("x3") = subtype;
    register void *x4 __asm__("x4") = attr;
    register long x5 __asm__("x5") = pid;
    register uint64_t x6 __asm__("x6") = tid;
    register long x16 __asm__("x16") = 323;
    long carry;
    __asm__ volatile("svc #0x80\n\tcset %1, cs" : "+r"(x0), "=r"(carry) : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x6), "r"(x16) : "memory", "cc");
    if (carry) {
        errno = (int)x0;
        return -1;
    }
    return x0;
}

static int get(struct cpuattr *a) {
    memset(a, 0xa5, sizeof *a);
    // PROCESS scope, GET, RESOURCE_USAGE, CPU, this process.
    return (int)pp(1, 11, 4, 3, a, 0, 0);
}

static volatile uint64_t sink;

static int child(const char *mode) {
    struct cpuattr a;
    if (get(&a) != 0) return 10;
    if (!strcmp(mode, "plain")) return a.attr == 5 && a.percentage == 90 && a.interval == 7 && a.deadline == 0 ? 0 : 11;
    if (!strcmp(mode, "defaults")) return a.attr == 5 && a.percentage == 50 && a.interval == 180 ? 0 : 12;
    if (!strcmp(mode, "burn")) {
        // A tenth of a second a second. Starting up may have used that
        // already, the monitor then reported and off before main; else
        // compute for most of a second.
        int fired = a.percentage == 0 && a.interval == 0;
        if (!fired && (a.percentage != 10 || a.interval != 1)) return 13;
        uint64_t until = clock_gettime_nsec_np(CLOCK_THREAD_CPUTIME_ID) + 600000000ull;
        while (!fired && clock_gettime_nsec_np(CLOCK_THREAD_CPUTIME_ID) < until) {
            for (int i = 0; i < 100000; i++) sink += (uint64_t)i * i;
        }
        if (get(&a) != 0) return 14;
        return a.percentage == 0 && a.interval == 0 ? 0 : 15;
    }
    if (!strcmp(mode, "none")) return a.attr == 0 && a.percentage == 0 && a.interval == 0 ? 0 : 16;
    return 9;
}

static int run(const char *self, const char *mode, uint64_t pct, uint64_t secs) {
    posix_spawnattr_t at;
    posix_spawnattr_init(&at);
    if (pct) posix_spawnattr_setcpumonitor(&at, pct, secs);
    char *args[] = {(char *)self, (char *)mode, NULL};
    pid_t pid;
    int e = posix_spawn(&pid, self, NULL, &at, args, environ);
    posix_spawnattr_destroy(&at);
    if (e) return 100 + e;
    int st;
    waitpid(pid, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : 200 + WTERMSIG(st);
}

int main(int argc, char **argv) {
    if (argc > 1) return child(argv[1]);
    int r;
    if ((r = run(argv[0], "none", 0, 0)) != 0) return printf("cpumon: no monitor: %d\n", r), 1;
    if ((r = run(argv[0], "plain", 90, 7)) != 0) return printf("cpumon: a spawn's monitor: %d\n", r), 1;
    if ((r = run(argv[0], "defaults", 0xfe, 0)) != 0) return printf("cpumon: the defaults: %d\n", r), 1;
    if ((r = run(argv[0], "burn", 10, 1)) != 0) return printf("cpumon: a thread past it: %d\n", r), 1;
    printf("cpumon ok\n");
    return 0;
}
