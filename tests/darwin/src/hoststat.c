// host_statistics(HOST_LOAD_INFO): avenrun and mach_factor, which
// compute_averages moves every scheduler tick from the runnable count:
// each average to (old * fract + now * (1000 - fract)) / 1000, fract 975,
// 995 and 997, now the count (avenrun) or the CPUs left over (mach_factor)
// in thousandths. Too short a count fails; an unknown flavor is invalid.
// A platform binary is not rate limited, so while three threads spin it
// sees each pass's steps (one a tick, or as many as a late pass catches up,
// SCHED_TICK_MAX_DELTA at most) when it looks within a tick of its last.

#include <mach/mach.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/sysctl.h>
#include <time.h>
#include <unistd.h>

#define CS_OPS_STATUS 0
#define CS_PLATFORM_BINARY 0x04000000
int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);

static int bad(const char *what, long got, long want) {
    printf("hoststat: %s: %ld, want %ld\n", what, got, want);
    fflush(stdout);
    return 1;
}

static atomic_int stop;

static void *spin(void *arg) {
    (void)arg;
    while (!atomic_load_explicit(&stop, memory_order_relaxed)) {
    }
    return NULL;
}

static const uint32_t fract[3] = {975, 995, 997};

static double now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

int main(void) {
    host_t h = mach_host_self();
    host_load_info_data_t li;
    mach_msg_type_number_t n = HOST_LOAD_INFO_COUNT;
    if (host_statistics(h, HOST_LOAD_INFO, (host_info_t)&li, &n) != KERN_SUCCESS || n != HOST_LOAD_INFO_COUNT) return bad("HOST_LOAD_INFO", n, HOST_LOAD_INFO_COUNT);
    n = HOST_LOAD_INFO_COUNT - 1;
    if (host_statistics(h, HOST_LOAD_INFO, (host_info_t)&li, &n) != KERN_FAILURE) return bad("a short count", 0, KERN_FAILURE);
    n = 64;
    integer_t big[64];
    if (host_statistics(h, 99, big, &n) != KERN_INVALID_ARGUMENT) return bad("an unknown flavor", 0, KERN_INVALID_ARGUMENT);
    // host_statistics64 gives the same flavor.
    n = HOST_LOAD_INFO_COUNT;
    if (host_statistics64(h, HOST_LOAD_INFO, (host_info64_t)&li, &n) != KERN_SUCCESS || n != HOST_LOAD_INFO_COUNT) return bad("HOST_LOAD_INFO by host_statistics64", n, HOST_LOAD_INFO_COUNT);
    int ncpu;
    size_t len = sizeof ncpu;
    sysctlbyname("hw.ncpu", &ncpu, &len, NULL, 0);
    for (int i = 0; i < 3; i++)
        if (li.mach_factor[i] > ncpu * 1000) return bad("a mach factor", li.mach_factor[i], ncpu * 1000);

    uint32_t status = 0;
    csops(getpid(), CS_OPS_STATUS, &status, sizeof status);
    if (status & CS_PLATFORM_BINARY) {
        pthread_t t[3];
        for (int i = 0; i < 3; i++) pthread_create(&t[i], NULL, spin, NULL);
        host_load_info_data_t prev = li;
        int steps = 0;
        double last = now(), start = last;
        while (steps < 4 && now() - start < 10) {
            usleep(5000);
            n = HOST_LOAD_INFO_COUNT;
            host_statistics(h, HOST_LOAD_INFO, (host_info_t)&li, &n);
            double at = now(), gap = at - last;
            last = at;
            if (!memcmp(&li, &prev, sizeof li)) continue;
            // Two passes (two counts) may fall between looks far apart.
            if (gap > 0.1) {
                prev = li;
                continue;
            }
            // A pass's steps, for one runnable count.
            int found = 0;
            for (uint32_t c = 0; c < 64 && !found; c++) {
                uint32_t avg = c * 1000, factor = c > (uint32_t)ncpu ? (ncpu * 1000) / (c + 1) : (ncpu - c) * 1000;
                uint32_t a[3], f[3];
                for (int i = 0; i < 3; i++) a[i] = (uint32_t)prev.avenrun[i], f[i] = (uint32_t)prev.mach_factor[i];
                for (int k = 1; k <= 8 && !found; k++) {
                    found = 1;
                    for (int i = 0; i < 3; i++) {
                        a[i] = (a[i] * fract[i] + avg * (1000 - fract[i])) / 1000;
                        f[i] = (f[i] * fract[i] + factor * (1000 - fract[i])) / 1000;
                        if ((uint32_t)li.avenrun[i] != a[i] || (uint32_t)li.mach_factor[i] != f[i]) found = 0;
                    }
                }
            }
            if (!found) return bad("a tick's step", li.avenrun[0], prev.avenrun[0]);
            prev = li;
            steps++;
        }
        atomic_store(&stop, 1);
        for (int i = 0; i < 3; i++) pthread_join(t[i], NULL);
        if (steps < 4) return bad("the steps seen in 10 seconds", steps, 4);
    }
    printf("hoststat ok\n");
    return 0;
}
