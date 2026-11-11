// vm.loadavg: averunnable, which compute_averunnable moves every 5 seconds
// from the count of runnable threads, each average to
// (cexp * old + nrun * FSCALE * (FSCALE - cexp)) >> FSHIFT, with cexp
// exp(-1/12), exp(-1/60) and exp(-1/180) in FSHIFT 11 fixed point. While
// three threads spin, every change is one such step of all three averages
// for the same count, at least those three, about 5 seconds after the last.

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <time.h>
#include <unistd.h>

static int bad(const char *what, long got, long want) {
    printf("loadavg: %s: %ld, want %ld\n", what, got, want);
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

static const uint32_t cexp_[3] = {1884, 2014, 2036};

static uint32_t step(uint32_t old, uint32_t i, uint32_t nrun) {
    return (cexp_[i] * old + nrun * 2048 * (2048 - cexp_[i])) >> 11;
}

static double now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

int main(void) {
    struct loadavg la;
    size_t len = sizeof la;
    if (sysctlbyname("vm.loadavg", &la, &len, NULL, 0)) return bad("vm.loadavg", 0, 1);
    if (len != 24 || sizeof la != 24) return bad("its size", (long)len, 24);
    if (la.fscale != 2048) return bad("fscale", la.fscale, 2048);
    // Too small a buffer: ENOMEM.
    len = 16;
    if (sysctlbyname("vm.loadavg", &la, &len, NULL, 0) != -1 || errno != ENOMEM) return bad("a short buffer", errno, ENOMEM);
    double d[3];
    if (getloadavg(d, 3) != 3) return bad("getloadavg", 0, 3);

    pthread_t t[3];
    for (int i = 0; i < 3; i++) pthread_create(&t[i], NULL, spin, NULL);
    uint32_t prev[3];
    len = sizeof la;
    sysctlbyname("vm.loadavg", &la, &len, NULL, 0);
    for (int i = 0; i < 3; i++) prev[i] = la.ldavg[i];
    double last = 0, start = now();
    int changes = 0;
    while (changes < 3 && now() - start < 20) {
        usleep(20000);
        len = sizeof la;
        sysctlbyname("vm.loadavg", &la, &len, NULL, 0);
        if (la.ldavg[0] == prev[0] && la.ldavg[1] == prev[1] && la.ldavg[2] == prev[2]) continue;
        double at = now();
        // The count that step made, the same for all three.
        int n = -1;
        for (uint32_t c = 0; c < 4096 && n < 0; c++)
            if (step(prev[0], 0, c) == la.ldavg[0] && step(prev[1], 1, c) == la.ldavg[1] && step(prev[2], 2, c) == la.ldavg[2]) n = (int)c;
        if (n < 0) return bad("a step of all three averages", la.ldavg[0], step(prev[0], 0, 3));
        // The spinners are runnable (but in a step made as they started).
        if (n < 3 && at - start > 0.2) return bad("the runnable count", n, 3);
        if (last != 0 && (at - last < 4.8 || at - last > 5.4)) return bad("the interval (ms)", (long)((at - last) * 1000), 5000);
        last = at;
        changes++;
        for (int i = 0; i < 3; i++) prev[i] = la.ldavg[i];
    }
    atomic_store(&stop, 1);
    for (int i = 0; i < 3; i++) pthread_join(t[i], NULL);
    if (changes < 3) return bad("the changes in 20 seconds", changes, 3);
    // getloadavg's doubles are the same averages over fscale (unless a
    // step falls between the looks).
    struct loadavg before, after;
    len = sizeof before;
    sysctlbyname("vm.loadavg", &before, &len, NULL, 0);
    if (getloadavg(d, 3) != 3) return bad("getloadavg", 0, 3);
    sysctlbyname("vm.loadavg", &after, &len, NULL, 0);
    if (before.ldavg[0] == after.ldavg[0] && d[0] != before.ldavg[0] / 2048.0) return bad("getloadavg's average", (long)(d[0] * 1000), (long)(before.ldavg[0] / 2.048));
    printf("loadavg ok\n");
    return 0;
}
