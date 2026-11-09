// The clocks a program reads without entering the kernel: the device's
// 24 MHz counter, mach_absolute_time built from it and the commpage's
// offset, mach_approximate_time ticking on with no call made, and
// gettimeofday's fast path from the commpage's timestamp, which the system
// call refreshes. And the commpage's two pages: what the read-only one
// holds, and the fields the kernel fills in at boot.

#include <mach/mach_time.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>

#define RW 0xFFFFFC000ull
#define RO 0xFFFFF4000ull

static uint8_t b(uint64_t a) { return *(volatile uint8_t *)a; }
static uint64_t q(uint64_t a) { return *(volatile uint64_t *)a; }

static uint64_t cntvct(void) {
    uint64_t v;
    __asm__ volatile("isb\n\tmrs %0, cntvct_el0" : "=r"(v));
    return v;
}

static uint64_t cntfrq(void) {
    uint64_t v;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(v));
    return v;
}

// gettimeofday's own call, past the fast path.
static long gtod_syscall(struct timeval *tv) {
    register void *x0 __asm__("x0") = tv;
    register long x1 __asm__("x1") = 0;
    register long x2 __asm__("x2") = 0;
    register long x16 __asm__("x16") = 116;
    __asm__ volatile("svc #0x80" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x16) : "memory", "cc");
    return (long)x0;
}

static int bad(const char *what, long long got, long long want) {
    printf("timebase: %s: %lld, want %lld\n", what, got, want);
    return 1;
}

static int64_t us(const struct timeval *t) { return (int64_t)t->tv_sec * 1000000 + t->tv_usec; }

int main(void) {
    if (cntfrq() != 24000000) return bad("CNTFRQ_EL0", (long long)cntfrq(), 24000000);
    mach_timebase_info_data_t tb;
    mach_timebase_info(&tb);
    if (tb.numer != 125 || tb.denom != 3) return bad("the timebase", tb.numer * 1000 + tb.denom, 125003);

    // User-readable, by an isb and CNTVCT; no continuous hardware clock;
    // no DTrace helpers in a release kernel.
    if (b(RW + 0x090) != 1) return bad("USER_TIMEBASE", b(RW + 0x090), 1);
    if (b(RW + 0x091) != 0) return bad("CONT_HWCLOCK", b(RW + 0x091), 0);
    if (b(RW + 0x092) != 0) return bad("DTRACE_DOF_ENABLED", b(RW + 0x092), 0);

    // mach_absolute_time is the counter plus the page's offset.
    uint64_t off = q(RW + 0x088);
    uint64_t t0 = mach_absolute_time(), c = cntvct() + off, t1 = mach_absolute_time();
    if (c < t0 || c > t1) return bad("counter plus offset between two absolute times", (long long)(c - t0), 0);

    // And the counter ticks at 24 MHz.
    uint64_t c0 = cntvct();
    struct timespec ts = {0, 200000000};
    nanosleep(&ts, NULL);
    uint64_t ticks = cntvct() - c0;
    if (ticks < 4800000 || ticks > 24000000) return bad("ticks over 200 ms", (long long)ticks, 4800000);

    // The approximate time moves on with no call made, and is never ahead
    // of the absolute time.
    if (b(RW + 0x0c8) != 1) return bad("APPROX_TIME_SUPPORTED", b(RW + 0x0c8), 1);
    uint64_t a0 = mach_approximate_time();
    uint64_t limit = cntvct() + 2 * 24000000;
    uint64_t a = a0;
    while (a == a0 && cntvct() < limit) a = mach_approximate_time();
    if (a == a0) return bad("mach_approximate_time moving with no call", 0, 1);
    uint64_t abs_now = mach_absolute_time();
    if (mach_approximate_time() > abs_now) return bad("approximate time ahead of absolute", 1, 0);

    // The system call stamps the page, and for the next second gettimeofday
    // works from the stamp alone: it does not change, and the times agree.
    struct timeval sys, fast;
    long r = gtod_syscall(&sys);
    if (r != 0) return bad("gettimeofday", r, 0);
    uint64_t stamp = q(RW + 0x120);
    if (stamp == 0) return bad("the timestamp after a system call", 0, 1);
    if (q(RW + 0x120 + 32) != 24000000) return bad("Ticks_per_sec", (long long)q(RW + 0x120 + 32), 24000000);
    gettimeofday(&fast, NULL);
    if (q(RW + 0x120) != stamp) return bad("the timestamp after the fast path", 1, 0);
    long long skew = us(&fast) - us(&sys);
    if (skew < 0 || skew > 200000) return bad("fast path less system call (us)", skew, 0);

    // The read-only page has the page shifts and the debugger answer, the
    // read-write one their legacy copies and all the rest.
    if (b(RO + 0x024) != 14 || b(RO + 0x025) != 14 || b(RO + 0x037) != 14) return bad("the read-only shifts", b(RO + 0x025), 14);
    if (*(volatile uint32_t *)(RO + 0x084) != 0) return bad("DEV_FIRM", *(volatile uint32_t *)(RO + 0x084), 0);
    if (b(RO + 0x022) != 0) return bad("the read-only page's NCPUS", b(RO + 0x022), 0);
    if (b(RW + 0x025) != 14) return bad("the legacy shift", b(RW + 0x025), 14);

    // The kernel's quiescent generation ticks over at least once a second.
    uint64_t gen = q(RW + 0x180);
    limit = cntvct() + 2 * 24000000;
    while (q(RW + 0x180) == gen && cntvct() < limit) {}
    if (q(RW + 0x180) == gen) return bad("the quiescent counter moving", 0, 1);

    // commpage_populate's remaining fields.
    if (q(RW + 0x148) != ~3ull) return bad("REMOTETIME_PARAMS", (long long)q(RW + 0x148), ~3ll);
    if (q(RW + 0x320) == 0) return bad("ASB value", 0, 1);
    if (q(RW + 0x328) < 0x0fc0000000ull) return bad("ASB address below the user limit", (long long)q(RW + 0x328), 0x0fc0000000ll);
    if (q(RW + 0x338) >= 0ull - (144ull << 30)) return bad("ASB kernel address in the kernel", 1, 0);
    printf("timebase ok\n");
    return 0;
}
