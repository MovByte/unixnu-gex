// The time the system booted: kern.boottime, and the commpage's copy that
// mach_boottime_usec reads, are the same moment, and the calendar time now
// is it plus the time since boot (mach_continuous_time).

#include <mach/mach_time.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/sysctl.h>
#include <sys/time.h>

uint64_t mach_boottime_usec(void);

static int bad(const char *what, long got, long want) {
    printf("boottime: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

int main(void) {
    struct timeval bt;
    size_t len = sizeof bt;
    if (sysctlbyname("kern.boottime", &bt, &len, NULL, 0) != 0 || len != sizeof bt) return bad("kern.boottime", (long)len, (long)sizeof bt);
    uint64_t bt_us = (uint64_t)bt.tv_sec * 1000000u + (uint64_t)bt.tv_usec;
    if (bt.tv_usec < 0 || bt.tv_usec >= 1000000) return bad("its microseconds", bt.tv_usec, 0);
    if (mach_boottime_usec() != bt_us) return bad("the commpage's boot time", (long)(mach_boottime_usec() - bt_us), 0);

    mach_timebase_info_data_t tb;
    mach_timebase_info(&tb);
    uint64_t up_us = mach_continuous_time() * tb.numer / tb.denom / 1000;
    struct timeval now;
    gettimeofday(&now, NULL);
    uint64_t now_us = (uint64_t)now.tv_sec * 1000000u + (uint64_t)now.tv_usec;
    long skew = (long)(now_us - (bt_us + up_us));
    if (skew < -100000 || skew > 100000) return bad("now less boot time less uptime (us)", skew, 0);
    printf("boottime ok\n");
    return 0;
}
