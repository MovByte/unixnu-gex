// The host's clocks, each its own port: the system clock reads the time
// since boot (as mach_absolute_time does), the calendar the time of day;
// and host_info's internal debug flavor is a development kernel's only.

#include <mach/clock.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <stdio.h>
#include <sys/time.h>

static int bad(const char *what, long got, long want) {
    printf("machclock: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

int main(void) {
    host_t host = mach_host_self();
    clock_serv_t sys = MACH_PORT_NULL, cal = MACH_PORT_NULL;
    kern_return_t kr = host_get_clock_service(host, SYSTEM_CLOCK, &sys);
    if (kr != KERN_SUCCESS) return bad("the system clock", kr, 0);
    kr = host_get_clock_service(host, CALENDAR_CLOCK, &cal);
    if (kr != KERN_SUCCESS) return bad("the calendar clock", kr, 0);
    if (sys == cal) return bad("one port for both clocks", sys, 0);
    kr = host_get_clock_service(host, 2, &cal);
    if (kr != KERN_INVALID_ARGUMENT) return bad("a third clock", kr, KERN_INVALID_ARGUMENT);
    host_get_clock_service(host, CALENDAR_CLOCK, &cal);

    // The system clock against the counter, to a second.
    mach_timebase_info_data_t tb;
    mach_timebase_info(&tb);
    uint64_t before = mach_absolute_time() * tb.numer / tb.denom / 1000000000;
    mach_timespec_t t;
    if (clock_get_time(sys, &t) != KERN_SUCCESS) return bad("the system clock's time", 0, 1);
    uint64_t after = mach_absolute_time() * tb.numer / tb.denom / 1000000000;
    if (t.tv_sec < before || t.tv_sec > after + 1) return bad("the system clock's seconds", t.tv_sec, before);
    if (t.tv_nsec < 0 || t.tv_nsec >= 1000000000) return bad("its nanoseconds", t.tv_nsec, 0);

    // The calendar against the time of day.
    struct timeval tv;
    gettimeofday(&tv, NULL);
    if (clock_get_time(cal, &t) != KERN_SUCCESS) return bad("the calendar's time", 0, 1);
    long d = (long)t.tv_sec - (long)tv.tv_sec;
    if (d < -1 || d > 1) return bad("the calendar's seconds", t.tv_sec, tv.tv_sec);

    // HOST_DEBUG_INFO_INTERNAL on a release kernel.
    integer_t info[64];
    mach_msg_type_number_t n = 64;
    kr = host_info(host, 10, info, &n);
    if (kr != KERN_NOT_SUPPORTED) return bad("host_info's internal debug flavor", kr, KERN_NOT_SUPPORTED);

    printf("machclock ok\n");
    return 0;
}
