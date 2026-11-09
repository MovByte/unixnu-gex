// proc_rlimit_control: the wakeups monitor each task starts with, what
// asking for its parameters reports after turning it off, and what the
// other flavors refuse.

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/resource.h>
#include <unistd.h>

// In libsystem; its declaration is private.
extern int proc_rlimit_control(pid_t, int, void *);
struct wakeupmon {
    uint32_t flags;
    int32_t rate;
};

static int bad(const char *what, long got, long want) {
    printf("rlimitctl: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

int main(void) {
    struct wakeupmon w = {WAKEMON_GET_PARAMS, 0};
    if (proc_rlimit_control(-1, RLIMIT_WAKEUPS_MONITOR, &w) != 0) return bad("reading the monitor", errno, 0);
    if (w.flags != WAKEMON_ENABLE || w.rate != 150) return bad("the monitor a task starts with", w.rate, 150);

    // Off: no more callbacks, but the limit is still there to report.
    w.flags = WAKEMON_DISABLE;
    if (proc_rlimit_control(getpid(), RLIMIT_WAKEUPS_MONITOR, &w) != 0) return bad("turning it off", errno, 0);
    w.flags = WAKEMON_GET_PARAMS;
    if (proc_rlimit_control(-1, RLIMIT_WAKEUPS_MONITOR, &w) != 0 || w.flags != WAKEMON_ENABLE || w.rate != 150) return bad("reading it after", w.rate, 150);

    // Back to the defaults; a rate of nothing is no rate.
    w.flags = WAKEMON_ENABLE | WAKEMON_SET_DEFAULTS;
    w.rate = 0;
    if (proc_rlimit_control(-1, RLIMIT_WAKEUPS_MONITOR, &w) != 0 || w.rate != 150) return bad("the defaults", w.rate, 150);
    w.flags = WAKEMON_ENABLE;
    w.rate = 0;
    errno = 0;
    if (proc_rlimit_control(-1, RLIMIT_WAKEUPS_MONITOR, &w) != -1 || errno != EINVAL) return bad("a rate of nothing", errno, EINVAL);

    // The other flavors, and what is not there to control.
    errno = 0;
    if (proc_rlimit_control(-1, RLIMIT_CPU_USAGE_MONITOR, (void *)0) != -1 || errno != EINVAL) return bad("no CPU monitor flag", errno, EINVAL);
    if (proc_rlimit_control(-1, RLIMIT_CPU_USAGE_MONITOR, (void *)CPUMON_MAKE_FATAL) != 0) return bad("a fatal CPU monitor", errno, 0);
    errno = 0;
    if (proc_rlimit_control(-1, RLIMIT_THREAD_CPULIMITS, (void *)0) != -1 || errno != EINVAL) return bad("a percentage of nothing", errno, EINVAL);
    errno = 0;
    if (proc_rlimit_control(getpid(), RLIMIT_THREAD_CPULIMITS, (void *)50) != -1 || errno != EINVAL) return bad("a pid for this thread's limit", errno, EINVAL);
    errno = 0;
    if (proc_rlimit_control(-1, 99, &w) != -1 || errno != EINVAL) return bad("a flavor that does not exist", errno, EINVAL);
    errno = 0;
    if (proc_rlimit_control(9999999, RLIMIT_WAKEUPS_MONITOR, &w) != -1 || errno != ESRCH) return bad("a process that does not exist", errno, ESRCH);

    printf("rlimitctl ok\n");
    return 0;
}
