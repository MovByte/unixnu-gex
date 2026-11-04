// Resource limits by kern_resource.c's rules: the first process's limit0
// (the stack's DFLSSIZ, 256 open files, maxprocperuid processes, no core),
// RLIM_INFINITY as (1 << 63) - 1, EINVAL for a bad resource or a soft limit
// over the hard one, EPERM for raising the hard limit, the process count
// clamped, RLIMIT_NOFILE enforced by open, and the stack limit moved below
// and back.

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/sysctl.h>
#include <unistd.h>

static int bad(const char *what, long v) {
    printf("rlimit: %s (%ld)\n", what, v);
    return 1;
}

static int is(int which, rlim_t cur, rlim_t max) {
    struct rlimit r;
    return getrlimit(which, &r) == 0 && r.rlim_cur == cur && r.rlim_max == max;
}

static long sysctl_int(const char *name) {
    int v = -1;
    size_t n = sizeof v;
    return sysctlbyname(name, &v, &n, NULL, 0) ? -1 : v;
}

int main(void) {
    struct rlimit r;
    if (RLIM_INFINITY != 0x7fffffffffffffffULL) return bad("RLIM_INFINITY", 0);
    if (!is(RLIMIT_STACK, 1024 * 1024 - 16 * 1024, 1024 * 1024 - 16 * 1024)) return bad("the stack's limit0", 0);
    if (!is(RLIMIT_NOFILE, 256, RLIM_INFINITY)) return bad("open files' limit0", 0);
    if (!is(RLIMIT_NPROC, 1333, 2000)) return bad("processes' limit0", 0);
    if (!is(RLIMIT_CORE, 0, RLIM_INFINITY)) return bad("core size's limit0", 0);
    if (!is(RLIMIT_CPU, RLIM_INFINITY, RLIM_INFINITY)) return bad("CPU time's limit0", 0);
    if (sysctl_int("kern.argmax") != 256 * 1024) return bad("kern.argmax", sysctl_int("kern.argmax"));
    if (sysctl_int("kern.maxprocperuid") != 1333) return bad("kern.maxprocperuid", sysctl_int("kern.maxprocperuid"));
    if (sysctl_int("kern.maxfiles") != 30720) return bad("kern.maxfiles", sysctl_int("kern.maxfiles"));

    if (getrlimit(RLIM_NLIMITS, &r) != -1 || errno != EINVAL) return bad("getrlimit past RLIM_NLIMITS", errno);
    r.rlim_cur = 20;
    r.rlim_max = 10;
    if (setrlimit(RLIMIT_NOFILE, &r) != -1 || errno != EINVAL) return bad("soft over hard", errno);
    if (getuid() != 0) {
        r.rlim_cur = r.rlim_max = 3000;
        if (setrlimit(RLIMIT_NPROC, &r) != -1 || errno != EPERM) return bad("raising the hard limit", errno);
    }
    // Lowered below what it was: clamped only when over maxprocperuid.
    r.rlim_cur = r.rlim_max = 1500;
    if (setrlimit(RLIMIT_NPROC, &r) || !is(RLIMIT_NPROC, getuid() == 0 ? 1500 : 1333, getuid() == 0 ? 1500 : 1333)) return bad("the process count clamped", errno);

    // Twenty open files: the twenty-first open fails.
    r.rlim_cur = 20;
    r.rlim_max = RLIM_INFINITY;
    if (setrlimit(RLIMIT_NOFILE | 0x1000, &r) || !is(RLIMIT_NOFILE, 20, RLIM_INFINITY)) return bad("RLIMIT_NOFILE with the POSIX flag", errno);
    int fd = -1, n = 0;
    while ((fd = open("/dev/null", O_RDONLY)) >= 0) n = fd;
    if (errno != EMFILE || n != 19) return bad("open at RLIMIT_NOFILE", n);
    for (int i = 3; i <= n; i++) close(i);

    // The stack's limit lowered under the current frame's reach, then
    // raised back: the pages between are made usable again.
    r.rlim_cur = 512 * 1024;
    r.rlim_max = 1024 * 1024 - 16 * 1024;
    if (setrlimit(RLIMIT_STACK, &r) || !is(RLIMIT_STACK, 512 * 1024, 1024 * 1024 - 16 * 1024)) return bad("lowering the stack limit", errno);
    r.rlim_cur = 1024 * 1024 - 16 * 1024;
    if (setrlimit(RLIMIT_STACK, &r) || !is(RLIMIT_STACK, r.rlim_cur, r.rlim_max)) return bad("raising the stack limit", errno);
    // Past maxsmap it is recorded as asked.
    if (getuid() == 0) {
        r.rlim_cur = r.rlim_max = 64 * 1024 * 1024;
        if (setrlimit(RLIMIT_STACK, &r) || !is(RLIMIT_STACK, r.rlim_cur, r.rlim_max)) return bad("a stack limit past maxsmap", errno);
    }
    printf("rlimit ok\n");
    return 0;
}
