// Timeouts as the kernel takes them: kevent64's must be a valid timespec
// (no more than INT32_MAX seconds, up to a whole second of nanoseconds,
// which waits that second); F_SETLKWTIMEOUT's zero timeout waits as
// F_SETLKW does, a short one gives ETIMEDOUT.

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/event.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int bad(const char *what, long got, long want) {
    printf("timeouts: %s: %ld, want %ld\n", what, got, want);
    fflush(stdout);
    return 1;
}

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

int main(void) {
    int kq = kqueue();
    struct kevent64_s ev;
    struct timespec ts = {(time_t)INT64_MAX, 0};
    int n = kevent64(kq, NULL, 0, &ev, 1, 0, &ts);
    if (n != -1 || errno != EINVAL) return bad("a timeout past INT32_MAX seconds", n == -1 ? errno : n, EINVAL);
    ts.tv_sec = (time_t)INT32_MAX + 1;
    n = kevent64(kq, NULL, 0, &ev, 1, 0, &ts);
    if (n != -1 || errno != EINVAL) return bad("2^31 seconds", n == -1 ? errno : n, EINVAL);
    ts.tv_sec = 0;
    ts.tv_nsec = 1000000001;
    n = kevent64(kq, NULL, 0, &ev, 1, 0, &ts);
    if (n != -1 || errno != EINVAL) return bad("more than a second of nanoseconds", n == -1 ? errno : n, EINVAL);
    ts.tv_nsec = 1000000000;
    double t0 = now();
    n = kevent64(kq, NULL, 0, &ev, 1, 0, &ts);
    double waited = now() - t0;
    if (n != 0) return bad("a second of nanoseconds", n == -1 ? errno : n, 0);
    if (waited < 0.9) return bad("its wait, in ms", (long)(waited * 1000), 1000);

    // A lock held by a child: a short timeout runs out, a zero one waits
    // for the child to let go.
    char path[] = "/tmp/gex-timeouts-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) return bad("a file", errno, 0);
    unlink(path);
    int go[2], held[2];
    pipe(go);
    pipe(held);
    pid_t c = fork();
    if (c == 0) {
        struct flock fl = {.l_type = F_WRLCK, .l_whence = SEEK_SET};
        if (fcntl(fd, F_SETLK, &fl)) _exit(10);
        write(held[1], "h", 1);
        char b;
        read(go[0], &b, 1);
        usleep(300000);
        _exit(0);
    }
    char b;
    read(held[0], &b, 1);
    struct flocktimeout ft = {.fl = {.l_type = F_WRLCK, .l_whence = SEEK_SET}, .timeout = {0, 100000000}};
    int r = fcntl(fd, F_SETLKWTIMEOUT, &ft);
    if (r != -1 || errno != ETIMEDOUT) return bad("a short timeout", r == -1 ? errno : r, ETIMEDOUT);
    write(go[1], "g", 1);
    ft.timeout.tv_nsec = 0;
    t0 = now();
    r = fcntl(fd, F_SETLKWTIMEOUT, &ft);
    waited = now() - t0;
    if (r != 0) return bad("a zero timeout", errno, 0);
    if (waited < 0.2) return bad("its wait, in ms", (long)(waited * 1000), 300);
    int st;
    waitpid(c, &st, 0);
    if (!WIFEXITED(st) || WEXITSTATUS(st)) return bad("the child", st, 0);
    printf("timeouts ok\n");
    return 0;
}
