// poll by sys_generic.c's poll_nocancel, on a kqueue of its own: a pipe's
// read end is readable once written and hung up (with POLLIN) once its
// writer is gone, its write end writable; a negative descriptor is
// skipped; a closed one is POLLNVAL and answers at once; a regular file is
// always readable (EV_POLL); POLLWRITE hears a write to a file; a timeout
// with nothing ready returns 0, and none at all only waits; a write from
// another thread ends a wait; a signal ends one with EINTR; too many
// descriptors are EINVAL.

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

static int bad(const char *what, long got, long want) {
    printf("poll: %s: %#lx, want %#lx\n", what, got, want);
    return 1;
}

static double now(void) {
    struct timeval t;
    gettimeofday(&t, NULL);
    return t.tv_sec + t.tv_usec / 1e6;
}

static int later_fd;

static void *write_later(void *arg) {
    usleep(100000);
    write(later_fd, arg, 1);
    return NULL;
}

static pthread_t poller;

static void on_usr1(int s) {
    (void)s;
}

static void *signal_later(void *arg) {
    (void)arg;
    usleep(100000);
    pthread_kill(poller, SIGUSR1);
    return NULL;
}

int main(void) {
    int p[2], r;
    pipe(p);
    struct pollfd f[3];

    f[0] = (struct pollfd){p[0], POLLIN | POLLRDNORM, 0};
    if ((r = poll(f, 1, 50)) != 0 || f[0].revents) return bad("an empty pipe", r, 0);
    write(p[1], "x", 1);
    f[0].revents = 0x55;
    if ((r = poll(f, 1, -1)) != 1 || f[0].revents != (POLLIN | POLLRDNORM)) return bad("a written pipe", f[0].revents, POLLIN | POLLRDNORM);
    f[0] = (struct pollfd){p[1], POLLOUT, 0};
    f[1] = (struct pollfd){-1, POLLIN, 0x55};
    if ((r = poll(f, 2, 0)) != 1 || f[0].revents != POLLOUT || f[1].revents != 0) return bad("a pipe's write end", f[0].revents, POLLOUT);

    // A closed descriptor: POLLNVAL at once, counted.
    f[0] = (struct pollfd){p[0], POLLIN, 0};
    f[1] = (struct pollfd){99, POLLIN, 0};
    char c;
    read(p[0], &c, 1);
    if ((r = poll(f, 2, -1)) != 1 || f[1].revents != POLLNVAL || f[0].revents != 0) return bad("a closed descriptor", f[1].revents, POLLNVAL);

    // A regular file is readable even at its end.
    char self[PATH_MAX];
    uint32_t n = sizeof self;
    _NSGetExecutablePath(self, &n);
    int file = open(self, O_RDONLY);
    lseek(file, 0, SEEK_END);
    f[0] = (struct pollfd){file, POLLIN, 0};
    if ((r = poll(f, 1, 0)) != 1 || f[0].revents != POLLIN) return bad("a file at its end", f[0].revents, POLLIN);

    // POLLWRITE: another thread writes to a file.
    char path[] = "/var/tmp/gex-poll-XXXXXX";
    int tmp = mkstemp(path);
    f[0] = (struct pollfd){tmp, POLLWRITE, 0};
    later_fd = tmp;
    pthread_t t;
    pthread_create(&t, NULL, write_later, "w");
    r = poll(f, 1, 5000);
    pthread_join(t, NULL);
    unlink(path);
    if (r != 1 || f[0].revents != POLLWRITE) return bad("a file written", f[0].revents, POLLWRITE);

    // A wait a write ends.
    f[0] = (struct pollfd){p[0], POLLIN, 0};
    later_fd = p[1];
    pthread_create(&t, NULL, write_later, "y");
    if ((r = poll(f, 1, 5000)) != 1 || !(f[0].revents & POLLIN)) return bad("a wait ended by a write", r, 1);
    pthread_join(t, NULL);
    read(p[0], &c, 1);

    // No descriptors: a sleep.
    double t0 = now();
    if ((r = poll(NULL, 0, 80)) != 0 || now() - t0 < 0.07) return bad("no descriptors", (long)((now() - t0) * 1000), 80);

    // A signal ends a wait.
    struct sigaction sa = {.sa_handler = on_usr1};
    sigaction(SIGUSR1, &sa, NULL);
    poller = pthread_self();
    pthread_create(&t, NULL, signal_later, NULL);
    f[0] = (struct pollfd){p[0], POLLIN, 0};
    r = poll(f, 1, 5000);
    int e = errno;
    pthread_join(t, NULL);
    if (r != -1 || e != EINTR) return bad("a signal", e, EINTR);

    // The writer gone: hung up, and readable.
    close(p[1]);
    if ((r = poll(f, 1, -1)) != 1 || f[0].revents != (POLLIN | POLLHUP)) return bad("a hung-up pipe", f[0].revents, POLLIN | POLLHUP);

    if (poll(f, OPEN_MAX + 1, 0) != -1 || errno != EINVAL) return bad("too many", errno, EINVAL);
    printf("poll ok\n");
    return 0;
}
