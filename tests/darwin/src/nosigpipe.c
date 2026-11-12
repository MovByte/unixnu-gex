// SO_NOSIGPIPE: the socket's SOF_NOSIGPIPE (read back as 1), which
// F_SETNOSIGPIPE and F_GETNOSIGPIPE set and read on a socket. A send whose
// EPIPE comes with it raises no SIGPIPE, nor does one with MSG_NOSIGNAL,
// whether it failed at once or after waiting for room. A socket shut down
// both ways (its own doing, or its peer's going) takes no more options.

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static volatile sig_atomic_t got;
static void on_pipe(int s) { got = s; }

static int bad(const char *what, long got_, long want) {
    printf("nosigpipe: %s: %ld, want %ld\n", what, got_, want);
    fflush(stdout);
    return 1;
}

static int pair(int sv[2]) { return socketpair(AF_UNIX, SOCK_STREAM, 0, sv); }

// A send on a socket whose peer goes while it waits for room: its errno and
// whether SIGPIPE came.
struct parked {
    int fd, flags, err;
};

static void *send_parked(void *arg) {
    struct parked *p = arg;
    static char big[65536];
    errno = 0;
    p->err = send(p->fd, big, sizeof big, p->flags) == -1 ? errno : 0;
    return NULL;
}

static int parked_send(int nosigpipe, int flags, int *err) {
    int sv[2];
    if (pair(sv)) return -1;
    if (nosigpipe) fcntl(sv[0], F_SETNOSIGPIPE, 1);
    // Full, so the send waits.
    fcntl(sv[0], F_SETFL, O_NONBLOCK);
    char b[1024] = {0};
    while (write(sv[0], b, sizeof b) > 0) {
    }
    fcntl(sv[0], F_SETFL, 0);
    got = 0;
    struct parked p = {sv[0], flags, -1};
    pthread_t t;
    pthread_create(&t, NULL, send_parked, &p);
    usleep(300000);
    close(sv[1]);
    pthread_join(t, NULL);
    close(sv[0]);
    *err = p.err;
    return got;
}

int main(void) {
    signal(SIGPIPE, on_pipe);
    int sv[2];
    if (pair(sv)) return bad("socketpair", errno, 0);
    int v = -1;
    socklen_t l = sizeof v;
    if (getsockopt(sv[0], SOL_SOCKET, SO_NOSIGPIPE, &v, &l) || v != 0 || l != 4) return bad("the default", v, 0);
    if (fcntl(sv[0], F_GETNOSIGPIPE) != 0) return bad("F_GETNOSIGPIPE", fcntl(sv[0], F_GETNOSIGPIPE), 0);
    if (fcntl(sv[0], F_SETNOSIGPIPE, 1) != 0) return bad("F_SETNOSIGPIPE", errno, 0);
    l = sizeof v;
    if (getsockopt(sv[0], SOL_SOCKET, SO_NOSIGPIPE, &v, &l) || v != 1) return bad("SO_NOSIGPIPE after F_SETNOSIGPIPE", v, 1);
    if (fcntl(sv[0], F_GETNOSIGPIPE) != 1) return bad("F_GETNOSIGPIPE after", fcntl(sv[0], F_GETNOSIGPIPE), 1);
    v = 7;
    if (setsockopt(sv[1], SOL_SOCKET, SO_NOSIGPIPE, &v, sizeof v)) return bad("setsockopt", errno, 0);
    l = sizeof v;
    if (getsockopt(sv[1], SOL_SOCKET, SO_NOSIGPIPE, &v, &l) || v != 1) return bad("SO_NOSIGPIPE of 7", v, 1);
    errno = 0;
    if (setsockopt(sv[1], SOL_SOCKET, SO_NOSIGPIPE, &v, 2) != -1 || errno != EINVAL) return bad("a short value", errno, EINVAL);

    // At once: with the flag.
    close(sv[1]);
    got = 0;
    if (write(sv[0], "x", 1) != -1 || errno != EPIPE || got) return bad("a write with SOF_NOSIGPIPE", got, 0);
    // Its peer gone, the socket is shut down both ways: the flag stays.
    errno = 0;
    if (fcntl(sv[0], F_SETNOSIGPIPE, 0) != -1 || errno != EINVAL) return bad("F_SETNOSIGPIPE with the peer gone", errno, EINVAL);
    if (fcntl(sv[0], F_GETNOSIGPIPE) != 1) return bad("the flag kept", fcntl(sv[0], F_GETNOSIGPIPE), 1);
    close(sv[0]);
    // Without it, and with MSG_NOSIGNAL.
    if (pair(sv)) return bad("socketpair", errno, 0);
    close(sv[1]);
    got = 0;
    if (write(sv[0], "x", 1) != -1 || errno != EPIPE || got != SIGPIPE) return bad("a write without it", got, SIGPIPE);
    got = 0;
    if (send(sv[0], "x", 1, MSG_NOSIGNAL) != -1 || errno != EPIPE || got) return bad("a send with MSG_NOSIGNAL", got, 0);
    close(sv[0]);

    // After waiting for room.
    int err;
    if (parked_send(0, 0, &err) != SIGPIPE || err != EPIPE) return bad("a waiting send", err, EPIPE);
    if (parked_send(1, 0, &err) != 0 || err != EPIPE) return bad("a waiting send with SOF_NOSIGPIPE", err, EPIPE);
    if (parked_send(0, MSG_NOSIGNAL, &err) != 0 || err != EPIPE) return bad("a waiting send with MSG_NOSIGNAL", err, EPIPE);

    // Shut down both ways: no more options.
    if (pair(sv)) return bad("socketpair", errno, 0);
    shutdown(sv[0], SHUT_RDWR);
    errno = 0;
    if (fcntl(sv[0], F_SETNOSIGPIPE, 1) != -1 || errno != EINVAL) return bad("F_SETNOSIGPIPE when shut down", errno, EINVAL);
    printf("nosigpipe ok\n");
    return 0;
}
