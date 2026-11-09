// kevent and poll on sockets (filt_soread_common, filt_sowrite_common): a
// connected unix stream's data and send space, a listener's queue, a peer's
// end, the low water mark, a datagram socket, a loopback TCP listener and
// connection, and a blocked kevent woken from another thread and process.

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static int bad(const char *what, long got, long want) {
    printf("sockevent: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

static const struct timespec zero = {0, 0};

// One event of the knote, none being -1.
static int one(int kq, struct kevent *ev) {
    return kevent(kq, NULL, 0, ev, 1, &zero) == 1 ? 0 : -1;
}

static int add(int kq, int fd, int filter, int fflags, long data) {
    struct kevent c;
    EV_SET(&c, fd, filter, EV_ADD | EV_CLEAR * 0, fflags, data, NULL);
    return kevent(kq, &c, 1, NULL, 0, &zero);
}

static void *later(void *arg) {
    usleep(100000);
    write(*(int *)arg, "late", 4);
    return NULL;
}

int main(void) {
    int kq = kqueue();
    int sv[2];
    struct kevent ev;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return bad("socketpair", errno, 0);
    if (add(kq, sv[0], EVFILT_READ, 0, 0) != 0) return bad("add read", errno, 0);
    if (one(kq, &ev) == 0) return bad("an empty socket readable", ev.data, 0);
    if (write(sv[1], "hello", 5) != 5) return bad("write", errno, 0);
    if (one(kq, &ev) != 0 || ev.filter != EVFILT_READ || ev.data != 5) return bad("data waiting", ev.data, 5);

    // NOTE_LOWAT: not until the mark.
    if (add(kq, sv[0], EVFILT_READ, NOTE_LOWAT, 6) != 0) return bad("low water", errno, 0);
    if (one(kq, &ev) == 0) return bad("below the mark", ev.data, 0);
    write(sv[1], "!", 1);
    if (one(kq, &ev) != 0 || ev.data != 6) return bad("at the mark", ev.data, 6);
    if (add(kq, sv[0], EVFILT_READ, 0, 0) != 0) return bad("no mark", errno, 0);
    char buf[64];
    if (read(sv[0], buf, sizeof buf) != 6) return bad("read", errno, 0);
    if (one(kq, &ev) == 0) return bad("readable after the read", ev.data, 0);

    // The send space is what the peer's buffer has left.
    if (add(kq, sv[0], EVFILT_WRITE, 0, 0) != 0) return bad("add write", errno, 0);
    if (one(kq, &ev) != 0 || ev.filter != EVFILT_WRITE || ev.data != 8192) return bad("the send space", ev.data, 8192);
    write(sv[0], "abcd", 4);
    if (one(kq, &ev) != 0 || ev.filter != EVFILT_WRITE || ev.data != 8188) return bad("less of it", ev.data, 8188);
    read(sv[1], buf, sizeof buf);

    // A peer's end: EV_EOF, with the data still there.
    write(sv[1], "xy", 2);
    close(sv[1]);
    struct kevent got[2];
    int n = kevent(kq, NULL, 0, got, 2, &zero);
    if (n != 2) return bad("the end's events", n, 2);
    for (int i = 0; i < 2; i++) {
        if (!(got[i].flags & EV_EOF)) return bad("EV_EOF", got[i].flags, EV_EOF);
        if (got[i].filter == EVFILT_READ && got[i].data != 2) return bad("the data at the end", got[i].data, 2);
    }
    close(sv[0]);

    // A stream not connected is not writable.
    int fresh = socket(AF_UNIX, SOCK_STREAM, 0);
    int k2 = kqueue();
    add(k2, fresh, EVFILT_WRITE, 0, 0);
    if (one(k2, &ev) == 0) return bad("an unconnected stream writable", ev.data, 0);

    // A listener: its queue's length.
    char path[104];
    snprintf(path, sizeof path, "/private/var/tmp/sockevent-%d", getpid());
    unlink(path);
    struct sockaddr_un un = {.sun_family = AF_UNIX};
    strcpy(un.sun_path, path);
    un.sun_len = sizeof un;
    int l = socket(AF_UNIX, SOCK_STREAM, 0);
    if (bind(l, (void *)&un, sizeof un) != 0 || listen(l, 5) != 0) return bad("listen", errno, 0);
    int k3 = kqueue();
    add(k3, l, EVFILT_READ, 0, 0);
    if (one(k3, &ev) == 0) return bad("an empty listener readable", ev.data, 0);
    int c1 = socket(AF_UNIX, SOCK_STREAM, 0), c2 = socket(AF_UNIX, SOCK_STREAM, 0);
    if (connect(c1, (void *)&un, sizeof un) != 0 || connect(c2, (void *)&un, sizeof un) != 0) return bad("connect", errno, 0);
    if (one(k3, &ev) != 0 || ev.data != 2) return bad("the queue", ev.data, 2);
    int a1 = accept(l, NULL, NULL);
    if (one(k3, &ev) != 0 || ev.data != 1) return bad("one taken", ev.data, 1);

    // poll is the same filters.
    struct pollfd p = {a1, POLLIN | POLLOUT, 0};
    if (poll(&p, 1, 0) != 1 || p.revents != POLLOUT) return bad("poll of an idle socket", p.revents, POLLOUT);
    write(c1, "z", 1);
    p.revents = 0;
    if (poll(&p, 1, 0) != 1 || p.revents != (POLLIN | POLLOUT)) return bad("poll with data", p.revents, POLLIN | POLLOUT);
    read(a1, buf, 1);

    // A blocked kevent woken by another thread's write.
    int k4 = kqueue();
    add(k4, a1, EVFILT_READ, 0, 0);
    pthread_t th;
    pthread_create(&th, NULL, later, &c1);
    struct timespec two = {20, 0};
    if (kevent(k4, NULL, 0, &ev, 1, &two) != 1 || ev.data != 4) return bad("woken by a thread", ev.data, 4);
    pthread_join(th, NULL);
    read(a1, buf, sizeof buf);

    // ... and by another process's.
    pid_t pid = fork();
    if (pid == 0) {
        usleep(100000);
        write(c1, "chld", 4);
        _exit(0);
    }
    if (kevent(k4, NULL, 0, &ev, 1, &two) != 1 || ev.data != 4) return bad("woken by a process", ev.data, 4);
    int st;
    waitpid(pid, &st, 0);
    unlink(path);

    // A datagram socket has no connection to need.
    int ds[2];
    socketpair(AF_UNIX, SOCK_DGRAM, 0, ds);
    int k5 = kqueue();
    add(k5, ds[0], EVFILT_READ, 0, 0);
    add(k5, ds[1], EVFILT_WRITE, 0, 0);
    if (one(k5, &ev) != 0 || ev.filter != EVFILT_WRITE || ev.data != 2048) return bad("a datagram's send space", ev.data, 2048);
    send(ds[1], "abc", 3, 0);
    send(ds[1], "de", 2, 0);
    n = kevent(k5, NULL, 0, got, 2, &zero);
    int saw = 0;
    for (int i = 0; i < n; i++) {
        if (got[i].filter == EVFILT_READ) {
            saw = 1;
            if (got[i].data != 5) return bad("all that waits", got[i].data, 5);
        }
    }
    if (!saw) return bad("no read event", n, 2);

    // Loopback TCP.
    int tl = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in in = {.sin_family = AF_INET, .sin_len = sizeof in, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    if (bind(tl, (void *)&in, sizeof in) != 0 || listen(tl, 5) != 0) return bad("tcp listen", errno, 0);
    socklen_t ln = sizeof in;
    getsockname(tl, (void *)&in, &ln);
    int k6 = kqueue();
    add(k6, tl, EVFILT_READ, 0, 0);
    if (one(k6, &ev) == 0) return bad("an empty tcp listener readable", ev.data, 0);
    int tc = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(tc, (void *)&in, sizeof in) != 0) return bad("tcp connect", errno, 0);
    if (kevent(k6, NULL, 0, &ev, 1, &two) != 1 || ev.data != 1) return bad("a tcp connection waiting", ev.data, 1);
    int ta = accept(tl, NULL, NULL);
    int k7 = kqueue();
    add(k7, ta, EVFILT_READ, 0, 0);
    write(tc, "tcp!", 4);
    if (kevent(k7, NULL, 0, &ev, 1, &two) != 1 || ev.data != 4) return bad("tcp data", ev.data, 4);
    read(ta, buf, sizeof buf);
    close(tc);
    if (kevent(k7, NULL, 0, &ev, 1, &two) != 1 || !(ev.flags & EV_EOF)) return bad("tcp's end", ev.flags, EV_EOF);

    puts("sockevent ok");
    return 0;
}
