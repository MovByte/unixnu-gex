// A TCP peer's shutdown(SHUT_WR) ends only this end's reading: EVFILT_READ
// has EV_EOF, EVFILT_WRITE fires without it and a write still reaches the
// peer; this end's own shutdown(SHUT_WR) gives EVFILT_WRITE its EV_EOF.

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <unistd.h>

static int bad(const char *what, long got, long want) {
    printf("halfclose: %s: %ld, want %ld\n", what, got, want);
    fflush(stdout);
    return 1;
}

// The event a filter on `fd` has now, within a second: its flags, or -1.
static long poll1(int kq, int fd, int filter) {
    struct kevent ch, ev;
    EV_SET(&ch, fd, filter, EV_ADD | EV_ONESHOT, 0, 0, NULL);
    struct timespec t = {1, 0};
    int n = kevent(kq, &ch, 1, &ev, 1, &t);
    return n == 1 ? (long)ev.flags : -1;
}

int main(void) {
    int l = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in in = {.sin_len = sizeof in, .sin_family = AF_INET};
    in.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(l, (struct sockaddr *)&in, sizeof in) || listen(l, 1)) return bad("listen", errno, 0);
    socklen_t il = sizeof in;
    getsockname(l, (struct sockaddr *)&in, &il);
    int c = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(c, (struct sockaddr *)&in, sizeof in)) return bad("connect", errno, 0);
    int s = accept(l, NULL, NULL);
    if (s < 0) return bad("accept", errno, 0);
    int kq = kqueue();

    if (shutdown(c, SHUT_WR)) return bad("shutdown", errno, 0);
    usleep(100000);
    long r = poll1(kq, s, EVFILT_READ);
    if (r < 0 || !(r & EV_EOF)) return bad("reading after the peer's FIN", r, EV_EOF);
    long w = poll1(kq, s, EVFILT_WRITE);
    if (w < 0) return bad("writing after the peer's FIN", w, 0);
    if (w & EV_EOF) return bad("EV_EOF on writing after the peer's FIN", w, 0);
    if (write(s, "hi", 2) != 2) return bad("a write after the peer's FIN", errno, 0);
    char b[4];
    ssize_t n = read(c, b, sizeof b);
    if (n != 2 || memcmp(b, "hi", 2)) return bad("the peer's read", n < 0 ? errno : n, 2);

    if (shutdown(s, SHUT_WR)) return bad("shutting down this end", errno, 0);
    w = poll1(kq, s, EVFILT_WRITE);
    if (w < 0 || !(w & EV_EOF)) return bad("writing after this end's shutdown", w, EV_EOF);
    printf("halfclose ok\n");
    return 0;
}
