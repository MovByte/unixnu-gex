// Socket-level options as XNU keeps them: an option bit reads back as the
// bit (TCP_NODELAY as TF_NODELAY); SO_ACCEPTCONN has no getsockopt case; the buffers are the
// protocols' (unix datagram's send low-water mark 1); a buffer past
// sb_max is cut to it once and then ENOBUFS; values below 1, short
// lengths and a missing value are refused; SO_LINGER_SEC is kept in ticks;
// a short read gets what fits; and the kqueue write filter honours
// SO_SNDLOWAT.

#include <TargetConditionals.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <unistd.h>

static int bad(const char *what, long got, long want) {
    printf("sockopts: %s: %ld, want %ld\n", what, got, want);
    fflush(stdout);
    return 1;
}

static long get(int s, int opt) {
    int v = -1;
    socklen_t l = sizeof v;
    if (getsockopt(s, SOL_SOCKET, opt, &v, &l)) return -1000 - errno;
    return v;
}

static int set(int s, int opt, int v) { return setsockopt(s, SOL_SOCKET, opt, &v, sizeof v) ? errno : 0; }

int main(void) {
    int t = socket(AF_INET, SOCK_STREAM, 0), u = socket(AF_INET, SOCK_DGRAM, 0), sv[2], dv[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    socketpair(AF_UNIX, SOCK_DGRAM, 0, dv);
    long v;
    // Bits.
    set(t, SO_REUSEADDR, 1);
    if ((v = get(t, SO_REUSEADDR)) != SO_REUSEADDR) return bad("SO_REUSEADDR read back", v, SO_REUSEADDR);
    set(t, SO_KEEPALIVE, 7);
    if ((v = get(t, SO_KEEPALIVE)) != SO_KEEPALIVE) return bad("SO_KEEPALIVE read back", v, SO_KEEPALIVE);
    set(t, SO_KEEPALIVE, 0);
    if ((v = get(t, SO_KEEPALIVE)) != 0) return bad("SO_KEEPALIVE off", v, 0);
    if ((v = get(t, SO_ACCEPTCONN)) != -1000 - ENOPROTOOPT) return bad("SO_ACCEPTCONN", v, -1000 - ENOPROTOOPT);
    // TCP_NODELAY reads back as TF_NODELAY.
    int one = 1, nd = -1;
    socklen_t ndl = sizeof nd;
    setsockopt(t, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    getsockopt(t, IPPROTO_TCP, TCP_NODELAY, &nd, &ndl);
    if (nd != 4) return bad("TCP_NODELAY read back", nd, 4);

    // The protocols' buffers.
#if TARGET_OS_OSX
    long tsnd = 131072, trcv = 131072;
#else
    long tsnd = 1448 * 256, trcv = 1448 * 384;
#endif
    long want[][3] = {{t, SO_SNDBUF, tsnd}, {t, SO_RCVBUF, trcv}, {t, SO_SNDLOWAT, 2048}, {t, SO_RCVLOWAT, 1},
                      {u, SO_SNDBUF, 9216}, {u, SO_RCVBUF, 786896}, {u, SO_SNDLOWAT, 2048},
                      {sv[0], SO_SNDBUF, 8192}, {sv[0], SO_RCVBUF, 8192}, {sv[0], SO_SNDLOWAT, 2048},
                      {dv[0], SO_SNDBUF, 2048}, {dv[0], SO_RCVBUF, 4096}, {dv[0], SO_SNDLOWAT, 1}};
    for (unsigned i = 0; i < sizeof want / sizeof want[0]; i++) {
        if ((v = get((int)want[i][0], (int)want[i][1])) != want[i][2]) return bad("a default buffer mark", v, want[i][2]);
    }

    // sbreserve against sb_max.
    if ((v = set(t, SO_SNDBUF, 1 << 30))) return bad("a buffer past sb_max", v, 0);
    if ((v = get(t, SO_SNDBUF)) != 8 << 20) return bad("cut to sb_max", v, 8 << 20);
    if ((v = set(t, SO_SNDBUF, 1 << 30)) != ENOBUFS) return bad("past sb_max again", v, ENOBUFS);
    if ((v = set(t, SO_RCVBUF, 0)) != EINVAL) return bad("a buffer of 0", v, EINVAL);
    if ((v = set(u, SO_SNDLOWAT, 100000000))) return bad("a low-water mark past the buffer", v, 0);
    if ((v = get(u, SO_SNDLOWAT)) != 9216) return bad("cut to the buffer", v, 9216);

    // Lengths and values.
    short sh = 1;
    if (setsockopt(t, SOL_SOCKET, SO_DEBUG, &sh, sizeof sh) != -1 || errno != EINVAL) return bad("a short value", errno, EINVAL);
    if (setsockopt(t, SOL_SOCKET, SO_DEBUG, NULL, 4) != -1 || errno != EFAULT) return bad("no value", errno, EFAULT);
    char two[2];
    socklen_t l = sizeof two;
    if (getsockopt(t, SOL_SOCKET, SO_SNDBUF, two, &l) || l != 2) return bad("a short read", l, 2);
    l = 4;
    if (getsockopt(t, SOL_SOCKET, SO_SNDBUF, NULL, &l) || l != 0) return bad("no buffer", l, 0);
    int f = open("/dev/null", O_RDONLY);
    if (set(f, SO_DEBUG, 1) != ENOTSOCK) return bad("a file", errno, ENOTSOCK);
    if (set(999, SO_DEBUG, 1) != EBADF) return bad("no descriptor", errno, EBADF);

    // SO_LINGER_SEC in ticks.
    struct linger lg = {0, 5}, out;
    setsockopt(u, SOL_SOCKET, SO_LINGER_SEC, &lg, sizeof lg);
    l = sizeof out;
    getsockopt(u, SOL_SOCKET, SO_LINGER, &out, &l);
    if (out.l_onoff != 0 || out.l_linger != 500) return bad("SO_LINGER after SO_LINGER_SEC 5", out.l_linger, 500);
    l = sizeof out;
    getsockopt(u, SOL_SOCKET, SO_LINGER_SEC, &out, &l);
    if (out.l_linger != 5) return bad("SO_LINGER_SEC", out.l_linger, 5);

    // The write filter waits for SO_SNDLOWAT bytes of room.
    if ((v = set(sv[0], SO_SNDLOWAT, 8192))) return bad("SO_SNDLOWAT", v, 0);
    write(sv[0], "x", 1);
    int kq = kqueue();
    struct kevent ch, ev;
    EV_SET(&ch, sv[0], EVFILT_WRITE, EV_ADD, 0, 0, NULL);
    struct timespec z = {0, 0};
    int n = kevent(kq, &ch, 1, &ev, 1, &z);
    if (n != 0) return bad("writable below the low-water mark", n, 0);
    char b;
    read(sv[1], &b, 1);
    n = kevent(kq, NULL, 0, &ev, 1, &z);
    if (n != 1) return bad("writable once there is room", n, 1);
    printf("sockopts ok\n");
    return 0;
}
