// A unix datagram socket's buffers as XNU keeps them: a send larger than
// the sender's buffer (unpdg_sendspace, SO_SNDBUF) is EMSGSIZE; a datagram
// the receiver's buffer has no space for is ENOBUFS, never a wait, its
// space the least of the room for bytes (each datagram with its sender's
// address) and for mbuf storage (sb_mbmax, eight times SO_RCVBUF, against
// the mbufs and clusters sosend copied it into). FIONREAD is the buffer's
// sb_cc, the addresses counted; SO_NREAD and a kevent the data; a full
// peer leaves a connected socket unwritable.

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/event.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static int bad(const char *what, long got, long want) {
    printf("dgrambuf: %s: %ld, want %ld\n", what, got, want);
    fflush(stdout);
    return 1;
}

static int geti(int fd, int name) {
    int v = -1;
    socklen_t l = sizeof v;
    if (getsockopt(fd, SOL_SOCKET, name, &v, &l)) return -errno;
    return v;
}

static int fionread(int fd) {
    int n = -1;
    ioctl(fd, FIONREAD, &n);
    return n;
}

// How many datagrams of `size` fit before ENOBUFS.
static int fit(int size, int rcvbuf, int *err) {
    int sv[2];
    socketpair(AF_UNIX, SOCK_DGRAM, 0, sv);
    if (rcvbuf) setsockopt(sv[1], SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof rcvbuf);
    static char b[2048];
    int n = 0;
    while (write(sv[0], b, size) == size) n++;
    *err = errno;
    close(sv[0]);
    close(sv[1]);
    return n;
}

static int writable(int fd) {
    struct pollfd p = {fd, POLLOUT, 0};
    return poll(&p, 1, 0) == 1 && (p.revents & POLLOUT);
}

static long kev(int kq, int fd, int filter) {
    struct kevent ev, out;
    EV_SET(&ev, fd, filter, EV_ADD | EV_ONESHOT, 0, 0, 0);
    struct timespec z = {0, 0};
    if (kevent(kq, &ev, 1, &out, 1, &z) != 1) return -1;
    return (long)out.data;
}

int main(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv)) return bad("socketpair", errno, 0);
    if (geti(sv[0], SO_SNDBUF) != 2048) return bad("SO_SNDBUF", geti(sv[0], SO_SNDBUF), 2048);
    if (geti(sv[1], SO_RCVBUF) != 4096) return bad("SO_RCVBUF", geti(sv[1], SO_RCVBUF), 4096);
    if (geti(sv[0], SO_SNDLOWAT) != 1) return bad("SO_SNDLOWAT", geti(sv[0], SO_SNDLOWAT), 1);
    static char big[4096];
    errno = 0;
    if (write(sv[0], big, 2049) != -1 || errno != EMSGSIZE) return bad("a send past SO_SNDBUF", errno, EMSGSIZE);
    if (write(sv[0], big, 2048) != 2048) return bad("a send of SO_SNDBUF", errno, 0);
    if (write(sv[0], "abc", 3) != 3) return bad("a second", errno, 0);
    // Unnamed: each with sun_noname's 16 bytes.
    if (fionread(sv[1]) != 16 + 2048 + 16 + 3) return bad("FIONREAD", fionread(sv[1]), 16 + 2048 + 16 + 3);
    if (geti(sv[1], SO_NREAD) != 2048) return bad("SO_NREAD", geti(sv[1], SO_NREAD), 2048);
    if (geti(sv[1], SO_NUMRCVPKT) != 2) return bad("SO_NUMRCVPKT", geti(sv[1], SO_NUMRCVPKT), 2);
    if (geti(sv[0], SO_NWRITE) != 0) return bad("SO_NWRITE", geti(sv[0], SO_NWRITE), 0);
    int kq = kqueue();
    if (kev(kq, sv[1], EVFILT_READ) != 2048 + 3) return bad("the read filter's data", kev(kq, sv[1], EVFILT_READ), 2048 + 3);
    if (read(sv[1], big, sizeof big) != 2048 || read(sv[1], big, sizeof big) != 3) return bad("the reads", errno, 0);
    if (fionread(sv[1]) != 0) return bad("FIONREAD after", fionread(sv[1]), 0);

    // Small ones until the storage runs out: 32 mbufs of address and data,
    // 1024 bytes each, are SO_RCVBUF's 4096 times eight. No wait, even on a
    // blocking socket.
    if (kev(kq, sv[0], EVFILT_WRITE) != 2048) return bad("the write filter's data", kev(kq, sv[0], EVFILT_WRITE), 2048);
    int n = 0;
    while (write(sv[0], "x", 1) == 1) n++;
    if (n != 32 || errno != ENOBUFS) return bad("small datagrams", n, 32);
    if (writable(sv[0])) return bad("POLLOUT with the peer full", 1, 0);
    if (kev(kq, sv[0], EVFILT_WRITE) != -1) return bad("the write filter with the peer full", kev(kq, sv[0], EVFILT_WRITE), -1);
    char c;
    read(sv[1], &c, 1);
    if (!writable(sv[0])) return bad("POLLOUT after a read", 0, 1);
    if (kev(kq, sv[0], EVFILT_WRITE) != 1024) return bad("the write filter after a read", kev(kq, sv[0], EVFILT_WRITE), 1024);
    close(sv[0]);
    close(sv[1]);

    // The count by size: an mbuf for up to MLEN (288) bytes, a 2 KB
    // cluster past it, the bytes' limit past 112.
    static const int sizes[][2] = {{0, 32}, {112, 32}, {113, 31}, {288, 13}, {289, 11}, {1024, 3}, {2033, 1}, {2048, 1}};
    for (unsigned i = 0; i < sizeof sizes / sizeof sizes[0]; i++) {
        int err;
        int got = fit(sizes[i][0], 0, &err);
        if (got != sizes[i][1] || err != ENOBUFS) return bad("datagrams of a size", sizes[i][0] * 1000 + got, sizes[i][0] * 1000 + sizes[i][1]);
    }
    // A larger receive buffer: its storage eight times as large.
    int err;
    if (fit(1, 8192, &err) != 64) return bad("small datagrams in 8192", fit(1, 8192, &err), 64);

    // A bound sender's datagrams carry its address, as long as bind gave.
    int a = socket(AF_UNIX, SOCK_DGRAM, 0), b = socket(AF_UNIX, SOCK_DGRAM, 0);
    struct sockaddr_un ua = {0}, ub = {0};
    ua.sun_family = ub.sun_family = AF_UNIX;
    snprintf(ua.sun_path, sizeof ua.sun_path, "/tmp/dgrambuf_a_%d", getpid());
    snprintf(ub.sun_path, sizeof ub.sun_path, "/tmp/dgrambuf_b_%d", getpid());
    socklen_t bl = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + strlen(ub.sun_path) + 1);
    if (bind(a, (struct sockaddr *)&ua, sizeof ua) || bind(b, (struct sockaddr *)&ub, bl)) return bad("bind", errno, 0);
    if (sendto(a, "xyz", 3, 0, (struct sockaddr *)&ub, bl) != 3) return bad("sendto", errno, 0);
    if (fionread(b) != (int)sizeof ua + 3) return bad("FIONREAD of a bound sender's", fionread(b), sizeof ua + 3);
    if (sendto(b, "xyz", 3, 0, (struct sockaddr *)&ua, sizeof ua) != 3) return bad("sendto back", errno, 0);
    if (fionread(a) != (int)bl + 3) return bad("FIONREAD of a short address's", fionread(a), bl + 3);
    unlink(ua.sun_path);
    unlink(ub.sun_path);

    // SO_SNDBUF bounds a send.
    int s2[2];
    socketpair(AF_UNIX, SOCK_DGRAM, 0, s2);
    int v = 100;
    if (setsockopt(s2[0], SOL_SOCKET, SO_SNDBUF, &v, sizeof v)) return bad("SO_SNDBUF 100", errno, 0);
    errno = 0;
    if (write(s2[0], big, 101) != -1 || errno != EMSGSIZE) return bad("a send past SO_SNDBUF 100", errno, EMSGSIZE);
    if (write(s2[0], big, 100) != 100) return bad("a send of 100", errno, 0);
    // Not options a caller sets.
    errno = 0;
    if (setsockopt(s2[0], SOL_SOCKET, SO_NREAD, &v, sizeof v) != -1 || errno != ENOPROTOOPT) return bad("setting SO_NREAD", errno, ENOPROTOOPT);

    // A stream: no records to count, its bytes for SO_NREAD.
    int st[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, st);
    write(st[0], "hello", 5);
    if (geti(st[1], SO_NUMRCVPKT) != -ENOPROTOOPT) return bad("SO_NUMRCVPKT of a stream", geti(st[1], SO_NUMRCVPKT), -ENOPROTOOPT);
    if (geti(st[1], SO_NREAD) != 5 || fionread(st[1]) != 5) return bad("a stream's SO_NREAD", geti(st[1], SO_NREAD), 5);
    printf("dgrambuf ok\n");
    return 0;
}
