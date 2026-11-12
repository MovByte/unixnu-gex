// A unix stream socket's buffers as XNU keeps them. A send goes straight
// into the peer's receive buffer and lowers the sender's own SO_SNDBUF
// limit by what it put there (uipc_send); the peer's reads give it back
// (uipc_rcvd); SO_SNDBUF reads that limit plus what waits at the peer, so a
// resize with data queued, or a peer gone with it, shows. A send waits (but
// on a non-blocking socket: MSG_DONTWAIT does not count) while there is
// less room than it, or than SO_SNDLOWAT. A receive stops where a record
// ends: a send with control starts one, and later sends join it. Every
// descriptor a message carries is installed in the receiver, however much
// of the control fits; a peek copies the control without them. SHUT_RD
// flushes what waits, zeroes the receive buffer's limits, and drops what
// the peer sends after.

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/event.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

static int bad(const char *what, long got, long want) {
    printf("streambuf: %s: %ld, want %ld\n", what, got, want);
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

// A filter's data on `fd` now, or -1 when it does not fire.
static long kev(int fd, int filter, int lowat) {
    int kq = kqueue();
    struct kevent ev, out;
    EV_SET(&ev, fd, filter, EV_ADD, lowat ? NOTE_LOWAT : 0, lowat, 0);
    struct timespec z = {0, 0};
    long r = kevent(kq, &ev, 1, &out, 1, &z) == 1 ? (long)out.data : -1;
    close(kq);
    return r;
}

static long fill(int fd, int size) {
    static char b[65536];
    long t = 0;
    ssize_t n;
    while ((n = write(fd, b, size)) > 0) t += n;
    return t;
}

static long drain(int fd) {
    char b[65536];
    long t = 0;
    ssize_t n;
    int fl = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    while ((n = read(fd, b, sizeof b)) > 0) t += n;
    fcntl(fd, F_SETFL, fl);
    return t;
}

static int nopen(void) {
    int n = 0;
    for (int i = 0; i < 256; i++)
        if (fcntl(i, F_GETFD) != -1) n++;
    return n;
}

static ssize_t send_fds(int s, const char *data, size_t len, const int *fds, int k) {
    struct msghdr mh = {0};
    struct iovec io = {(void *)data, len};
    mh.msg_iov = &io;
    mh.msg_iovlen = 1;
    char cbuf[256];
    mh.msg_control = cbuf;
    mh.msg_controllen = CMSG_LEN(k * sizeof(int));
    struct cmsghdr *c = CMSG_FIRSTHDR(&mh);
    c->cmsg_len = CMSG_LEN(k * sizeof(int));
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    memcpy(CMSG_DATA(c), fds, k * sizeof(int));
    return sendmsg(s, &mh, 0);
}

static int drained_fd = -1;
static long drained;
static void *drainer(void *a) {
    (void)a;
    usleep(300000);
    char b[65536];
    long t = 0;
    for (int i = 0; i < 200; i++) {
        ssize_t n = recv(drained_fd, b, sizeof b, MSG_DONTWAIT);
        if (n > 0)
            t += n;
        else
            usleep(10000);
        if (t >= drained) break;
    }
    drained = t;
    return NULL;
}

static int closer_fd = -1;
static void *closer(void *a) {
    (void)a;
    usleep(300000);
    char b[1000];
    read(closer_fd, b, sizeof b);
    close(closer_fd);
    return NULL;
}

static int sender_fd = -1;
static void *sender(void *a) {
    (void)a;
    usleep(300000);
    write(sender_fd, "late", 4);
    return NULL;
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) return bad("socketpair", errno, 0);
    if (geti(sv[0], SO_SNDBUF) != 8192 || geti(sv[0], SO_RCVBUF) != 8192) return bad("the buffers", geti(sv[0], SO_SNDBUF), 8192);
    if (geti(sv[0], SO_SNDLOWAT) != 2048 || geti(sv[0], SO_RCVLOWAT) != 1) return bad("the low-water marks", geti(sv[0], SO_SNDLOWAT), 2048);
    fcntl(sv[0], F_SETFL, O_NONBLOCK);
    long n = fill(sv[0], 1);
    if (n != 8192 || errno != EAGAIN) return bad("one-byte sends", n, 8192);
    drain(sv[1]);
    // 1000 at a time: the last 192 bytes of room are under SO_SNDLOWAT.
    if ((n = fill(sv[0], 1000)) != 8000) return bad("1000-byte sends", n, 8000);
    if (geti(sv[0], SO_SNDBUF) != 8192) return bad("SO_SNDBUF with 8000 queued", geti(sv[0], SO_SNDBUF), 8192);
    if (kev(sv[0], EVFILT_WRITE, 0) != -1 || kev(sv[0], EVFILT_WRITE, 100) != -1) return bad("the write filter under SO_SNDLOWAT", kev(sv[0], EVFILT_WRITE, 100), -1);
    struct pollfd p = {sv[0], POLLOUT, 0};
    if (poll(&p, 1, 0) != 0) return bad("POLLOUT under SO_SNDLOWAT", p.revents, 0);
    if (geti(sv[0], SO_NWRITE) != 0 || fionread(sv[1]) != 8000) return bad("FIONREAD", fionread(sv[1]), 8000);
    drain(sv[1]);
    static char big[65536];
    if ((n = write(sv[0], big, 20000)) != 8192) return bad("a 20000-byte send", n, 8192);
    drain(sv[1]);

    // SO_SNDBUF with data queued: the limit set afresh, what waits added
    // when read, and given back on top when the peer reads.
    if (fill(sv[0], 1000) != 8000) return bad("8000 queued", 0, 8000);
    int v = 4096;
    setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &v, sizeof v);
    if (geti(sv[0], SO_SNDBUF) != 12096) return bad("SO_SNDBUF 4096 with 8000 queued", geti(sv[0], SO_SNDBUF), 12096);
    if (write(sv[0], "x", 1) != 1) return bad("a send after", errno, 0);
    drain(sv[1]);
    if (geti(sv[0], SO_SNDBUF) != 12096) return bad("SO_SNDBUF drained", geti(sv[0], SO_SNDBUF), 12096);
    if ((n = fill(sv[0], 1)) != 12096) return bad("its room", n, 12096);
    close(sv[0]);
    close(sv[1]);
    // The peer gone with data queued: what it took stays taken.
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    fcntl(sv[0], F_SETFL, O_NONBLOCK);
    fill(sv[0], 1000);
    close(sv[1]);
    if (geti(sv[0], SO_SNDBUF) != 192) return bad("SO_SNDBUF with the peer gone", geti(sv[0], SO_SNDBUF), 192);
    close(sv[0]);

    // Flags: an address on a connected stream is not looked at; MSG_EOR is
    // not a stream's; urgent data not a unix socket's.
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    struct sockaddr_un u = {0};
    u.sun_family = AF_UNIX;
    strcpy(u.sun_path, "/nonexistent");
    if (sendto(sv[0], "ab", 2, 0, (struct sockaddr *)&u, sizeof u) != 2) return bad("sendto with an address", errno, 0);
    errno = 0;
    if (send(sv[0], "ab", 2, MSG_EOR) != -1 || errno != EINVAL) return bad("MSG_EOR", errno, EINVAL);
    errno = 0;
    if (send(sv[0], "ab", 2, MSG_OOB) != -1 || errno != EOPNOTSUPP) return bad("MSG_OOB sent", errno, EOPNOTSUPP);
    char b[100];
    errno = 0;
    if (recv(sv[1], b, sizeof b, MSG_OOB) != -1 || errno != EOPNOTSUPP) return bad("MSG_OOB received", errno, EOPNOTSUPP);
    drain(sv[1]);

    // Records: a send with control starts one, the next joins it.
    int pfd[2];
    pipe(pfd);
    write(sv[0], "AB", 2);
    if (send_fds(sv[0], "CD", 2, &pfd[0], 1) != 2) return bad("sendmsg with a descriptor", errno, 0);
    write(sv[0], "EF", 2);
    if (fionread(sv[1]) != 22) return bad("FIONREAD with control", fionread(sv[1]), 22);
    if (geti(sv[1], SO_NREAD) != 6 || kev(sv[1], EVFILT_READ, 0) != 6) return bad("the data alone", geti(sv[1], SO_NREAD), 6);
    if ((n = read(sv[1], b, sizeof b)) != 2) return bad("a read to the record's end", n, 2);
    struct msghdr rh = {0};
    struct iovec rio = {b, sizeof b};
    rh.msg_iov = &rio;
    rh.msg_iovlen = 1;
    char rc[64];
    rh.msg_control = rc;
    rh.msg_controllen = sizeof rc;
    n = recvmsg(sv[1], &rh, 0);
    if (n != 4 || memcmp(b, "CDEF", 4) || rh.msg_controllen != 16 || rh.msg_flags != 0) return bad("the record with control", n, 4);
    int got;
    memcpy(&got, CMSG_DATA((struct cmsghdr *)rc), sizeof got);
    struct stat st1, st2;
    if (fstat(got, &st1) || fstat(pfd[0], &st2) || st1.st_ino != st2.st_ino) return bad("the descriptor received", got, pfd[0]);
    close(got);
    // Control alone: a send of none, a record of its control.
    if (send_fds(sv[0], "", 0, &pfd[0], 1) != 0) return bad("control alone", errno, 0);
    if (fionread(sv[1]) != 16) return bad("FIONREAD of control alone", fionread(sv[1]), 16);
    rh.msg_controllen = sizeof rc;
    if ((n = recvmsg(sv[1], &rh, MSG_DONTWAIT)) != 0 || rh.msg_controllen != 16) return bad("its receive", n, 0);
    memcpy(&got, CMSG_DATA((struct cmsghdr *)rc), sizeof got);
    close(got);

    // Every descriptor installed: past a short control buffer, and on a
    // read with none.
    int three[3] = {pfd[0], pfd[1], pfd[0]};
    send_fds(sv[0], "X", 1, three, 3);
    int before = nopen();
    rh.msg_controllen = CMSG_LEN(sizeof(int));
    rh.msg_flags = 0;
    if ((n = recvmsg(sv[1], &rh, 0)) != 1 || rh.msg_controllen != 16 || rh.msg_flags != MSG_CTRUNC || nopen() - before != 3) return bad("a short control buffer", nopen() - before, 3);
    if (((struct cmsghdr *)rc)->cmsg_len != 24) return bad("its cmsg_len", ((struct cmsghdr *)rc)->cmsg_len, 24);
    send_fds(sv[0], "X", 1, three, 3);
    before = nopen();
    if (read(sv[1], b, sizeof b) != 1 || nopen() - before != 3) return bad("a read of control", nopen() - before, 3);
    // A peek: the control copied, its descriptors not.
    send_fds(sv[0], "X", 1, three, 3);
    before = nopen();
    rh.msg_controllen = sizeof rc;
    rh.msg_flags = 0;
    if ((n = recvmsg(sv[1], &rh, MSG_PEEK)) != 1 || rh.msg_controllen != 24 || rh.msg_flags != MSG_PEEK || nopen() != before) return bad("a peek", rh.msg_controllen, 24);
    memcpy(&got, CMSG_DATA((struct cmsghdr *)rc), sizeof got);
    if (got != 0) return bad("a peeked descriptor", got, 0);
    rh.msg_controllen = sizeof rc;
    if (recvmsg(sv[1], &rh, 0) != 1 || nopen() - before != 3) return bad("after the peek", nopen() - before, 3);

    // sendmsg's checks.
    struct msghdr mh = {0};
    errno = 0;
    if (sendmsg(sv[0], &mh, 0) != -1 || errno != EMSGSIZE) return bad("no vector", errno, EMSGSIZE);
    struct iovec io = {"a", 1};
    mh.msg_iov = &io;
    mh.msg_iovlen = 1;
    char c[16] = {0};
    mh.msg_control = c;
    mh.msg_controllen = 8;
    errno = 0;
    if (sendmsg(sv[0], &mh, 0) != -1 || errno != EINVAL) return bad("short control", errno, EINVAL);
    struct cmsghdr *cm = (struct cmsghdr *)c;
    cm->cmsg_len = 12;
    cm->cmsg_level = SOL_SOCKET;
    cm->cmsg_type = SCM_TIMESTAMP;
    mh.msg_controllen = 12;
    errno = 0;
    if (sendmsg(sv[0], &mh, 0) != -1 || errno != EINVAL) return bad("not SCM_RIGHTS", errno, EINVAL);
    cm->cmsg_type = SCM_RIGHTS;
    mh.msg_controllen = 16;
    errno = 0;
    if (sendmsg(sv[0], &mh, 0) != -1 || errno != EINVAL) return bad("a length not the control's", errno, EINVAL);
    cm->cmsg_len = 16;
    int bogus = 999;
    memcpy(c + 12, &bogus, 4);
    errno = 0;
    if (sendmsg(sv[0], &mh, 0) != -1 || errno != EBADF) return bad("a bad descriptor", errno, EBADF);
    int kq = kqueue();
    memcpy(c + 12, &kq, 4);
    errno = 0;
    if (sendmsg(sv[0], &mh, 0) != -1 || errno != EINVAL) return bad("a kqueue", errno, EINVAL);
    if (fionread(sv[1]) != 0) return bad("nothing sent", fionread(sv[1]), 0);
    close(kq);
    close(sv[0]);
    close(sv[1]);

    // A blocking send waits for room, MSG_DONTWAIT or not, and completes.
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    write(sv[0], big, 8192);
    drained_fd = sv[1];
    drained = 8192 + 1;
    pthread_t t;
    pthread_create(&t, NULL, drainer, NULL);
    if ((n = send(sv[0], "x", 1, MSG_DONTWAIT)) != 1) return bad("MSG_DONTWAIT on a blocking send", errno, 0);
    pthread_join(t, NULL);
    // A long one: all of it, in rounds as the reader makes room.
    drained = 40000;
    pthread_create(&t, NULL, drainer, NULL);
    if ((n = write(sv[0], big, 40000)) != 40000) return bad("a blocking write of 40000", n, 40000);
    pthread_join(t, NULL);
    if (drained != 40000) return bad("what the reader got", drained, 40000);
    // With control: none of the room left, the lowered limit is under its
    // length (EMSGSIZE); some, and it waits before its first byte.
    write(sv[0], big, 8192);
    errno = 0;
    if (send_fds(sv[0], "Y", 1, &pfd[0], 1) != -1 || errno != EMSGSIZE) return bad("control with no room", errno, EMSGSIZE);
    drain(sv[1]);
    write(sv[0], big, 8092);
    drained = 8092 + 200;
    pthread_create(&t, NULL, drainer, NULL);
    if ((n = send_fds(sv[0], big, 200, &pfd[0], 1)) != 200) return bad("a waiting sendmsg", n, 200);
    pthread_join(t, NULL);
    if (drained != 8292) return bad("what the reader got after", drained, 8292);
    // The peer going while it waits: EPIPE.
    closer_fd = sv[1];
    pthread_create(&t, NULL, closer, NULL);
    errno = 0;
    if (write(sv[0], big, 20000) != -1 || errno != EPIPE) return bad("a write the peer left", errno, EPIPE);
    pthread_join(t, NULL);
    close(sv[0]);
    // A blocking receive waits for data.
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    sender_fd = sv[0];
    pthread_create(&t, NULL, sender, NULL);
    if ((n = read(sv[1], b, sizeof b)) != 4 || memcmp(b, "late", 4)) return bad("a waiting read", n, 4);
    pthread_join(t, NULL);
    errno = 0;
    if (recv(sv[1], b, sizeof b, MSG_DONTWAIT) != -1 || errno != EAGAIN) return bad("MSG_DONTWAIT on an empty receive", errno, EAGAIN);
    if (recv(sv[1], b, 0, 0) != 0) return bad("a receive of nothing", errno, 0);

    // SHUT_RD: what waits flushed, the limits zeroed, the peer's sends
    // dropped.
    write(sv[0], "hello", 5);
    shutdown(sv[1], SHUT_RD);
    if (fionread(sv[1]) != 0 || read(sv[1], b, sizeof b) != 0) return bad("a read after SHUT_RD", fionread(sv[1]), 0);
    if (geti(sv[1], SO_RCVBUF) != 0 || geti(sv[1], SO_RCVLOWAT) != 0) return bad("the limits after SHUT_RD", geti(sv[1], SO_RCVBUF), 0);
    if (write(sv[0], "abc", 3) != 3 || fionread(sv[1]) != 0) return bad("a send after SHUT_RD", fionread(sv[1]), 0);
    if (geti(sv[0], SO_SNDBUF) != 8192) return bad("the sender's SO_SNDBUF", geti(sv[0], SO_SNDBUF), 8192);
    if (kev(sv[0], EVFILT_WRITE, 0) != -1) return bad("the write filter after SHUT_RD", kev(sv[0], EVFILT_WRITE, 0), -1);
    close(sv[0]);
    close(sv[1]);

    // Neither SOCK_SEQPACKET nor a protocol is a unix socket's.
    errno = 0;
    if (socket(AF_UNIX, SOCK_SEQPACKET, 0) != -1 || errno != EPROTONOSUPPORT) return bad("SOCK_SEQPACKET", errno, EPROTONOSUPPORT);
    errno = 0;
    if (socket(AF_UNIX, SOCK_STREAM, 1) != -1 || errno != EPROTONOSUPPORT) return bad("a protocol", errno, EPROTONOSUPPORT);

    // An accepted connection's socket is its listener's: its buffers'
    // sizes and SO_NOSIGPIPE, as they were at the connect.
    int l = socket(AF_UNIX, SOCK_STREAM, 0);
    snprintf(u.sun_path, sizeof u.sun_path, "/tmp/streambuf_%d", getpid());
    unlink(u.sun_path);
    if (bind(l, (struct sockaddr *)&u, sizeof u) || listen(l, 4)) return bad("listen", errno, 0);
    v = 4096;
    setsockopt(l, SOL_SOCKET, SO_SNDBUF, &v, sizeof v);
    v = 1;
    setsockopt(l, SOL_SOCKET, SO_NOSIGPIPE, &v, sizeof v);
    int cl = socket(AF_UNIX, SOCK_STREAM, 0);
    if (connect(cl, (struct sockaddr *)&u, sizeof u)) return bad("connect", errno, 0);
    v = 16384;
    setsockopt(l, SOL_SOCKET, SO_SNDBUF, &v, sizeof v);
    int ac = accept(l, NULL, NULL);
    if (ac < 0) return bad("accept", errno, 0);
    if (geti(ac, SO_SNDBUF) != 4096 || geti(ac, SO_NOSIGPIPE) != 1 || geti(ac, SO_SNDLOWAT) != 2048) return bad("the accepted socket", geti(ac, SO_SNDBUF), 4096);
    if (geti(cl, SO_SNDBUF) != 8192 || geti(cl, SO_NOSIGPIPE) != 0) return bad("the connecting socket", geti(cl, SO_SNDBUF), 8192);
    // And, at the accept, its file flags: O_NONBLOCK.
    fcntl(l, F_SETFL, O_NONBLOCK);
    int cl2 = socket(AF_UNIX, SOCK_STREAM, 0);
    if (connect(cl2, (struct sockaddr *)&u, sizeof u)) return bad("connect again", errno, 0);
    int ac2 = accept(l, NULL, NULL);
    if (ac2 < 0 || !(fcntl(ac2, F_GETFL) & O_NONBLOCK)) return bad("the accepted socket's O_NONBLOCK", ac2 < 0 ? errno : fcntl(ac2, F_GETFL), O_NONBLOCK);
    errno = 0;
    if (recv(ac2, b, sizeof b, 0) != -1 || errno != EAGAIN) return bad("its empty receive", errno, EAGAIN);
    unlink(u.sun_path);
    printf("streambuf ok\n");
    return 0;
}
