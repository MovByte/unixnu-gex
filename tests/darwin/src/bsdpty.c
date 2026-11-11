// The BSD ptys tty_pty.c makes, as XNU's cdevsw has them: /dev/ttypN
// (PTS_MAJOR, 4) runs the primary's functions and /dev/ptypN (PTC_MAJOR,
// 5) the replica's. A primary's open unlocks its replica (open_reset);
// TIOCPTYGNAME names the ttypN node, which a grant gives the caller with
// group tty and mode 0620; pty_init marks the majors' kqueue kinds the
// other way round, so kevent is EINVAL and poll POLLNVAL, while select
// works; the replica hangs up when the primary closes.

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/event.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

static int bad(const char *what, long got, long want) {
    printf("bsdpty: %s: %ld, want %ld\n", what, got, want);
    fflush(stdout);
    return 1;
}

static ssize_t drain(int fd, char *buf, size_t len) {
    size_t got = 0;
    for (int i = 0; i < 50 && got < len; i++) {
        // poll refuses these nodes; select takes them.
        fd_set r;
        FD_ZERO(&r);
        FD_SET(fd, &r);
        struct timeval tv = {0, 20000};
        if (select(fd + 1, &r, NULL, NULL, &tv) <= 0) {
            if (got) break;
            continue;
        }
        ssize_t n = read(fd, buf + got, len - got);
        if (n <= 0) break;
        got += (size_t)n;
    }
    return (ssize_t)got;
}

int main(void) {
    char tname[16], pname[16];
    int m = -1, n;
    for (n = 0; n < 16; n++) {
        snprintf(tname, sizeof tname, "/dev/ttyp%x", n);
        snprintf(pname, sizeof pname, "/dev/ptyp%x", n);
        m = open(tname, O_RDWR | O_NOCTTY);
        if (m >= 0) break;
        if (errno != EBUSY) return bad("opening a primary", errno, 0);
    }
    if (m < 0) return bad("a free BSD pty", 0, 1);
    struct stat st;
    fstat(m, &st);
    if (major(st.st_rdev) != 4 || (int)minor(st.st_rdev) != n) return bad("ttypN's device", (long)st.st_rdev, (4 << 24) | n);
    if (stat(pname, &st) || major(st.st_rdev) != 5) return bad("ptypN's device", (long)st.st_rdev, (5 << 24) | n);
    if (open(tname, O_RDWR | O_NOCTTY) != -1 || errno != EBUSY) return bad("a second primary open", errno, EBUSY);
    int s = open(pname, O_RDWR | O_NOCTTY);
    if (s < 0) return bad("opening the replica", errno, 0);

    char name[128] = {0};
    if (ioctl(m, TIOCPTYGNAME, name) || strcmp(name, tname)) return bad("TIOCPTYGNAME", 0, 1);
    if (ioctl(s, TIOCPTYGNAME, name) != -1 || errno != ENOTTY) return bad("TIOCPTYGNAME on the replica", errno, ENOTTY);
    if (ioctl(m, TIOCPTYGRANT)) return bad("TIOCPTYGRANT", errno, 0);
    if (stat(tname, &st) || st.st_uid != getuid() || st.st_gid != 4 || (st.st_mode & 07777) != 0620) return bad("the granted node", st.st_mode & 07777, 0620);

    // Input on the primary, read whole by the replica, echoed.
    if (write(m, "hi\r", 3) != 3) return bad("typing", errno, 0);
    char b[64];
    if (read(s, b, sizeof b) != 3 || memcmp(b, "hi\n", 3)) return bad("the line read", 0, 3);
    ssize_t r = drain(m, b, sizeof b);
    if (r != 4 || memcmp(b, "hi\r\n", 4)) return bad("the echo", r, 4);

    // kqueue refuses both nodes, poll too; select takes them.
    int kq = kqueue();
    struct kevent ch, ev;
    for (int i = 0; i < 2; i++) {
        int fd = i ? s : m;
        EV_SET(&ch, fd, EVFILT_READ, EV_ADD | EV_RECEIPT, 0, 0, NULL);
        if (kevent(kq, &ch, 1, &ev, 1, NULL) != 1 || !(ev.flags & EV_ERROR) || ev.data != EINVAL) return bad("kevent", (long)ev.data, EINVAL);
        struct pollfd p = {fd, POLLOUT, 0};
        if (poll(&p, 1, 0) != 1 || p.revents != POLLNVAL) return bad("poll", p.revents, POLLNVAL);
        fd_set w;
        FD_ZERO(&w);
        FD_SET(fd, &w);
        struct timeval tv = {1, 0};
        if (select(fd + 1, NULL, &w, NULL, &tv) != 1) return bad("select for writing", 0, 1);
    }
    close(kq);

    close(m);
    if (read(s, b, sizeof b) != 0) return bad("reading after the hangup", errno, 0);
    if (write(s, "x", 1) != -1 || errno != EIO) return bad("writing after the hangup", errno, EIO);
    close(s);
    // The pty stays: its primary opens again.
    m = open(tname, O_RDWR | O_NOCTTY);
    if (m < 0) return bad("opening the primary again", errno, 0);
    close(m);
    printf("bsdpty ok\n");
    return 0;
}
