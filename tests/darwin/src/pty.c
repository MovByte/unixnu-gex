// A pseudo-terminal pair as XNU's ptmx driver makes it: the primary's
// device number names its replica, which exists from the open as a 0620
// node and opens only once unlocked; the replica starts with ttydefaults'
// termios; input is edited and echoed by the line discipline and output
// gets ONLCR; window size, raw mode and packet mode behave as tty.c and
// tty_dev.c have them; the replica hangs up (EOF, EIO) when the primary
// closes, and its node goes with the last close. A primary is no terminal
// until its replica has opened (TS_IOCTL_NOT_OK).

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

// `D_TTY` (`sys/conf.h`).
#define D_TTY 3

static int bad(const char *what, long got, long want) {
    printf("pty: %s: %ld, want %ld\n", what, got, want);
    fflush(stdout);
    return 1;
}

// Everything readable from `fd` within a moment.
static ssize_t drain(int fd, char *buf, size_t len) {
    size_t got = 0;
    for (int i = 0; i < 50 && got < len; i++) {
        struct pollfd p = {fd, POLLIN, 0};
        if (poll(&p, 1, 20) <= 0) {
            if (got) break;
            continue;
        }
        ssize_t n = read(fd, buf + got, len - got);
        if (n <= 0) break;
        got += (size_t)n;
    }
    return (ssize_t)got;
}

static int same(const char *what, const char *got, ssize_t n, const char *want, size_t wn) {
    if (n != (ssize_t)wn || memcmp(got, want, wn) != 0) {
        printf("pty: %s: %zd bytes [", what, n);
        for (ssize_t i = 0; i < n; i++) printf("%02x", (unsigned char)got[i]);
        printf("], want [");
        for (size_t i = 0; i < wn; i++) printf("%02x", (unsigned char)want[i]);
        printf("]\n");
        fflush(stdout);
        return 1;
    }
    return 0;
}

int main(void) {
    int m = posix_openpt(O_RDWR | O_NOCTTY);
    if (m < 0) return bad("posix_openpt", errno, 0);
    struct stat st;
    if (fstat(m, &st)) return bad("fstat of the primary", errno, 0);
    if (major(st.st_rdev) != 15) return bad("the primary's major", major(st.st_rdev), 15);
    int n = minor(st.st_rdev);
    char want[32];
    snprintf(want, sizeof want, "/dev/ttys%03d", n);
    const char *name = ptsname(m);
    if (!name || strcmp(name, want)) return bad("ptsname names the primary's minor", name ? 1 : 0, 0);
    char path[64];
    strcpy(path, name);
    if (stat(path, &st)) return bad("stat of the replica's node", errno, 0);
    if (!S_ISCHR(st.st_mode) || (st.st_mode & 07777) != 0620) return bad("the replica's mode", st.st_mode, S_IFCHR | 0620);
    if (major(st.st_rdev) != 16 || (int)minor(st.st_rdev) != n) return bad("the replica's device", (long)st.st_rdev, (16 << 24) | n);

    // Before its replica opens, a primary takes only the pty's own ioctls;
    // FIODTYPE is vn_ioctl's, and says it is a terminal.
    struct termios tio;
    if (ioctl(m, TIOCGETA, &tio) != -1 || errno != ENOTTY) return bad("TIOCGETA of a primary with no replica", errno, ENOTTY);
    int t = ioctl(m, FIODTYPE, &t) == 0 ? t : -1;
    if (t != D_TTY) return bad("FIODTYPE", t, D_TTY);
    char b[256];
    if (pread(m, b, 1, 0) != -1 || errno != ENXIO) return bad("pread of a terminal", errno, ENXIO);

    // The node is root's until granted; then the replica opens only once
    // unlocked.
    if (getuid() != 0 && (open(path, O_RDWR | O_NOCTTY) != -1 || errno != EACCES)) return bad("opening an ungranted replica", errno, EACCES);
    if (grantpt(m)) return bad("grantpt", errno, 0);
    if (stat(path, &st) || st.st_uid != getuid() || st.st_gid != 4) return bad("the granted replica's owner", st.st_uid, getuid());
    if (open(path, O_RDWR | O_NOCTTY) != -1 || errno != EAGAIN) return bad("opening a locked replica", errno, EAGAIN);
    if (unlockpt(m)) return bad("unlockpt", errno, 0);
    int s = open(path, O_RDWR | O_NOCTTY);
    if (s < 0) return bad("opening the replica", errno, 0);
    if (!isatty(m)) return bad("isatty of the primary", 0, 1);

    if (tcgetattr(s, &tio)) return bad("tcgetattr", errno, 0);
    if (tio.c_iflag != (BRKINT | ICRNL | IMAXBEL | IXON | IXANY)) return bad("c_iflag", (long)tio.c_iflag, BRKINT | ICRNL | IMAXBEL | IXON | IXANY);
    if (tio.c_oflag != (OPOST | ONLCR)) return bad("c_oflag", (long)tio.c_oflag, OPOST | ONLCR);
    if (tio.c_cflag != (CREAD | CS8 | HUPCL)) return bad("c_cflag", (long)tio.c_cflag, CREAD | CS8 | HUPCL);
    if (tio.c_lflag != (ECHO | ICANON | ISIG | IEXTEN | ECHOE | ECHOKE | ECHOCTL)) return bad("c_lflag", (long)tio.c_lflag, ECHO | ICANON | ISIG | IEXTEN | ECHOE | ECHOKE | ECHOCTL);
    if (cfgetispeed(&tio) != B9600 || cfgetospeed(&tio) != B9600) return bad("the speeds", (long)cfgetospeed(&tio), B9600);
    if (tio.c_cc[VERASE] != 0177 || tio.c_cc[VINTR] != 3 || tio.c_cc[VMIN] != 1 || tio.c_cc[VTIME] != 0 || tio.c_cc[VSTATUS] != 20) return bad("c_cc", tio.c_cc[VERASE], 0177);

    // A line typed: an erase, a CR made NL; read whole, echoed with "\b \b".
    if (write(m, "hel\x7flo\r", 7) != 7) return bad("typing", errno, 0);
    ssize_t r = read(s, b, sizeof b);
    if (same("the line read", b, r, "helo\n", 5)) return 1;
    r = drain(m, b, sizeof b);
    if (same("the echo", b, r, "hel\b \blo\r\n", 10)) return 1;

    // Output: ONLCR; TIOCOUTQ counts what the primary has not read.
    if (write(s, "a\tb\n", 4) != 4) return bad("writing the replica", errno, 0);
    int q = -1;
    if (ioctl(s, TIOCOUTQ, &q) || q != 5) return bad("TIOCOUTQ", q, 5);
    r = drain(m, b, sizeof b);
    if (same("the output", b, r, "a\tb\r\n", 5)) return 1;
    if (write(m, "x\n", 2) != 2) return bad("typing a line", errno, 0);
    q = -1;
    if (ioctl(s, FIONREAD, &q) || q != 2) return bad("FIONREAD", q, 2);
    drain(m, b, sizeof b);
    read(s, b, sizeof b);

    // The window size, set by the primary, seen by the replica.
    struct winsize ws = {24, 80, 640, 480}, ws2;
    if (ioctl(m, TIOCSWINSZ, &ws)) return bad("TIOCSWINSZ", errno, 0);
    if (ioctl(s, TIOCGWINSZ, &ws2) || memcmp(&ws, &ws2, sizeof ws)) return bad("TIOCGWINSZ", ws2.ws_row, 24);

    // Raw: what is typed is read as it comes, unechoed.
    cfmakeraw(&tio);
    if (tcsetattr(s, TCSANOW, &tio)) return bad("tcsetattr", errno, 0);
    if (write(m, "xyz\r", 4) != 4) return bad("typing raw", errno, 0);
    r = drain(s, b, sizeof b);
    if (same("raw input", b, r, "xyz\r", 4)) return 1;
    struct pollfd pm = {m, POLLIN, 0};
    if (poll(&pm, 1, 50) != 0) return bad("an echo in raw mode", pm.revents, 0);

    // Packet mode: each read of the primary starts with its packet byte.
    // Raw mode's IXON going was a TIOCPKT_NOSTOP for the primary, which
    // the first packet read reports alone.
    int one = 1;
    if (ioctl(m, TIOCPKT, &one)) return bad("TIOCPKT", errno, 0);
    if (write(s, "z", 1) != 1) return bad("writing in packet mode", errno, 0);
    r = drain(m, b, sizeof b);
    if (same("the packets", b, r, "\x10\0z", 3)) return 1;

    // Not this process's terminal: TIOCSTI is refused.
    char c = 'k';
    if (getuid() != 0 && (ioctl(s, TIOCSTI, &c) != -1 || errno != EACCES)) return bad("TIOCSTI", errno, EACCES);

    // The primary's close hangs the replica up.
    int kq = kqueue();
    struct kevent ch, ev;
    EV_SET(&ch, s, EVFILT_READ, EV_ADD, 0, 0, NULL);
    if (kevent(kq, &ch, 1, NULL, 0, NULL)) return bad("EVFILT_READ on the replica", errno, 0);
    close(m);
    struct timespec ts1 = {1, 0};
    if (kevent(kq, NULL, 0, &ev, 1, &ts1) != 1 || !(ev.flags & EV_EOF)) return bad("EV_EOF after the hangup", ev.flags, EV_EOF);
    if (read(s, b, sizeof b) != 0) return bad("reading after the hangup", errno, 0);
    if (write(s, "x", 1) != -1 || errno != EIO) return bad("writing after the hangup", errno, EIO);
    close(s);
    close(kq);
    if (stat(path, &st) != -1 || errno != ENOENT) return bad("the replica's node after the last close", errno, ENOENT);
    printf("pty ok\n");
    return 0;
}
