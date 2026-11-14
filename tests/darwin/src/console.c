// /dev/console as cnopen and km make it: devfs's node (major 0, root's,
// group wheel, 0622), so writable only for anyone but root; a terminal
// (D_TTY) whose settings are km's first open's (TTYDEF's, its control
// flags CREAD|CS8|CLOCAL), which keeps CLOCAL whatever a new termios says
// and refuses a new window size; its output out to the console as soon as
// it is written.

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/filio.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

// `D_TTY` (`sys/conf.h`).
#define D_TTY 3

static int bad(const char *what, long got, long want) {
    printf("console: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

int main(void) {
    struct stat st;
    if (stat("/dev/console", &st)) return bad("stat", errno, 0);
    if (!S_ISCHR(st.st_mode) || st.st_rdev != makedev(0, 0)) return bad("the node's device", (long)st.st_rdev, 0);
    if ((st.st_mode & 07777) != 0622 || st.st_uid != 0 || st.st_gid != 0) return bad("the node's mode", st.st_mode & 07777, 0622);
    if (getuid() != 0) {
        errno = 0;
        if (open("/dev/console", O_RDONLY | O_NOCTTY) != -1 || errno != EACCES) return bad("a read open", errno, EACCES);
    }
    int fd = open("/dev/console", O_WRONLY | O_NOCTTY);
    if (fd < 0) return bad("open", errno, 0);
    if (!isatty(fd)) return bad("isatty", 0, 1);
    int type = -1;
    if (ioctl(fd, FIODTYPE, &type) || type != D_TTY) return bad("FIODTYPE", type, D_TTY);
    struct termios t;
    if (tcgetattr(fd, &t)) return bad("tcgetattr", errno, 0);
    if (t.c_cflag != (CREAD | CS8 | CLOCAL)) return bad("c_cflag", (long)t.c_cflag, CREAD | CS8 | CLOCAL);
    if (t.c_iflag != (BRKINT | ICRNL | IMAXBEL | IXON | IXANY)) return bad("c_iflag", (long)t.c_iflag, BRKINT | ICRNL | IMAXBEL | IXON | IXANY);
    if (t.c_oflag != (OPOST | ONLCR)) return bad("c_oflag", (long)t.c_oflag, OPOST | ONLCR);
    if (t.c_lflag != (ECHO | ICANON | ISIG | IEXTEN | ECHOE | ECHOKE | ECHOCTL)) return bad("c_lflag", (long)t.c_lflag, ECHO | ICANON | ISIG | IEXTEN | ECHOE | ECHOKE | ECHOCTL);
    if (cfgetospeed(&t) != 9600 || cfgetispeed(&t) != 9600) return bad("the speeds", (long)cfgetospeed(&t), 9600);
    if (t.c_cc[VINTR] != 3 || t.c_cc[VEOF] != 4) return bad("the control characters", t.c_cc[VINTR], 3);
    // The km device is always local.
    t.c_cflag &= ~CLOCAL;
    if (tcsetattr(fd, TCSANOW, &t)) return bad("tcsetattr", errno, 0);
    struct termios u;
    if (tcgetattr(fd, &u)) return bad("tcgetattr after", errno, 0);
    if (!(u.c_cflag & CLOCAL)) return bad("CLOCAL kept", (long)u.c_cflag, CREAD | CS8 | CLOCAL);
    struct winsize w = {24, 80, 0, 0};
    errno = 0;
    if (ioctl(fd, TIOCSWINSZ, &w) != -1 || errno != EINVAL) return bad("TIOCSWINSZ", errno, EINVAL);
    const char msg[] = "console ok\n";
    if (write(fd, msg, sizeof msg - 1) != (ssize_t)(sizeof msg - 1)) return bad("write", errno, 0);
    // Out to the console at once: nothing is left queued.
    int queued = -1;
    if (ioctl(fd, TIOCOUTQ, &queued) || queued != 0) return bad("TIOCOUTQ", queued, 0);
    if (close(fd)) return bad("close", errno, 0);
    printf("console ok\n");
    return 0;
}
