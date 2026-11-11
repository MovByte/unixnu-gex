// Controlling terminals and job control on a pty, as tty.c, tty_tty.c,
// open1 and proc_exit have them: a session leader's first open of a
// terminal without O_NOCTTY makes it its controlling terminal (open1's
// TIOCSCTTY), which another TIOCSCTTY leaves as it is; /dev/tty then
// reaches it (select
// through cttyselect; poll's kqueue refuses it, POLLNVAL); ^C signals the
// foreground group; a background read is SIGTTIN and EINTR; a member that
// is not the leader may give the terminal up; the leader's exit hangs up
// the foreground group and revokes the terminal (EOF, EIO).

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

static int rp[2];
static volatile sig_atomic_t got_int, got_ttin, got_hup;

static void on_int(int s) {
    (void)s;
    got_int = 1;
}
static void on_ttin(int s) {
    (void)s;
    got_ttin = 1;
}
static void on_hup(int s) {
    (void)s;
    got_hup = 1;
}

// A child's failure, told to the parent through the report pipe.
static void fail(const char *what, long got, long want) {
    char b[160];
    int n = snprintf(b, sizeof b, "!%s: %ld, want %ld\n", what, got, want);
    write(rp[1], b, (size_t)n);
    _exit(1);
}

static void report(char c) {
    write(rp[1], &c, 1);
}

static void child(const char *name) {
    if (setsid() < 0) fail("setsid", errno, 0);
    // No controlling terminal yet; an O_NOCTTY open makes none.
    if (open("/dev/tty", O_RDWR) != -1 || errno != ENXIO) fail("/dev/tty with no terminal", errno, ENXIO);
    int s0 = open(name, O_RDWR | O_NOCTTY);
    if (s0 < 0) fail("opening the replica with O_NOCTTY", errno, 0);
    if (open("/dev/tty", O_RDWR) != -1 || errno != ENXIO) fail("/dev/tty after an O_NOCTTY open", errno, ENXIO);
    // The first open without it does.
    int s = open(name, O_RDWR);
    if (s < 0) fail("opening the replica", errno, 0);
    close(s0);
    if (ioctl(s, TIOCSCTTY, 0)) fail("TIOCSCTTY of the session's own terminal", errno, 0);
    if (tcgetpgrp(s) != getpid()) fail("the foreground group", tcgetpgrp(s), getpid());
    if (tcgetsid(s) != getpid()) fail("TIOCGSID", tcgetsid(s), getpid());
    int t = open("/dev/tty", O_RDWR);
    if (t < 0) fail("opening /dev/tty", errno, 0);
    struct pollfd p = {t, POLLIN, 0};
    if (poll(&p, 1, 0) != 1 || p.revents != POLLNVAL) fail("poll of /dev/tty", p.revents, POLLNVAL);
    fd_set w;
    FD_ZERO(&w);
    FD_SET(t, &w);
    struct timeval tv = {1, 0};
    if (select(t + 1, NULL, &w, NULL, &tv) != 1) fail("select of /dev/tty for writing", 0, 1);
    signal(SIGINT, on_int);
    report('R');

    // A line typed by the parent, read through /dev/tty.
    char b[64];
    ssize_t r = read(t, b, sizeof b);
    if (r != 5 || memcmp(b, "ping\n", 5)) fail("the line read through /dev/tty", r, 5);
    report('P');

    // ^C from the parent: the foreground group's SIGINT.
    for (int i = 0; i < 200 && !got_int; i++) usleep(10000);
    if (!got_int) fail("SIGINT from ^C", 0, 1);
    report('I');

    // A background read: SIGTTIN to its group, and EINTR.
    pid_t g = fork();
    if (g == 0) {
        if (setpgid(0, 0)) fail("setpgid", errno, 0);
        signal(SIGTTIN, on_ttin);
        if (read(s, b, sizeof b) != -1 || errno != EINTR) fail("a background read", errno, EINTR);
        if (!got_ttin) fail("SIGTTIN for a background read", 0, 1);
        _exit(0);
    }
    int st;
    if (waitpid(g, &st, 0) != g || !WIFEXITED(st) || WEXITSTATUS(st)) _exit(1);
    report('B');

    // A member that is not the leader gives the terminal up.
    g = fork();
    if (g == 0) {
        int u = open("/dev/tty", O_RDWR);
        if (u < 0) fail("/dev/tty in a member", errno, 0);
        if (ioctl(u, TIOCNOTTY, 0)) fail("TIOCNOTTY", errno, 0);
        if (open("/dev/tty", O_RDWR) != -1 || errno != ENXIO) fail("/dev/tty after TIOCNOTTY", errno, ENXIO);
        _exit(0);
    }
    if (waitpid(g, &st, 0) != g || !WIFEXITED(st) || WEXITSTATUS(st)) _exit(1);
    if (ioctl(t, TIOCNOTTY, 0) != -1 || errno != EINVAL) fail("TIOCNOTTY by the leader", errno, EINVAL);
    report('N');

    // A member of the foreground group outlives the leader.
    int gp[2];
    pipe(gp);
    g = fork();
    if (g == 0) {
        close(gp[0]);
        signal(SIGHUP, on_hup);
        write(gp[1], "g", 1);
        for (int i = 0; i < 300 && !got_hup; i++) usleep(10000);
        if (!got_hup) fail("SIGHUP at the leader's exit", 0, 1);
        usleep(300000);
        // Revoked: deadfs's EOF and EIO.
        if (read(s, b, sizeof b) != 0) fail("reading the revoked terminal", errno, 0);
        if (write(s, "x", 1) != -1 || errno != EIO) fail("writing the revoked terminal", errno, EIO);
        report('h');
        _exit(0);
    }
    close(gp[1]);
    read(gp[0], b, 1);
    report('X');
    _exit(0);
}

int main(void) {
    int m = posix_openpt(O_RDWR | O_NOCTTY);
    if (m < 0 || grantpt(m) || unlockpt(m)) {
        printf("ptyjob: the pty: %d\n", errno);
        return 1;
    }
    char name[64];
    strcpy(name, ptsname(m));
    pipe(rp);
    pid_t c = fork();
    if (c == 0) {
        close(rp[0]);
        close(m);
        child(name);
    }
    close(rp[1]);
    char seen[64] = {0};
    size_t n = 0;
    char b[256];
    // The parent types what the child waits for, drains the echo, and
    // collects the reports until every writer is gone.
    for (;;) {
        struct pollfd p[2] = {{rp[0], POLLIN, 0}, {m, POLLIN, 0}};
        if (poll(p, 2, 5000) <= 0) break;
        if (p[1].revents & POLLIN) read(m, b, sizeof b);
        if (p[0].revents & (POLLIN | POLLHUP)) {
            ssize_t r = read(rp[0], b, sizeof b);
            if (r <= 0) break;
            for (ssize_t i = 0; i < r && n < sizeof seen - 1; i++) {
                seen[n++] = b[i];
                if (b[i] == 'R') write(m, "ping\r", 5);
                if (b[i] == 'P') write(m, "\x03", 1);
            }
            if (memchr(b, '!', (size_t)r)) {
                ssize_t more = read(rp[0], b, sizeof b - 1);
                if (more > 0) b[more] = 0;
                printf("ptyjob: %s%s", seen, more > 0 ? b : "\n");
                return 1;
            }
        }
    }
    int st;
    if (waitpid(c, &st, 0) != c || !WIFEXITED(st) || WEXITSTATUS(st)) {
        printf("ptyjob: the leader's status %#x after %s\n", st, seen);
        return 1;
    }
    if (strcmp(seen, "RPIBNXh")) {
        printf("ptyjob: reports %s, want RPIBNXh\n", seen);
        return 1;
    }
    printf("ptyjob ok\n");
    return 0;
}
