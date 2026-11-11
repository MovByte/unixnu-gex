// fcntl with a command it does not know, on a terminal: sys_fcntl_nocancel
// sends it down to the vnode's ioctl with no argument, and the terminal
// (master, replica, or /dev/tty for the session's) does not know it
// either: ENOTTY.

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int bad(const char *what, long got, long want) {
    printf("fcntltty: %s: %ld, want %ld\n", what, got, want);
    fflush(stdout);
    return 1;
}

static int unknown(int fd) {
    errno = 0;
    return fcntl(fd, 200, 0) == -1 ? errno : 0;
}

int main(void) {
    int m = posix_openpt(O_RDWR | O_NOCTTY);
    if (m < 0 || grantpt(m) || unlockpt(m)) return bad("a pty", errno, 0);
    char name[128];
    strlcpy(name, ptsname(m), sizeof name);
    int s = open(name, O_RDWR | O_NOCTTY);
    if (s < 0) return bad("the replica", errno, 0);
    int cmds[] = {16, 30, 200, 1000, 0x1234};
    for (int i = 0; i < 5; i++) {
        errno = 0;
        if (fcntl(m, cmds[i], 0) != -1 || errno != ENOTTY) return bad("the master", errno, ENOTTY);
        errno = 0;
        if (fcntl(s, cmds[i], 0) != -1 || errno != ENOTTY) return bad("the replica", errno, ENOTTY);
    }
    // /dev/tty: to the session's terminal.
    int pipefd[2];
    pipe(pipefd);
    pid_t p = fork();
    if (p == 0) {
        setsid();
        int c = open(name, O_RDWR);
        int d = open("/dev/tty", O_RDWR);
        int e = (c < 0 || d < 0) ? -1 : unknown(d);
        write(pipefd[1], &e, sizeof e);
        _exit(0);
    }
    int e = -2;
    read(pipefd[0], &e, sizeof e);
    waitpid(p, NULL, 0);
    if (e != ENOTTY) return bad("/dev/tty", e, ENOTTY);
    printf("fcntltty ok\n");
    return 0;
}
