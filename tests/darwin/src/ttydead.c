// A terminal its session leader's exit has revoked (proc_exit): the vnode
// is dead (VBAD on the dead mount). vn_ioctl's switch takes no case for
// it, so every ioctl is ENOTTY, FIONBIO's included; fcntl's unknown
// command is refused by VNOP_IOCTL itself (ENOTTY), before deadfs; deadfs
// reads a terminal's EOF and fails its writes (EIO).

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>

static int bad(const char *what, long got, long want) {
    printf("ttydead: %s: %ld, want %ld\n", what, got, want);
    fflush(stdout);
    return 1;
}

int main(void) {
    int m = posix_openpt(O_RDWR | O_NOCTTY);
    if (m < 0 || grantpt(m) || unlockpt(m)) return bad("a pty", errno, 0);
    char name[128];
    strlcpy(name, ptsname(m), sizeof name);
    int go[2], res[2];
    pipe(go);
    pipe(res);
    pid_t leader = fork();
    if (leader == 0) {
        setsid();
        int c = open(name, O_RDWR);
        if (c < 0) _exit(2);
        // The child is left with the terminal once the leader has gone, and
        // its hangup with it (ignored from before it is made).
        signal(SIGHUP, SIG_IGN);
        if (fork() == 0) {
            char g;
            read(go[0], &g, 1);
            int e[5];
            struct winsize ws;
            errno = 0;
            e[0] = ioctl(c, TIOCGWINSZ, &ws) == -1 ? errno : 0;
            int one = 1;
            errno = 0;
            e[1] = ioctl(c, FIONBIO, &one) == -1 ? errno : 0;
            errno = 0;
            e[2] = fcntl(c, 200, 0) == -1 ? errno : 0;
            char b;
            errno = 0;
            e[3] = (int)read(c, &b, 1);
            errno = 0;
            e[4] = write(c, "x", 1) == -1 ? errno : 0;
            write(res[1], e, sizeof e);
            _exit(0);
        }
        _exit(0);
    }
    close(res[1]);
    waitpid(leader, NULL, 0);
    write(go[1], "g", 1);
    int e[5] = {-1, -1, -1, -1, -1};
    if (read(res[0], e, sizeof e) != sizeof e) return bad("the results", errno, 0);
    if (e[0] != ENOTTY) return bad("an ioctl", e[0], ENOTTY);
    if (e[1] != ENOTTY) return bad("FIONBIO", e[1], ENOTTY);
    if (e[2] != ENOTTY) return bad("fcntl's unknown command", e[2], ENOTTY);
    if (e[3] != 0) return bad("a read", e[3], 0);
    if (e[4] != EIO) return bad("a write", e[4], EIO);
    printf("ttydead ok\n");
    return 0;
}
