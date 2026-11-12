// A session leader's exit revokes its controlling terminal (proc_exit):
// its output drained first (ttywait), then the vnode reclaimed after the
// calls in it have left (vnode_drain). A reader asleep in it is woken
// (TIOCREVOKE) to the dead vnode's EOF; a writer asleep in it finishes
// when there is room (its sleep ending in ERESTART if the terminal has
// changed meanwhile), returning what it wrote; the leader's exit waits.

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

static int bad(const char *what, long got, long want) {
    printf("ttydrain: %s: %ld, want %ld\n", what, got, want);
    fflush(stdout);
    return 1;
}

int main(void) {
    int m = posix_openpt(O_RDWR | O_NOCTTY);
    if (m < 0 || grantpt(m) || unlockpt(m)) return bad("a pty", errno, 0);
    char name[128];
    strlcpy(name, ptsname(m), sizeof name);
    int res[2];
    pipe(res);
    pid_t leader = fork();
    if (leader == 0) {
        setsid();
        int c = open(name, O_RDWR);
        if (c < 0) _exit(2);
        struct termios t;
        tcgetattr(c, &t);
        cfmakeraw(&t);
        tcsetattr(c, TCSANOW, &t);
        // Its group's hangup at the exit, ignored by those that stay.
        signal(SIGHUP, SIG_IGN);
        if (fork() == 0) {
            static char big[20000];
            memset(big, 'x', sizeof big);
            errno = 0;
            long out[3] = {0, 0, 0};
            out[0] = write(c, big, sizeof big);
            out[1] = errno;
            char b;
            out[2] = read(c, &b, 1);
            write(res[1], out, sizeof out);
            _exit(0);
        }
        if (fork() == 0) {
            char b;
            long out[3] = {-2, 0, 0};
            out[0] = read(c, &b, 1);
            write(res[1], out, sizeof out);
            _exit(0);
        }
        usleep(300000);
        _exit(0);
    }
    close(res[1]);
    // The exit waits while the output has nowhere to go.
    int st;
    pid_t w = 0;
    for (int i = 0; i < 100 && w == 0; i++) {
        w = waitpid(leader, &st, WNOHANG);
        if (!w) usleep(10000);
    }
    if (w == leader) return bad("the leader's exit with its output undrained", 1, 0);
    char buf[4096];
    long got = 0;
    fcntl(m, F_SETFL, O_NONBLOCK);
    long r[2][3];
    int n = 0;
    for (int i = 0; i < 1000 && (w != leader || n < 2); i++) {
        ssize_t k = read(m, buf, sizeof buf);
        if (k > 0)
            got += k;
        else
            usleep(10000);
        if (w != leader) w = waitpid(leader, &st, WNOHANG);
        fcntl(res[0], F_SETFL, O_NONBLOCK);
        if (n < 2 && read(res[0], r[n], sizeof r[n]) == sizeof r[n]) n++;
    }
    if (w != leader) return bad("the leader's exit", 0, 1);
    if (n != 2) return bad("the reader and writer", n, 2);
    for (int i = 0; i < 2; i++) {
        if (r[i][0] == 0) {
            // The reader: EOF.
            continue;
        }
        // The writer: what it wrote, all of which the primary read (all of
        // it, when the exit's drain did not see the queue empty before it
        // was done); then the dead vnode's EOF.
        if (r[i][0] <= 0 || r[i][0] > 20000 || r[i][0] != got) return bad("the writer's count", r[i][0], got);
        if (r[i][2] != 0) return bad("the writer's read after", r[i][2], 0);
    }
    if (!((r[0][0] == 0) ^ (r[1][0] == 0))) return bad("one reader's EOF", r[0][0], 0);
    printf("ttydrain ok\n");
    return 0;
}
