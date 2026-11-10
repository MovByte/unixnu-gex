// select and pselect by sys_generic.c, each kind of file's answer as measured
// on an APFS volume: sets written back, the count of bits, the clamp to the
// descriptor table, timeouts, and pselect's mask.

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/event.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

static int bad(const char *what, long got, long want) {
    printf("select: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

// What one descriptor answers in one set, with no wait.
static int ready(int fd, int set) {
    fd_set s;
    FD_ZERO(&s);
    FD_SET(fd, &s);
    struct timeval t = {0, 0};
    int r = select(fd + 1, set == 0 ? &s : 0, set == 1 ? &s : 0, set == 2 ? &s : 0, &t);
    if (r < 0) return -errno;
    if (r != (FD_ISSET(fd, &s) ? 1 : 0)) return -1000;
    return r;
}

static int check(const char *what, int fd, int r, int w, int x) {
    int got[3] = {ready(fd, 0), ready(fd, 1), ready(fd, 2)};
    if (got[0] != r || got[1] != w || got[2] != x) {
        printf("select: %s: %d %d %d, want %d %d %d\n", what, got[0], got[1], got[2], r, w, x);
        return 1;
    }
    return 0;
}

static volatile sig_atomic_t caught;
static void on_usr1(int s) {
    (void)s;
    caught++;
}

int main(void) {
    char name[64];
    snprintf(name, sizeof name, "/private/var/tmp/select-%d", getpid());
    int f = open(name, O_CREAT | O_RDWR, 0644);
    unlink(name);
    if (check("an empty file", f, 1, 1, 1)) return 1;
    if (check("/dev/null", open("/dev/null", O_RDWR), 1, 1, 1)) return 1;
    if (check("a directory", open("/private/var/tmp", O_RDONLY), 1, 1, 1)) return 1;

    int p[2];
    pipe(p);
    if (check("an empty pipe's read end", p[0], 0, 1, 0)) return 1;
    if (check("a pipe's write end", p[1], 0, 1, 0)) return 1;
    write(p[1], "x", 1);
    if (check("a pipe with data", p[0], 1, 1, 0)) return 1;
    close(p[1]);
    if (check("a pipe at its end", p[0], 1, 1, 0)) return 1;
    pipe(p);
    close(p[0]);
    if (check("a pipe with no reader", p[1], 1, 1, 0)) return 1;

    int s[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, s);
    if (check("an empty socket", s[0], 0, 1, 0)) return 1;
    write(s[1], "x", 1);
    if (check("a socket with data", s[0], 1, 1, 0)) return 1;
    close(s[1]);
    if (check("a socket at its end", s[0], 1, 1, 0)) return 1;
    if (check("an unconnected socket", socket(AF_UNIX, SOCK_STREAM, 0), 0, 0, 0)) return 1;
    if (check("a UDP socket", socket(AF_INET, SOCK_DGRAM, 0), 0, 1, 0)) return 1;

    // Several at once: each set rewritten, the bits counted.
    int q[2];
    pipe(q);
    write(q[1], "y", 1);
    fd_set r, w;
    FD_ZERO(&r);
    FD_ZERO(&w);
    FD_SET(q[0], &r);
    FD_SET(q[1], &w);
    FD_SET(q[1], &r);
    struct timeval now = {0, 0};
    int n = select((q[0] > q[1] ? q[0] : q[1]) + 1, &r, &w, NULL, &now);
    if (n != 2) return bad("the count", n, 2);
    if (!FD_ISSET(q[0], &r) || FD_ISSET(q[1], &r) || !FD_ISSET(q[1], &w)) return bad("the sets", 0, 1);

    // Errors, which leave the sets alone.
    fd_set e;
    FD_ZERO(&e);
    FD_SET(20, &e);
    struct timeval t0 = {0, 0};
    if (select(21, &e, 0, 0, &t0) != -1 || errno != EBADF) return bad("an unopened descriptor", errno, EBADF);
    if (!FD_ISSET(20, &e)) return bad("the set after an error", 0, 1);
    // Past the descriptor table: not looked at.
    FD_ZERO(&e);
    FD_SET(900, &e);
    t0.tv_sec = 0;
    if (select(1000, &e, 0, 0, &t0) != 0) return bad("past the table", errno, 0);
    // Only the part of the set it looked at is written back.
    if (!FD_ISSET(900, &e)) return bad("past the table's bit", 0, 1);

    struct timeval tv = {0, 1000000};
    if (select(0, 0, 0, 0, &tv) != -1 || errno != EINVAL) return bad("microseconds", errno, EINVAL);
    struct timeval neg = {-1, 0};
    if (select(0, 0, 0, 0, &neg) != -1 || errno != EINVAL) return bad("negative seconds", errno, EINVAL);
    if (select(-1, 0, 0, 0, 0) != -1 || errno != EINVAL) return bad("a negative count", errno, EINVAL);
    struct timespec nsbad = {0, 1000000001};
    if (pselect(0, 0, 0, 0, &nsbad, NULL) != -1 || errno != EINVAL) return bad("nanoseconds", errno, EINVAL);

    // A timeout passes, and nothing is left set.
    int z[2];
    pipe(z);
    fd_set zr;
    FD_ZERO(&zr);
    FD_SET(z[0], &zr);
    struct timeval wait = {0, 50000}, a, b;
    gettimeofday(&a, NULL);
    if (select(z[0] + 1, &zr, 0, 0, &wait) != 0) return bad("a timeout", errno, 0);
    gettimeofday(&b, NULL);
    long ms = (b.tv_sec - a.tv_sec) * 1000 + (b.tv_usec - a.tv_usec) / 1000;
    if (ms < 45) return bad("how long it waited", ms, 50);
    if (FD_ISSET(z[0], &zr)) return bad("the set after a timeout", 1, 0);

    // A child wakes a sleeping select.
    pid_t c = fork();
    if (c == 0) {
        usleep(20000);
        write(z[1], "w", 1);
        _exit(0);
    }
    FD_ZERO(&zr);
    FD_SET(z[0], &zr);
    if (select(z[0] + 1, &zr, 0, 0, NULL) != 1 || !FD_ISSET(z[0], &zr)) return bad("woken", errno, 0);
    waitpid(c, NULL, 0);

    // pselect: the signal blocked outside is taken inside, EINTR, its
    // handler having run, and the mask is as it was.
    signal(SIGUSR1, on_usr1);
    sigset_t block, none, now_mask;
    sigemptyset(&block);
    sigaddset(&block, SIGUSR1);
    sigemptyset(&none);
    sigprocmask(SIG_BLOCK, &block, NULL);
    kill(getpid(), SIGUSR1);
    if (caught) return bad("delivered while blocked", caught, 0);
    int pr[2];
    pipe(pr);
    fd_set pf;
    FD_ZERO(&pf);
    FD_SET(pr[0], &pf);
    struct timespec ts = {5, 0};
    if (pselect(pr[0] + 1, &pf, 0, 0, &ts, &none) != -1 || errno != EINTR) return bad("pselect interrupted", errno, EINTR);
    if (caught != 1) return bad("its handler", caught, 1);
    if (!FD_ISSET(pr[0], &pf)) return bad("the set after EINTR", 0, 1);
    sigprocmask(SIG_SETMASK, NULL, &now_mask);
    if (!sigismember(&now_mask, SIGUSR1)) return bad("the mask afterwards", 0, 1);

    // A pselect that finishes puts it back too.
    struct timespec zero = {0, 0};
    FD_ZERO(&pf);
    if (pselect(0, 0, 0, 0, &zero, &none) != 0) return bad("pselect with nothing", errno, 0);
    sigprocmask(SIG_SETMASK, NULL, &now_mask);
    if (!sigismember(&now_mask, SIGUSR1)) return bad("the mask after a return", 0, 1);

    // An open file with no name left is still a vnode to a knote.
    int kq = kqueue();
    write(f, "abc", 3);
    lseek(f, 1, SEEK_SET);
    struct kevent ch, ev;
    EV_SET(&ch, f, EVFILT_READ, EV_ADD, 0, 0, 0);
    struct timespec knone = {0, 0};
    if (kevent(kq, &ch, 1, &ev, 1, &knone) != 1 || ev.data != 2) return bad("a knote on an unlinked file", ev.data, 2);

    puts("select ok");
    return 0;
}
