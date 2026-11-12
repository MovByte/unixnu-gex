// revoke(2) of a terminal (vnode_reclaim_internal with REVOKEALL): a
// reader asleep in it is woken (TIOCREVOKE) and reads the dead vnode's
// EOF; the revoke waits for a writer asleep in it (vnode_drain), whose
// sleep ends in ERESTART once the terminal has changed, so it returns what
// it wrote; afterwards the descriptor reads EOF, fails writes with EIO and
// ioctls with ENOTTY. Not a device: ENOTSUP. Someone else's device, to a
// caller who is not the superuser: EPERM.

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

static int bad(const char *what, long got, long want) {
    printf("revoke: %s: %ld, want %ld\n", what, got, want);
    fflush(stdout);
    return 1;
}

static char name[128];
static int s;
static atomic_int wdone, rdone, readdone;
static ssize_t wres, rres;
static int rret, rerr;

static void *writer(void *a) {
    (void)a;
    static char big[20000];
    memset(big, 'x', sizeof big);
    wres = write(s, big, sizeof big);
    atomic_store(&wdone, 1);
    return NULL;
}

static void *reader(void *a) {
    int fd = *(int *)a;
    char c;
    rres = read(fd, &c, 1);
    atomic_store(&readdone, 1);
    return NULL;
}

static void *revoker(void *a) {
    (void)a;
    errno = 0;
    rret = revoke(name);
    rerr = errno;
    atomic_store(&rdone, 1);
    return NULL;
}

static int pty(void) {
    int m = posix_openpt(O_RDWR | O_NOCTTY);
    if (m < 0 || grantpt(m) || unlockpt(m)) return -1;
    strlcpy(name, ptsname(m), sizeof name);
    return m;
}

int main(void) {
    // Not a device.
    errno = 0;
    if (revoke("/etc/hosts") != -1 || errno != ENOTSUP) return bad("a file", errno, ENOTSUP);

    // A reader asleep in it: woken, and the dead vnode's EOF.
    int m = pty();
    if (m < 0) return bad("a pty", errno, 0);
    int r = open(name, O_RDWR | O_NOCTTY);
    if (r < 0) return bad("the replica", errno, 0);
    pthread_t rt;
    pthread_create(&rt, NULL, reader, &r);
    usleep(300000);
    if (atomic_load(&readdone)) return bad("the reader before the revoke", 1, 0);
    if (revoke(name)) return bad("revoke", errno, 0);
    pthread_join(rt, NULL);
    if (rres != 0) return bad("the woken reader", rres, 0);
    char c;
    errno = 0;
    if (read(r, &c, 1) != 0) return bad("a read after", errno, 0);
    errno = 0;
    if (write(r, "x", 1) != -1 || errno != EIO) return bad("a write after", errno, EIO);
    struct winsize ws;
    errno = 0;
    if (ioctl(r, TIOCGWINSZ, &ws) != -1 || errno != ENOTTY) return bad("an ioctl after", errno, ENOTTY);
    close(r);
    close(m);

    // A writer asleep in it: the revoke waits for it.
    m = pty();
    s = open(name, O_RDWR | O_NOCTTY);
    if (s < 0) return bad("the replica", errno, 0);
    struct termios t;
    tcgetattr(s, &t);
    cfmakeraw(&t);
    tcsetattr(s, TCSANOW, &t);
    pthread_t wt, vt;
    pthread_create(&wt, NULL, writer, NULL);
    usleep(300000);
    if (atomic_load(&wdone)) return bad("the writer before the revoke", 1, 0);
    pthread_create(&vt, NULL, revoker, NULL);
    usleep(500000);
    if (atomic_load(&rdone)) return bad("the revoke with a writer in it", 1, 0);
    // Room for the writer: it ends, then the revoke.
    char buf[4096];
    long got = 0;
    fcntl(m, F_SETFL, O_NONBLOCK);
    for (int i = 0; i < 500 && !atomic_load(&rdone); i++) {
        ssize_t n = read(m, buf, sizeof buf);
        if (n > 0)
            got += n;
        else
            usleep(10000);
    }
    pthread_join(vt, NULL);
    pthread_join(wt, NULL);
    if (rret != 0) return bad("the revoke", rerr, 0);
    if (wres <= 0 || wres >= 20000 || wres != got) return bad("the writer's count", wres, got);
    close(s);
    close(m);

    // Someone else's: EPERM, but to its owner or the superuser.
    struct stat st;
    if (stat("/dev/ttyp0", &st)) return bad("stat /dev/ttyp0", errno, 0);
    int want = (geteuid() == 0 || st.st_uid == geteuid()) ? 0 : EPERM;
    errno = 0;
    int e = revoke("/dev/ttyp0") ? errno : 0;
    if (e != want) return bad("revoke of /dev/ttyp0", e, want);
    printf("revoke ok\n");
    return 0;
}
