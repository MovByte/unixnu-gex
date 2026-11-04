// Advisory locks by kern_lockf.c's rules, in one process: a POSIX lock
// never conflicts with its own process but does with an OFD lock, and goes
// when any descriptor of the file closes; flock and OFD locks belong to the
// open file; a blocked flock sleeps until the holder unlocks; O_EXLOCK.

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/file.h>
#include <unistd.h>

#define PATH "/tmp/gex-lockf"

static int bad(const char *what, long v) {
    printf("lockf: %s (%ld)\n", what, v);
    return 1;
}

static int a, b;
static volatile int got;

static void *waiter(void *arg) {
    (void)arg;
    if (flock(b, LOCK_EX) == 0) got = 1;
    return NULL;
}

int main(void) {
    a = open(PATH, O_RDWR | O_CREAT | O_TRUNC, 0600);
    b = open(PATH, O_RDWR);
    write(a, "0123456789", 10);

    struct flock fl = {.l_start = 0, .l_len = 5, .l_type = F_WRLCK, .l_whence = SEEK_SET};
    if (fcntl(a, F_SETLK, &fl)) return bad("F_SETLK", errno);
    // The process's own lock never blocks it.
    struct flock q = {.l_start = 0, .l_len = 0, .l_type = F_WRLCK, .l_whence = SEEK_SET};
    if (fcntl(b, F_GETLK, &q) || q.l_type != F_UNLCK) return bad("F_GETLK of our own lock", q.l_type);
    // An OFD lock on another open file is another owner.
    q = (struct flock){.l_start = 2, .l_len = 1, .l_type = F_RDLCK, .l_whence = SEEK_SET};
    if (fcntl(b, F_OFD_GETLK, &q) || q.l_type != F_WRLCK || q.l_start != 0 || q.l_len != 5 || q.l_pid != getpid()) return bad("F_OFD_GETLK", q.l_type);
    q = (struct flock){.l_start = 2, .l_len = 1, .l_type = F_RDLCK, .l_whence = SEEK_SET};
    if (fcntl(b, F_OFD_SETLK, &q) != -1 || errno != EAGAIN) return bad("F_OFD_SETLK over a POSIX lock", errno);
    // Closing any descriptor of the file drops the process's POSIX locks.
    int c = dup(a);
    close(c);
    q = (struct flock){.l_start = 0, .l_len = 0, .l_type = F_WRLCK, .l_whence = SEEK_SET};
    if (fcntl(b, F_OFD_GETLK, &q) || q.l_type != F_UNLCK) return bad("a POSIX lock outlived a close", q.l_type);

    // flock: a's exclusive lock blocks b's until it is unlocked.
    if (flock(a, LOCK_EX)) return bad("flock", errno);
    if (flock(b, LOCK_EX | LOCK_NB) != -1 || errno != EWOULDBLOCK) return bad("flock LOCK_NB", errno);
    if (open(PATH, O_RDONLY | O_SHLOCK | O_NONBLOCK) != -1 || errno != EAGAIN) return bad("O_SHLOCK over a flock", errno);
    pthread_t t;
    pthread_create(&t, NULL, waiter, NULL);
    usleep(30000);
    if (got) return bad("a blocked flock went through", got);
    flock(a, LOCK_UN);
    pthread_join(t, NULL);
    if (!got) return bad("the blocked flock was not woken", got);
    if (!(fcntl(b, F_GETFL) & 0x4000)) return bad("FWASLOCKED in F_GETFL", fcntl(b, F_GETFL));
    // b's last close takes its flock with it.
    close(b);
    int d = open(PATH, O_RDONLY | O_EXLOCK | O_NONBLOCK);
    if (d < 0) return bad("O_EXLOCK after the last close", errno);
    close(d);
    close(a);
    unlink(PATH);
    printf("lockf ok\n");
    return 0;
}
