// Asynchronous I/O by xnu-10063's kern_aio.c: what is refused (all EAGAIN
// once a request is made), reading and writing at an offset or appending,
// the per-process limit until aio_return, aio_cancel and aio_suspend's
// answers, aio_fsync, lio_listio's modes, opcodes and one signal for a
// group, and kern.aio*.

#include <aio.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <unistd.h>

static int bad(const char *what, long got, long want) {
    printf("aio: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

static int expect(const char *what, long r, int e) {
    if (r != -1 || errno != e) return bad(what, r == -1 ? errno : r, e);
    return 0;
}

static volatile sig_atomic_t usr1;
static void on_usr1(int s) {
    (void)s;
    usr1++;
}

static struct aiocb at(int fd, void *buf, size_t n, off_t off) {
    struct aiocb cb;
    memset(&cb, 0, sizeof cb);
    cb.aio_fildes = fd;
    cb.aio_buf = buf;
    cb.aio_nbytes = n;
    cb.aio_offset = off;
    return cb;
}

int main(void) {
    int v = 0;
    size_t len = sizeof v;
    if (sysctlbyname("kern.aioprocmax", &v, &len, NULL, 0) || v != 8) return bad("kern.aioprocmax", v, 8);
    if (sysctlbyname("kern.aiomax", &v, &len, NULL, 0) || v != 20) return bad("kern.aiomax", v, 20);
    if (sysctlbyname("kern.aiothreads", &v, &len, NULL, 0) || v != 2) return bad("kern.aiothreads", v, 2);

    char name[64], buf[32];
    snprintf(name, sizeof name, "/private/var/tmp/aio-%d", getpid());
    int f = open(name, O_CREAT | O_RDWR | O_TRUNC, 0644);
    unlink(name);
    write(f, "hello world", 11);

    // No request anywhere yet.
    struct aiocb cb = at(f, buf, 5, 6);
    const struct aiocb *list[1] = {&cb};
    if (expect("aio_error with none", aio_error(&cb), EINVAL)) return 1;
    if (expect("aio_return with none", aio_return(&cb), EINVAL)) return 1;
    if (aio_cancel(f, NULL) != AIO_ALLDONE) return bad("aio_cancel with none", errno, AIO_ALLDONE);
    if (expect("aio_suspend with none", aio_suspend(list, 1, NULL), EINVAL)) return 1;

    // Refusals: aio_create_queue_entry's failure is EAGAIN.
    int p[2];
    pipe(p);
    struct aiocb no = at(999, buf, 4, 0);
    if (expect("a closed descriptor", aio_read(&no), EAGAIN)) return 1;
    no = at(p[0], buf, 4, 0);
    if (expect("a pipe", aio_read(&no), EAGAIN)) return 1;
    no = at(p[1], buf, 4, 0);
    if (expect("reading a write end", aio_read(&no), EAGAIN)) return 1;
    no = at(f, buf, 4, -1);
    if (expect("a negative offset", aio_read(&no), EAGAIN)) return 1;
    no = at(f, NULL, 4, 0);
    if (expect("no buffer", aio_read(&no), EAGAIN)) return 1;
    no = at(f, buf, 4, 0);
    no.aio_sigevent.sigev_notify = SIGEV_SIGNAL;
    no.aio_sigevent.sigev_signo = SIGKILL;
    if (expect("SIGKILL", aio_read(&no), EAGAIN)) return 1;
    no.aio_sigevent.sigev_notify = SIGEV_THREAD;
    if (expect("SIGEV_THREAD", aio_read(&no), EAGAIN)) return 1;

    // A read at an offset.
    memset(buf, 0, sizeof buf);
    if (aio_read(&cb)) return bad("aio_read", errno, 0);
    if (expect("the same control block again", aio_read(&cb), EAGAIN)) return 1;
    if (aio_suspend(list, 1, NULL)) return bad("aio_suspend of a done one", errno, 0);
    if (aio_error(&cb) != 0) return bad("aio_error", aio_error(&cb), 0);
    if (aio_cancel(f, &cb) != AIO_ALLDONE) return bad("aio_cancel of a done one", errno, AIO_ALLDONE);
    if (expect("aio_cancel of another descriptor's", aio_cancel(p[0], NULL), EBADF)) return 1;
    struct aiocb other = cb;
    other.aio_fildes = p[0];
    if (expect("aio_cancel with the wrong descriptor", aio_cancel(f, &other), EBADF)) return 1;
    if (aio_return(&cb) != 5 || memcmp(buf, "world", 5)) return bad("aio_return", 0, 5);
    if (expect("aio_return twice", aio_return(&cb), EINVAL)) return 1;

    // Appending ignores the offset and moves the descriptor's.
    int fa = open(name, O_CREAT | O_RDWR | O_APPEND, 0644);
    unlink(name);
    write(fa, "abc", 3);
    lseek(fa, 0, SEEK_SET);
    struct aiocb w = at(fa, "XY", 2, 0);
    if (aio_write(&w) || aio_return(&w) != 2) return bad("an append", errno, 0);
    if (lseek(fa, 0, SEEK_CUR) != 5) return bad("the offset after it", (long)lseek(fa, 0, SEEK_CUR), 5);
    struct aiocb r = at(fa, buf, 5, 0);
    if (aio_read(&r) || aio_return(&r) != 5 || memcmp(buf, "abcXY", 5)) return bad("what was appended", 0, 1);

    // Eight not yet returned, then no more for this process.
    struct aiocb many[9];
    for (int i = 0; i < 8; i++) {
        many[i] = at(f, buf + i, 1, i);
        if (aio_read(&many[i])) return bad("one of eight", i, 0);
    }
    many[8] = at(f, buf, 1, 0);
    if (expect("a ninth", aio_read(&many[8]), EAGAIN)) return 1;
    for (int i = 0; i < 8; i++)
        if (aio_return(&many[i]) != 1) return bad("returning them", i, 1);

    // aio_suspend: its checks, and a timeout with nothing done.
    struct aiocb idle = at(f, buf, 1, 0);
    struct aiocb keep = at(f, buf, 1, 0);
    aio_read(&keep);
    const struct aiocb *wait1[1] = {&idle};
    struct timespec negative = {0, -1}, short_wait = {0, 50000000};
    if (expect("a bad timeout", aio_suspend(wait1, 1, &negative), EINVAL)) return 1;
    if (expect("nine", aio_suspend(wait1, 9, NULL), EINVAL)) return 1;
    struct timeval t0, t1;
    gettimeofday(&t0, NULL);
    if (expect("nothing done in time", aio_suspend(wait1, 1, &short_wait), EAGAIN)) return 1;
    gettimeofday(&t1, NULL);
    if ((t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_usec - t0.tv_usec) / 1000 < 45) return bad("how long it waited", 0, 50);

    // aio_fsync.
    struct aiocb s = at(f, NULL, 0, 0);
    if (expect("an unknown op", aio_fsync(5, &s), EINVAL)) return 1;
    if (aio_fsync(O_SYNC, &s) || aio_error(&s) || aio_return(&s) != 0) return bad("aio_fsync", errno, 0);

    // A signal for a request.
    signal(SIGUSR1, on_usr1);
    struct aiocb sig = at(f, buf, 1, 0);
    sig.aio_sigevent.sigev_notify = SIGEV_SIGNAL;
    sig.aio_sigevent.sigev_signo = SIGUSR1;
    if (aio_read(&sig)) return bad("a read with a signal", errno, 0);
    if (usr1 != 1) return bad("its signal", usr1, 1);
    aio_return(&sig);

    // lio_listio.
    struct aiocb a1 = at(f, buf, 2, 0), a2 = at(f, buf + 2, 2, 2), *l2[3] = {&a1, NULL, &a2};
    if (expect("mode 3", lio_listio(3, l2, 3, NULL), EINVAL)) return 1;
    if (expect("seventeen", lio_listio(LIO_WAIT, l2, 17, NULL), EINVAL)) return 1;
    a1.aio_lio_opcode = 7;
    if (expect("an unknown opcode", lio_listio(LIO_WAIT, l2, 3, NULL), EAGAIN)) return 1;
    a1.aio_lio_opcode = LIO_READ;
    a2.aio_lio_opcode = LIO_READ;
    if (lio_listio(LIO_WAIT, l2, 3, NULL)) return bad("LIO_WAIT", errno, 0);
    if (aio_return(&a1) != 2 || aio_return(&a2) != 2 || memcmp(buf, "hell", 4)) return bad("what it read", 0, 1);
    struct sigevent group = {0};
    group.sigev_notify = SIGEV_SIGNAL;
    group.sigev_signo = SIGUSR1;
    usr1 = 0;
    if (lio_listio(LIO_NOWAIT, l2, 3, &group)) return bad("LIO_NOWAIT", errno, 0);
    if (usr1 != 1) return bad("one signal for the group", usr1, 1);
    aio_return(&a1);
    aio_return(&a2);
    // LIO_NOP is queued, and a worker has no operation for it.
    a1.aio_lio_opcode = LIO_NOP;
    struct aiocb *l1[1] = {&a1};
    if (lio_listio(LIO_WAIT, l1, 1, NULL)) return bad("LIO_NOP", errno, 0);
    if (aio_error(&a1) != EINVAL || aio_return(&a1) != 0) return bad("LIO_NOP's result", aio_error(&a1), EINVAL);

    aio_return(&keep);
    puts("aio ok");
    return 0;
}
