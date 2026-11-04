// kevent's descriptor filters: EVFILT_READ on a pipe (the bytes waiting,
// EOF when the writer closes, EV_CLEAR, a read filter on the write end
// that only fires at EOF), on a regular file (the bytes past the offset),
// and a libdispatch read source on a pipe another thread writes.

#include <dispatch/dispatch.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <unistd.h>

static int wfd;

static void *writer(void *arg) {
    (void)arg;
    usleep(20000);
    write(wfd, "hello", 5);
    return NULL;
}

static int fail(const char *what) {
    printf("kq-pipe: %s\n", what);
    return 1;
}

int main(void) {
    int p[2];
    pipe(p);
    int kq = kqueue();
    struct kevent ev, out;

    // Blocks until another thread writes; data is what is buffered.
    EV_SET(&ev, p[0], EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, NULL);
    if (kevent(kq, &ev, 1, NULL, 0, NULL)) return fail("register");
    struct timespec zero = {0, 0};
    if (kevent(kq, NULL, 0, &out, 1, &zero) != 0) return fail("an empty pipe is readable");
    wfd = p[1];
    pthread_t t;
    pthread_create(&t, NULL, writer, NULL);
    if (kevent(kq, NULL, 0, &out, 1, NULL) != 1 || out.ident != (uintptr_t)p[0] || out.data != 5) return fail("the write did not wake kevent with 5 bytes");
    pthread_join(t, NULL);
    // EV_CLEAR: nothing new, nothing reported.
    if (kevent(kq, NULL, 0, &out, 1, &zero) != 0) return fail("EV_CLEAR reported again");
    write(p[1], "!", 1);
    if (kevent(kq, NULL, 0, &out, 1, &zero) != 1 || out.data != 6) return fail("a second write");

    // A read filter on the write end is neutered until EOF.
    int q[2];
    pipe(q);
    EV_SET(&ev, q[1], EVFILT_READ, EV_ADD, 0, 0, NULL);
    kevent(kq, &ev, 1, NULL, 0, NULL);
    if (kevent(kq, NULL, 0, &out, 1, &zero) != 0) return fail("the neutered filter fired");
    close(q[0]);
    if (kevent(kq, NULL, 0, &out, 1, &zero) != 1 || out.ident != (uintptr_t)q[1] || !(out.flags & EV_EOF)) return fail("no EOF on the write end");
    EV_SET(&ev, q[1], EVFILT_READ, EV_DELETE, 0, 0, NULL);
    kevent(kq, &ev, 1, NULL, 0, NULL);

    // EOF on the read end once the writer closes.
    char buf[16];
    read(p[0], buf, sizeof buf);
    close(p[1]);
    if (kevent(kq, NULL, 0, &out, 1, &zero) != 1 || !(out.flags & EV_EOF) || out.data != 0) return fail("no EOF on the read end");

    // A regular file: readable by the bytes past the offset.
    int f = open("/tmp/gex-kq-file", O_RDWR | O_CREAT | O_TRUNC, 0600);
    write(f, "0123456789", 10);
    lseek(f, 4, SEEK_SET);
    EV_SET(&ev, f, EVFILT_READ, EV_ADD, 0, 0, NULL);
    kevent(kq, &ev, 1, NULL, 0, NULL);
    if (kevent(kq, NULL, 0, &out, 1, &zero) != 1 || out.data != 6) return fail("a regular file's data");
    close(f);
    unlink("/tmp/gex-kq-file");

    // A dispatch read source, written from another queue.
    int d[2];
    pipe(d);
    int dr = d[0], dw = d[1];
    dispatch_queue_t qq = dispatch_queue_create("gex.kq-pipe", NULL);
    dispatch_source_t s = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, dr, 0, qq);
    __block size_t got = 0;
    dispatch_source_set_event_handler(s, ^{
        char b[64];
        ssize_t r = read(dr, b, sizeof b);
        if (r > 0) got += r;
        if (r == 0) {
            printf("kq-pipe %zu\n", got);
            exit(0);
        }
    });
    dispatch_activate(s);
    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        write(dw, "abc", 3);
        usleep(10000);
        write(dw, "defg", 4);
        usleep(10000);
        close(dw);
    });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        printf("kq-pipe: the read source timed out at %zu\n", got);
        exit(1);
    });
    dispatch_main();
}
