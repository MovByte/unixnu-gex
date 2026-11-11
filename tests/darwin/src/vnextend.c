// EVFILT_VNODE's NOTE_EXTEND: a write past a file's end is NOTE_WRITE and
// NOTE_EXTEND, one inside it NOTE_WRITE alone; a truncate that grows the
// file is NOTE_ATTRIB and NOTE_EXTEND, one that shrinks it NOTE_ATTRIB.

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/event.h>
#include <unistd.h>

static int bad(const char *what, long got, long want) {
    printf("vnextend: %s: %#lx, want %#lx\n", what, got, want);
    fflush(stdout);
    return 1;
}

// The notes the knote has gathered, at once.
static long notes(int kq) {
    struct kevent ev;
    struct timespec t = {0, 200000000};
    int n = kevent(kq, NULL, 0, &ev, 1, &t);
    return n == 1 ? (long)ev.fflags : (n == 0 ? 0 : -errno);
}

int main(void) {
    char path[] = "/tmp/gex-vnextend-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) return bad("a file", errno, 0);
    int kq = kqueue();
    struct kevent ch;
    EV_SET(&ch, fd, EVFILT_VNODE, EV_ADD | EV_CLEAR, NOTE_WRITE | NOTE_EXTEND | NOTE_ATTRIB, 0, NULL);
    if (kevent(kq, &ch, 1, NULL, 0, NULL)) return bad("the knote", errno, 0);
    long f;
    if (write(fd, "abc", 3) != 3) return bad("a write", errno, 0);
    if ((f = notes(kq)) != (NOTE_WRITE | NOTE_EXTEND)) return bad("a write past the end", f, NOTE_WRITE | NOTE_EXTEND);
    if (pwrite(fd, "x", 1, 0) != 1) return bad("a write inside", errno, 0);
    if ((f = notes(kq)) != NOTE_WRITE) return bad("a write inside it", f, NOTE_WRITE);
    if (ftruncate(fd, 100)) return bad("growing", errno, 0);
    if ((f = notes(kq)) != (NOTE_ATTRIB | NOTE_EXTEND)) return bad("a truncate that grows it", f, NOTE_ATTRIB | NOTE_EXTEND);
    if (ftruncate(fd, 10)) return bad("shrinking", errno, 0);
    if ((f = notes(kq)) != NOTE_ATTRIB) return bad("a truncate that shrinks it", f, NOTE_ATTRIB);
    unlink(path);
    printf("vnextend ok\n");
    return 0;
}
