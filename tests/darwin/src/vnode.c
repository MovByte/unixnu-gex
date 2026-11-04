// EVFILT_VNODE by kpi_vfs.c's notes: a write is NOTE_WRITE, a chmod
// NOTE_ATTRIB, a link NOTE_LINK, a flock unlock NOTE_FUNLOCK, a rename
// NOTE_RENAME, an unlink NOTE_DELETE|NOTE_LINK; a directory hears
// NOTE_WRITE for a name made and NOTE_WRITE|NOTE_LINK for a directory made;
// and an EVFILT_READ at the end of a file wakes when it grows.

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/event.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#define D "/tmp/gex-vnode"
#define ALL (NOTE_DELETE | NOTE_WRITE | NOTE_EXTEND | NOTE_ATTRIB | NOTE_LINK | NOTE_RENAME | NOTE_FUNLOCK)

static int kq;

static unsigned got(int fd) {
    struct kevent ev;
    struct timespec zero = {0, 0};
    int n = kevent(kq, NULL, 0, &ev, 1, &zero);
    return n == 1 && (int)ev.ident == fd ? ev.fflags : (n == 0 ? 0 : 0x80000000u);
}

static int bad(const char *what, unsigned v) {
    printf("vnode: %s (%#x)\n", what, v);
    return 1;
}

int main(void) {
    mkdir(D, 0755);
    int f = open(D "/f", O_RDWR | O_CREAT | O_TRUNC, 0644);
    int d = open(D, O_RDONLY);
    kq = kqueue();
    struct kevent ev;
    EV_SET(&ev, f, EVFILT_VNODE, EV_ADD | EV_CLEAR, ALL, 0, NULL);
    kevent(kq, &ev, 1, NULL, 0, NULL);
    unsigned v;
    if ((v = got(f)) != 0) return bad("a note before anything happened", v);
    write(f, "abc", 3);
    if ((v = got(f)) != NOTE_WRITE) return bad("write", v);
    fchmod(f, 0600);
    if ((v = got(f)) != NOTE_ATTRIB) return bad("chmod", v);
    link(D "/f", D "/g");
    if ((v = got(f)) != NOTE_LINK) return bad("link", v);
    flock(f, LOCK_EX);
    flock(f, LOCK_UN);
    if ((v = got(f)) != NOTE_FUNLOCK) return bad("flock unlock", v);
    rename(D "/f", D "/h");
    if ((v = got(f)) != NOTE_RENAME) return bad("rename", v);
    unlink(D "/h");
    if ((v = got(f)) != (NOTE_DELETE | NOTE_LINK)) return bad("unlink", v);

    EV_SET(&ev, d, EVFILT_VNODE, EV_ADD | EV_CLEAR, ALL, 0, NULL);
    kevent(kq, &ev, 1, NULL, 0, NULL);
    close(open(D "/n", O_WRONLY | O_CREAT, 0644));
    if ((v = got(d)) != NOTE_WRITE) return bad("a name made in the directory", v);
    mkdir(D "/sub", 0755);
    if ((v = got(d)) != (NOTE_WRITE | NOTE_LINK)) return bad("a directory made in it", v);

    // EVFILT_READ at the end of a file: nothing, until another descriptor
    // appends. (Not g: g is f's vnode, whose knote would hear it first.)
    int e = open(D "/e", O_RDWR | O_CREAT, 0644);
    write(e, "abc", 3);
    close(e);
    int r = open(D "/e", O_RDONLY);
    lseek(r, 0, SEEK_END);
    // What the directory heard of e's making goes first.
    struct kevent drain;
    struct timespec none = {0, 0};
    while (kevent(kq, NULL, 0, &drain, 1, &none) == 1) {
    }
    EV_SET(&ev, r, EVFILT_READ, EV_ADD, 0, 0, NULL);
    kevent(kq, &ev, 1, NULL, 0, NULL);
    struct kevent out;
    struct timespec zero = {0, 0};
    if (kevent(kq, NULL, 0, &out, 1, &zero) != 0) return bad("readable at its end", 0);
    int w = open(D "/e", O_WRONLY | O_APPEND);
    write(w, "more", 4);
    if (kevent(kq, NULL, 0, &out, 1, &zero) != 1 || out.ident != (uintptr_t)r || out.data != 4) return bad("EVFILT_READ after the file grew", (unsigned)out.data);
    close(w);
    close(r);
    close(f);
    close(d);
    unlink(D "/g");
    unlink(D "/e");
    unlink(D "/n");
    rmdir(D "/sub");
    rmdir(D);
    printf("vnode ok\n");
    return 0;
}
