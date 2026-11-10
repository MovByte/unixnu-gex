// ioctl and fcntl's flags by sys_generic.c's and kern_descrip.c's rules:
// FIONREAD on a pipe and a file, FIONBIO setting what F_GETFL reports,
// FIOCLEX, FIOSETOWN and FIOGETOWN on a pipe, ENOTTY for a command a file
// has no use for, and F_SETFL keeping O_SYNC and O_DSYNC.

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/filio.h>
#include <sys/ioctl.h>
#include <unistd.h>

static int bad(const char *what, long v) {
    printf("ioctl: %s (%ld)\n", what, v);
    return 1;
}

int main(void) {
    int p[2], n = -1, on = 1, own = 0;
    pipe(p);
    write(p[1], "hello", 5);
    if (ioctl(p[0], FIONREAD, &n) || n != 5) return bad("FIONREAD on a pipe", n);
    if (ioctl(p[0], FIONBIO, &on) || !(fcntl(p[0], F_GETFL) & O_NONBLOCK)) return bad("FIONBIO", errno);
    char b[8];
    read(p[0], b, sizeof b);
    if (read(p[0], b, sizeof b) != -1 || errno != EAGAIN) return bad("a FIONBIO pipe blocked", errno);
    if (ioctl(p[1], FIOCLEX) || fcntl(p[1], F_GETFD) != FD_CLOEXEC) return bad("FIOCLEX", errno);
    if (ioctl(p[1], FIONCLEX) || fcntl(p[1], F_GETFD) != 0) return bad("FIONCLEX", errno);
    int pg = -getpgrp();
    if (ioctl(p[0], FIOSETOWN, &pg) || ioctl(p[0], FIOGETOWN, &own) || own != getpgrp()) return bad("FIOSETOWN on a pipe", own);
    struct winsize ws;
    if (ioctl(p[0], TIOCGWINSZ, &ws) != -1 || errno != ENOTTY) return bad("TIOCGWINSZ on a pipe", errno);

    int f = open("/tmp/gex-ioctl", O_RDWR | O_CREAT | O_TRUNC, 0600);
    write(f, "0123456789", 10);
    lseek(f, 3, SEEK_SET);
    if (ioctl(f, FIONREAD, &n) || n != 7) return bad("FIONREAD on a file", n);
    if (ioctl(f, TIOCGWINSZ, &ws) != -1 || errno != ENOTTY) return bad("TIOCGWINSZ on a file", errno);
    if (fcntl(f, F_SETFL, O_SYNC | O_APPEND) || (fcntl(f, F_GETFL) & (O_SYNC | O_APPEND | O_ACCMODE)) != (O_SYNC | O_APPEND | O_RDWR)) return bad("F_SETFL O_SYNC", fcntl(f, F_GETFL));
    if (fcntl(f, F_SETFL, O_DSYNC) || (fcntl(f, F_GETFL) & (O_SYNC | O_DSYNC | O_APPEND)) != O_DSYNC) return bad("F_SETFL O_DSYNC", fcntl(f, F_GETFL));
    // fcntl's vnode commands: the flags F_GETFL shows, a full sync, an
    // advisory read checked, no storage allocated ahead, no protection
    // class, and none of it on a pipe.
    if (fcntl(f, F_NOCACHE, 1) || !(fcntl(f, F_GETFL) & 0x40000)) return bad("F_NOCACHE", fcntl(f, F_GETFL));
    if (fcntl(f, F_RDAHEAD, 0) || !(fcntl(f, F_GETFL) & 0x80000)) return bad("F_RDAHEAD", fcntl(f, F_GETFL));
    if (fcntl(f, F_FULLFSYNC)) return bad("F_FULLFSYNC", errno);
    struct radvisory ra = {.ra_offset = -1, .ra_count = 10};
    if (fcntl(f, F_RDADVISE, &ra) != -1 || errno != EINVAL) return bad("F_RDADVISE of a negative offset", errno);
    ra.ra_offset = 0;
    if (fcntl(f, F_RDADVISE, &ra)) return bad("F_RDADVISE", errno);
    fstore_t fst = {.fst_flags = F_ALLOCATEALL, .fst_posmode = F_PEOFPOSMODE, .fst_offset = 0, .fst_length = 4096, .fst_bytesalloc = 77};
    fst.fst_posmode = 0;
    if (fcntl(f, F_PREALLOCATE, &fst) != -1 || errno != EINVAL || fst.fst_bytesalloc != 0) return bad("F_PREALLOCATE of no position mode", errno);
    // A command with no case of its own is an ioctl of the vnode.
    if (fcntl(f, 9999) != -1 || errno != ENOTTY) return bad("an unknown fcntl of a file", errno);
    if (fcntl(p[0], 9999) != -1 || errno != EBADF) return bad("an unknown fcntl of a pipe", errno);
    int dn = open("/dev/null", O_RDWR);
    if (fcntl(dn, 9999) != -1 || errno != ENODEV) return bad("an unknown fcntl of a device", errno);
    close(dn);
    if (fcntl(p[1], F_NOCACHE, 1) != -1 || errno != EBADF) return bad("F_NOCACHE on a pipe", errno);
    close(f);
    unlink("/tmp/gex-ioctl");
    printf("ioctl ok\n");
    return 0;
}
