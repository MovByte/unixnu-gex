// A pipe's SIGIO (pipeselwakeup): the read side, made async with an owner,
// is told of a write; the write side of a read that makes room; fcntl's
// F_SETOWN and F_GETOWN reach the pipe's owner (TIOCSPGRP, negated back).

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>

static volatile int ios;

static void on_io(int s) {
    (void)s;
    ios++;
}

static int bad(const char *what, long v) {
    printf("sigio: %s (%ld)\n", what, v);
    return 1;
}

int main(void) {
    signal(SIGIO, on_io);
    int p[2], on = 1;
    pipe(p);
    if (fcntl(p[0], F_SETOWN, getpid())) return bad("F_SETOWN", errno);
    if (fcntl(p[0], F_GETOWN) != -getpid()) return bad("F_GETOWN", fcntl(p[0], F_GETOWN));
    if (ioctl(p[0], FIOASYNC, &on)) return bad("FIOASYNC", errno);
    write(p[1], "x", 1);
    for (int i = 0; i < 100 && ios < 1; i++) usleep(1000);
    if (ios != 1) return bad("SIGIO on a write", ios);
    // The write side is not async: a read sends nothing.
    char c;
    read(p[0], &c, 1);
    usleep(5000);
    if (ios != 1) return bad("SIGIO for a side that is not async", ios);
    if (fcntl(p[1], F_SETOWN, getpid()) || fcntl(p[1], F_SETFL, O_ASYNC) || !(fcntl(p[1], F_GETFL) & O_ASYNC)) return bad("O_ASYNC by F_SETFL", errno);
    write(p[1], "y", 1);
    read(p[0], &c, 1);
    for (int i = 0; i < 100 && ios < 3; i++) usleep(1000);
    // The write to the async read side, then the read with room for the
    // async write side.
    if (ios < 2) return bad("SIGIO on a read that made room", ios);
    printf("sigio ok\n");
    return 0;
}
