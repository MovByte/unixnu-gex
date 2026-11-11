// A replica's last close drains its output first (ttylclose's ttywflush,
// ptsclose bounding it at 60 ticks): with nobody reading the primary the
// close waits that long and the output is flushed, the primary then at
// EOF; with another thread of the process reading it, the close returns
// as soon as the output is out, and the reader has it all.

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int bad(const char *what, long got, long want) {
    printf("ptyclose: %s: %ld, want %ld\n", what, got, want);
    fflush(stdout);
    return 1;
}

static long ms_since(const struct timespec *t0) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (t.tv_sec - t0->tv_sec) * 1000 + (t.tv_nsec - t0->tv_nsec) / 1000000;
}

static int pair(int *s) {
    int m = posix_openpt(O_RDWR | O_NOCTTY);
    if (m < 0 || grantpt(m) || unlockpt(m)) return -1;
    *s = open(ptsname(m), O_RDWR | O_NOCTTY);
    return *s < 0 ? -1 : m;
}

static int primary;
static char got[64];
static ssize_t ngot;

static void *reader(void *arg) {
    (void)arg;
    usleep(150000);
    ngot = read(primary, got, sizeof got);
    return NULL;
}

int main(void) {
    struct timespec t0;
    int s;
    int m = pair(&s);
    if (m < 0) return bad("the first pair", errno, 0);
    if (write(s, "lost\n", 5) != 5) return bad("writing", errno, 0);
    clock_gettime(CLOCK_MONOTONIC, &t0);
    close(s);
    long dt = ms_since(&t0);
    if (dt < 500 || dt > 2000) return bad("a close with nobody reading (ms)", dt, 600);
    char b[16];
    ssize_t r = read(m, b, sizeof b);
    if (r != 0) return bad("the primary after the flush", r, 0);
    close(m);

    primary = pair(&s);
    if (primary < 0) return bad("the second pair", errno, 0);
    if (write(s, "kept\n", 5) != 5) return bad("writing", errno, 0);
    pthread_t t;
    pthread_create(&t, NULL, reader, NULL);
    clock_gettime(CLOCK_MONOTONIC, &t0);
    close(s);
    dt = ms_since(&t0);
    pthread_join(t, NULL);
    if (dt < 100 || dt > 450) return bad("a close another thread drains (ms)", dt, 150);
    if (ngot != 6 || memcmp(got, "kept\r\n", 6)) return bad("what the reader had", ngot, 6);
    printf("ptyclose ok\n");
    return 0;
}
