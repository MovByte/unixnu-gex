// Darwin pipes, by sys_pipe.c's rules: fstat's size and block size as the
// buffer grows (512 bytes, then a pipesize_blocks size a write needs),
// partial non-blocking writes, atomic
// writes of up to PIPE_BUF, and EPIPE with SIGPIPE unless F_SETNOSIGPIPE.

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static volatile int pipes;
static char big[70000];

static void on_pipe(int s) {
    (void)s;
    pipes++;
}

static int bad(const char *what, long got) {
    printf("pipe: %s (%ld)\n", what, got);
    return 1;
}

static int rq;
static long drained;

static void *reader(void *arg) {
    (void)arg;
    char b[1000];
    ssize_t r;
    usleep(10000);
    while ((r = read(rq, b, sizeof b)) > 0) {
        drained += r;
    }
    return NULL;
}

int main(void) {
    int p[2];
    struct stat st;
    if (pipe(p)) return bad("pipe", errno);
    if (fstat(p[0], &st) || !S_ISFIFO(st.st_mode) || st.st_blksize != 16384 || st.st_size != 0 || st.st_nlink != 0) return bad("fstat of a new pipe", st.st_blksize);
    write(p[1], "abc", 3);
    if (fstat(p[1], &st) || st.st_size != 3 || st.st_blksize != 16384) return bad("fstat of the write end", st.st_size);

    fcntl(p[1], F_SETFL, O_NONBLOCK);
    ssize_t n = write(p[1], big, 20000);
    if (n != 20000) return bad("a write that grows the buffer", n);
    if (fstat(p[0], &st) || st.st_blksize != 65536 || st.st_size != 20003) return bad("fstat after growing", st.st_blksize);
    n = write(p[1], big, sizeof big);
    if (n != 65536 - 20003) return bad("a partial non-blocking write", n);
    n = write(p[1], big, 100);
    if (n != -1 || errno != EAGAIN) return bad("an atomic write to a full pipe", n);

    // A blocking write larger than the biggest buffer is written whole.
    int q[2];
    pipe(q);
    rq = q[0];
    pthread_t t;
    pthread_create(&t, NULL, reader, NULL);
    static char huge[200000];
    n = write(q[1], huge, sizeof huge);
    close(q[1]);
    pthread_join(t, NULL);
    if (n != (ssize_t)sizeof huge || drained != (long)sizeof huge) return bad("a blocking write written whole", n);

    char drain[4096];
    fcntl(p[0], F_SETFL, O_NONBLOCK);
    while (read(p[0], drain, sizeof drain) > 0) {
    }
    close(p[0]);
    fcntl(p[1], F_SETNOSIGPIPE, 1);
    if (fcntl(p[1], F_GETNOSIGPIPE) != 1) return bad("F_GETNOSIGPIPE", 0);
    n = write(p[1], "x", 1);
    if (n != -1 || errno != EPIPE) return bad("EPIPE without SIGPIPE", n);
    signal(SIGPIPE, on_pipe);
    fcntl(p[1], F_SETNOSIGPIPE, 0);
    n = write(p[1], "x", 1);
    if (n != -1 || errno != EPIPE || pipes != 1) return bad("EPIPE with SIGPIPE", pipes);
    printf("pipe ok\n");
    return 0;
}
