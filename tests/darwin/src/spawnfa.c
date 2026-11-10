// posix_spawn file actions with file ports and open locks: a file port's
// file becomes the child's descriptor (not close-on-exec), an open with
// O_EXLOCK leaves the child holding the file's lock, and one with
// O_NONBLOCK fails the spawn while another holds it; what is no file port
// fails it too.

#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <unistd.h>

int fileport_makeport(int fd, mach_port_t *port);
int posix_spawn_file_actions_add_fileportdup2_np(posix_spawn_file_actions_t *, mach_port_t, int);

extern char **environ;

static int bad(const char *what, long got, long want) {
    printf("spawnfa: %s: %ld, want %ld\n", what, got, want);
    fflush(stdout);
    return 1;
}

int main(int argc, char **argv) {
    if (argc > 1) {
        // The child: fd 5 the file port's pipe, fd 6 the locked file.
        int f5 = fcntl(5, F_GETFD), f6 = fcntl(6, F_GETFD);
        if (f5 != 0 || f6 != 0) return 10 + (f5 != 0);
        write(5, "hi", 2);
        char c;
        read(0, &c, 1);
        return 0;
    }
    int fail = 0, e;
    char path[64];
    snprintf(path, sizeof path, "/private/var/tmp/spawnfa-%d", getpid());
    int out[2], in[2];
    pipe(out);
    pipe(in);
    mach_port_t fp;
    if (fileport_makeport(out[1], &fp)) return bad("makeport", errno, 0);

    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, in[0], 0);
    posix_spawn_file_actions_add_fileportdup2_np(&fa, fp, 5);
    posix_spawn_file_actions_addopen(&fa, 6, path, O_RDWR | O_CREAT | O_EXLOCK, 0644);
    char *args[] = {argv[0], "child", NULL};
    pid_t c;
    if ((e = posix_spawn(&c, argv[0], &fa, NULL, args, environ))) return bad("spawn", e, 0);
    posix_spawn_file_actions_destroy(&fa);
    close(out[1]);
    char buf[4] = {0};
    fail |= read(out[0], buf, 2) != 2 || strcmp(buf, "hi") ? bad("through the file port", buf[0], 'h') : 0;
    // The child holds the lock its open took.
    int fd = open(path, O_RDWR);
    fail |= flock(fd, LOCK_EX | LOCK_NB) != -1 || errno != EWOULDBLOCK ? bad("child's lock", errno, EWOULDBLOCK) : 0;
    // A spawn whose open may not wait fails while the lock is held.
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addopen(&fa, 6, path, O_RDWR | O_EXLOCK | O_NONBLOCK, 0);
    pid_t c2;
    e = posix_spawn(&c2, argv[0], &fa, NULL, args, environ);
    fail |= e != EAGAIN ? bad("non-blocking open lock", e, EAGAIN) : 0;
    posix_spawn_file_actions_destroy(&fa);
    write(in[1], "x", 1);
    int st;
    waitpid(c, &st, 0);
    fail |= !WIFEXITED(st) || WEXITSTATUS(st) ? bad("child", st, 0) : 0;
    fail |= flock(fd, LOCK_EX | LOCK_NB) ? bad("lock after the child", errno, 0) : 0;
    close(fd);

    // No file port: an invalid name, and a send right of something else.
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_add_fileportdup2_np(&fa, 0x1234567, 5);
    e = posix_spawn(&c2, argv[0], &fa, NULL, args, environ);
    fail |= e != EINVAL ? bad("no such file port", e, EINVAL) : 0;
    posix_spawn_file_actions_destroy(&fa);
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_add_fileportdup2_np(&fa, mach_task_self(), 5);
    e = posix_spawn(&c2, argv[0], &fa, NULL, args, environ);
    fail |= e != EINVAL ? bad("not a file port", e, EINVAL) : 0;
    posix_spawn_file_actions_destroy(&fa);
    unlink(path);
    if (!fail) printf("spawnfa ok\n");
    return fail;
}
