// open1's access mode and the flags only it takes, in an open and in a
// spawn's open action alike: both mode bits, or O_EXEC with a read or
// write mode, are EINVAL; O_SYMLINK opens the link itself, O_NOFOLLOW_ANY
// refuses a path through a link, and O_CLOFORK marks the descriptor (which
// the action's dup2 to another number does not keep).

#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef O_EXEC
#define O_EXEC 0x40000000
#endif
#ifndef O_NOFOLLOW_ANY
#define O_NOFOLLOW_ANY 0x20000000
#endif
#ifndef O_CLOFORK
#define O_CLOFORK 0x08000000
#endif

extern char **environ;

static int bad(const char *what, long got, long want) {
    printf("openmode: %s: %#lx, want %#lx\n", what, got, want);
    fflush(stdout);
    return 1;
}

static int err(int fd) {
    if (fd >= 0) {
        close(fd);
        return 0;
    }
    return errno;
}

// A spawn of this program as a child that reports on descriptor `to`,
// with one open action; its exit status, or the spawn's error plus 256.
static int spawn_to(const char *self, const char *what, const char *path, int oflag, int to) {
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addopen(&fa, to, path, oflag, 0644);
    char n[16];
    snprintf(n, sizeof n, "%d", to);
    char *args[] = {(char *)self, (char *)what, n, NULL};
    pid_t c;
    int e = posix_spawn(&c, self, &fa, NULL, args, environ);
    posix_spawn_file_actions_destroy(&fa);
    if (e) return 256 + e;
    int st;
    waitpid(c, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : 255;
}

static int spawn_open(const char *self, const char *what, const char *path, int oflag) {
    return spawn_to(self, what, path, oflag, 5);
}

int main(int argc, char **argv) {
    if (argc > 2) {
        int fd = atoi(argv[2]);
        struct stat st;
        if (fstat(fd, &st)) return 10;
        if (!strcmp(argv[1], "link")) return S_ISLNK(st.st_mode) ? 0 : 11;
        if (!strcmp(argv[1], "clofork")) {
            // A fork of the child does not get it.
            pid_t g = fork();
            if (g == 0) _exit(fcntl(fd, F_GETFD) == -1 && errno == EBADF ? 0 : 12);
            int st;
            waitpid(g, &st, 0);
            return WIFEXITED(st) ? WEXITSTATUS(st) : 14;
        }
        return S_ISREG(st.st_mode) ? 0 : 13;
    }
    int fail = 0, e;
    char file[64], link[64];
    snprintf(file, sizeof file, "/private/var/tmp/openmode-%d", getpid());
    snprintf(link, sizeof link, "/private/var/tmp/openmode-%d.l", getpid());
    int fd = open(file, O_RDWR | O_CREAT | O_TRUNC, 0755);
    if (fd < 0) return bad("create", errno, 0);
    close(fd);
    if (symlink(file, link)) return bad("symlink", errno, 0);

    fail |= (e = err(open(file, O_RDWR | O_WRONLY))) != EINVAL ? bad("both mode bits", e, EINVAL) : 0;
    fail |= (e = err(open(file, O_EXEC | O_RDWR))) != EINVAL ? bad("O_EXEC | O_RDWR", e, EINVAL) : 0;
    fail |= (e = err(open(file, O_EXEC | O_WRONLY))) != EINVAL ? bad("O_EXEC | O_WRONLY", e, EINVAL) : 0;
    fail |= (e = err(openat(AT_FDCWD, file, O_RDWR | O_WRONLY | O_CREAT, 0644))) != EINVAL ? bad("openat both mode bits", e, EINVAL) : 0;
    fail |= (e = err(open(file, O_RDONLY))) ? bad("plain open", e, 0) : 0;

    // A spawn's open action is open1's too.
    fail |= (e = spawn_open(argv[0], "file", file, O_RDONLY)) ? bad("spawn plain", e, 0) : 0;
    fail |= (e = spawn_open(argv[0], "file", file, O_RDWR | O_WRONLY)) != 256 + EINVAL ? bad("spawn both mode bits", e, 256 + EINVAL) : 0;
    fail |= (e = spawn_open(argv[0], "file", file, O_EXEC | O_RDWR)) != 256 + EINVAL ? bad("spawn O_EXEC | O_RDWR", e, 256 + EINVAL) : 0;
    fail |= (e = spawn_open(argv[0], "link", link, O_RDONLY | O_SYMLINK)) ? bad("spawn O_SYMLINK", e, 0) : 0;
    fail |= (e = spawn_open(argv[0], "file", link, O_RDONLY)) ? bad("spawn through the link", e, 0) : 0;
    fail |= (e = spawn_open(argv[0], "file", link, O_RDONLY | O_NOFOLLOW_ANY)) != 256 + ELOOP ? bad("spawn O_NOFOLLOW_ANY", e, 256 + ELOOP) : 0;
    // The open lands on the lowest free number: asked for that one, the
    // descriptor keeps O_CLOFORK; asked for another, the dup2 drops it.
    int low = dup(0);
    close(low);
    fail |= (e = spawn_to(argv[0], "clofork", file, O_RDONLY | O_CLOFORK, low)) ? bad("spawn O_CLOFORK", e, 0) : 0;
    fail |= (e = spawn_to(argv[0], "clofork", file, O_RDONLY, low)) != 12 ? bad("spawn without O_CLOFORK", e, 12) : 0;
    fail |= (e = spawn_open(argv[0], "clofork", file, O_RDONLY | O_CLOFORK)) != 12 ? bad("spawn O_CLOFORK moved", e, 12) : 0;

    unlink(link);
    unlink(file);
    if (!fail) printf("openmode ok\n");
    return fail;
}
