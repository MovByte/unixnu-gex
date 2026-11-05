// POSIX_SPAWN_SETEXEC by kern_exec.c's posix_spawn: execve with options. A
// spawn that fails leaves the caller as it was, its file actions undone
// (they act on a copy of its descriptors and directory); one that succeeds
// keeps the pid and runs the new image with the actions' descriptors and
// directory, its group set (POSIX_SPAWN_SETPGROUP) and its signal mask
// (POSIX_SPAWN_SETSIGMASK), and its watchers hear NOTE_EXEC.

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

extern int spawn_addchdir(posix_spawn_file_actions_t *, const char *) __asm("_posix_spawn_file_actions_addchdir_np");

static char self[PATH_MAX];

static int bad(const char *what, long v) {
    printf("setexec: %s (%ld)\n", what, v);
    return 1;
}

// The new image: what it was given, said on fd 1 as one word.
static int image(const char *pid) {
    const char *say = "ok";
    struct stat here, there;
    char c;
    sigset_t m;
    sigprocmask(SIG_BLOCK, NULL, &m);
    if (getpid() != atoi(pid)) say = "pid";
    else if (getpgrp() != getpid()) say = "group";
    else if (stat(".", &here) || stat("/var/tmp", &there) || here.st_ino != there.st_ino || here.st_dev != there.st_dev) say = "directory";
    else if (read(9, &c, 1) != 1) say = "the opened descriptor";
    else if (!sigismember(&m, SIGUSR1)) say = "mask";
    write(1, say, strlen(say));
    return 7;
}

static int setexec(int out, const char *path, char *const *args, int close_fd) {
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, out, 1);
    posix_spawn_file_actions_addopen(&fa, 9, self, O_RDONLY, 0);
    if (close_fd >= 0) posix_spawn_file_actions_addclose(&fa, close_fd);
    spawn_addchdir(&fa, "/var/tmp");
    posix_spawnattr_t at;
    posix_spawnattr_init(&at);
    sigset_t m;
    sigemptyset(&m);
    sigaddset(&m, SIGUSR1);
    posix_spawnattr_setsigmask(&at, &m);
    posix_spawnattr_setpgroup(&at, 0);
    posix_spawnattr_setflags(&at, POSIX_SPAWN_SETEXEC | POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSIGMASK);
    char *env[] = {"MallocNanoZone=0", NULL};
    return posix_spawn(NULL, path, &fa, &at, args, env);
}

int main(int argc, char **argv) {
    if (argc > 2 && !strcmp(argv[1], "image")) return image(argv[2]);
    uint32_t n = sizeof self;
    _NSGetExecutablePath(self, &n);
    setpgid(0, 0);
    int p[2], go[2];
    pipe(p);
    pipe(go);
    pid_t pid = fork();
    if (pid < 0) return bad("fork", errno);
    if (pid == 0) {
        close(p[0]);
        close(go[1]);
        char k;
        read(go[0], &k, 1);
        char cwd[PATH_MAX];
        getcwd(cwd, sizeof cwd);
        // A spawn that fails: nothing it would have done is done.
        char *none[] = {"/nonexistent", NULL};
        int e = setexec(p[1], "/nonexistent", none, go[0]);
        char now[PATH_MAX];
        getcwd(now, sizeof now);
        if (e != ENOENT) _exit(20);
        if (fcntl(go[0], F_GETFD) == -1) _exit(21);
        if (fcntl(9, F_GETFD) != -1) _exit(22);
        if (strcmp(cwd, now)) _exit(23);
        if (getpgrp() == getpid()) _exit(24);
        char me[16];
        snprintf(me, sizeof me, "%d", getpid());
        char *args[] = {self, "image", me, NULL};
        e = setexec(p[1], self, args, -1);
        _exit(30 + e);
    }
    close(p[1]);
    close(go[0]);
    int kq = kqueue();
    struct kevent ev;
    EV_SET(&ev, pid, EVFILT_PROC, EV_ADD, NOTE_EXEC, 0, 0);
    if (kevent(kq, &ev, 1, NULL, 0, NULL)) return bad("the knote", errno);
    write(go[1], "g", 1);
    char buf[64] = {0};
    size_t got = 0;
    ssize_t k;
    while ((k = read(p[0], buf + got, sizeof buf - 1 - got)) > 0) got += k;
    int st;
    if (waitpid(pid, &st, 0) != pid) return bad("waitpid", errno);
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 7) return bad("the new image's end", WIFEXITED(st) ? WEXITSTATUS(st) : -st);
    if (strcmp(buf, "ok")) {
        printf("setexec: the new image: %s\n", buf);
        return 1;
    }
    if (kevent(kq, NULL, 0, &ev, 1, NULL) != 1 || !(ev.fflags & NOTE_EXEC)) return bad("NOTE_EXEC", ev.fflags);
    printf("setexec ok\n");
    return 0;
}
