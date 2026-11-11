// posix_spawn with POSIX_SPAWN_SETEXEC whose spawn attributes fail after
// the new image is in: a session leader asking for POSIX_SPAWN_SETSID is
// killed (SIGKILL) before the image runs; one that is not a leader gets
// its session and runs.

#include <errno.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static int bad(const char *what, long got, long want) {
    printf("setexecbad: %s: %ld, want %ld\n", what, got, want);
    fflush(stdout);
    return 1;
}

// Exec this program in place, asking for a new session.
static void setexec_setsid(const char *self, const char *arg) {
    posix_spawnattr_t a;
    posix_spawnattr_init(&a);
    posix_spawnattr_setflags(&a, POSIX_SPAWN_SETEXEC | POSIX_SPAWN_SETSID);
    char *args[] = {(char *)self, (char *)arg, NULL};
    int e = posix_spawn(NULL, self, NULL, &a, args, environ);
    // Only an exec that never happened comes back.
    _exit(100 + e);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        // The new image: it is its session's leader.
        if (!strcmp(argv[1], "ran")) return getsid(0) == getpid() ? 7 : 8;
        return 9;
    }
    int fail = 0, st;
    // A leader already: the session cannot be made, and the exec dies.
    pid_t c = fork();
    if (c == 0) {
        if (setsid() < 0) _exit(50);
        setexec_setsid(argv[0], "ran");
    }
    waitpid(c, &st, 0);
    fail |= !WIFSIGNALED(st) || WTERMSIG(st) != SIGKILL ? bad("a leader's exec", st, SIGKILL) : 0;
    // Not a leader: it runs, its session made.
    c = fork();
    if (c == 0) setexec_setsid(argv[0], "ran");
    waitpid(c, &st, 0);
    fail |= !WIFEXITED(st) || WEXITSTATUS(st) != 7 ? bad("another's exec", st, 7 << 8) : 0;
    if (!fail) printf("setexecbad ok\n");
    return fail;
}
