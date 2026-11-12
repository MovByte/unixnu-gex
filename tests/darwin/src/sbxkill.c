// Sandbox's exec hook kills an exec whose seatbelt-profiles entitlement
// names two profiles (stacked profiles are not supported), holds a value
// that is not a name, or names no builtin profile: a spawn's child dies of
// SIGKILL. A child its entitlement gives a sandbox is seen to have one by
// another process's sandbox_check, which has none itself, as soon as
// posix_spawn returns: the exec's label update is done in the parent's
// call. The children are this program's siblings: its path with "sbxkill"
// replaced.

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

int sandbox_check(pid_t pid, const char *operation, int type, ...);

#define SANDBOX_CHECK_NO_REPORT 0x40000000

extern char **environ;

static char prefix[1024];

static int fail(const char *what, long got) {
    printf("sbxkill: %s: %ld\n", what, got);
    return 1;
}

static const char *sibling(const char *name, char *buf, size_t n) {
    snprintf(buf, n, "%s%s", prefix, name);
    return buf;
}

static int killed(const char *name) {
    char path[1100];
    char *argv[] = {(char *)sibling(name, path, sizeof path), NULL};
    pid_t pid;
    int e = posix_spawn(&pid, path, NULL, NULL, argv, environ);
    if (e != 0) return fail(name, e), 0;
    int st = 0;
    if (waitpid(pid, &st, 0) != pid || !WIFSIGNALED(st) || WTERMSIG(st) != SIGKILL) return fail(name, st), 0;
    return 1;
}

int main(int argc, char **argv) {
    (void)argc;
    const char *self = argv[0];
    const char *at = strstr(self, "sbxkill");
    if (!at || (size_t)(at - self) >= sizeof prefix) return fail("argv[0]", 0);
    memcpy(prefix, self, at - self);
    prefix[at - self] = 0;
    if (!killed("sbxstacked") || !killed("sbxnotstr") || !killed("sbxunknown")) return 1;
    // A sandboxed child, which waits on a pipe.
    int fds[2];
    if (pipe(fds) != 0) return fail("pipe", errno);
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, fds[0], 0);
    posix_spawn_file_actions_addclose(&fa, fds[1]);
    char path[1100];
    char *cargv[] = {(char *)sibling("sbxexec", path, sizeof path), "wait", NULL};
    pid_t pid;
    int e = posix_spawn(&pid, path, &fa, NULL, cargv, environ);
    if (e != 0) return fail("spawn sbxexec", e);
    close(fds[0]);
    int r;
    if ((r = sandbox_check(pid, NULL, 0)) != 1) return fail("the child's sandbox", r);
    if ((r = sandbox_check(pid, "forbidden-sandbox-reinit", SANDBOX_CHECK_NO_REPORT)) != 1) return fail("the child's forbidden", r);
    if ((r = sandbox_check(getpid(), NULL, 0)) != 0) return fail("own sandbox", r);
    (void)write(fds[1], "x", 1);
    close(fds[1]);
    int st = 0;
    if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st) || WEXITSTATUS(st) != 0) return fail("sbxexec wait", st);
    printf("sbxkill ok\n");
    return 0;
}
