// POSIX_SPAWN_START_SUSPENDED (kern_exec.c): the new process is stopped
// (SSTOP) with its task suspended before it runs a single instruction,
// which wait4 with WUNTRACED reports as a stop with status 0, and a
// SIGCONT lets it run.

#include <limits.h>
#include <mach-o/dyld.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

static int bad(const char *what, long got, long want) {
    printf("startsusp: %s: %#lx, want %#lx\n", what, got, want);
    return 1;
}

int main(int argc, char **argv) {
    if (argc > 1) {
        write(1, "r", 1);
        return 0;
    }
    int out[2];
    pipe(out);
    char self[PATH_MAX];
    uint32_t len = sizeof self;
    _NSGetExecutablePath(self, &len);
    char *args[] = {self, "child", NULL};
    char *env[] = {"MallocNanoZone=0", NULL};
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, out[1], 1);
    posix_spawnattr_t at;
    posix_spawnattr_init(&at);
    posix_spawnattr_setflags(&at, POSIX_SPAWN_START_SUSPENDED);
    pid_t pid;
    int e;
    if ((e = posix_spawn(&pid, self, &fa, &at, args, env))) return bad("spawning", e, 0);
    close(out[1]);

    // Held: nothing written however long it is given.
    struct pollfd p = {out[0], POLLIN, 0};
    if (poll(&p, 1, 2000) != 0) return bad("a suspended child's output", p.revents, 0);
    int st = -1;
    if (waitpid(pid, &st, WUNTRACED | WNOHANG) != pid || !WIFSTOPPED(st) || WSTOPSIG(st) != 0) return bad("its stop", st, 0x7f);

    kill(pid, SIGCONT);
    char c = 0;
    if (read(out[0], &c, 1) != 1 || c != 'r') return bad("its output once continued", c, 'r');
    if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st) || WEXITSTATUS(st) != 0) return bad("its exit", st, 0);
    printf("startsusp ok\n");
    return 0;
}
