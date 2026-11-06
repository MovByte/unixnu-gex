// A process's credential as an ordinary user sees it: its real and
// effective ids alike, one group (its effective group id), no set-id
// taint; setting an id it already has changes nothing, root's ids and the
// group list are refused (EPERM); a thread has no identity of its own
// (gettid: ESRCH). Only a set-id exec fills a closed standard descriptor
// with /dev/null: a child spawned with stderr closed has none.

#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static int bad(const char *what, long got, long want) {
    printf("creds: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

int main(int argc, char **argv) {
    if (argc > 1) {
        // The child: its stderr is closed.
        return fcntl(2, F_GETFL) == -1 && errno == EBADF ? 0 : 3;
    }
    uid_t uid = getuid();
    gid_t gid = getgid();
    if (uid == 0) return bad("running as root", uid, 501);
    if (geteuid() != uid || getegid() != gid) return bad("its effective ids", geteuid(), uid);
    if (issetugid()) return bad("issetugid", 1, 0);
    if (setuid(uid) || seteuid(uid) || setreuid(-1, -1) || setgid(gid) || setegid(gid) || setregid(-1, -1)) return bad("setting its own ids", errno, 0);
    if (issetugid()) return bad("issetugid after", 1, 0);
    if (setuid(0) != -1 || errno != EPERM) return bad("setuid(0)", errno, EPERM);
    if (seteuid(0) != -1 || errno != EPERM) return bad("seteuid(0)", errno, EPERM);
    if (setreuid(0, -1) != -1 || errno != EPERM) return bad("setreuid(0)", errno, EPERM);
    if (setgid(0) != -1 || errno != EPERM) return bad("setgid(0)", errno, EPERM);
    gid_t g[16];
    g[0] = gid;
    if (setgroups(1, g) != -1 || errno != EPERM) return bad("setgroups", errno, EPERM);
    int n = getgroups(0, NULL);
    if (n < 1 || getgroups(16, g) != n || g[0] != getegid()) return bad("its groups", n, 1);
    uid_t tu;
    gid_t tg;
    if (syscall(SYS_gettid, &tu, &tg) != -1 || errno != ESRCH) return bad("gettid", errno, ESRCH);
    // A child spawned with its stderr closed.
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addclose(&fa, 2);
    char *args[] = {argv[0], "child", NULL};
    pid_t pid;
    if (posix_spawn(&pid, argv[0], &fa, NULL, args, environ)) return bad("spawn", errno, 0);
    int st = 0;
    if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st) || WEXITSTATUS(st) != 0) return bad("the child's stderr", st, 0);
    printf("creds ok\n");
    return 0;
}
