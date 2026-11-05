// posix_spawn by kern_exec.c's rules. What fails comes back as the call's
// error with no pid written: ENOENT, ENOEXEC, a file action on a closed
// descriptor (EBADF), and the CPU type preferences: EBADARCH for a thin
// image of another type, and for a fat one when the preferences run out
// (the first empty one) before a slice is found, EBADEXEC when all four
// are given and none is there. A child it makes has the file actions done (an open onto a
// chosen descriptor, a dup2, a close, an inherit, a chdir), only those
// descriptors under POSIX_SPAWN_CLOEXEC_DEFAULT, the signal mask and
// defaults asked for, its own process group, and this process as parent;
// it reports through the pipe it was handed, and its end is that pipe's.

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <mach/machine.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

extern char **environ;

// The SDK hides it from iOS programs; libsystem_kernel exports it.
extern int spawn_addchdir(posix_spawn_file_actions_t *, const char *) __asm("_posix_spawn_file_actions_addchdir_np");

static int bad(const char *what, long v) {
    printf("spawn: %s (%ld)\n", what, v);
    return 1;
}

static int child(char **argv) {
    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof cwd) || strcmp(cwd, "/tmp")) return bad("the chdir action", 0);
    if (write(5, "five", 4) != 4) return bad("the opened descriptor", errno);
    if (fcntl(7, F_GETFD) != 0) return bad("the inherited descriptor", errno);
    if (fcntl(atoi(argv[2]), F_GETFD) != -1 || errno != EBADF) return bad("a descriptor CLOEXEC_DEFAULT closed", 0);
    if (fcntl(atoi(argv[3]), F_GETFD) != -1 || errno != EBADF) return bad("the closed descriptor", 0);
    sigset_t m;
    sigprocmask(SIG_BLOCK, NULL, &m);
    if (!sigismember(&m, SIGUSR1) || sigismember(&m, SIGUSR2)) return bad("the signal mask", 0);
    struct sigaction sa;
    sigaction(SIGUSR2, NULL, &sa);
    if (sa.sa_handler != SIG_DFL) return bad("SIGUSR2's default", 0);
    sigaction(SIGHUP, NULL, &sa);
    if (sa.sa_handler != SIG_IGN) return bad("an ignored signal still ignored", 0);
    if (getpgrp() != getpid()) return bad("its own process group", getpgrp());
    if (getppid() != atoi(argv[4])) return bad("its parent", getppid());
    printf("child ok\n");
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "child")) return child(argv);
    char self[PATH_MAX];
    uint32_t n = sizeof self;
    _NSGetExecutablePath(self, &n);
    char *env[] = {"MallocNanoZone=0", NULL};
    pid_t pid = -7;
    char *none[] = {"x", NULL};

    if (posix_spawn(&pid, "/tmp/gex-spawn-none", NULL, NULL, none, env) != ENOENT || pid != -7) return bad("ENOENT", pid);
    int fd = open("/tmp/gex-spawn-junk", O_WRONLY | O_CREAT | O_TRUNC, 0755);
    write(fd, "junk\n", 5);
    close(fd);
    if (posix_spawn(&pid, "/tmp/gex-spawn-junk", NULL, NULL, none, env) != ENOEXEC || pid != -7) return bad("ENOEXEC", pid);
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, 100, 9);
    if (posix_spawn(&pid, self, &fa, NULL, none, env) != EBADF || pid != -7) return bad("EBADF from a file action", pid);
    posix_spawn_file_actions_destroy(&fa);
    posix_spawnattr_t at;
    posix_spawnattr_init(&at);
    cpu_type_t x86 = CPU_TYPE_X86_64;
    size_t ocount;
    posix_spawnattr_setbinpref_np(&at, 1, &x86, &ocount);
    if (posix_spawn(&pid, self, NULL, &at, none, env) != 86 || pid != -7) return bad("EBADARCH for another CPU type", pid);
    posix_spawnattr_destroy(&at);
    posix_spawnattr_init(&at);
    posix_spawnattr_setarchpref_np(&at, 1, (cpu_type_t[]){CPU_TYPE_ARM64}, (cpu_subtype_t[]){CPU_SUBTYPE_ARM64E}, &ocount);
    if (posix_spawn(&pid, "/var/tmp/gex-spawn-fat", NULL, &at, none, env) != 86 || pid != -7) return bad("EBADARCH for a fat file when the preferences run out", pid);
    posix_spawnattr_destroy(&at);
    posix_spawnattr_init(&at);
    cpu_type_t four[4] = {CPU_TYPE_ARM64, CPU_TYPE_ARM64, CPU_TYPE_ARM64, CPU_TYPE_ARM64};
    cpu_subtype_t e4[4] = {CPU_SUBTYPE_ARM64E, CPU_SUBTYPE_ARM64E, CPU_SUBTYPE_ARM64E, CPU_SUBTYPE_ARM64E};
    posix_spawnattr_setarchpref_np(&at, 4, four, e4, &ocount);
    if (posix_spawn(&pid, "/var/tmp/gex-spawn-fat", NULL, &at, none, env) != 85 || pid != -7) return bad("EBADEXEC for a fat file without the slice", pid);
    posix_spawnattr_destroy(&at);

    // The child's world.
    int p[2];
    pipe(p);
    // Clear of the descriptors the actions make (1, 5, 7).
    int stray = fcntl(open("/dev/null", O_RDONLY), F_DUPFD, 20);
    int keep = fcntl(open("/dev/null", O_RDONLY), F_DUPFD, 30);
    int gone = fcntl(open("/dev/null", O_RDONLY), F_DUPFD, 40);
    signal(SIGUSR2, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addopen(&fa, 5, "/tmp/gex-spawn-five", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    posix_spawn_file_actions_adddup2(&fa, p[1], 1);
    posix_spawn_file_actions_adddup2(&fa, keep, 7);
    posix_spawn_file_actions_addinherit_np(&fa, 7);
    posix_spawn_file_actions_addclose(&fa, gone);
    spawn_addchdir(&fa, "/tmp");
    posix_spawnattr_init(&at);
    sigset_t m;
    sigemptyset(&m);
    sigaddset(&m, SIGUSR1);
    posix_spawnattr_setsigmask(&at, &m);
    sigemptyset(&m);
    sigaddset(&m, SIGUSR2);
    posix_spawnattr_setsigdefault(&at, &m);
    posix_spawnattr_setpgroup(&at, 0);
    posix_spawnattr_setflags(&at, POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_CLOEXEC_DEFAULT);
    char s1[16], s2[16], s3[16];
    snprintf(s1, sizeof s1, "%d", stray);
    snprintf(s2, sizeof s2, "%d", gone);
    snprintf(s3, sizeof s3, "%d", getpid());
    char *args[] = {self, "child", s1, s2, s3, NULL};
    int r = posix_spawn(&pid, self, &fa, &at, args, env);
    if (r) return bad("posix_spawn", r);
    if (pid <= 0 || pid == getpid()) return bad("the child's pid", pid);
    close(p[1]);
    char buf[256] = {0};
    size_t got = 0;
    ssize_t k;
    while ((k = read(p[0], buf + got, sizeof buf - 1 - got)) > 0) got += k;
    if (strcmp(buf, "child ok\n")) {
        printf("spawn: the child said: %s", buf);
        return 1;
    }
    char five[8] = {0};
    fd = open("/tmp/gex-spawn-five", O_RDONLY);
    if (read(fd, five, sizeof five) != 4 || strcmp(five, "five")) return bad("what the child wrote", 0);
    printf("spawn ok\n");
    return 0;
}
