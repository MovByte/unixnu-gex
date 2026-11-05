// execve by kern_exec.c's rules. What fails comes back: ENOENT, EACCES for
// a file without an execute bit and for a directory, ENOEXEC for an empty
// file, for one no activator claims and for a script whose interpreter is a
// script, E2BIG past ARG_MAX, ENAMETOOLONG past MAXPATHLEN. Then a #! script
// runs its interpreter (this program) with the line's words and the
// script's path before the arguments, and the new image keeps what exec
// keeps: the pid, the signal mask and what is pending, ignored signals
// ignored, caught ones back to their default (an ignored-by-default one's
// pending copy dropped), descriptors without close-on-exec (and their flock
// locks), the environment; the close-on-exec ones, the kqueue, the signal
// stack and the old IPC space's names are gone. Last, a fat file runs its
// arm64 slice, where an arm64e-only one fails with EBADARCH.

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

extern char **environ;

static int bad(const char *what, long v) {
    printf("exec: %s (%ld)\n", what, v);
    return 1;
}

static void handler(int s) { (void)s; }

static void put(const char *p, const char *s, mode_t mode) {
    int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, mode);
    write(fd, s, strlen(s));
    close(fd);
    chmod(p, mode);
}

static int fails(const char *path, char **argv, int want) {
    execve(path, argv, environ);
    return errno == want;
}

#define S "/tmp/gex-exec.sh"
#define S2 "/tmp/gex-exec2.sh"
#define KEEP "/tmp/gex-exec-keep"
#define GONE "/tmp/gex-exec-gone"

// The new image: argv is the interpreter, the line's words, the script,
// then what the script was run with.
static int second(int argc, char **argv) {
    char self[PATH_MAX];
    uint32_t n = sizeof self;
    _NSGetExecutablePath(self, &n);
    if (argc != 9 || strcmp(argv[1], "-s") || strcmp(argv[2], "word") || strcmp(argv[3], S) || strcmp(argv[4], "a")) return bad("the interpreter's arguments", argc);
    if (strcmp(argv[0], self)) return bad("argv[0] is the interpreter", 0);
    if (!getenv("GEX_EXEC") || strcmp(getenv("GEX_EXEC"), "1")) return bad("the environment", 0);
    if (atoi(argv[5]) != getpid()) return bad("the pid", getpid());

    struct sigaction sa;
    sigaction(SIGUSR1, NULL, &sa);
    if (sa.sa_handler != SIG_DFL) return bad("a caught signal back to its default", 0);
    sigaction(SIGUSR2, NULL, &sa);
    if (sa.sa_handler != SIG_IGN) return bad("an ignored signal ignored", 0);
    sigaction(SIGWINCH, NULL, &sa);
    if (sa.sa_handler != SIG_DFL || (sa.sa_flags & SA_ONSTACK)) return bad("SIGWINCH's action", sa.sa_flags);
    sigset_t mask, pend;
    sigprocmask(SIG_BLOCK, NULL, &mask);
    if (!sigismember(&mask, SIGTERM) || !sigismember(&mask, SIGWINCH)) return bad("the signal mask", 0);
    sigpending(&pend);
    if (!sigismember(&pend, SIGTERM)) return bad("a pending signal kept", 0);
    if (sigismember(&pend, SIGWINCH)) return bad("a caught, ignored-by-default signal's pending copy dropped", 0);
    stack_t ss;
    sigaltstack(NULL, &ss);
    if (!(ss.ss_flags & SS_DISABLE)) return bad("the signal stack", ss.ss_flags);

    int keep = atoi(argv[6]), gone = atoi(argv[7]), kq = atoi(argv[8]);
    if (fcntl(keep, F_GETFD) != 0) return bad("a descriptor without close-on-exec", errno);
    if (fcntl(gone, F_GETFD) != -1 || errno != EBADF) return bad("a close-on-exec descriptor", gone);
    if (fcntl(kq, F_GETFD) != -1 || errno != EBADF) return bad("the kqueue", kq);
    // The kept descriptor's flock lock is still held; the closed one's is
    // gone with its last descriptor.
    int k2 = open(KEEP, O_RDONLY), g2 = open(GONE, O_RDONLY);
    if (flock(k2, LOCK_EX | LOCK_NB) != -1 || errno != EWOULDBLOCK) return bad("the kept file's flock", errno);
    if (flock(g2, LOCK_EX | LOCK_NB)) return bad("the closed file's flock", errno);

    // The old space's names mean nothing in the new one.
    mach_port_type_t t;
    if (mach_port_type(mach_task_self(), (mach_port_name_t)strtoul(getenv("GEX_EXEC_PORT"), NULL, 0), &t) != KERN_INVALID_NAME) return bad("a name from the old space", 0);
    printf("exec ok\n");
    fflush(stdout);
    char *hello[] = {"/var/tmp/gex-exec-fat", "x", NULL};
    char *env[] = {"MallocNanoZone=0", NULL};
    execve("/var/tmp/gex-exec-arm64e", hello, env);
    if (errno != 86) return bad("EBADARCH for an arm64e image", errno);
    execve("/var/tmp/gex-exec-fat", hello, env);
    return bad("execve of the fat file", errno);
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "-s")) return second(argc, argv);
    char self[PATH_MAX];
    uint32_t n = sizeof self;
    _NSGetExecutablePath(self, &n);
    char *none[] = {"x", NULL};

    if (!fails("/tmp/gex-exec-none", none, ENOENT)) return bad("ENOENT", errno);
    put("/tmp/gex-exec-rw", "#!/bin/sh\n", 0644);
    if (!fails("/tmp/gex-exec-rw", none, EACCES)) return bad("EACCES for no execute bit", errno);
    if (!fails("/tmp", none, EACCES)) return bad("EACCES for a directory", errno);
    put("/tmp/gex-exec-empty", "", 0755);
    if (!fails("/tmp/gex-exec-empty", none, ENOEXEC)) return bad("ENOEXEC for an empty file", errno);
    put("/tmp/gex-exec-junk", "not a program\n", 0755);
    if (!fails("/tmp/gex-exec-junk", none, ENOEXEC)) return bad("ENOEXEC for junk", errno);
    put("/tmp/gex-exec-bang", "#!\n", 0755);
    if (!fails("/tmp/gex-exec-bang", none, ENOEXEC)) return bad("ENOEXEC for an empty #! line", errno);
    // A script whose interpreter is a script: one level only.
    put(S2, "#!/tmp/gex-exec-junk\n", 0755);
    char line[PATH_MAX + 64];
    snprintf(line, sizeof line, "#!" S2 "\n");
    put("/tmp/gex-exec-nest", line, 0755);
    if (!fails("/tmp/gex-exec-nest", none, ENOEXEC)) return bad("ENOEXEC for a nested interpreter", errno);
    char *big = malloc(300 * 1024);
    memset(big, 'a', 300 * 1024 - 1);
    big[300 * 1024 - 1] = 0;
    char *huge[] = {"x", big, NULL};
    if (!fails(self, huge, E2BIG)) return bad("E2BIG", errno);
    char longp[1200];
    memset(longp, 'a', sizeof longp - 1);
    longp[0] = '/';
    longp[sizeof longp - 1] = 0;
    if (!fails(longp, none, ENAMETOOLONG)) return bad("ENAMETOOLONG", errno);

    // What the new image is to find.
    signal(SIGUSR1, handler);
    signal(SIGUSR2, SIG_IGN);
    struct sigaction sa = {.sa_handler = handler, .sa_flags = SA_ONSTACK};
    sigaction(SIGWINCH, &sa, NULL);
    static char altstack[SIGSTKSZ];
    stack_t ss = {.ss_sp = altstack, .ss_size = sizeof altstack};
    sigaltstack(&ss, NULL);
    sigset_t m;
    sigemptyset(&m);
    sigaddset(&m, SIGTERM);
    sigaddset(&m, SIGWINCH);
    sigprocmask(SIG_BLOCK, &m, NULL);
    kill(getpid(), SIGTERM);
    kill(getpid(), SIGWINCH);
    put(KEEP, "k", 0644);
    put(GONE, "g", 0644);
    int keep = open(KEEP, O_RDONLY), gone = open(GONE, O_RDONLY | O_CLOEXEC), kq = kqueue();
    if (flock(keep, LOCK_EX) || flock(gone, LOCK_EX)) return bad("flock", errno);
    // A name of its own choosing, far past what a starting image's
    // allocations reach: a fresh space reuses low names.
    mach_port_t port = 0x300003;
    if (mach_port_allocate_name(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, port)) return bad("mach_port_allocate_name", 0);
    char portenv[64];
    snprintf(portenv, sizeof portenv, "GEX_EXEC_PORT=0x%x", port);

    snprintf(line, sizeof line, "#!  %s  -s\tword  # the rest\n", self);
    put(S, line, 0755);
    char pid[16], k[16], g[16], q[16];
    snprintf(pid, sizeof pid, "%d", getpid());
    snprintf(k, sizeof k, "%d", keep);
    snprintf(g, sizeof g, "%d", gone);
    snprintf(q, sizeof q, "%d", kq);
    char *args[] = {"ignored", "a", pid, k, g, q, NULL};
    char *env[] = {"GEX_EXEC=1", portenv, "MallocNanoZone=0", NULL};
    execve(S, args, env);
    return bad("execve of the script", errno);
}
