// Job control by kern_sig.c and kern_exit.c: SIGSTOP stops a child (its
// output stops), wait4 reports the stop once (P_LWAITED) and waitid again
// under WNOWAIT, the parent's SIGCHLD is CLD_STOPPED with the signal for
// SIGSTOP and zero for any other stop (WEXITSTATUS of p_xstat); SIGCONT
// continues it (WCONTINUED; waitid's si_pid is the child's own); a caught
// signal sent while stopped runs only once continued; SIGTERM ends a stopped
// child; SA_NOCLDSTOP keeps the stop's SIGCHLD; a masked SIGTSTP stops at
// its unmask; a terminal stop is discarded in an orphaned group; setpgid of
// a child that has exec'd is EACCES and of one that has not moves it; and
// a group made orphaned with a stopped member gets SIGHUP then SIGCONT.

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static char self[PATH_MAX];
static volatile siginfo_t got;
static volatile int chlds;

static int bad(const char *what, long v) {
    printf("jobctl: %s (%ld)\n", what, v);
    return 1;
}

static void on_chld(int s, siginfo_t *si, void *uc) {
    (void)s;
    (void)uc;
    got = *si;
    chlds++;
}

// The child's: ticks on standard output, a caught SIGUSR1 as 'U', SIGHUP as
// 'H' and an end.
static void on_usr1(int s) {
    (void)s;
    write(1, "U", 1);
}

static void on_hup(int s) {
    (void)s;
    write(1, "H", 1);
    _exit(0);
}

// Ticks until ended, saying so on `ready` once its handlers are set.
static void tick(int unblock_on_input, int ready) {
    signal(SIGUSR1, on_usr1);
    signal(SIGHUP, on_hup);
    if (ready >= 0) write(ready, "r", 1);
    if (unblock_on_input) fcntl(0, F_SETFL, O_NONBLOCK);
    for (;;) {
        write(1, "t", 1);
        usleep(20000);
        char c;
        if (unblock_on_input && read(0, &c, 1) == 1) {
            sigset_t m;
            sigemptyset(&m);
            sigaddset(&m, SIGTSTP);
            sigprocmask(SIG_UNBLOCK, &m, NULL);
        }
    }
}

// A child running `mode`, its output on *out (and, for "blocked", its input
// from *in).
static pid_t run(const char *mode, int *out, int *in, short flags) {
    int o[2], i[2];
    pipe(o);
    pipe(i);
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, o[1], 1);
    posix_spawn_file_actions_adddup2(&fa, i[0], 0);
    posix_spawn_file_actions_addclose(&fa, o[0]);
    posix_spawn_file_actions_addclose(&fa, i[1]);
    posix_spawnattr_t at;
    posix_spawnattr_init(&at);
    posix_spawnattr_setflags(&at, flags);
    char *args[] = {self, (char *)mode, NULL};
    char *env[] = {"MallocNanoZone=0", NULL};
    pid_t pid = -1;
    if (posix_spawn(&pid, self, &fa, &at, args, env)) return -1;
    close(o[1]);
    close(i[0]);
    fcntl(o[0], F_SETFL, O_NONBLOCK);
    *out = o[0];
    if (in) *in = i[1];
    else close(i[1]);
    return pid;
}

// What arrives on fd within `ms`.
static int drain(int fd, int ms, char *buf, int max) {
    int n = 0;
    for (int waited = 0; waited < ms; waited += 10) {
        ssize_t k;
        while (n < max && (k = read(fd, buf + n, max - n)) > 0) n += k;
        usleep(10000);
    }
    return n;
}

// Wait for a new child's first tick, however long it takes to start.
static int started(int fd) {
    char c;
    fcntl(fd, F_SETFL, 0);
    int ok = read(fd, &c, 1) == 1;
    fcntl(fd, F_SETFL, O_NONBLOCK);
    return ok;
}

// Whether the child goes on ticking: output written after what was
// already there, within three seconds, however slowly it runs.
static int ticking(int fd) {
    char c;
    while (read(fd, &c, 1) == 1) {
    }
    for (int i = 0; i < 300; i++) {
        if (read(fd, &c, 1) == 1) return 1;
        usleep(10000);
    }
    return 0;
}

static int has(const char *buf, int n, char c) {
    return memchr(buf, c, n) != NULL;
}

static int wait_chlds(int n) {
    for (int i = 0; i < 300 && chlds < n; i++) usleep(10000);
    return chlds >= n;
}

static int stopped_by(pid_t pid, int sig) {
    int st;
    return waitpid(pid, &st, WUNTRACED) == pid && WIFSTOPPED(st) && WSTOPSIG(st) == sig;
}

int main(int argc, char **argv) {
    if (argc > 1) {
        if (!strcmp(argv[1], "tick")) tick(0, -1);
        if (!strcmp(argv[1], "blocked")) {
            sigset_t m;
            sigemptyset(&m);
            sigaddset(&m, SIGTSTP);
            sigprocmask(SIG_BLOCK, &m, NULL);
            tick(1, -1);
        }
        if (!strcmp(argv[1], "middle")) {
            int r[2];
            pipe(r);
            pid_t c = fork();
            if (c == 0) tick(0, r[1]);
            char k;
            if (read(r[0], &k, 1) != 1) _exit(12);
            if (setpgid(c, c)) _exit(10);
            kill(c, SIGSTOP);
            if (!stopped_by(c, SIGSTOP)) _exit(11);
            _exit(0);
        }
        return 2;
    }
    uint32_t n = sizeof self;
    _NSGetExecutablePath(self, &n);
    // A group of its own, in its parent's session, for job control.
    setpgid(0, 0);
    struct sigaction sa = {.sa_sigaction = on_chld, .sa_flags = SA_SIGINFO | SA_RESTART};
    sigaction(SIGCHLD, &sa, NULL);
    char buf[512];
    int out, in, st;

    pid_t pid = run("tick", &out, NULL, 0);
    if (pid <= 0) return bad("spawning", pid);
    if (!started(out)) return bad("the child's ticks", 0);
    int before = chlds;
    kill(pid, SIGSTOP);
    if (!stopped_by(pid, SIGSTOP)) return bad("wait4 of a stop", 0);
    if (!wait_chlds(before + 1) || got.si_code != CLD_STOPPED || got.si_pid != pid || got.si_status != SIGSTOP) return bad("SIGCHLD of a SIGSTOP", got.si_status);
    drain(out, 50, buf, sizeof buf);
    if (drain(out, 200, buf, sizeof buf) != 0) return bad("a stopped child ticking", 0);
    if (waitpid(pid, &st, WUNTRACED | WNOHANG) != 0) return bad("a stop reported twice", st);
    siginfo_t si;
    memset(&si, 0, sizeof si);
    // P_LWAITED is wait4's as much as waitid's: a stop wait4 took is not
    // waitid's to see.
    if (waitid(P_PID, pid, &si, WSTOPPED | WNOWAIT | WNOHANG) || si.si_pid != 0) return bad("waitid of a stop wait4 reported", si.si_code);
    kill(pid, SIGUSR1);
    if (has(buf, drain(out, 200, buf, sizeof buf), 'U')) return bad("a caught signal while stopped", 0);
    kill(pid, SIGCONT);
    if (waitpid(pid, &st, WCONTINUED) != pid || !WIFCONTINUED(st)) return bad("wait4 of a continue", st);
    int k = drain(out, 200, buf, sizeof buf);
    if (!has(buf, k, 'U') || !has(buf, k, 't')) return bad("the child once continued", k);

    // waitid: the stop again under WNOWAIT, then taken; the continue with
    // the child as its continuer and SIGCONT as its status.
    kill(pid, SIGSTOP);
    memset(&si, 0, sizeof si);
    if (waitid(P_PID, pid, &si, WSTOPPED | WNOWAIT) || si.si_code != CLD_STOPPED || si.si_status != SIGSTOP || si.si_pid != pid) return bad("waitid of a stop", si.si_code);
    memset(&si, 0, sizeof si);
    if (waitid(P_PID, pid, &si, WSTOPPED) || si.si_code != CLD_STOPPED) return bad("waitid of a stop, again", si.si_code);
    memset(&si, 0, sizeof si);
    if (waitid(P_PID, pid, &si, WSTOPPED | WNOHANG) || si.si_pid != 0) return bad("waitid of a stop it took", si.si_pid);
    kill(pid, SIGCONT);
    memset(&si, 0, sizeof si);
    if (waitid(P_PID, pid, &si, WCONTINUED) || si.si_code != CLD_CONTINUED || si.si_pid != pid || si.si_status != SIGCONT) return bad("waitid of a continue", si.si_code);

    // SIGTSTP: CLD_STOPPED with status zero.
    before = chlds;
    kill(pid, SIGTSTP);
    if (!stopped_by(pid, SIGTSTP)) return bad("wait4 of a SIGTSTP stop", 0);
    if (!wait_chlds(before + 1) || got.si_code != CLD_STOPPED || got.si_status != 0) return bad("SIGCHLD of a SIGTSTP", got.si_status);
    // A default kill ends a stopped process.
    kill(pid, SIGTERM);
    if (waitpid(pid, &st, 0) != pid || !WIFSIGNALED(st) || WTERMSIG(st) != SIGTERM) return bad("SIGTERM to a stopped child", st);
    close(out);

    // SA_NOCLDSTOP: no SIGCHLD for a stop.
    sa.sa_flags |= SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);
    pid = run("tick", &out, NULL, 0);
    started(out);
    before = chlds;
    kill(pid, SIGSTOP);
    if (!stopped_by(pid, SIGSTOP)) return bad("a stop under SA_NOCLDSTOP", 0);
    usleep(100000);
    if (chlds != before) return bad("SIGCHLD for a stop under SA_NOCLDSTOP", chlds);
    kill(pid, SIGKILL);
    waitpid(pid, &st, 0);
    close(out);
    sa.sa_flags &= ~SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);

    // A masked SIGTSTP stops when it is let through (issignal).
    pid = run("blocked", &out, &in, 0);
    started(out);
    kill(pid, SIGTSTP);
    if (!ticking(out)) return bad("a masked SIGTSTP stopping", 0);
    if (waitpid(pid, &st, WUNTRACED | WNOHANG) != 0) return bad("a masked SIGTSTP reported", st);
    before = chlds;
    write(in, "u", 1);
    if (!stopped_by(pid, SIGTSTP)) return bad("SIGTSTP at its unmask", 0);
    if (!wait_chlds(before + 1) || got.si_code != CLD_STOPPED || got.si_status != 0) return bad("SIGCHLD of an issignal stop", got.si_status);
    kill(pid, SIGKILL);
    waitpid(pid, &st, 0);
    close(out);
    close(in);

    // An orphaned group (a session of its own): SIGTSTP is discarded,
    // SIGSTOP still stops.
    pid = run("tick", &out, NULL, POSIX_SPAWN_SETSID);
    started(out);
    kill(pid, SIGTSTP);
    if (!ticking(out) || waitpid(pid, &st, WUNTRACED | WNOHANG) != 0) return bad("SIGTSTP in an orphaned group", st);
    kill(pid, SIGSTOP);
    if (!stopped_by(pid, SIGSTOP)) return bad("SIGSTOP in an orphaned group", 0);
    // setpgid of a child that has exec'd.
    if (setpgid(pid, pid) != -1 || errno != EPERM) return bad("setpgid of a child in another session", errno);
    kill(pid, SIGKILL);
    waitpid(pid, &st, 0);
    close(out);
    pid = run("tick", &out, NULL, 0);
    if (setpgid(pid, pid) != -1 || errno != EACCES) return bad("setpgid of a child that has exec'd", errno);
    kill(pid, SIGKILL);
    waitpid(pid, &st, 0);
    close(out);

    // A group made orphaned (its member's parent gone) with a member
    // stopped: SIGHUP, then SIGCONT.
    pid = run("middle", &out, NULL, 0);
    if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st) || WEXITSTATUS(st) != 0) return bad("the middle process", st);
    int got_h = 0;
    for (int i = 0; i < 50 && !got_h; i++) got_h = has(buf, drain(out, 100, buf, sizeof buf), 'H');
    if (!got_h) return bad("SIGHUP to an orphaned stopped group", 0);
    close(out);

    printf("jobctl ok\n");
    return 0;
}
