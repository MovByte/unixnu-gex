// EVFILT_PROC by kern_event.c's rules: ESRCH for no such process, ENOTSUP
// for tracking across forks; a signal posted to the process (even one it
// ignores) as NOTE_SIGNAL; its exit as NOTE_EXIT with the wait status as the
// data under NOTE_EXITSTATUS, ending the knote (EV_EOF); no NOTE_EXEC for a
// spawn that came before the knote; NOTE_FORK on the spawner; and with
// NOTE_REAP asked for, the exit leaving the knote and the reap ending it.
// With NOTE_EXIT_DETAIL, a code signing kill (CS_KILL, then marked invalid)
// as NOTE_EXIT_CSERROR; proc_pidinfo(PROC_PIDNOTEEXIT) giving its parent the
// same data, and anyone else EACCES. Of an exit(0x12345), `p_xstat` is
// 0x1234500: the knote has its low half, PROC_PIDNOTEEXIT its low 20 bits,
// a zombie's pbi_xstatus all of it.

#include <errno.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <sys/event.h>
#include <sys/wait.h>
#include <unistd.h>

#define REAP 0x10000000u
#define PROC_PIDNOTEEXIT 21
#define CS_OPS_MARKINVALID 1
#define CS_OPS_MARKKILL 3

int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);
int proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int buffersize);

static char self[PATH_MAX];

static int bad(const char *what, long v) {
    printf("procknote: %s (%lx)\n", what, v);
    return 1;
}

// A child reading its standard input until the end, then exiting 3 (or,
// for `mode` "cs", killed for its code signing).
static pid_t run(int *wr, char *mode) {
    int p[2];
    pipe(p);
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, p[0], 0);
    posix_spawn_file_actions_addclose(&fa, p[1]);
    char *args[] = {self, mode, NULL};
    char *env[] = {"MallocNanoZone=0", NULL};
    pid_t pid = -1;
    if (posix_spawn(&pid, self, &fa, NULL, args, env)) return -1;
    close(p[0]);
    *wr = p[1];
    return pid;
}

// The next event, however long a child takes to start.
static int one(int kq, struct kevent *ev) {
    return kevent(kq, NULL, 0, ev, 1, NULL);
}

static int add(int kq, uintptr_t id, unsigned fflags, struct kevent *out) {
    struct kevent ev;
    EV_SET(&ev, id, EVFILT_PROC, EV_ADD | EV_RECEIPT, fflags, 0, 0);
    return kevent(kq, &ev, 1, out, 1, NULL);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        char c;
        while (read(0, &c, 1) > 0) {
        }
        if (strcmp(argv[1], "big") == 0) _exit(0x12345);
        if (strcmp(argv[1], "cs") != 0) return 3;
        uint32_t d;
        errno = 0;
        if (proc_pidinfo(getppid(), PROC_PIDNOTEEXIT, NOTE_EXITSTATUS, &d, sizeof d) != 0 || errno != EACCES) return 7;
        if (csops(0, CS_OPS_MARKKILL, NULL, 0) != 0 || csops(0, CS_OPS_MARKINVALID, NULL, 0) != 0) return 8;
        for (;;) pause();
    }
    uint32_t n = sizeof self;
    _NSGetExecutablePath(self, &n);
    signal(SIGUSR2, SIG_IGN);
    int kq = kqueue();
    struct kevent ev;

    if (add(kq, 999999, NOTE_EXIT, &ev) != 1 || !(ev.flags & EV_ERROR) || ev.data != ESRCH) return bad("ESRCH", ev.data);
    if (add(kq, getpid(), NOTE_TRACK, &ev) != 1 || !(ev.flags & EV_ERROR) || ev.data != ENOTSUP) return bad("ENOTSUP for NOTE_TRACK", ev.data);
    if (add(kq, getpid(), NOTE_FORK, &ev) != 1 || ev.data != 0) return bad("a knote on itself", ev.data);

    int wr;
    pid_t pid = run(&wr, "child");
    if (pid <= 0) return bad("spawning", pid);
    if (one(kq, &ev) != 1 || ev.ident != (uintptr_t)getpid() || !(ev.fflags & NOTE_FORK)) return bad("NOTE_FORK", ev.fflags);
    if (add(kq, pid, NOTE_EXIT | NOTE_EXITSTATUS | NOTE_SIGNAL | NOTE_EXEC, &ev) != 1 || ev.data != 0) return bad("a knote on the child", ev.data);
    kill(pid, SIGUSR2);
    if (one(kq, &ev) != 1 || ev.ident != (uintptr_t)pid || ev.fflags != NOTE_SIGNAL) return bad("NOTE_SIGNAL for an ignored signal", ev.fflags);
    close(wr);
    if (one(kq, &ev) != 1 || ev.fflags != (NOTE_EXIT | NOTE_EXITSTATUS) || ev.data != (3 << 8) || !(ev.flags & EV_EOF)) return bad("NOTE_EXIT with its status", ev.fflags);
    uint32_t d = 0;
    if (proc_pidinfo(pid, PROC_PIDNOTEEXIT, NOTE_EXITSTATUS | NOTE_EXIT_DETAIL, &d, sizeof d) != sizeof d || d != (3 << 8)) return bad("PROC_PIDNOTEEXIT of an exit", d);
    int st;
    waitpid(pid, &st, 0);

    pid = run(&wr, "big");
    one(kq, &ev);  // its NOTE_FORK
    add(kq, pid, NOTE_EXIT | NOTE_EXITSTATUS, &ev);
    close(wr);
    if (one(kq, &ev) != 1 || ev.data != 0x4500) return bad("NOTE_EXIT of exit(0x12345)", ev.data);
    if (proc_pidinfo(pid, PROC_PIDNOTEEXIT, NOTE_EXITSTATUS, &d, sizeof d) != sizeof d || d != 0x34500) return bad("PROC_PIDNOTEEXIT of exit(0x12345)", d);
    uint32_t bsd[34];
    if (proc_pidinfo(pid, 3, 1, bsd, 136) != 136 || bsd[1] != 5 || bsd[2] != 0x1234500) return bad("a zombie's pbi_xstatus", bsd[2]);
    waitpid(pid, &st, 0);
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0x45) return bad("exit(0x12345)'s status", st);

    pid = run(&wr, "cs");
    one(kq, &ev);  // its NOTE_FORK
    add(kq, pid, NOTE_EXIT | NOTE_EXITSTATUS | NOTE_EXIT_DETAIL, &ev);
    close(wr);
    if (one(kq, &ev) != 1 || ev.fflags != (NOTE_EXIT | NOTE_EXITSTATUS | NOTE_EXIT_DETAIL) || ev.data != (SIGKILL | NOTE_EXIT_CSERROR)) return bad("NOTE_EXIT_CSERROR", ev.data);
    if (proc_pidinfo(pid, PROC_PIDNOTEEXIT, NOTE_EXIT_DETAIL, &d, sizeof d) != sizeof d || d != NOTE_EXIT_CSERROR) return bad("PROC_PIDNOTEEXIT of a code signing kill", d);
    if (proc_pidinfo(pid, PROC_PIDNOTEEXIT, NOTE_EXITSTATUS, &d, sizeof d) != sizeof d || d != SIGKILL) return bad("PROC_PIDNOTEEXIT's status alone", d);
    waitpid(pid, &st, 0);
    if (!WIFSIGNALED(st) || WTERMSIG(st) != SIGKILL) return bad("the code signing kill", st);

    pid = run(&wr, "child");
    one(kq, &ev);  // its NOTE_FORK
    add(kq, pid, NOTE_EXIT | REAP, &ev);
    close(wr);
    if (one(kq, &ev) != 1 || ev.fflags != NOTE_EXIT || (ev.flags & EV_EOF)) return bad("NOTE_EXIT before the reap", ev.flags);
    waitpid(pid, &st, 0);
    if (one(kq, &ev) != 1 || !(ev.fflags & REAP) || !(ev.flags & EV_EOF)) return bad("NOTE_REAP", ev.fflags);
    printf("procknote ok\n");
    return 0;
}
