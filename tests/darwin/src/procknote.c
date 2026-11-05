// EVFILT_PROC by kern_event.c's rules: ESRCH for no such process, ENOTSUP
// for tracking across forks; a signal posted to the process (even one it
// ignores) as NOTE_SIGNAL; its exit as NOTE_EXIT with the wait status as the
// data under NOTE_EXITSTATUS, ending the knote (EV_EOF); no NOTE_EXEC for a
// spawn that came before the knote; NOTE_FORK on the spawner; and with
// NOTE_REAP asked for, the exit leaving the knote and the reap ending it.

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

static char self[PATH_MAX];

static int bad(const char *what, long v) {
    printf("procknote: %s (%lx)\n", what, v);
    return 1;
}

// A child reading its standard input until the end, then exiting 3.
static pid_t run(int *wr) {
    int p[2];
    pipe(p);
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, p[0], 0);
    posix_spawn_file_actions_addclose(&fa, p[1]);
    char *args[] = {self, "child", NULL};
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
        return 3;
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
    pid_t pid = run(&wr);
    if (pid <= 0) return bad("spawning", pid);
    if (one(kq, &ev) != 1 || ev.ident != (uintptr_t)getpid() || !(ev.fflags & NOTE_FORK)) return bad("NOTE_FORK", ev.fflags);
    if (add(kq, pid, NOTE_EXIT | NOTE_EXITSTATUS | NOTE_SIGNAL | NOTE_EXEC, &ev) != 1 || ev.data != 0) return bad("a knote on the child", ev.data);
    kill(pid, SIGUSR2);
    if (one(kq, &ev) != 1 || ev.ident != (uintptr_t)pid || ev.fflags != NOTE_SIGNAL) return bad("NOTE_SIGNAL for an ignored signal", ev.fflags);
    close(wr);
    if (one(kq, &ev) != 1 || ev.fflags != (NOTE_EXIT | NOTE_EXITSTATUS) || ev.data != (3 << 8) || !(ev.flags & EV_EOF)) return bad("NOTE_EXIT with its status", ev.fflags);
    int st;
    waitpid(pid, &st, 0);

    pid = run(&wr);
    one(kq, &ev);  // its NOTE_FORK
    add(kq, pid, NOTE_EXIT | REAP, &ev);
    close(wr);
    if (one(kq, &ev) != 1 || ev.fflags != NOTE_EXIT || (ev.flags & EV_EOF)) return bad("NOTE_EXIT before the reap", ev.flags);
    waitpid(pid, &st, 0);
    if (one(kq, &ev) != 1 || !(ev.fflags & REAP) || !(ev.flags & EV_EOF)) return bad("NOTE_REAP", ev.fflags);
    printf("procknote ok\n");
    return 0;
}
