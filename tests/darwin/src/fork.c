// fork by kern_fork.c's rules: the parent gets the child's pid, the child
// zero (its x1 set) with this process as its parent; the child has the
// descriptors but not the kqueue (FG_CONFINED), a task of its own whose
// ports work (libSystem's fork handlers set them up again in its new
// space) and thread calls (a kqueue timer fires in it), and its end is the
// parent's to collect; the parent's EVFILT_PROC knote on itself hears
// NOTE_FORK.

#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <stdio.h>
#include <string.h>
#include <sys/event.h>
#include <sys/wait.h>
#include <unistd.h>

static int bad(const char *what, long v) {
    printf("fork: %s (%ld)\n", what, v);
    return 1;
}

int main(void) {
    int p[2];
    pipe(p);
    int kq = kqueue();
    struct kevent ev;
    EV_SET(&ev, getpid(), EVFILT_PROC, EV_ADD, NOTE_FORK, 0, 0);
    if (kevent(kq, &ev, 1, NULL, 0, NULL)) return bad("the knote", errno);
    pid_t parent = getpid();
    pid_t pid = fork();
    if (pid < 0) return bad("fork", errno);
    if (pid == 0) {
        close(p[0]);
        const char *say = "child ok";
        if (getpid() == parent || getppid() != parent) say = "child: pids";
        else if (fcntl(kq, F_GETFD) != -1 || errno != EBADF) say = "child: the kqueue";
        else {
            int who = -1;
            if (pid_for_task(mach_task_self(), &who) != KERN_SUCCESS || who != getpid()) say = "child: its task port";
            int kq2 = kqueue();
            struct kevent t;
            EV_SET(&t, 1, EVFILT_TIMER, EV_ADD | EV_ONESHOT, 0, 50, 0);
            struct timespec two = {2, 0};
            if (kevent(kq2, &t, 1, &t, 1, &two) != 1 || t.filter != EVFILT_TIMER) say = "child: a timer";
        }
        write(p[1], say, strlen(say));
        _exit(5);
    }
    close(p[1]);
    char buf[64] = {0};
    size_t got = 0;
    ssize_t k;
    while ((k = read(p[0], buf + got, sizeof buf - 1 - got)) > 0) got += k;
    if (strcmp(buf, "child ok")) {
        printf("fork: %s\n", buf);
        return 1;
    }
    int st;
    if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st) || WEXITSTATUS(st) != 5) return bad("the child's end", st);
    if (kevent(kq, NULL, 0, &ev, 1, NULL) != 1 || !(ev.fflags & NOTE_FORK) || (pid_t)ev.data != 0) return bad("NOTE_FORK", ev.fflags);
    printf("fork ok\n");
    return 0;
}
