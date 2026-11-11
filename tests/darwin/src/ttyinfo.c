// The terminal's status line (VSTATUS, ttyinfo_locked): the load average
// (averunnable's first, to two places), then the foreground group's pick:
// its command, pid, its first thread's run state, and its user and system
// times (calcru) to hundredths. A child spinning is "running"; one asleep
// in pause() is "waiting".

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

static int bad(const char *what, long got, long want) {
    printf("ttyinfo: %s: %ld, want %ld\n", what, got, want);
    fflush(stdout);
    return 1;
}

static int load_now(void) {
    struct loadavg la;
    size_t len = sizeof la;
    if (sysctlbyname("vm.loadavg", &la, &len, NULL, 0)) return -1;
    return (int)((la.ldavg[0] * 100 + 1024) >> 11);
}

// The status line for the child, which spins (or sleeps), as the master
// reads it.
static int status_of(int spin, char *line, size_t cap, pid_t *child, int *before, int *after) {
    int m = posix_openpt(O_RDWR | O_NOCTTY);
    if (m < 0 || grantpt(m) || unlockpt(m)) return -1;
    char name[128];
    strlcpy(name, ptsname(m), sizeof name);
    int ready[2];
    if (pipe(ready)) return -1;
    pid_t p = fork();
    if (p == 0) {
        setsid();
        int s = open(name, O_RDWR);
        if (s < 0) _exit(2);
        write(ready[1], "r", 1);
        if (spin)
            for (;;) {
            }
        for (;;) pause();
    }
    char c;
    if (read(ready[0], &c, 1) != 1) return -1;
    // Its time, and its state settled (asleep, or on its CPU).
    usleep(spin ? 600000 : 300000);
    *before = load_now();
    struct termios t;
    // The terminal as the child left it: its own replica's settings.
    int s = open(name, O_RDWR | O_NOCTTY);
    if (s < 0 || tcgetattr(s, &t)) return -1;
    write(m, &t.c_cc[VSTATUS], 1);
    usleep(300000);
    *after = load_now();
    size_t n = 0;
    fcntl(m, F_SETFL, O_NONBLOCK);
    for (int tries = 0; tries < 20 && n < cap - 1; tries++) {
        ssize_t r = read(m, line + n, cap - 1 - n);
        if (r > 0) {
            n += (size_t)r;
            if (memchr(line, '\n', n)) break;
        } else
            usleep(50000);
    }
    line[n] = 0;
    kill(p, SIGKILL);
    waitpid(p, NULL, 0);
    close(s);
    close(m);
    close(ready[0]);
    close(ready[1]);
    *child = p;
    return 0;
}

int main(void) {
    // p_comm, as the kernel has it.
    struct kinfo_proc kp;
    size_t len = sizeof kp;
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    if (sysctl(mib, 4, &kp, &len, NULL, 0)) return bad("kern.proc.pid", errno, 0);
    for (int spin = 1; spin >= 0; spin--) {
        char line[512];
        pid_t child;
        int before, after;
        if (status_of(spin, line, sizeof line, &child, &before, &after)) return bad("the terminal", errno, 0);
        int l1, l2, pid;
        char comm[64], state[32];
        long us, uc, ss, sc;
        if (sscanf(line, "load: %d.%d  cmd: %63s %d %31s %ld.%ldu %ld.%lds", &l1, &l2, comm, &pid, state, &us, &uc, &ss, &sc) != 9) {
            printf("ttyinfo: the line: \"%s\"\n", line);
            return 1;
        }
        // Exactly as ttyprintf made it: tputchar puts a carriage return
        // before the newline, which ONLCR then outputs as both.
        char want_line[512];
        snprintf(want_line, sizeof want_line, "load: %d.%02d  cmd: %s %d %s %ld.%02ldu %ld.%02lds\r\r\n", l1, l2, comm, pid, state, us, uc, ss, sc);
        if (strcmp(line, want_line)) {
            printf("ttyinfo: the line: \"%s\", want \"%s\"\n", line, want_line);
            return 1;
        }
        int load = l1 * 100 + l2;
        if (load != before && load != after) return bad("the load", load, before);
        if (strcmp(comm, kp.kp_proc.p_comm)) {
            printf("ttyinfo: the command: %s, want %s\n", comm, kp.kp_proc.p_comm);
            return 1;
        }
        if (pid != child) return bad("the pid", pid, child);
        const char *want = spin ? "running" : "waiting";
        if (strcmp(state, want)) {
            printf("ttyinfo: the state: %s, want %s\n", state, want);
            return 1;
        }
        // Over half a second spinning: user time (however busy the CPUs).
        if (spin && us * 100 + uc < 5) return bad("the user time (1/100 s)", us * 100 + uc, 5);
        if (uc > 99 || sc > 99) return bad("the hundredths", uc, 99);
    }
    printf("ttyinfo ok\n");
    return 0;
}
