// Interval timers by kern_time.c: the real timer fires SIGALRM once, or by
// its interval until disarmed; getitimer reports its interval and the time
// left (none once fired); setitimer reports the old value, and without a
// new one only reports; a value out of range or an unknown timer is
// EINVAL; the virtual and profiling timers read as set (disarmed here);
// and an exec keeps the real timer running (proc_inherit_itimers).

#include <errno.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile int alarms;

static void on_alrm(int s) {
    (void)s;
    alarms++;
}

static int bad(const char *what, long got, long want) {
    printf("itimer: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

static long us(struct timeval t) {
    return t.tv_sec * 1000000L + t.tv_usec;
}

static void wait_for(int n) {
    sigset_t none;
    sigemptyset(&none);
    while (alarms < n) sigsuspend(&none);
}

int main(int argc, char **argv) {
    struct itimerval it, old;
    if (argc > 1) {
        // After the exec: the timer runs on.
        getitimer(ITIMER_REAL, &it);
        return us(it.it_value) > 0 && us(it.it_value) <= 60000000 && us(it.it_interval) == 7000 ? 0 : 1;
    }
    struct sigaction sa = {.sa_handler = on_alrm};
    sigaction(SIGALRM, &sa, NULL);
    sigset_t m;
    sigemptyset(&m);
    sigaddset(&m, SIGALRM);
    sigprocmask(SIG_BLOCK, &m, NULL);

    memset(&it, 0x55, sizeof it);
    if (getitimer(ITIMER_REAL, &it) || us(it.it_value) || us(it.it_interval)) return bad("a timer never set", us(it.it_value), 0);
    it = (struct itimerval){{0, 0}, {0, 100000}};
    memset(&old, 0x55, sizeof old);
    if (setitimer(ITIMER_REAL, &it, &old) || us(old.it_value)) return bad("setting it", errno, 0);
    getitimer(ITIMER_REAL, &it);
    if (us(it.it_value) <= 0 || us(it.it_value) > 100000) return bad("the time left", us(it.it_value), 100000);
    wait_for(1);
    getitimer(ITIMER_REAL, &it);
    if (us(it.it_value) != 0) return bad("a fired one-shot", us(it.it_value), 0);

    // By its interval, three times, then disarmed.
    it = (struct itimerval){{0, 50000}, {0, 50000}};
    setitimer(ITIMER_REAL, &it, NULL);
    wait_for(4);
    it = (struct itimerval){{0, 0}, {0, 0}};
    if (setitimer(ITIMER_REAL, &it, &old) || us(old.it_interval) != 50000) return bad("disarming", us(old.it_interval), 50000);
    // Only reporting.
    if (setitimer(ITIMER_REAL, NULL, &old) || us(old.it_value)) return bad("a report", us(old.it_value), 0);

    it = (struct itimerval){{0, 0}, {0, 1000000}};
    if (setitimer(ITIMER_REAL, &it, NULL) != -1 || errno != EINVAL) return bad("a microsecond count of a second", errno, EINVAL);
    it.it_value.tv_usec = 0;
    if (setitimer(3, &it, NULL) != -1 || errno != EINVAL) return bad("an unknown timer", errno, EINVAL);
    it = (struct itimerval){{0, 0}, {0, 0}};
    if (setitimer(ITIMER_VIRTUAL, &it, NULL) || getitimer(ITIMER_PROF, &old) || us(old.it_value)) return bad("the virtual timers", errno, 0);

    // An exec keeps it.
    pid_t pid = fork();
    if (pid == 0) {
        char self[PATH_MAX];
        uint32_t n = sizeof self;
        _NSGetExecutablePath(self, &n);
        it = (struct itimerval){{0, 7000}, {60, 0}};
        setitimer(ITIMER_REAL, &it, NULL);
        char *args[] = {self, "child", NULL};
        char *env[] = {"MallocNanoZone=0", NULL};
        execve(self, args, env);
        _exit(9);
    }
    int st;
    if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st) || WEXITSTATUS(st)) return bad("the timer after an exec", st, 0);
    printf("itimer ok\n");
    return 0;
}
