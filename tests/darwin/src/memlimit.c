// A task's memory limit, by memorystatus and the phys_footprint ledger:
// a fatal limit set with MEMORYSTATUS_CMD_SET_MEMLIMIT_PROPERTIES kills the
// task whose touched pages go past it (SIGKILL); pages it made reusable or
// unmapped are not counted; a task that nears its limit (80 %) is told by
// its EVFILT_MEMORYSTATUS knote (NOTE_MEMORYSTATUS_PROC_LIMIT_WARN). Needs
// the com.apple.private.memorystatus entitlement.

#include <errno.h>
#include <mach-o/dyld.h>
#include <limits.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/event.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#define MEMORYSTATUS_CMD_SET_MEMLIMIT_PROPERTIES 7
#define MEMORYSTATUS_MEMLIMIT_ATTR_FATAL 0x1
#ifndef EVFILT_MEMORYSTATUS
#define EVFILT_MEMORYSTATUS (-14)
#endif
#define NOTE_MEMORYSTATUS_PROC_LIMIT_WARN 0x10

int memorystatus_control(uint32_t command, int32_t pid, uint32_t flags, void *buffer, size_t buffersize);

typedef struct {
    int32_t active;
    uint32_t active_attr;
    int32_t inactive;
    uint32_t inactive_attr;
} props_t;

static const size_t MB = 1 << 20;

static int bad(const char *what, long got, long want) {
    printf("memlimit: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

static int limit(int mb) {
    props_t p = {mb, MEMORYSTATUS_MEMLIMIT_ATTR_FATAL, mb, MEMORYSTATUS_MEMLIMIT_ATTR_FATAL};
    return memorystatus_control(MEMORYSTATUS_CMD_SET_MEMLIMIT_PROPERTIES, getpid(), 0, &p, sizeof p) ? errno : 0;
}

static char *touched(size_t n) {
    char *p = mmap(NULL, n, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (p == MAP_FAILED) _exit(20);
    for (size_t i = 0; i < n; i += 4096) p[i] = 1;
    return p;
}

static int child(const char *mode) {
    if (limit(strcmp(mode, "near") ? 48 : 100)) return 10;
    if (!strcmp(mode, "over")) {
        touched(96 * MB);
        sleep(3);
        return 11;
    }
    if (!strcmp(mode, "freed")) {
        // Made reusable, then unmapped: each is gone from the footprint.
        for (int i = 0; i < 4; i++) {
            char *p = touched(32 * MB);
            if (madvise(p, 32 * MB, MADV_FREE_REUSABLE)) return 12;
        }
        for (int i = 0; i < 4; i++) munmap(touched(32 * MB), 32 * MB);
        sleep(1);
        return 0;
    }
    if (!strcmp(mode, "near")) {
        int kq = kqueue();
        struct kevent ev;
        EV_SET(&ev, 0, EVFILT_MEMORYSTATUS, EV_ADD, NOTE_MEMORYSTATUS_PROC_LIMIT_WARN, 0, NULL);
        if (kevent(kq, &ev, 1, NULL, 0, NULL)) return 13;
        touched(84 * MB);
        struct timespec ts = {3, 0};
        int n = kevent(kq, NULL, 0, &ev, 1, &ts);
        if (n != 1 || ev.filter != EVFILT_MEMORYSTATUS || !(ev.fflags & NOTE_MEMORYSTATUS_PROC_LIMIT_WARN)) return 14;
        return 0;
    }
    return 15;
}

static int run(const char *mode) {
    char self[PATH_MAX];
    uint32_t len = sizeof self;
    _NSGetExecutablePath(self, &len);
    char *args[] = {self, (char *)mode, NULL};
    char *env[] = {"MallocNanoZone=0", NULL};
    pid_t pid;
    int st;
    if (posix_spawn(&pid, self, NULL, NULL, args, env) || waitpid(pid, &st, 0) != pid) return -1;
    return st;
}

int main(int argc, char **argv) {
    if (argc > 1) return child(argv[1]);
    int st = run("over");
    if (!WIFSIGNALED(st) || WTERMSIG(st) != SIGKILL) return bad("past a fatal limit", st, SIGKILL);
    if ((st = run("freed")) != 0) return bad("memory made reusable or unmapped", st, 0);
    if ((st = run("near")) != 0) return bad("near the limit", st, 0);
    printf("memlimit ok\n");
    return 0;
}
