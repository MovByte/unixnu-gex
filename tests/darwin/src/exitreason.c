// Exit reasons (sys_reason.c), as a parent reads them with
// proc_pidinfo(PROC_PIDEXITREASONINFO and ..BASICINFO): abort_with_reason
// and abort_with_payload end the child by SIGABRT for a reason from
// userspace (its namespace and code; a crash report, from userspace, an
// abort's) whose kcdata holds the description and the payload (cut to 2048
// bytes, PAYLOAD_TRUNCATED); terminate_with_reason ends another process by
// SIGKILL for its reason (not an abort's; the kernel's no-crashed-thread
// flag is not one userspace may give, so it is masked off); a signal that
// kills by default carries a reason naming its sender, a fault one naming
// "exc handler"; a signal caught leaves none (ENOENT). Only the parent may
// ask (EACCES).

#include <errno.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define PROC_PIDEXITREASONINFO 24
#define PROC_PIDEXITREASONBASICINFO 25
#define FLAG_GENERATE_CRASH_REPORT 0x2
#define FLAG_FROM_USERSPACE 0x4
#define FLAG_PAYLOAD_TRUNCATED 0x10
#define FLAG_ABORT 0x200

extern char **environ;
int proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int buffersize);
int proc_name(int pid, void *buffer, uint32_t buffersize);
void abort_with_reason(uint32_t ns, uint64_t code, const char *s, uint64_t flags) __attribute__((noreturn));
void abort_with_payload(uint32_t ns, uint64_t code, void *payload, uint32_t size, const char *s, uint64_t flags) __attribute__((noreturn));
int terminate_with_reason(int pid, uint32_t ns, uint64_t code, const char *s, uint64_t flags);

struct basic {
    uint32_t ns;
    uint64_t code;
    uint64_t flags;
    uint32_t size;
} __attribute__((packed));

struct full {
    uint32_t ns;
    uint64_t code;
    uint64_t flags;
    uint32_t size;
    uint64_t buf;
} __attribute__((packed));

static char self[1024];
static char kcd[8192];

static int bad(const char *what, long got, long want) {
    printf("exitreason: %s: %#lx, want %#lx\n", what, got, want);
    return 1;
}

static void on_term(int s) {
    (void)s;
}

static volatile sig_atomic_t ready;

static void on_ready(int s) {
    (void)s;
    ready = 1;
}

static int child(const char *mode) {
    char c;
    if (!strcmp(mode, "abort")) abort_with_reason(18, 0x42, "boom", 0);
    if (!strcmp(mode, "payload")) {
        static char p[3000];
        memset(p, 'p', sizeof p);
        abort_with_payload(18, 0x43, p, sizeof p, NULL, 0);
    }
    if (!strcmp(mode, "fault")) {
        volatile int *z = (volatile int *)0x7ff000000000;
        *z = 1;
    }
    if (!strcmp(mode, "caught")) {
        signal(SIGTERM, on_term);
        kill(getppid(), SIGUSR2);
    }
    if (!strcmp(mode, "nosy")) {
        struct basic b;
        errno = 0;
        return proc_pidinfo(getppid(), PROC_PIDEXITREASONBASICINFO, 0, &b, sizeof b) == 0 && errno == EACCES ? 0 : 9;
    }
    // Until its standard input ends.
    while (read(0, &c, 1) > 0) {
    }
    return 0;
}

static pid_t run(const char *mode, int *wr) {
    int p[2];
    pipe(p);
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, p[0], 0);
    posix_spawn_file_actions_addclose(&fa, p[1]);
    char *args[] = {self, (char *)mode, NULL};
    pid_t pid = -1;
    if (posix_spawn(&pid, self, &fa, NULL, args, environ)) return -1;
    close(p[0]);
    *wr = p[1];
    return pid;
}

// The child's end, it still a zombie: its wait status.
static int ended(pid_t pid) {
    siginfo_t si;
    if (waitid(P_PID, pid, &si, WEXITED | WNOWAIT) != 0) return -1;
    return si.si_code == CLD_EXITED ? 0x1000 | si.si_status : si.si_status;
}

// The kcdata item of `type` in the buffer (its data, its size).
static char *item(uint32_t type, uint32_t len, uint32_t *size) {
    uint32_t at = 0;
    while (at + 16 <= len) {
        uint32_t t, s;
        memcpy(&t, kcd + at, 4);
        memcpy(&s, kcd + at + 4, 4);
        if (t == type) {
            *size = s;
            return kcd + at + 16;
        }
        at += 16 + s;
    }
    return NULL;
}

static int full(pid_t pid, struct full *f) {
    memset(kcd, 0, sizeof kcd);
    f->size = sizeof kcd;
    f->buf = (uint64_t)(uintptr_t)kcd;
    return proc_pidinfo(pid, PROC_PIDEXITREASONINFO, 0, f, sizeof *f);
}

int main(int argc, char **argv) {
    if (argc > 1) return child(argv[1]);
    strcpy(self, argv[0]);
    int wr, st;
    struct basic b;
    struct full f;
    uint32_t n;
    char *d;

    // abort_with_reason: SIGABRT, the userspace reason and its description.
    pid_t pid = run("abort", &wr);
    if ((st = ended(pid)) != SIGABRT) return bad("abort_with_reason's end", st, SIGABRT);
    if (proc_pidinfo(pid, PROC_PIDEXITREASONBASICINFO, 0, &b, sizeof b) != sizeof b) return bad("basic info", errno, 0);
    if (b.ns != 18 || b.code != 0x42 || b.flags != (FLAG_FROM_USERSPACE | FLAG_GENERATE_CRASH_REPORT | FLAG_ABORT)) return bad("its reason", (long)b.flags, FLAG_FROM_USERSPACE | FLAG_GENERATE_CRASH_REPORT | FLAG_ABORT);
    if (full(pid, &f) != sizeof f || f.size != b.size || f.ns != 18 || f.code != 0x42) return bad("full info", f.size, b.size);
    uint32_t begin;
    memcpy(&begin, kcd, 4);
    if (begin != 0x53A20900) return bad("its kcdata", begin, 0x53A20900);
    if (!(d = item(0x1002, f.size, &n)) || strcmp(d, "boom")) return bad("its description", n, 16);
    struct full small = {0};
    small.size = 8;
    small.buf = (uint64_t)(uintptr_t)kcd;
    if (proc_pidinfo(pid, PROC_PIDEXITREASONINFO, 0, &small, sizeof small) != 0 || errno != ENOMEM) return bad("a buffer too small", errno, ENOMEM);
    close(wr);
    waitpid(pid, &st, 0);

    // abort_with_payload: the payload, cut to its maximum.
    pid = run("payload", &wr);
    if ((st = ended(pid)) != SIGABRT) return bad("abort_with_payload's end", st, SIGABRT);
    if (full(pid, &f) != sizeof f || f.code != 0x43 || f.flags != (FLAG_FROM_USERSPACE | FLAG_GENERATE_CRASH_REPORT | FLAG_ABORT | FLAG_PAYLOAD_TRUNCATED)) return bad("its reason", (long)f.flags, 0);
    if (!(d = item(0x1003, f.size, &n)) || n != 2048 || d[0] != 'p' || d[2047] != 'p') return bad("its payload", n, 2048);
    close(wr);
    waitpid(pid, &st, 0);

    // kill: a signal reason naming this process.
    pid = run("wait", &wr);
    kill(pid, SIGTERM);
    if ((st = ended(pid)) != SIGTERM) return bad("SIGTERM's end", st, SIGTERM);
    if (full(pid, &f) != sizeof f || f.ns != 2 || f.code != SIGTERM || f.flags != 0) return bad("a signal's reason", (long)f.code, SIGTERM);
    pid_t sender;
    char name[64] = {0};
    proc_name(getpid(), name, sizeof name);
    if (!(d = item(0x36, f.size, &n)) || (memcpy(&sender, d, 4), sender != getpid())) return bad("its sender", sender, getpid());
    if (!(d = item(0x37, f.size, &n)) || n != 48 || strcmp(d, name)) return bad("its sender's name", n, 48);
    close(wr);
    waitpid(pid, &st, 0);

    // A signal caught, then an exit: no reason. (It says when its
    // handler is in place.)
    sigset_t usr2, old;
    sigemptyset(&usr2);
    sigaddset(&usr2, SIGUSR2);
    signal(SIGUSR2, on_ready);
    sigprocmask(SIG_BLOCK, &usr2, &old);
    pid = run("caught", &wr);
    while (!ready) sigsuspend(&old);
    sigprocmask(SIG_SETMASK, &old, NULL);
    kill(pid, SIGTERM);
    close(wr);
    if ((st = ended(pid)) != 0x1000) return bad("the exit", st, 0x1000);
    if (proc_pidinfo(pid, PROC_PIDEXITREASONBASICINFO, 0, &b, sizeof b) != 0 || errno != ENOENT) return bad("no reason", errno, ENOENT);
    waitpid(pid, &st, 0);

    // terminate_with_reason: SIGKILL, not an abort's.
    pid = run("wait", &wr);
    if (terminate_with_reason(pid, 18, 0x44, "ended", FLAG_ABORT) != 0) return bad("terminate_with_reason", errno, 0);
    if ((st = ended(pid)) != SIGKILL) return bad("its end", st, SIGKILL);
    if (proc_pidinfo(pid, PROC_PIDEXITREASONBASICINFO, 0, &b, sizeof b) != sizeof b || b.code != 0x44 || b.flags != (FLAG_FROM_USERSPACE | FLAG_GENERATE_CRASH_REPORT)) return bad("its reason", (long)b.flags, FLAG_FROM_USERSPACE | FLAG_GENERATE_CRASH_REPORT);
    close(wr);
    waitpid(pid, &st, 0);

    // A fault: "exc handler" sent it, the child itself.
    pid = run("fault", &wr);
    if ((st = ended(pid)) != SIGSEGV && st != SIGBUS) return bad("the fault's end", st, SIGSEGV);
    if (full(pid, &f) != sizeof f || f.ns != 2 || (int)f.code != st) return bad("the fault's reason", (long)f.code, st);
    if (!(d = item(0x36, f.size, &n)) || (memcpy(&sender, d, 4), sender != pid)) return bad("the fault's sender", sender, pid);
    if (!(d = item(0x37, f.size, &n)) || strcmp(d, "exc handler")) return bad("the fault's sender's name", n, 48);
    close(wr);
    waitpid(pid, &st, 0);

    // Another's parent only.
    pid = run("nosy", &wr);
    close(wr);
    if ((st = ended(pid)) != 0x1000) return bad("asking of another's", st, 0x1000);
    waitpid(pid, &st, 0);
    printf("exitreason ok\n");
    return 0;
}
