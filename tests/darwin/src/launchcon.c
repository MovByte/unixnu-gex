// AMFI's launch constraints (mpo_proc_check_launch_constraints): what a
// launch requires of the process launched, its parent and its responsible
// process. This program's trust cache entry has category 5 (it must be
// platform code; its parent launchd, or the mobile backup agent on the
// system volume), which pid 1 meets; a copy it spawns does not. The
// children (lcchild.c) carry constraints of their own in their signatures.
// A violation lets the spawn succeed, and the child is killed by SIGKILL
// carrying OS_REASON_CODESIGNING's
// CODESIGNING_EXIT_REASON_LAUNCH_CONSTRAINT_VIOLATION (a crash report, a
// consistent failure) and the 1024-byte description AMFI made.

#include <dlfcn.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define PROC_PIDEXITREASONINFO 24
#define OS_REASON_CODESIGNING 3
#define CODESIGNING_EXIT_REASON_LAUNCH_CONSTRAINT_VIOLATION 4
#define FLAGS (0x2 | 0x40)

extern char **environ;
int proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int buffersize);
int posix_spawnattr_setmacpolicyinfo_np(posix_spawnattr_t *attr, const char *policyname, void *datap, size_t datalen);

struct full {
    uint32_t ns;
    uint64_t code;
    uint64_t flags;
    uint32_t size;
    uint64_t buf;
} __attribute__((packed));

static char kcd[8192];

static int bad(const char *what, const char *got) {
    printf("launchcon: %s: %s\n", what, got);
    return 1;
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

// `pid` was killed for a launch constraint violation described as `want`.
static int violated(const char *what, pid_t pid, const char *want) {
    static char got[256];
    int st = ended(pid);
    if (st != SIGKILL) {
        snprintf(got, sizeof got, "ended %#x, want SIGKILL", st);
        return bad(what, got);
    }
    struct full f = {0};
    memset(kcd, 0, sizeof kcd);
    f.size = sizeof kcd;
    f.buf = (uint64_t)(uintptr_t)kcd;
    if (proc_pidinfo(pid, PROC_PIDEXITREASONINFO, 0, &f, sizeof f) != sizeof f) return bad(what, "no exit reason");
    if (f.ns != OS_REASON_CODESIGNING || f.code != CODESIGNING_EXIT_REASON_LAUNCH_CONSTRAINT_VIOLATION || f.flags != FLAGS) {
        snprintf(got, sizeof got, "reason %u %llu flags %#llx", f.ns, (unsigned long long)f.code, (unsigned long long)f.flags);
        return bad(what, got);
    }
    uint32_t n = 0;
    char *d = item(0x1002, f.size, &n);
    if (!d || n != 1024) return bad(what, "no 1024-byte description");
    if (strcmp(d, want)) return bad(what, d);
    int s;
    waitpid(pid, &s, 0);
    return 0;
}

static pid_t spawn(const char *path, posix_spawnattr_t *attr) {
    char *args[] = {(char *)path, "child", NULL};
    pid_t pid = -1;
    if (posix_spawn(&pid, path, NULL, attr, args, environ)) return -1;
    return pid;
}

#define DESC "Launch Constraint Violation, error info: "
#define ME "/private/var/tmp/gex-darwin-launchcon"

int main(int argc, char **argv) {
    // A copy spawned to be refused: running is the failure.
    if (argc > 1) return 7;
    int st;
    char want[512];

    // Its own category: platform code only, and a parent that is launchd
    // or the mobile backup agent. This process is neither.
    pid_t pid = spawn("/var/tmp/gex-darwin-launchcon", NULL);
    if (violated("category 5's parent", pid, DESC "c[1]p[2]m[1]e[5], (Constraint not matched) launch type 0, failure proc [vc: 1]: " ME)) return 1;

    // Constraints in the child's own signature: on itself, its parent and
    // its responsible process (the kernel's); a fact no encyclopedia has.
    if (violated("its own constraint", spawn("/var/tmp/gex-darwin-lcself", NULL), DESC "c[4]p[1]m[1]e[0], (Constraint not matched) launch type 0, failure proc [vc: 1]: /private/var/tmp/gex-darwin-lcself")) return 1;
    if (violated("its parent constraint", spawn("/var/tmp/gex-darwin-lcparent", NULL), DESC "c[4]p[2]m[1]e[0], (Constraint not matched) launch type 0, failure proc [vc: 1]: " ME)) return 1;
    if (violated("its responsible constraint", spawn("/var/tmp/gex-darwin-lcresp", NULL), DESC "c[4]p[3]m[1]e[0], (Constraint not matched) launch type 0, failure proc [vc: 0]: ")) return 1;
    if (violated("an unknown fact", spawn("/var/tmp/gex-darwin-lcfact", NULL), DESC "c[4]p[1]m[5]e[5], (no-such-fact) launch type 0, failure proc [vc: 1]: /private/var/tmp/gex-darwin-lcfact")) return 1;
    // All three met, an $optional unknown fact among them.
    pid = spawn("/var/tmp/gex-darwin-lcok", NULL);
    if ((st = ended(pid)) != 0x1000) return bad("the constraints met", "it did not run");
    waitpid(pid, &st, 0);

    // A launch type only launchd may give.
    int (*set_launch_type)(posix_spawnattr_t *, uint8_t) = (int (*)(posix_spawnattr_t *, uint8_t))dlsym(RTLD_DEFAULT, "posix_spawnattr_set_launch_type_np");
    if (!set_launch_type) return bad("posix_spawnattr_set_launch_type_np", "missing");
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    set_launch_type(&attr, 3);
    if (violated("the application launch type", spawn("/var/tmp/gex-darwin-lcok", &attr), DESC "c[7]p[2]m[3]e[255], (Caller provided a disallowed launch type) launch type 3, failure proc [vc: 1]: " ME)) return 1;
    posix_spawnattr_destroy(&attr);

    // A constraint the spawn passes (AMFI's MAC extension): platform code
    // may; the child's validation category is 1, not 2.
    static unsigned char lwcr[] = {0x70, 0x3f, 0x02, 0x01, 0x01, 0xb0, 0x3a, 0x30, 0x09, 0x0c, 0x04, 0x63, 0x6f, 0x6d, 0x70, 0x02, 0x01, 0x01, 0x30, 0x22, 0x0c, 0x04, 0x72, 0x65, 0x71, 0x73, 0xb0, 0x1a, 0x30, 0x18, 0x0c, 0x13, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2d, 0x63, 0x61, 0x74, 0x65, 0x67, 0x6f, 0x72, 0x79, 0x02, 0x01, 0x02, 0x30, 0x09, 0x0c, 0x04, 0x76, 0x65, 0x72, 0x73, 0x02, 0x01, 0x01};
    posix_spawnattr_init(&attr);
    posix_spawnattr_setmacpolicyinfo_np(&attr, "AMFI", lwcr, sizeof lwcr);
    if (violated("the spawn's constraint", spawn("/var/tmp/gex-darwin-lcok", &attr), DESC "c[5]p[1]m[1]e[0], (Constraint not matched) launch type 0, failure proc [vc: 1]: /private/var/tmp/gex-darwin-lcok")) return 1;
    posix_spawnattr_destroy(&attr);
    static unsigned char junk[] = {0x30, 0x00};
    posix_spawnattr_init(&attr);
    posix_spawnattr_setmacpolicyinfo_np(&attr, "AMFI", junk, sizeof junk);
    if (violated("a spawn constraint that is not one", spawn("/var/tmp/gex-darwin-lcok", &attr), DESC "c[5]p[2]m[4]e[1], (Caller provided an invalid constraint as a spawnattr) launch type 0, failure proc [vc: 1]: " ME)) return 1;
    posix_spawnattr_destroy(&attr);

    // An exec is judged as a spawn is.
    pid = fork();
    if (pid == 0) {
        char *args[] = {"/var/tmp/gex-darwin-lcself", NULL};
        execve(args[0], args, environ);
        _exit(9);
    }
    snprintf(want, sizeof want, DESC "c[4]p[1]m[1]e[0], (Constraint not matched) launch type 0, failure proc [vc: 1]: /private/var/tmp/gex-darwin-lcself");
    if (violated("an exec", pid, want)) return 1;

    printf("launchcon ok\n");
    return 0;
}
