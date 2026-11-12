// The code signing policies as an iPad without Developer Mode applies
// them to a platform program whose one entitlement is no-container (what
// the platform profile asks of a program that execs from /private/var):
// its csops status (valid,
// signed, a platform binary, killed and hardened when invalid, library
// validation, enforcement), its cdhash and identifier and no team; dyld's
// policy from AMFI; no task port of its own from task_for_pid (AMFI allows
// that only with Developer Mode), nor of a child of its user, which passes
// the POSIX check; no JIT mapping (not entitled); and the MAC system call's
// errors.

#include <errno.h>
#include <mach/mach.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <spawn.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);
int csops_audittoken(pid_t pid, unsigned int ops, void *useraddr, size_t usersize, audit_token_t *token);
int __mac_syscall(const char *policy, int call, void *arg);

#define CS_VALID 0x1
#define CS_HARD 0x100
#define CS_KILL 0x200
#define CS_ENFORCEMENT 0x1000
#define CS_REQUIRE_LV 0x2000
#define CS_NO_UNTRUSTED_HELPERS 0x2000000
#define CS_PLATFORM_BINARY 0x4000000
#define CS_SIGNED 0x20000000

static int bad(const char *what, long got, long want) {
    printf("policy: %s: %#lx, want %#lx\n", what, got, want);
    return 1;
}

int main(int argc, char **argv, char **envp, char **apple) {
    (void)envp;
    if (argc > 1) {
        for (;;) pause();
    }
    uint32_t st = 0;
    if (csops(0, 0, &st, sizeof st)) return bad("CS_OPS_STATUS", errno, 0);
    uint32_t want = CS_VALID | CS_SIGNED | CS_PLATFORM_BINARY | CS_HARD | CS_KILL | CS_REQUIRE_LV | CS_ENFORCEMENT | CS_NO_UNTRUSTED_HELPERS;
    if ((st & want) != want) return bad("its status", st, want);
    // Its cdhash, as exec gave it.
    uint8_t h[20];
    if (csops(getpid(), 5, h, sizeof h)) return bad("CS_OPS_CDHASH", errno, 0);
    char hex[41] = {0};
    for (int i = 0; i < 20; i++) snprintf(hex + 2 * i, 3, "%02x", h[i]);
    int seen = 0;
    for (char **a = apple; *a; a++)
        if (!strncmp(*a, "executable_cdhash=", 18)) seen = !strcmp(*a + 18, hex);
    if (!seen) return bad("its cdhash", 0, 1);
    if (csops(0, 5, h, 19) != -1 || errno != EINVAL) return bad("a short cdhash buffer", errno, EINVAL);
    // Its identifier, under a blob header; no team.
    char id[256];
    if (csops(0, 11, id, sizeof id)) return bad("CS_OPS_IDENTITY", errno, 0);
    uint32_t len = ((uint8_t)id[4] << 24) | ((uint8_t)id[5] << 16) | ((uint8_t)id[6] << 8) | (uint8_t)id[7];
    if (len != 8 + strlen(id + 8) + 1 || !strstr(id + 8, "policy")) return bad("its identifier", len, 0);
    if (csops(0, 14, id, sizeof id) != -1 || errno != ENOENT) return bad("CS_OPS_TEAMID", errno, ENOENT);
    if (csops(0, 15, NULL, 0) != -1 || errno != ENOTSUP) return bad("CS_OPS_CLEAR_LV", errno, ENOTSUP);
    if (csops(99999, 0, &st, sizeof st) != -1 || errno != ESRCH) return bad("another pid", errno, ESRCH);
    audit_token_t tok;
    memset(&tok, 0, sizeof tok);
    tok.val[5] = getpid() + 1;
    if (csops_audittoken(0, 0, &st, sizeof st, &tok) != -1 || errno != ESRCH) return bad("a token for another", errno, ESRCH);
    // AMFI's dyld policy: @path, fallback paths, interposing, and failed
    // library insertion (library validation is on).
    struct { uint64_t flags; uint64_t *out; } q;
    uint64_t pol = 0;
    q.flags = 0, q.out = &pol;
    if (__mac_syscall("AMFI", 90, &q)) return bad("AMFI's dyld policy", errno, 0);
    if (pol != 0x69) return bad("the policy", pol, 0x69);
    if (__mac_syscall("NoSuchPolicy", 0, NULL) != -1 || errno != ENOPOLICY) return bad("an unknown policy", errno, ENOPOLICY);
    if (__mac_syscall("AMFI", 1, NULL) != -1 || errno != ENOSYS) return bad("an unknown AMFI call", errno, ENOSYS);
    task_t t = 1;
    kern_return_t kr = task_for_pid(mach_task_self(), getpid(), &t);
    if (kr != KERN_FAILURE || t != MACH_PORT_NULL) return bad("task_for_pid of itself", kr, KERN_FAILURE);
    pid_t child;
    char *cargs[] = {argv[0], "wait", NULL};
    if (posix_spawn(&child, argv[0], NULL, NULL, cargs, envp)) return bad("a child", errno, 0);
    t = 1;
    kr = task_for_pid(mach_task_self(), child, &t);
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    if (kr != KERN_FAILURE || t != MACH_PORT_NULL) return bad("task_for_pid of a child", kr, KERN_FAILURE);
    if (mmap(NULL, 16384, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON | MAP_JIT, -1, 0) != MAP_FAILED || errno != EINVAL) return bad("a JIT mapping", errno, EINVAL);
    printf("policy ok\n");
    return 0;
}
