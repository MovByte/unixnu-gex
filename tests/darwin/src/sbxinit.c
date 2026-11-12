// sandbox_init with a builtin profile (SANDBOX_NAMED_BUILTIN, the Sandbox
// policy's call 1) gives the caller that profile's sandbox, once: a second
// is refused (forbidden-sandbox-reinit), as are an unknown name and a path.
// The sandbox decides what the platform profile allows: this profile
// denies mach-priv-host-port and allows process-fork, and a fork's child
// carries the sandbox. Call 22 says whether a builtin profile is named so;
// call 67 that no container is expected or held.

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

int sandbox_init(const char *profile, uint64_t flags, char **errorbuf);
void sandbox_free_error(char *errorbuf);
int sandbox_check(pid_t pid, const char *operation, int type, ...);
int __sandbox_ms(const char *policy, int call, void *arg);

#define SANDBOX_NAMED_BUILTIN 2
#define SANDBOX_CHECK_NO_REPORT 0x40000000
#define PROFILE "com.apple.nesessionmanager"

static int fail(const char *what, long got) {
    printf("sbxinit: %s: %ld\n", what, got);
    return 1;
}

// Call 22, as libsandbox's sandbox_compile_named makes it: 0, or the errno.
static int builtin_exists(const char *name) {
    const char *arg = name;
    return __sandbox_ms("Sandbox", 22, &arg) == 0 ? 0 : errno;
}

// sandbox_init's answer: 0, or the error it gave, which is strerror's.
static int init(const char *name) {
    char *err = NULL;
    if (sandbox_init(name, SANDBOX_NAMED_BUILTIN, &err) == 0) return 0;
    int e = -1;
    for (int i = 1; i < 107 && err; i++) {
        if (strcmp(err, strerror(i)) == 0) {
            e = i;
            break;
        }
    }
    if (err) sandbox_free_error(err);
    return e;
}

// Call 67 (sandbox_get_container_expected): {&expected, &has_container}.
static int no_container(void) {
    uint64_t expected = 9, has = 9;
    uint64_t *arg[2] = {&expected, &has};
    return __sandbox_ms("Sandbox", 67, arg) == 0 && expected == 0 && has == 0;
}

int main(void) {
    pid_t me = getpid();
    int r;
    if ((r = sandbox_check(me, NULL, 0)) != 0) return fail("sandboxed before", r);
    if ((r = sandbox_check(me, "forbidden-sandbox-reinit", SANDBOX_CHECK_NO_REPORT)) != 0) return fail("forbidden before", r);
    if ((r = builtin_exists(PROFILE)) != 0) return fail("builtin " PROFILE, r);
    if ((r = builtin_exists("gex-no-such-profile")) != ENOENT) return fail("builtin gex-no-such-profile", r);
    if (!no_container()) return fail("container before", 0);
    if ((r = init("gex-no-such-profile")) != EINVAL) return fail("init gex-no-such-profile", r);
    if ((r = init("/usr/libexec/x")) != ENOTSUP) return fail("init a path", r);
    if ((r = sandbox_check(me, NULL, 0)) != 0) return fail("sandboxed by a refusal", r);
    if ((r = init(PROFILE)) != 0) return fail("init " PROFILE, r);
    if ((r = sandbox_check(me, NULL, 0)) != 1) return fail("sandboxed after", r);
    if ((r = sandbox_check(me, "forbidden-sandbox-reinit", SANDBOX_CHECK_NO_REPORT)) != 1) return fail("forbidden after", r);
    if ((r = sandbox_check(me, "mach-priv-host-port", SANDBOX_CHECK_NO_REPORT)) != 1) return fail("mach-priv-host-port", r);
    if ((r = sandbox_check(me, "process-fork", SANDBOX_CHECK_NO_REPORT)) != 0) return fail("process-fork", r);
    if (!no_container()) return fail("container after", 0);
    if ((r = init(PROFILE)) != EPERM) return fail("init again", r);
    pid_t pid = fork();
    if (pid < 0) return fail("fork", errno);
    if (pid == 0) _exit(sandbox_check(getpid(), NULL, 0) == 1 && init(PROFILE) == EPERM ? 0 : 1);
    int st = 0;
    if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st) || WEXITSTATUS(st) != 0) return fail("the child's sandbox", st);
    printf("sbxinit ok\n");
    return 0;
}
