// An exec gives the program the builtin profile its seatbelt-profiles
// entitlement names: it starts with that profile's sandbox, which denies
// mach-priv-host-port and allows process-fork, expects no container, can
// not be replaced, and goes to a fork's child. With "wait", it writes a
// byte to its standard output and reads one from its standard input, then
// exits 0 if it has a sandbox.

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

static int fail(const char *what, long got) {
    printf("sbxexec: %s: %ld\n", what, got);
    return 1;
}

static int refused_again(void) {
    char *err = NULL;
    int r = sandbox_init("com.apple.nesessionmanager", SANDBOX_NAMED_BUILTIN, &err);
    int eperm = r != 0 && err && strcmp(err, strerror(EPERM)) == 0;
    if (err) sandbox_free_error(err);
    return eperm;
}

int main(int argc, char **argv) {
    pid_t me = getpid();
    int sandboxed = sandbox_check(me, NULL, 0) == 1;
    if (argc > 1 && strcmp(argv[1], "wait") == 0) {
        char c = 'r';
        (void)write(1, &c, 1);
        (void)read(0, &c, 1);
        return sandboxed ? 0 : 1;
    }
    int r;
    if (!sandboxed) return fail("sandboxed", 0);
    if ((r = sandbox_check(me, "mach-priv-host-port", SANDBOX_CHECK_NO_REPORT)) != 1) return fail("mach-priv-host-port", r);
    if ((r = sandbox_check(me, "process-fork", SANDBOX_CHECK_NO_REPORT)) != 0) return fail("process-fork", r);
    uint64_t expected = 9, has = 9;
    uint64_t *arg[2] = {&expected, &has};
    if (__sandbox_ms("Sandbox", 67, arg) != 0 || expected != 0 || has != 0) return fail("container", (long)expected);
    if (!refused_again()) return fail("sandbox_init", 0);
    pid_t pid = fork();
    if (pid < 0) return fail("fork", errno);
    if (pid == 0) _exit(sandbox_check(getpid(), NULL, 0) == 1 ? 0 : 1);
    int st = 0;
    if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st) || WEXITSTATUS(st) != 0) return fail("the child's sandbox", st);
    printf("sbxexec ok\n");
    return 0;
}
