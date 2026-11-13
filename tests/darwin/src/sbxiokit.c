// Sandbox's IOKit checks on opening the GPU's accelerator. A process in
// com.apple.WebKit.GPU's sandbox may open it and its device client: the
// profile's iokit-open-service and iokit-open-user-client admit an object
// whose own classes or whose providers' (iokit-connection) include IOGPU.
// One in MTLCompilerService's may open the service but not a client, which
// its profile admits only with an iokit-user-client-class exception
// extension it does not hold: kIOReturnNotPermitted. Each sandbox is a
// child's, which looks the service up in it.

#include <IOKit/IOKitLib.h>
#include <mach/mach.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

#define SANDBOX_NAMED_BUILTIN 2

int sandbox_init(const char *profile, uint64_t flags, char **errorbuf);

static int fail(const char *what, long got) {
    printf("sbxiokit: %s: %#lx\n", what, got);
    return 1;
}

// In a child sandboxed by `profile`: find the IOGPU service, open its
// device client (type 1), and say how that went.
static int open_in(const char *profile, kern_return_t want) {
    pid_t pid = fork();
    if (pid < 0) return fail("fork", 0);
    if (pid == 0) {
        char *err = NULL;
        if (sandbox_init(profile, SANDBOX_NAMED_BUILTIN, &err) != 0) _exit(2);
        io_service_t gpu = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOGPU"));
        if (gpu == IO_OBJECT_NULL) _exit(3);
        io_connect_t conn = MACH_PORT_NULL;
        kern_return_t kr = IOServiceOpen(gpu, mach_task_self(), 1, &conn);
        if (kr != want) {
            printf("sbxiokit: %s: %#x, want %#x\n", profile, kr, want);
            fflush(stdout);
            _exit(1);
        }
        _exit(0);
    }
    int st = 0;
    if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st) || WEXITSTATUS(st) != 0) return fail(profile, st);
    return 0;
}

int main(void) {
    if (open_in("com.apple.WebKit.GPU", KERN_SUCCESS)) return 1;
    if (open_in("MTLCompilerService", kIOReturnNotPermitted)) return 1;
    printf("sbxiokit ok\n");
    return 0;
}
