// Sandbox's call filter masks. The platform profile's Unix call mask
// leaves undelete (205) to be asked, and its syscall-unix denies it
// (EPERM), for every process, a fork's child too. A sandbox's masks are
// its profile's and-ed with the platform profile's: those of
// com.apple.WebKit.Networking let through the calls its bitmaps name and
// ask of the rest, which it denies: getppid (EPERM), pid_for_task (trap
// 46, KERN_DENIED), mach_thread_self (trap 27, which returns a port:
// MACH_PORT_NULL), host_statistics (routine 216, a KERN_DENIED reply);
// host_info (routine 200), in its kernel MIG mask, still answers.

#include <errno.h>
#include <mach/mach.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

#define SANDBOX_NAMED_BUILTIN 2

int sandbox_init(const char *profile, uint64_t flags, char **errorbuf);

static int fail(const char *what, long got) {
    printf("sbxmask: %s: %ld\n", what, got);
    return 1;
}

// undelete("/"): -1 with EPERM, refused by the platform profile.
static int undelete_refused(void) {
    errno = 0;
    return syscall(205, "/") == -1 && errno == EPERM;
}

int main(void) {
    if (!undelete_refused()) return fail("undelete", errno);
    pid_t pid = fork();
    if (pid < 0) return fail("fork", errno);
    if (pid == 0) _exit(undelete_refused() ? 0 : 1);
    int st = 0;
    if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st) || WEXITSTATUS(st) != 0) return fail("the child's undelete", st);
    // Each call answers before the sandbox.
    if (getppid() <= 0) return fail("getppid before", errno);
    int me = 0;
    kern_return_t kr;
    if ((kr = pid_for_task(mach_task_self(), &me)) != KERN_SUCCESS || me != getpid()) return fail("pid_for_task before", kr);
    mach_port_t th = mach_thread_self();
    if (th == MACH_PORT_NULL) return fail("mach_thread_self before", 0);
    mach_port_deallocate(mach_task_self(), th);
    host_load_info_data_t load;
    mach_msg_type_number_t n = HOST_LOAD_INFO_COUNT;
    if ((kr = host_statistics(mach_host_self(), HOST_LOAD_INFO, (host_info_t)&load, &n)) != KERN_SUCCESS) return fail("host_statistics before", kr);
    char *err = NULL;
    if (sandbox_init("com.apple.WebKit.Networking", SANDBOX_NAMED_BUILTIN, &err) != 0) return fail("sandbox_init", errno);
    errno = 0;
    if (getppid() != -1 || errno != EPERM) return fail("getppid", errno);
    if ((kr = pid_for_task(mach_task_self(), &me)) != KERN_DENIED) return fail("pid_for_task", kr);
    if ((th = mach_thread_self()) != MACH_PORT_NULL) return fail("mach_thread_self", th);
    n = HOST_LOAD_INFO_COUNT;
    if ((kr = host_statistics(mach_host_self(), HOST_LOAD_INFO, (host_info_t)&load, &n)) != KERN_DENIED) return fail("host_statistics", kr);
    host_basic_info_data_t hb;
    n = HOST_BASIC_INFO_COUNT;
    if ((kr = host_info(mach_host_self(), HOST_BASIC_INFO, (host_info_t)&hb, &n)) != KERN_SUCCESS) return fail("host_info", kr);
    if (!undelete_refused()) return fail("undelete in the sandbox", errno);
    printf("sbxmask ok\n");
    return 0;
}
