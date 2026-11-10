// Calls settled before any work on an arm64 kernel: the stubs, and the
// callers refused for want of root, an entitlement or the right kind of
// task.

#include <errno.h>
#include <mach/mach.h>
#include <stdio.h>
#include <unistd.h>

int syscall(int, ...);

static int check(const char *what, long r, int e) {
    if (r != -1 || errno != e) {
        printf("fixedcalls: %s: %ld errno %d, want errno %d\n", what, r, errno, e);
        return 1;
    }
    return 0;
}

#define ENOTSUP_ 45
#define EOPNOTSUPP_ 102

int main(void) {
    if (getuid() == 0) {
        puts("fixedcalls: expected an unprivileged caller");
        return 1;
    }
    errno = 0;
    if (check("crossarch_trap", syscall(38, 0), ENOTSUP_)) return 1;
    if (check("crossarch_trap's namespace", syscall(38, 1), EINVAL)) return 1;
    if (check("swapon", syscall(85, 0), ENOTSUP_)) return 1;
    if (check("undelete", syscall(205, "/x"), ENOTSUP_)) return 1;
    if (check("searchfs", syscall(225, 0, 0, 0, 0, 0, 0), ENOTSUP_)) return 1;
    if (check("kas_info", syscall(439, 0, 0, 0), ENOTSUP_)) return 1;
    if (check("debug_syscall_reject", syscall(547, 0), ENOTSUP_)) return 1;
    if (check("debug_syscall_reject_config", syscall(548, 0, 0), ENOTSUP_)) return 1;
    if (check("quotactl", syscall(165, "/", 0, 0, 0), EOPNOTSUPP_)) return 1;

    if (check("revoke of a directory", syscall(56, "/"), ENOTSUP_)) return 1;
    if (check("revoke of nothing", syscall(56, "/private/var/tmp/nothing"), ENOENT)) return 1;

    if (check("acct", syscall(51, 0), EPERM)) return 1;
    if (check("reboot", syscall(55, 0, 0), EPERM)) return 1;
    if (check("chroot", syscall(61, "/"), EPERM)) return 1;
    if (check("vfs_purge", syscall(455), EPERM)) return 1;
    if (check("microstackshot", syscall(492, 0, 0, 0), EPERM)) return 1;
    if (check("usrctl", syscall(445, 0), EPERM)) return 1;
    if (check("panic_with_data", syscall(185, 0, 0, 0, 0), EPERM)) return 1;
    if (check("tracker_action", syscall(546, 0, 0, 0), EPERM)) return 1;
    if (check("graftdmg", syscall(549, 0, 0, 0, 0), EPERM)) return 1;
    if (check("ungraftdmg", syscall(555, 0, 0), EPERM)) return 1;
    if (check("record_system_event", syscall(552, 0, 0, 0, 0), EPERM)) return 1;
    if (check("log_data", syscall(533, 0, 0, 0, 0), EPERM)) return 1;

    // setprivexec answers with what was set.
    if (syscall(152, 1) != 0) return 1;
    if (syscall(152, 0) != 1) return 1;
    if (syscall(152, 0) != 0) return 1;

    // PE_i_can_has_debugger, on a production device.
    int can = -1;
    mach_msg_type_number_t count = 1;
    if (host_info(mach_host_self(), 11, &can, &count) != KERN_SUCCESS || can != 0 || count != 1) { printf("fixedcalls: HOST_CAN_HAS_DEBUGGER: %d\n", can); return 1; }

    puts("fixedcalls ok");
    return 0;
}
