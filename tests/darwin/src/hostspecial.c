// host_set_special_port (host.c): a user port's id, which only launchd may
// set but for the telemetry port, which a task entitled to monitor launchd's
// events may; then the MAC policies' check, Sandbox's
// mach-host-special-port-set: the platform profile allows it (reporting a
// setter it does not expect), com.apple.nesessionmanager's profile denies
// it. Run as root, whose host port is the privileged one.
#include <errno.h>
#include <mach/mach.h>
#include <stdint.h>
#include <stdio.h>

#define SANDBOX_NAMED_BUILTIN 2

int sandbox_init(const char *profile, uint64_t flags, char **errorbuf);

static int bad(const char *what, kern_return_t kr, kern_return_t want) {
    printf("hostspecial: %s: %d, want %d\n", what, kr, want);
    return 1;
}

int main(void) {
    mach_port_t priv = mach_host_self(), p, got = MACH_PORT_NULL;
    kern_return_t kr;
    if ((kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &p)) != KERN_SUCCESS) return bad("allocate", kr, KERN_SUCCESS);
    if ((kr = mach_port_insert_right(mach_task_self(), p, p, MACH_MSG_TYPE_MAKE_SEND)) != KERN_SUCCESS) return bad("insert", kr, KERN_SUCCESS);
    // A kernel port's id is not the user's to set.
    if ((kr = host_set_special_port(priv, HOST_PRIV_PORT, p)) != KERN_INVALID_ARGUMENT) return bad("kernel id", kr, KERN_INVALID_ARGUMENT);
    // Not launchd: the telemetry port only, by the entitlement.
    if ((kr = host_set_special_port(priv, HOST_ATM_NOTIFICATION_PORT, p)) != KERN_NO_ACCESS) return bad("atm port", kr, KERN_NO_ACCESS);
    if ((kr = host_set_special_port(priv, HOST_TELEMETRY_PORT, p)) != KERN_SUCCESS) return bad("telemetry port", kr, KERN_SUCCESS);
    if ((kr = host_get_special_port(priv, HOST_LOCAL_NODE, HOST_TELEMETRY_PORT, &got)) != KERN_SUCCESS) return bad("get telemetry port", kr, KERN_SUCCESS);
    if (got != p) return bad("telemetry port's name", (kern_return_t)got, (kern_return_t)p);
    if ((kr = host_set_special_port(priv, HOST_TELEMETRY_PORT, MACH_PORT_NULL)) != KERN_SUCCESS) return bad("clear telemetry port", kr, KERN_SUCCESS);
    // In a sandbox whose profile denies it.
    char *err = NULL;
    if (sandbox_init("com.apple.nesessionmanager", SANDBOX_NAMED_BUILTIN, &err) != 0) return bad("sandbox_init", errno, 0);
    if ((kr = host_set_special_port(priv, HOST_TELEMETRY_PORT, p)) != KERN_NO_ACCESS) return bad("sandboxed telemetry port", kr, KERN_NO_ACCESS);
    printf("hostspecial ok\n");
    return 0;
}
