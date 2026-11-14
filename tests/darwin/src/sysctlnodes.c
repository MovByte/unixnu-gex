// The sysctl tree's own machinery: names to numbers and back, walking on to
// the next node, a node's format, and what a read or a write of the wrong
// kind gets: a directory is not a node, numbers go no further than a leaf,
// a read-only node refuses a write, and a read shorter than the value fails
// without giving part of it.

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/sysctl.h>
#include <unistd.h>

static int bad(const char *what, long got, long want) {
    printf("sysctlnodes: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

int main(void) {
    // A name and its numbers.
    int mib[CTL_MAXNAME];
    size_t n = CTL_MAXNAME;
    if (sysctlnametomib("kern.ostype", mib, &n) != 0 || n != 2 || mib[0] != CTL_KERN || mib[1] != KERN_OSTYPE) return bad("kern.ostype's numbers", (long)n, 2);
    char buf[64];
    size_t len = sizeof buf;
    if (sysctl(mib, 2, buf, &len, NULL, 0) != 0 || strcmp(buf, "Darwin") != 0 || len != 7) return bad("kern.ostype", (long)len, 7);

    // {0, 1}: numbers to the name; a number past a handler's node is itself.
    int nm[4] = {0, 1, CTL_KERN, KERN_OSTYPE};
    len = sizeof buf;
    if (sysctl(nm, 4, buf, &len, NULL, 0) != 0 || strcmp(buf, "kern.ostype") != 0) return bad("the name of {1, 1}", errno, 0);
    int nmp[6] = {0, 1, CTL_KERN, KERN_PROC, KERN_PROC_PID, 7};
    len = sizeof buf;
    if (sysctl(nmp, 6, buf, &len, NULL, 0) != 0 || strcmp(buf, "kern.proc.pid.7") != 0) return bad("the name of kern.proc.pid.7", errno, 0);

    // {0, 2}: the node after one, a directory's first child in number order.
    int nx[4] = {0, 2, CTL_KERN, KERN_OSTYPE};
    int out[CTL_MAXNAME];
    len = sizeof out;
    if (sysctl(nx, 4, out, &len, NULL, 0) != 0 || len != 2 * sizeof(int) || out[0] != CTL_KERN || out[1] != KERN_OSRELEASE) return bad("the node after kern.ostype", errno, 0);

    // {0, 4}: a node's kind and format.
    int fm[4] = {0, 4, CTL_KERN, KERN_OSTYPE};
    unsigned char f[32];
    len = sizeof f;
    if (sysctl(fm, 4, f, &len, NULL, 0) != 0 || (*(uint32_t *)f & 0xf) != CTLTYPE_STRING || strcmp((char *)f + 4, "A") != 0) return bad("kern.ostype's format", errno, 0);

    // A directory is not a node to read, and numbers end at a leaf.
    int dir[2] = {CTL_KERN, KERN_PROC};
    len = sizeof buf;
    errno = 0;
    if (sysctl(dir, 2, buf, &len, NULL, 0) != -1 || errno != ENOENT) return bad("reading a directory", errno, ENOENT);
    int past[3] = {CTL_KERN, KERN_OSTYPE, 1};
    len = sizeof buf;
    errno = 0;
    if (sysctl(past, 3, buf, &len, NULL, 0) != -1 || errno != EISDIR) return bad("numbers past a leaf", errno, EISDIR);

    // A short read fails whole.
    char small[3] = {1, 1, 1};
    len = sizeof small;
    errno = 0;
    if (sysctl(mib, 2, small, &len, NULL, 0) != -1 || errno != ENOMEM) return bad("a short read", errno, ENOMEM);
    if (small[0] != 1) return bad("a short read's copy", small[0], 1);

    // A read-only node refuses a value; osreleasetype is launchd's to set.
    errno = 0;
    if (sysctl(mib, 2, NULL, NULL, "x", 2) != -1 || errno != EPERM) return bad("writing kern.ostype", errno, EPERM);
    errno = 0;
    if (sysctlbyname("kern.osreleasetype", NULL, NULL, "x", 2) != -1 || errno != EPERM) return bad("setting kern.osreleasetype", errno, EPERM);

    // Numbers are as wide as their nodes: 64 bits, and an int alias.
    int64_t q = 0;
    len = sizeof q;
    if (sysctlbyname("hw.pagesize", &q, &len, NULL, 0) != 0 || len != 8 || q != 16384) return bad("hw.pagesize", (long)len, 8);
    int w = 0;
    len = sizeof w;
    if (sysctlbyname("hw.pagesize_compat", &w, &len, NULL, 0) != 0 || len != 4 || w != 16384) return bad("hw.pagesize_compat", (long)len, 4);
    q = 0;
    len = sizeof q;
    if (sysctlbyname("hw.cachelinesize", &q, &len, NULL, 0) != 0 || len != 8 || q != 64) return bad("hw.cachelinesize", (long)len, 8);

    // The device tree's zeroed bytes, whole.
    unsigned char env[64];
    memset(env, 0xff, sizeof env);
    len = sizeof env;
    if (sysctlbyname("hw.osenvironment", env, &len, NULL, 0) != 0 || len != 32 || env[0] != 0 || env[31] != 0 || env[32] != 0xff) return bad("hw.osenvironment", (long)len, 32);

    // The platform's names, and what only launchd may say.
    len = sizeof buf;
    if (sysctlbyname("hw.target", buf, &len, NULL, 0) != 0 || strcmp(buf, "J120AP") != 0) return bad("hw.target", errno, 0);
    len = sizeof buf;
    if (sysctlbyname("hw.product", buf, &len, NULL, 0) != 0 || strcmp(buf, "iPad7,1") != 0) return bad("hw.product", errno, 0);
    int spawned = 1;
    errno = 0;
    if (sysctlbyname("kern.initproc_spawned", NULL, NULL, &spawned, sizeof spawned) != -1 || errno != EPERM) return bad("setting kern.initproc_spawned", errno, EPERM);

    // The A10X's features: crypto, and none of ARMv8.1's atomics.
    w = 7;
    len = sizeof w;
    if (sysctlbyname("hw.optional.arm.FEAT_AES", &w, &len, NULL, 0) != 0 || w != 1) return bad("FEAT_AES", w, 1);
    w = 7;
    len = sizeof w;
    if (sysctlbyname("hw.optional.armv8_1_atomics", &w, &len, NULL, 0) != 0 || w != 0) return bad("armv8_1_atomics", w, 0);

    // AMFI's Developer Mode status: off, as the device has it; read-only.
    w = -1;
    len = sizeof w;
    if (sysctlbyname("security.mac.amfi.developer_mode_status", &w, &len, NULL, 0) != 0 || len != 4 || w != 0) return bad("security.mac.amfi.developer_mode_status", w, 0);
    errno = 0;
    if (sysctlbyname("security.mac.amfi.developer_mode_status", NULL, NULL, &w, sizeof w) != -1 || errno != EPERM) return bad("setting developer_mode_status", errno, EPERM);

    // The name of a node that does not exist.
    errno = 0;
    len = sizeof buf;
    if (sysctlbyname("kern.no_such_node", buf, &len, NULL, 0) != -1 || errno != ENOENT) return bad("a name that does not exist", errno, ENOENT);
    printf("sysctlnodes ok\n");
    return 0;
}
