// IOSurface across tasks: a surface made by this task and named to a child
// it spawns by a send right (one of the child's registered ports). The
// child finds it by the right but not by its id (a surface is found by id
// only in its creator's task, global lookups being off), sees what this
// task wrote under a lock, its seed, its use count and its values, writes
// under its own lock and once outside any lock, and this task sees both
// writes when it next locks the surface, the seed the child's lock raised,
// and the child's value.

#include <CoreFoundation/CoreFoundation.h>
#include <IOSurface/IOSurfaceRef.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

extern int posix_spawnattr_set_registered_ports_np(posix_spawnattr_t *, mach_port_t[], uint32_t);
extern char **environ;

typedef struct {
    mach_msg_header_t h;
    mach_msg_trailer_t t;
} rcv_t;

static int bad(const char *who, const char *what, long got, long want) {
    printf("iosurfacex: %s: %s: %#lx, want %#lx\n", who, what, got, want);
    return 1;
}

static int bytes_are(const unsigned char *p, size_t n, unsigned char v) {
    for (size_t i = 0; i < n; i++)
        if (p[i] != v) return 0;
    return 1;
}

static int child(IOSurfaceID id) {
    mach_port_array_t ports;
    mach_msg_type_number_t n;
    kern_return_t kr;
    if ((kr = mach_ports_lookup(mach_task_self(), &ports, &n)) || n < 2 || !MACH_PORT_VALID(ports[0]) || !MACH_PORT_VALID(ports[1])) return bad("child", "its registered ports", kr ? kr : n, 3);
    // Not by its id: this task did not create it.
    IOSurfaceRef by_id = IOSurfaceLookup(id);
    if (by_id != NULL) return bad("child", "the surface by id", 1, 0);
    IOSurfaceRef s = IOSurfaceLookupFromMachPort(ports[0]);
    if (s == NULL) return bad("child", "the surface by its send right", 0, 1);
    if (IOSurfaceGetID(s) != id || IOSurfaceGetWidth(s) != 64 || IOSurfaceGetHeight(s) != 64 || IOSurfaceGetBytesPerRow(s) != 256 || IOSurfaceGetAllocSize(s) != 16384) return bad("child", "its description", IOSurfaceGetID(s), id);
    // What the kernel's shared record says, mapped into this task too.
    if (!IOSurfaceIsInUse(s)) return bad("child", "the parent's use", 0, 1);
    if (IOSurfaceGetSeed(s) != 1) return bad("child", "the seed", IOSurfaceGetSeed(s), 1);
    CFTypeRef v = IOSurfaceCopyValue(s, CFSTR("gex.parent"));
    if (v == NULL || !CFEqual(v, CFSTR("hello"))) return bad("child", "the parent's value", 0, 1);
    CFRelease(v);
    uint32_t seed = 0;
    unsigned char *base = IOSurfaceGetBaseAddress(s);
    if ((kr = IOSurfaceLock(s, kIOSurfaceLockReadOnly, &seed)) || seed != 1) return bad("child", "the read lock's seed", kr ? kr : seed, 1);
    if (!bytes_are(base, 4096, 0x5a) || !bytes_are(base + 4096, 4096, 0)) return bad("child", "what the parent wrote", base[0], 0x5a);
    IOSurfaceUnlock(s, kIOSurfaceLockReadOnly, NULL);
    if ((kr = IOSurfaceLock(s, 0, &seed)) || seed != 2) return bad("child", "the write lock's seed", kr ? kr : seed, 2);
    memset(base + 8192, 0xc3, 100);
    IOSurfaceUnlock(s, 0, NULL);
    // Outside any lock.
    ((volatile unsigned char *)base)[12000] = 0x99;
    IOSurfaceSetValue(s, CFSTR("gex.child"), CFSTR("yes"));
    // Tell the parent, and stay until it has looked.
    struct {
        mach_msg_header_t h;
    } m = {{.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE), .msgh_size = sizeof m, .msgh_remote_port = ports[1], .msgh_id = 1}};
    mach_port_t reply;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &reply);
    m.h.msgh_local_port = reply;
    if ((kr = mach_msg(&m.h, MACH_SEND_MSG, sizeof m, 0, MACH_PORT_NULL, 0, MACH_PORT_NULL))) return bad("child", "telling the parent", kr, 0);
    rcv_t r;
    if ((kr = mach_msg(&r.h, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof r, reply, 60000, MACH_PORT_NULL)) || r.h.msgh_id != 2) return bad("child", "the parent's answer", kr ? kr : r.h.msgh_id, 2);
    CFRelease(s);
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 2) return child((IOSurfaceID)strtoul(argv[2], NULL, 0));
    CFMutableDictionaryRef d = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    long w = 64, bpe = 4, fmt = 'BGRA';
    CFNumberRef nw = CFNumberCreate(NULL, kCFNumberLongType, &w), nb = CFNumberCreate(NULL, kCFNumberLongType, &bpe), nf = CFNumberCreate(NULL, kCFNumberLongType, &fmt);
    CFDictionarySetValue(d, kIOSurfaceWidth, nw);
    CFDictionarySetValue(d, kIOSurfaceHeight, nw);
    CFDictionarySetValue(d, kIOSurfaceBytesPerElement, nb);
    CFDictionarySetValue(d, kIOSurfacePixelFormat, nf);
    IOSurfaceRef s = IOSurfaceCreate(d);
    if (s == NULL) return bad("parent", "creating the surface", 0, 1);
    uint32_t seed = 0;
    unsigned char *base = IOSurfaceGetBaseAddress(s);
    IOSurfaceLock(s, 0, &seed);
    memset(base, 0x5a, 4096);
    IOSurfaceUnlock(s, 0, NULL);
    IOSurfaceIncrementUseCount(s);
    IOSurfaceSetValue(s, CFSTR("gex.parent"), CFSTR("hello"));

    // The child, with a send right to the surface (which holds a use of
    // its own) and one to a port of this task's.
    mach_port_t port = IOSurfaceCreateMachPort(s), back;
    if (port == MACH_PORT_NULL) return bad("parent", "the surface's send right", 0, 1);
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &back);
    mach_port_insert_right(mach_task_self(), back, back, MACH_MSG_TYPE_MAKE_SEND);
    char self[PATH_MAX], idarg[16];
    uint32_t len = sizeof self;
    _NSGetExecutablePath(self, &len);
    snprintf(idarg, sizeof idarg, "%u", IOSurfaceGetID(s));
    char *args[] = {self, "child", idarg, NULL};
    posix_spawnattr_t at;
    posix_spawnattr_init(&at);
    mach_port_t reg[2] = {port, back};
    posix_spawnattr_set_registered_ports_np(&at, reg, 2);
    pid_t pid;
    int e;
    if ((e = posix_spawn(&pid, self, NULL, &at, args, environ))) return bad("parent", "spawning", e, 0);
    posix_spawnattr_destroy(&at);
    rcv_t m;
    kern_return_t kr = mach_msg(&m.h, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof m, back, 120000, MACH_PORT_NULL);
    int fail = 0;
    if (kr || m.h.msgh_id != 1) {
        fail = bad("parent", "the child's message", kr ? kr : m.h.msgh_id, 1);
    } else {
        // The child's writes, under its lock and outside one, and the seed
        // its lock raised.
        if ((kr = IOSurfaceLock(s, kIOSurfaceLockReadOnly, &seed)) || seed != 2) fail = bad("parent", "the seed after the child's lock", kr ? kr : seed, 2);
        else if (!bytes_are(base + 8192, 100, 0xc3)) fail = bad("parent", "the child's locked write", base[8192], 0xc3);
        else if (base[12000] != 0x99) fail = bad("parent", "the child's write outside a lock", base[12000], 0x99);
        else if (!bytes_are(base, 4096, 0x5a)) fail = bad("parent", "its own write", base[0], 0x5a);
        IOSurfaceUnlock(s, kIOSurfaceLockReadOnly, NULL);
        CFTypeRef v = IOSurfaceCopyValue(s, CFSTR("gex.child"));
        if (!fail && (v == NULL || !CFEqual(v, CFSTR("yes")))) fail = bad("parent", "the child's value", 0, 1);
        if (v) CFRelease(v);
        mach_msg_header_t a = {.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0), .msgh_size = sizeof a, .msgh_remote_port = m.h.msgh_remote_port, .msgh_id = 2};
        mach_msg(&a, MACH_SEND_MSG, sizeof a, 0, MACH_PORT_NULL, 0, MACH_PORT_NULL);
    }
    int st;
    if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st) || WEXITSTATUS(st)) return fail ? fail : bad("parent", "the child's status", st, 0);
    if (fail) return fail;
    // The child's handles went with it; the surface is this task's still.
    IOSurfaceDecrementUseCount(s);
    mach_port_deallocate(mach_task_self(), port);
    if (IOSurfaceIsInUse(s)) return bad("parent", "in use after the child and the right", 1, 0);
    CFRelease(s);
    printf("iosurfacex ok\n");
    return 0;
}
