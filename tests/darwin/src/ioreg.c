// The registry from its root: the root entry, the device tree hanging from
// it in the IODeviceTree plane (its root named by its first compatible name
// there, and device-tree in the plane, the platform expert device, whose
// parent in the IOService plane is the root too), registry iterators flat,
// recursive and entered by hand, an iterator out of the start, the
// exhausted iterator's kIOReturnNoDevice, and a kernel-only node's
// properties read empty.

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <mach/mach.h>
#include <mach/mig.h>
#include <mach/mig_errors.h>
#include <stdio.h>
#include <string.h>

// io_iterator_next's reply code, its request (msgh_id 2802, no arguments)
// sent by hand as the MIG stubs send a kernel object's calls: an error
// reply carries the code after its NDR record.
extern mach_msg_return_t mach_msg2_internal(void *data, uint64_t option64, uint64_t bits_and_send_size,
    uint64_t remote_and_local_port, uint64_t voucher_and_id, uint64_t desc_count_and_rcv_name,
    uint64_t rcv_size_and_priority, uint64_t timeout);

static kern_return_t io_iterator_next_code(mach_port_t iterator) {
    const uint64_t send_msg = 1, rcv_msg = 2, kobject_call = 0x200000000ull;
    union {
        mach_msg_header_t head;
        mig_reply_error_t error;
        char room[256];
    } m;
    memset(&m, 0, sizeof m);
    mach_port_t reply = mig_get_reply_port();
    uint32_t bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    m.head.msgh_bits = bits;
    m.head.msgh_size = sizeof(mach_msg_header_t);
    m.head.msgh_remote_port = iterator;
    m.head.msgh_local_port = reply;
    m.head.msgh_id = 2802;
    kern_return_t kr = mach_msg2_internal(&m, send_msg | rcv_msg | kobject_call,
        (uint64_t)sizeof(mach_msg_header_t) << 32 | bits, (uint64_t)reply << 32 | iterator,
        (uint64_t)2802 << 32, (uint64_t)reply << 32, sizeof m, 0);
    if (kr != KERN_SUCCESS) return kr;
    if (m.head.msgh_bits & MACH_MSGH_BITS_COMPLEX) return KERN_SUCCESS;
    return m.error.RetCode;
}

static int bad(const char *what, long got, long want) {
    printf("ioreg: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

// The entries below `e` in the device tree plane, by child iterators.
static int count_below(io_registry_entry_t e) {
    io_iterator_t it;
    if (IORegistryEntryGetChildIterator(e, kIODeviceTreePlane, &it) != KERN_SUCCESS) return -1000000;
    int n = 0;
    io_object_t c;
    while ((c = IOIteratorNext(it)) != IO_OBJECT_NULL) {
        n += 1 + count_below(c);
        IOObjectRelease(c);
    }
    IOObjectRelease(it);
    return n;
}

int main(void) {
    mach_port_t main_port = MACH_PORT_NULL;
    if (IOMainPort(MACH_PORT_NULL, &main_port) != KERN_SUCCESS) return bad("the main port", 0, 1);
    io_name_t name, cls;

    io_registry_entry_t root = IORegistryGetRootEntry(main_port);
    if (root == IO_OBJECT_NULL) return bad("the root entry", 0, 1);
    IORegistryEntryGetName(root, name);
    if (strcmp(name, "Root") != 0) return bad("the root's name", 0, 1);
    IOObjectGetClass(root, cls);
    if (strcmp(cls, "IORegistryEntry") != 0) return bad("the root's class", 0, 1);
    if (IOObjectConformsTo(root, "IOService")) return bad("the root an IOService", 1, 0);

    // Flat over the root in the device tree plane: the device tree's root.
    io_iterator_t it;
    kern_return_t kr = IORegistryCreateIterator(main_port, kIODeviceTreePlane, 0, &it);
    if (kr != KERN_SUCCESS) return bad("a registry iterator", kr, 0);
    io_registry_entry_t dt = IOIteratorNext(it);
    if (dt == IO_OBJECT_NULL) return bad("the device tree", 0, 1);
    io_object_t extra = IOIteratorNext(it);
    if (extra != IO_OBJECT_NULL) return bad("the root's one child", 2, 1);
    kr = io_iterator_next_code(it);
    if (kr != (kern_return_t)0xe00002c0) return bad("next past the end", kr, 0xe00002c0);
    IOObjectRelease(it);

    // Its names: the first compatible, and device-tree in its plane.
    CFDataRef compat = IORegistryEntryCreateCFProperty(dt, CFSTR("compatible"), kCFAllocatorDefault, 0);
    if (compat == NULL) return bad("the compatible names", 0, 1);
    IORegistryEntryGetName(dt, name);
    if (strcmp(name, (const char *)CFDataGetBytePtr(compat)) != 0) return bad("the device tree root's name", 0, 1);
    IORegistryEntryGetNameInPlane(dt, kIODeviceTreePlane, name);
    if (strcmp(name, "device-tree") != 0) return bad("its name in the plane", 0, 1);
    if (!IOObjectConformsTo(dt, "IOPlatformExpertDevice")) return bad("its class", 0, 1);

    // The platform expert device by matching is that entry.
    io_service_t pe = IOServiceGetMatchingService(main_port, IOServiceMatching("IOPlatformExpertDevice"));
    if (!IOObjectIsEqualTo(pe, dt)) return bad("the matched platform expert device", 0, 1);
    IOObjectRelease(pe);
    io_registry_entry_t up = IO_OBJECT_NULL;
    if (IORegistryEntryGetParentEntry(dt, kIOServicePlane, &up) != KERN_SUCCESS || !IOObjectIsEqualTo(up, root)) return bad("its IOService parent", 0, 1);
    IOObjectRelease(up);
    if (IORegistryEntryGetParentEntry(dt, kIODeviceTreePlane, &up) != KERN_SUCCESS || !IOObjectIsEqualTo(up, root)) return bad("its IODeviceTree parent", 0, 1);
    IOObjectRelease(up);

    // Recursive from the root: the device tree's root and all below it,
    // and the same again after a reset.
    int below = count_below(dt);
    if (below < 1) return bad("entries below the device tree root", below, 1);
    kr = IORegistryCreateIterator(main_port, kIODeviceTreePlane, kIORegistryIterateRecursively, &it);
    if (kr != KERN_SUCCESS) return bad("a recursive iterator", kr, 0);
    for (int round = 0; round < 2; round++) {
        int n = 0;
        io_object_t o;
        while ((o = IOIteratorNext(it)) != IO_OBJECT_NULL) {
            n++;
            IOObjectRelease(o);
        }
        if (n != below + 1) return bad("entries recursively", n, below + 1);
        IOIteratorReset(it);
    }
    IOObjectRelease(it);

    // By hand from the device tree root: enter the first child, take its
    // children, and come out to its siblings; the start cannot be left.
    kr = IORegistryEntryCreateIterator(dt, kIODeviceTreePlane, 0, &it);
    if (kr != KERN_SUCCESS) return bad("an entry's iterator", kr, 0);
    io_object_t first = IOIteratorNext(it);
    int first_below = 0;
    {
        io_iterator_t ci;
        IORegistryEntryGetChildIterator(first, kIODeviceTreePlane, &ci);
        io_object_t c;
        while ((c = IOIteratorNext(ci)) != IO_OBJECT_NULL) {
            first_below++;
            IOObjectRelease(c);
        }
        IOObjectRelease(ci);
    }
    if (IORegistryIteratorEnterEntry(it) != KERN_SUCCESS) return bad("entering", 0, 1);
    int got = 0;
    io_object_t o;
    while ((o = IOIteratorNext(it)) != IO_OBJECT_NULL) {
        io_registry_entry_t p = IO_OBJECT_NULL;
        IORegistryEntryGetParentEntry(o, kIODeviceTreePlane, &p);
        if (!IOObjectIsEqualTo(p, first)) return bad("a child of the entry entered", 0, 1);
        IOObjectRelease(p);
        IOObjectRelease(o);
        got++;
    }
    if (got != first_below) return bad("children of the entry entered", got, first_below);
    if (IORegistryIteratorExitEntry(it) != KERN_SUCCESS) return bad("exiting", 0, 1);
    int siblings = 0;
    while ((o = IOIteratorNext(it)) != IO_OBJECT_NULL) {
        io_registry_entry_t p = IO_OBJECT_NULL;
        IORegistryEntryGetParentEntry(o, kIODeviceTreePlane, &p);
        if (!IOObjectIsEqualTo(p, dt)) return bad("a sibling after exiting", 0, 1);
        IOObjectRelease(p);
        IOObjectRelease(o);
        siblings++;
    }
    io_iterator_t ci;
    IORegistryEntryGetChildIterator(dt, kIODeviceTreePlane, &ci);
    int kids = 0;
    while ((o = IOIteratorNext(ci)) != IO_OBJECT_NULL) {
        kids++;
        IOObjectRelease(o);
    }
    IOObjectRelease(ci);
    if (siblings + 1 != kids) return bad("siblings after exiting", siblings + 1, kids);
    kr = IORegistryIteratorExitEntry(it);
    if (kr != (kern_return_t)0xe00002c0) return bad("exiting the start", kr, 0xe00002c0);
    IOObjectRelease(first);
    IOObjectRelease(it);

    // Enter and exit are a registry iterator's only.
    kr = IOServiceGetMatchingServices(main_port, IOServiceMatching("IOPlatformExpertDevice"), &it);
    if (kr != KERN_SUCCESS) return bad("a matching iterator", kr, 0);
    kr = IORegistryIteratorEnterEntry(it);
    if (kr != (kern_return_t)0xe00002c2) return bad("entering a matching iterator", kr, 0xe00002c2);
    IOObjectRelease(it);

    // A kernel-only node's properties read empty.
    io_registry_entry_t mm = IORegistryEntryFromPath(main_port, "IODeviceTree:/chosen/memory-map");
    if (mm != IO_OBJECT_NULL) {
        CFDataRef n = IORegistryEntryCreateCFProperty(mm, CFSTR("name"), kCFAllocatorDefault, 0);
        CFDataRef ko = IORegistryEntryCreateCFProperty(mm, CFSTR("kernel-only"), kCFAllocatorDefault, 0);
        if (ko != NULL) {
            if (n == NULL || CFDataGetLength(n) != 0) return bad("a kernel-only node's name", n ? CFDataGetLength(n) : -1, 0);
            CFRelease(ko);
        }
        if (n) CFRelease(n);
        IOObjectRelease(mm);
    }

    CFRelease(compat);
    IOObjectRelease(dt);
    IOObjectRelease(root);
    printf("ioreg ok\n");
    return 0;
}
