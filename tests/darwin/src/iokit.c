// IOKit from a task: the main port, the device tree's entries and their
// properties, a path that does not exist, the APFS volumes as services
// with their roles and the container above them (an iterator over them
// reset to its first), and a matching
// notification: the volumes already there, the last first, then none; a
// termination notification has none, and an unknown kind is refused.

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <stdio.h>
#include <string.h>

static int bad(const char *what, long got, long want) {
    printf("iokit: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

static void notified(void *ref, io_iterator_t it) {
}

// The registry ids an iterator gives, up to 64.
static int ids(io_iterator_t it, uint64_t *out) {
    int n = 0;
    io_object_t o;
    while ((o = IOIteratorNext(it)) != IO_OBJECT_NULL) {
        if (n < 64) IORegistryEntryGetRegistryEntryID(o, &out[n++]);
        IOObjectRelease(o);
    }
    return n;
}

int main(void) {
    mach_port_t main_port = MACH_PORT_NULL;
    if (IOMainPort(MACH_PORT_NULL, &main_port) != KERN_SUCCESS || main_port == MACH_PORT_NULL) return bad("the main port", 0, 1);

    io_registry_entry_t chosen = IORegistryEntryFromPath(main_port, "IODeviceTree:/chosen");
    if (chosen == IO_OBJECT_NULL) return bad("IODeviceTree:/chosen", 0, 1);
    CFTypeRef type = IORegistryEntryCreateCFProperty(chosen, CFSTR("boot-type"), kCFAllocatorDefault, 0);
    if (type == NULL || CFGetTypeID(type) != CFDataGetTypeID()) return bad("boot-type", 0, 1);
    if (CFDataGetLength(type) != 12 || memcmp(CFDataGetBytePtr(type), "local", 6) != 0) return bad("boot-type's bytes", CFDataGetLength(type), 12);
    CFRelease(type);
    if (IORegistryEntryCreateCFProperty(chosen, CFSTR("no-such-property"), kCFAllocatorDefault, 0) != NULL) return bad("a property that does not exist", 1, 0);
    IOObjectRelease(chosen);
    if (IORegistryEntryFromPath(main_port, "IODeviceTree:/no-such-node") != IO_OBJECT_NULL) return bad("a path that does not exist", 1, 0);

    io_iterator_t it = IO_OBJECT_NULL;
    kern_return_t kr = IOServiceGetMatchingServices(main_port, IOServiceMatching("AppleAPFSVolume"), &it);
    if (kr != KERN_SUCCESS || it == IO_OBJECT_NULL) return bad("matching the volumes", kr, 0);
    int volumes = 0, system = 0;
    io_object_t v;
    while ((v = IOIteratorNext(it)) != IO_OBJECT_NULL) {
        volumes++;
        CFTypeRef role = IORegistryEntryCreateCFProperty(v, CFSTR("Role"), kCFAllocatorDefault, 0);
        if (role == NULL || CFGetTypeID(role) != CFArrayGetTypeID() || CFArrayGetCount(role) != 1) return bad("a volume's Role", 0, 1);
        CFStringRef name = CFArrayGetValueAtIndex(role, 0);
        if (CFStringCompare(name, CFSTR("System"), 0) == kCFCompareEqualTo) {
            system++;
            io_registry_entry_t scheme = IO_OBJECT_NULL, media = IO_OBJECT_NULL;
            if (IORegistryEntryGetParentEntry(v, kIOServicePlane, &scheme) != KERN_SUCCESS) return bad("the volume's scheme", 0, 1);
            if (IORegistryEntryGetParentEntry(scheme, kIOServicePlane, &media) != KERN_SUCCESS) return bad("the scheme's media", 0, 1);
            CFTypeRef bsd = IORegistryEntryCreateCFProperty(media, CFSTR("BSD Name"), kCFAllocatorDefault, 0);
            if (bsd == NULL || CFGetTypeID(bsd) != CFStringGetTypeID() || CFStringCompare(bsd, CFSTR("disk1"), 0) != kCFCompareEqualTo) return bad("the container's BSD name", 0, 1);
            CFRelease(bsd);
        }
        CFRelease(role);
        IOObjectRelease(v);
    }
    // Reset: the same volumes again, from the first; still valid.
    if (!IOIteratorIsValid(it)) return bad("the iterator valid", 0, 1);
    IOIteratorReset(it);
    int again = 0;
    while ((v = IOIteratorNext(it)) != IO_OBJECT_NULL) {
        again++;
        IOObjectRelease(v);
    }
    if (again != volumes) return bad("volumes after a reset", again, volumes);
    IOObjectRelease(it);
    if (volumes != 6) return bad("volumes", volumes, 6);
    if (system != 1) return bad("system volumes", system, 1);

    uint64_t a[64], b[64];
    IOServiceGetMatchingServices(main_port, IOServiceMatching("AppleAPFSVolume"), &it);
    int na = ids(it, a);
    IOObjectRelease(it);
    IONotificationPortRef np = IONotificationPortCreate(main_port);
    if (np == NULL) return bad("a notification port", 0, 1);
    io_iterator_t ni = IO_OBJECT_NULL;
    kr = IOServiceAddMatchingNotification(np, kIOFirstMatchNotification, IOServiceMatching("AppleAPFSVolume"), notified, NULL, &ni);
    if (kr != KERN_SUCCESS || ni == IO_OBJECT_NULL) return bad("a matching notification", kr, 0);
    int nb = ids(ni, b);
    if (nb != na) return bad("services notified", nb, na);
    for (int i = 0; i < na; i++) {
        if (b[i] != a[na - 1 - i]) return bad("notified the last first", i, 0);
    }
    if (!IOIteratorIsValid(ni)) return bad("the notification valid", 0, 1);
    IOIteratorReset(ni);
    if (IOIteratorNext(ni) != IO_OBJECT_NULL) return bad("nothing after a reset", 1, 0);
    io_iterator_t ti = IO_OBJECT_NULL;
    kr = IOServiceAddMatchingNotification(np, kIOTerminatedNotification, IOServiceMatching("AppleAPFSVolume"), notified, NULL, &ti);
    if (kr != KERN_SUCCESS || IOIteratorNext(ti) != IO_OBJECT_NULL) return bad("a termination notification", kr, 0);
    io_iterator_t bi = IO_OBJECT_NULL;
    kr = IOServiceAddMatchingNotification(np, "IOServiceNoSuchKind", IOServiceMatching("AppleAPFSVolume"), notified, NULL, &bi);
    if (kr != (kern_return_t)0xe00002c7) return bad("an unknown kind", kr, 0xe00002c7);
    IOObjectRelease(ti);
    IOObjectRelease(ni);
    IONotificationPortDestroy(np);

    printf("iokit ok\n");
    return 0;
}
