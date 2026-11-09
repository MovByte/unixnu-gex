// IOKit from a task: the main port, the device tree's entries and their
// properties, a path that does not exist, and the APFS volumes as services
// with their roles and the container above them.

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <stdio.h>
#include <string.h>

static int bad(const char *what, long got, long want) {
    printf("iokit: %s: %ld, want %ld\n", what, got, want);
    return 1;
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
    IOObjectRelease(it);
    if (volumes != 6) return bad("volumes", volumes, 6);
    if (system != 1) return bad("system volumes", system, 1);

    printf("iokit ok\n");
    return 0;
}
