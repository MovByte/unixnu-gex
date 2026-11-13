// IOSurface in one task, through IOSurface.framework and the kernel's
// IOSurfaceRoot: the service the framework finds by name, the geometry a
// surface's properties give (rows aligned to 64 bytes, planes and
// allocations to the GPU's 16 KiB pages), its mapping, lock and unlock with
// their seeds, values, bulk attachments, use counts, purgeability, a send
// right to the surface looked up again, the graphics comm page, and the
// errors the kernel answers.
//
// It runs as splashboardd, as launchd starts it (user mobile, no sandbox):
// the platform profile admits IOSurfaceRootUserClient to an unsandboxed
// program by its signing identifier or by an iokit-user-client-class
// entitlement naming the class, as splashboardd's does. With "container",
// it runs as an app does, in the container profile's sandbox, which admits
// the user client but refuses the root's IOMatchCategory
// (iokit-get-properties): there it opens the root, makes a surface, locks
// it, and looks it up.

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <IOSurface/IOSurfaceRef.h>
#include <mach/mach.h>
#include <stdio.h>
#include <string.h>

// The framework's own call, which the SDK does not declare.
extern void *IOSurfaceGetGraphicsCommPageAddress(void);

// IOKitLib's IORegistryEntryGetProperty (io_registry_entry_get_property_bytes),
// which the iOS SDK marks unavailable.
extern kern_return_t registry_entry_get_property(io_registry_entry_t entry, const char *name, char *buffer, uint32_t *size) __asm__("_IORegistryEntryGetProperty");

#define SANDBOX_NAMED_BUILTIN 2

int sandbox_init(const char *profile, uint64_t flags, char **errorbuf);

static int contained;

static int bad(const char *what, long got, long want) {
    printf("iosurface: %s: %#lx, want %#lx\n", what, got, want);
    return 1;
}

static void set_num(CFMutableDictionaryRef d, CFStringRef k, long v) {
    CFNumberRef n = CFNumberCreate(NULL, kCFNumberLongType, &v);
    CFDictionarySetValue(d, k, n);
    CFRelease(n);
}

static IOSurfaceRef bgra(long width, long height, long bpr) {
    CFMutableDictionaryRef d = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    set_num(d, kIOSurfaceWidth, width);
    set_num(d, kIOSurfaceHeight, height);
    set_num(d, kIOSurfaceBytesPerElement, 4);
    set_num(d, kIOSurfacePixelFormat, 'BGRA');
    if (bpr) set_num(d, kIOSurfaceBytesPerRow, bpr);
    IOSurfaceRef s = IOSurfaceCreate(d);
    CFRelease(d);
    return s;
}

// The kernel's service, as the framework finds it.
static int service(void) {
    io_iterator_t it = IO_OBJECT_NULL;
    kern_return_t kr = IOServiceGetMatchingServices(kIOMainPortDefault, IOServiceNameMatching("IOCoreSurfaceRoot"), &it);
    if (kr != KERN_SUCCESS) return bad("matching IOCoreSurfaceRoot", kr, 0);
    io_service_t root = IOIteratorNext(it);
    if (root == IO_OBJECT_NULL || IOIteratorNext(it) != IO_OBJECT_NULL) return bad("one IOCoreSurfaceRoot", root, 1);
    IOObjectRelease(it);
    io_name_t cls;
    if (IOObjectGetClass(root, cls) != KERN_SUCCESS || strcmp(cls, "IOSurfaceRoot") != 0) return bad("the root's class", 0, 1);
    CFTypeRef cat = IORegistryEntryCreateCFProperty(root, CFSTR("IOMatchCategory"), NULL, 0);
    if (contained) {
        // iokit-get-properties refused: no value, and the routine's
        // kIOReturnNotPermitted for its bytes.
        if (cat != NULL) return bad("the root's match category in the container", 1, 0);
        char buf[64];
        uint32_t len = sizeof buf;
        kr = registry_entry_get_property(root, "IOMatchCategory", buf, &len);
        if (kr != kIOReturnNotPermitted) return bad("the bytes of the root's match category in the container", kr, kIOReturnNotPermitted);
    } else {
        if (cat == NULL || !CFEqual(cat, CFSTR("IOSurfaceRoot"))) return bad("the root's match category", 0, 1);
        CFRelease(cat);
    }
    io_connect_t c;
    kr = IOServiceOpen(root, mach_task_self(), 1, &c);
    if (kr != kIOReturnUnsupported) return bad("opening type 1", kr, kIOReturnUnsupported);
    kr = IOServiceOpen(root, mach_task_self(), 0, &c);
    if (kr != KERN_SUCCESS) return bad("opening type 0", kr, 0);
    if (IOObjectGetClass(c, cls) != KERN_SUCCESS || strcmp(cls, "IOSurfaceRootUserClient") != 0) return bad("the client's class", 0, 1);
    if (contained) {
        IOServiceClose(c);
        IOObjectRelease(root);
        return 0;
    }
    // The limits the framework checks at connect (selector 13).
    unsigned char lim[40];
    size_t n = sizeof lim;
    memset(lim, 0xff, sizeof lim);
    kr = IOConnectCallStructMethod(c, 13, NULL, 0, lim, &n);
    if (kr != KERN_SUCCESS || n != 40) return bad("the limits", kr, 0);
    uint32_t off_mask, row_mask;
    uint64_t max_row, max_w, max_h;
    uint16_t version;
    memcpy(&off_mask, lim, 4);
    memcpy(&row_mask, lim + 4, 4);
    memcpy(&max_row, lim + 8, 8);
    memcpy(&max_w, lim + 16, 8);
    memcpy(&max_h, lim + 24, 8);
    memcpy(&version, lim + 0x22, 2);
    if (off_mask != 0x3fff || row_mask != 0x3f) return bad("the alignment masks", off_mask, 0x3fff);
    if (max_row != 0x8000 || max_w != 0x4000 || max_h != 0x4000) return bad("the maxima", (long)max_row, 0x8000);
    if (lim[0x20] != 0 || version != 1) return bad("the version", version, 1);
    // The checks of each selector's counts, and one past them.
    uint64_t in[2] = {0, 0};
    kr = IOConnectCallScalarMethod(c, 14, in, 1, NULL, NULL);
    if (kr != kIOReturnBadArgument) return bad("selector 14 with one scalar", kr, kIOReturnBadArgument);
    kr = IOConnectCallScalarMethod(c, 54, in, 0, NULL, NULL);
    if (kr != kIOReturnBadArgument) return bad("selector 54", kr, kIOReturnBadArgument);
    // A surface the client has no handle for.
    kr = IOConnectCallScalarMethod(c, 14, in, 2, NULL, NULL);
    if (kr != kIOReturnBadArgument) return bad("a use count of no surface", kr, kIOReturnBadArgument);
    IOServiceClose(c);
    IOObjectRelease(root);
    return 0;
}

static int geometry(void) {
    IOSurfaceRef s = bgra(100, 50, 0);
    if (s == NULL) return bad("creating a 100x50 BGRA surface", 0, 1);
    if (IOSurfaceGetWidth(s) != 100 || IOSurfaceGetHeight(s) != 50) return bad("width", IOSurfaceGetWidth(s), 100);
    if (IOSurfaceGetBytesPerElement(s) != 4 || IOSurfaceGetElementWidth(s) != 1 || IOSurfaceGetElementHeight(s) != 1) return bad("bytes per element", IOSurfaceGetBytesPerElement(s), 4);
    // 400 bytes rounded to 64; 22400 rounded to the GPU's 16 KiB page.
    if (IOSurfaceGetBytesPerRow(s) != 448) return bad("bytes per row", IOSurfaceGetBytesPerRow(s), 448);
    if (IOSurfaceGetAllocSize(s) != 32768) return bad("allocation size", IOSurfaceGetAllocSize(s), 32768);
    if (IOSurfaceGetPixelFormat(s) != 'BGRA' || IOSurfaceGetPlaneCount(s) != 0) return bad("pixel format", IOSurfaceGetPixelFormat(s), 'BGRA');
    if (IOSurfaceGetID(s) == 0) return bad("the id", 0, 1);
    // Its memory: mapped into this task, read-write, inherited by no child.
    vm_address_t addr = (vm_address_t)IOSurfaceGetBaseAddress(s);
    vm_size_t size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t obj = MACH_PORT_NULL;
    vm_address_t at = addr;
    kern_return_t kr = vm_region_64(mach_task_self(), &at, &size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count, &obj);
    if (kr != KERN_SUCCESS || at != addr || size != 32768) return bad("the surface's mapping", (long)size, 32768);
    if (info.protection != (VM_PROT_READ | VM_PROT_WRITE) || info.inheritance != VM_INHERIT_NONE) return bad("its protection", info.protection, 3);
    for (size_t i = 0; i < 32768; i++)
        if (((volatile unsigned char *)addr)[i] != 0) return bad("new memory", (long)i, 0);
    CFRelease(s);

    // A row given is taken as it is; a row too small is refused.
    s = bgra(100, 50, 512);
    if (s == NULL || IOSurfaceGetBytesPerRow(s) != 512 || IOSurfaceGetAllocSize(s) != 32768) return bad("a given row", s ? (long)IOSurfaceGetBytesPerRow(s) : 0, 512);
    CFRelease(s);
    if (bgra(100, 50, 396) != NULL) return bad("a row too small", 1, 0);

    // Two planes, as CoreVideo describes 420v: the second plane at the next
    // 16 KiB.
    CFMutableDictionaryRef d = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    set_num(d, kIOSurfaceWidth, 64);
    set_num(d, kIOSurfaceHeight, 64);
    set_num(d, kIOSurfacePixelFormat, '420v');
    CFMutableArrayRef planes = CFArrayCreateMutable(NULL, 2, &kCFTypeArrayCallBacks);
    long dims[2][3] = {{64, 64, 1}, {32, 32, 2}};
    for (int i = 0; i < 2; i++) {
        CFMutableDictionaryRef p = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        set_num(p, kIOSurfacePlaneWidth, dims[i][0]);
        set_num(p, kIOSurfacePlaneHeight, dims[i][1]);
        set_num(p, kIOSurfacePlaneBytesPerElement, dims[i][2]);
        CFArrayAppendValue(planes, p);
        CFRelease(p);
    }
    CFDictionarySetValue(d, kIOSurfacePlaneInfo, planes);
    CFRelease(planes);
    s = IOSurfaceCreate(d);
    CFRelease(d);
    if (s == NULL) return bad("creating a two-plane surface", 0, 1);
    if (IOSurfaceGetPlaneCount(s) != 2) return bad("plane count", IOSurfaceGetPlaneCount(s), 2);
    if (IOSurfaceGetBytesPerRowOfPlane(s, 0) != 64 || IOSurfaceGetBytesPerRowOfPlane(s, 1) != 64) return bad("plane rows", IOSurfaceGetBytesPerRowOfPlane(s, 1), 64);
    if (IOSurfaceGetWidthOfPlane(s, 1) != 32 || IOSurfaceGetHeightOfPlane(s, 1) != 32 || IOSurfaceGetBytesPerElementOfPlane(s, 1) != 2) return bad("plane 1's size", IOSurfaceGetWidthOfPlane(s, 1), 32);
    char *base = IOSurfaceGetBaseAddress(s);
    if ((char *)IOSurfaceGetBaseAddressOfPlane(s, 0) != base || (char *)IOSurfaceGetBaseAddressOfPlane(s, 1) != base + 16384) return bad("plane 1's offset", (char *)IOSurfaceGetBaseAddressOfPlane(s, 1) - base, 16384);
    if (IOSurfaceGetAllocSize(s) != 32768) return bad("the planes' allocation", IOSurfaceGetAllocSize(s), 32768);
    CFRelease(s);
    return 0;
}

static int locks(void) {
    IOSurfaceRef s = bgra(64, 64, 0);
    if (s == NULL) return bad("creating a surface", 0, 1);
    uint32_t seed = 0xdead;
    // A lock that allows writing raises the seed when it is taken.
    if (IOSurfaceGetSeed(s) != 0) return bad("a new surface's seed", IOSurfaceGetSeed(s), 0);
    kern_return_t kr = IOSurfaceLock(s, 0, &seed);
    if (kr != KERN_SUCCESS || seed != 1 || IOSurfaceGetSeed(s) != 1) return bad("the write lock's seed", seed, 1);
    memset(IOSurfaceGetBaseAddress(s), 0x5a, 4096);
    kr = IOSurfaceUnlock(s, 0, &seed);
    if (kr != KERN_SUCCESS || seed != 1) return bad("the unlock's seed", seed, 1);
    // A read-only lock leaves it.
    kr = IOSurfaceLock(s, kIOSurfaceLockReadOnly, &seed);
    if (kr != KERN_SUCCESS || seed != 1) return bad("the read lock's seed", seed, 1);
    if (((unsigned char *)IOSurfaceGetBaseAddress(s))[4095] != 0x5a) return bad("what the write lock wrote", 0, 0x5a);
    kr = IOSurfaceUnlock(s, kIOSurfaceLockReadOnly, &seed);
    if (kr != KERN_SUCCESS) return bad("the read unlock", kr, 0);
    // Unlocking what is not locked.
    kr = IOSurfaceUnlock(s, kIOSurfaceLockReadOnly, NULL);
    if (kr != kIOReturnBadArgument) return bad("a read unlock with none held", kr, kIOReturnBadArgument);
    kr = IOSurfaceUnlock(s, 0, NULL);
    if (kr != kIOReturnBadArgument) return bad("a write unlock with none held", kr, kIOReturnBadArgument);
    // Locks nest, and readers and writers do not exclude each other.
    IOSurfaceLock(s, 0, NULL);
    IOSurfaceLock(s, 0, NULL);
    IOSurfaceLock(s, kIOSurfaceLockReadOnly, &seed);
    if (seed != 3) return bad("two more write locks", seed, 3);
    if (IOSurfaceUnlock(s, 0, NULL) || IOSurfaceUnlock(s, 0, NULL) || IOSurfaceUnlock(s, kIOSurfaceLockReadOnly, NULL)) return bad("their unlocks", 1, 0);
    // A store outside any lock is the surface's all the same.
    ((volatile unsigned char *)IOSurfaceGetBaseAddress(s))[100] = 0x77;
    IOSurfaceLock(s, kIOSurfaceLockReadOnly, NULL);
    if (((unsigned char *)IOSurfaceGetBaseAddress(s))[100] != 0x77) return bad("a store outside a lock", 0, 0x77);
    IOSurfaceUnlock(s, kIOSurfaceLockReadOnly, NULL);
    CFRelease(s);
    return 0;
}

static int values(void) {
    IOSurfaceRef s = bgra(16, 16, 0);
    if (s == NULL) return bad("creating a surface", 0, 1);
    long v = 1234;
    CFNumberRef n = CFNumberCreate(NULL, kCFNumberLongType, &v);
    IOSurfaceSetValue(s, CFSTR("gex.number"), n);
    CFRelease(n);
    IOSurfaceSetValue(s, CFSTR("gex.string"), CFSTR("surface"));
    CFTypeRef got = IOSurfaceCopyValue(s, CFSTR("gex.number"));
    long back = 0;
    if (got == NULL || CFGetTypeID(got) != CFNumberGetTypeID() || !CFNumberGetValue(got, kCFNumberLongType, &back) || back != 1234) return bad("a number value", back, 1234);
    CFRelease(got);
    got = IOSurfaceCopyValue(s, CFSTR("gex.string"));
    if (got == NULL || !CFEqual(got, CFSTR("surface"))) return bad("a string value", 0, 1);
    CFRelease(got);
    // Every value: the creation properties among them.
    CFDictionaryRef all = IOSurfaceCopyAllValues(s);
    if (all == NULL || !CFDictionaryContainsKey(all, CFSTR("gex.number")) || !CFDictionaryContainsKey(all, CFSTR("CreationProperties"))) return bad("all values", 0, 1);
    CFDictionaryRef cp = CFDictionaryGetValue(all, CFSTR("CreationProperties"));
    long w = 0;
    CFNumberRef wn = cp ? CFDictionaryGetValue(cp, kIOSurfaceWidth) : NULL;
    if (wn == NULL || !CFNumberGetValue(wn, kCFNumberLongType, &w) || w != 16) return bad("the creation properties' width", w, 16);
    CFRelease(all);
    IOSurfaceRemoveValue(s, CFSTR("gex.number"));
    got = IOSurfaceCopyValue(s, CFSTR("gex.number"));
    if (got != NULL) return bad("a removed value", 1, 0);
    // A bulk attachment (the framework's key for it, and CoreVideo's value),
    // read from the record the kernel shares.
    IOSurfaceSetValue(s, CFSTR("IOSurfaceYCbCrMatrix"), CFSTR("ITU_R_709_2"));
    got = IOSurfaceCopyValue(s, CFSTR("IOSurfaceYCbCrMatrix"));
    if (got == NULL || !CFEqual(got, CFSTR("ITU_R_709_2"))) return bad("a bulk attachment", 0, 1);
    CFRelease(got);
    CFRelease(s);
    return 0;
}

static int uses(void) {
    IOSurfaceRef s = bgra(16, 16, 0);
    if (s == NULL) return bad("creating a surface", 0, 1);
    if (IOSurfaceIsInUse(s)) return bad("a new surface in use", 1, 0);
    IOSurfaceIncrementUseCount(s);
    IOSurfaceIncrementUseCount(s);
    if (!IOSurfaceIsInUse(s) || IOSurfaceGetUseCount(s) != 2) return bad("two uses", IOSurfaceGetUseCount(s), 2);
    IOSurfaceDecrementUseCount(s);
    IOSurfaceDecrementUseCount(s);
    if (IOSurfaceIsInUse(s) || IOSurfaceGetUseCount(s) != 0) return bad("no uses", IOSurfaceGetUseCount(s), 0);
    // A send right holds a use of its own.
    mach_port_t port = IOSurfaceCreateMachPort(s);
    if (port == MACH_PORT_NULL) return bad("a send right", 0, 1);
    if (!IOSurfaceIsInUse(s)) return bad("in use by its send right", 0, 1);
    // Looked up by it: the same surface (the framework's own client).
    IOSurfaceRef t = IOSurfaceLookupFromMachPort(port);
    if (t == NULL || IOSurfaceGetID(t) != IOSurfaceGetID(s) || IOSurfaceGetBaseAddress(t) != IOSurfaceGetBaseAddress(s)) return bad("the surface by its send right", 0, 1);
    CFRelease(t);
    // By id, from its creator's task.
    t = IOSurfaceLookup(IOSurfaceGetID(s));
    if (t == NULL || IOSurfaceGetID(t) != IOSurfaceGetID(s)) return bad("the surface by id", 0, 1);
    CFRelease(t);
    mach_port_deallocate(mach_task_self(), port);
    if (IOSurfaceIsInUse(s)) return bad("in use after its send right went", 1, 0);
    CFRelease(s);
    return 0;
}

static int purgeable(void) {
    IOSurfaceRef s = bgra(16, 16, 0);
    if (s == NULL) return bad("creating a surface", 0, 1);
    memset(IOSurfaceGetBaseAddress(s), 0x11, 64);
    uint32_t old = 0xff;
    if (IOSurfaceSetPurgeable(s, kIOSurfacePurgeableVolatile, &old) || old != kIOSurfacePurgeableNonVolatile) return bad("volatile from non-volatile", old, 0);
    if (IOSurfaceSetPurgeable(s, kIOSurfacePurgeableKeepCurrent, &old) || old != kIOSurfacePurgeableVolatile) return bad("the current state", old, 1);
    if (IOSurfaceSetPurgeable(s, kIOSurfacePurgeableEmpty, &old) || old != kIOSurfacePurgeableVolatile) return bad("empty from volatile", old, 1);
    if (((unsigned char *)IOSurfaceGetBaseAddress(s))[0] != 0) return bad("emptied memory", ((unsigned char *)IOSurfaceGetBaseAddress(s))[0], 0);
    // What was emptied stays empty.
    if (IOSurfaceSetPurgeable(s, kIOSurfacePurgeableVolatile, &old) || old != kIOSurfacePurgeableEmpty) return bad("volatile from empty", old, 2);
    if (IOSurfaceSetPurgeable(s, kIOSurfacePurgeableNonVolatile, &old) || old != kIOSurfacePurgeableEmpty) return bad("non-volatile from empty", old, 2);
    if (IOSurfaceSetPurgeable(s, kIOSurfacePurgeableNonVolatile, &old) || old != kIOSurfacePurgeableNonVolatile) return bad("non-volatile again", old, 0);
    if (IOSurfaceSetPurgeable(s, 7, &old) != kIOReturnBadArgument) return bad("state 7", 0, 1);
    CFRelease(s);
    return 0;
}

static int comm_page(void) {
    volatile uint32_t *page = IOSurfaceGetGraphicsCommPageAddress();
    if (page == NULL) return bad("the graphics comm page", 0, 1);
    // Tracing is off: IOGPU's word is 0.
    if (page[0] != 0) return bad("the comm page's word", page[0], 0);
    vm_address_t at = (vm_address_t)page;
    vm_size_t size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t obj = MACH_PORT_NULL;
    kern_return_t kr = vm_region_64(mach_task_self(), &at, &size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count, &obj);
    if (kr != KERN_SUCCESS || size != 16384 || info.protection != VM_PROT_READ) return bad("the comm page's mapping", info.protection, VM_PROT_READ);
    return 0;
}

int main(int argc, char **argv) {
    contained = argc > 1 && strcmp(argv[1], "container") == 0;
    if (contained) {
        char *err = NULL;
        if (sandbox_init("container", SANDBOX_NAMED_BUILTIN, &err) != 0) return bad("the container sandbox", 0, 1);
        if (service() || locks() || uses()) return 1;
    } else if (service() || geometry() || locks() || values() || uses() || purgeable() || comm_page()) {
        return 1;
    }
    printf("iosurface ok\n");
    return 0;
}
