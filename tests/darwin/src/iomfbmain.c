// The display as QuartzCore's display server finds it:
// IOMobileFramebufferGetMainDisplay.
//
// - The framework counts arm-io's display pipes in the device tree (its
//   children of device_type display-subsystem or ext-display-subsystem,
//   and paravirtualized graphics), then has a thread of its own (after
//   MediaToolbox's virtual display hook) watch for IOMobileFramebuffer
//   services through an IONotificationPort (IOServiceFirstMatch). The
//   services already registered come back on the notification's iterator,
//   which the thread drains at once; it waits for more on its run loop only
//   while fewer framebuffers than pipes are known.
// - Each framebuffer found is classified by its dfr, AppleTV and external
//   properties: the panel's AppleCLCD has none of them, so it is the
//   primary display, and there is no secondary one.
// - The main display opens like any framebuffer, and its service and size
//   are the panel's.
// - It answers what QuartzCore's display reads first: the color remap mode
//   and the pipe's runtime properties, published or never registered; and
//   the blocks it asks for (types 77, 74 and 72), which the pipe has no
//   handler for (kIOReturnUnsupported), with the selector's own refusals.

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <stdio.h>
#include <string.h>

typedef struct { double w, h; } FbSize;
typedef void *Framebuffer;

static int bad(const char *what, long got, long want) {
    printf("iomfbmain: %s: %#lx, want %#lx\n", what, got, want);
    return 1;
}

int main(void) {
    void *h = dlopen("/System/Library/PrivateFrameworks/IOMobileFramebuffer.framework/IOMobileFramebuffer", RTLD_NOW);
    if (h == NULL) return bad("loading IOMobileFramebuffer.framework", 0, 1);
    kern_return_t (*get_main)(Framebuffer *) = dlsym(h, "IOMobileFramebufferGetMainDisplay");
    kern_return_t (*get_secondary)(Framebuffer *) = dlsym(h, "IOMobileFramebufferGetSecondaryDisplay");
    io_service_t (*service_of)(Framebuffer) = dlsym(h, "IOMobileFramebufferGetServiceObject");
    kern_return_t (*display_size)(Framebuffer, FbSize *) = dlsym(h, "IOMobileFramebufferGetDisplaySize");
    if (!get_main || !get_secondary || !service_of || !display_size) return bad("the framework's functions", 0, 1);

    Framebuffer fb = NULL;
    kern_return_t kr = get_main(&fb);
    if (kr != KERN_SUCCESS || fb == NULL) return bad("IOMobileFramebufferGetMainDisplay", kr, 0);

    // Its service is the panel's AppleCLCD.
    io_service_t clcd = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("AppleCLCD"));
    if (clcd == IO_OBJECT_NULL) return bad("the AppleCLCD", 0, 1);
    io_service_t s = service_of(fb);
    if (s == IO_OBJECT_NULL || !IOObjectIsEqualTo(s, clcd)) return bad("the main display's service", s, clcd);

    // The size is the panel's mode, as the device tree gives it.
    io_registry_entry_t disp0 = IORegistryEntryFromPath(kIOMainPortDefault, "IODeviceTree:/arm-io/disp0");
    CFDataRef timing = disp0 ? IORegistryEntryCreateCFProperty(disp0, CFSTR("display-timing-info"), NULL, 0) : NULL;
    if (timing == NULL || CFDataGetLength(timing) != 32) return bad("disp0's display-timing-info", 0, 1);
    uint32_t words[8];
    CFDataGetBytes(timing, CFRangeMake(0, 32), (UInt8 *)words);
    FbSize size = {0, 0};
    if ((kr = display_size(fb, &size)) != KERN_SUCCESS) return bad("the main display's size", kr, 0);
    if (size.w != (words[0] & 0xffff) || size.h != (words[4] & 0xffff)) return bad("the main display's width", (long)size.w, words[0] & 0xffff);

    // What QuartzCore's display reads as it starts: the color remap mode
    // (the pipe's runtime property BlendOutputCSCMethod, 0, which the
    // framebuffer also publishes), SupportsAOTPowerSaving (false), and
    // neither IOMFBSupportsGPLite nor VRRIdleEnabled, which the pipe never
    // registers.
    kern_return_t (*color_remap)(Framebuffer, uint32_t *) = dlsym(h, "IOMobileFramebufferGetColorRemapMode");
    CFTypeRef (*copy_property)(Framebuffer, CFStringRef) = dlsym(h, "IOMobileFramebufferCopyProperty");
    if (!color_remap || !copy_property) return bad("the framework's property functions", 0, 1);
    uint32_t mode = 9;
    if ((kr = color_remap(fb, &mode)) != KERN_SUCCESS || mode != 0) return bad("the color remap mode", kr ? kr : mode, 0);
    CFTypeRef aot = copy_property(fb, CFSTR("SupportsAOTPowerSaving"));
    if (aot != kCFBooleanFalse) return bad("SupportsAOTPowerSaving", (long)aot, (long)kCFBooleanFalse);
    CFNumberRef csc = copy_property(fb, CFSTR("BlendOutputCSCMethod"));
    int csc_value = -1;
    if (csc == NULL || CFGetTypeID(csc) != CFNumberGetTypeID() || !CFNumberGetValue(csc, kCFNumberIntType, &csc_value) || csc_value != 0) return bad("BlendOutputCSCMethod", csc_value, 0);
    if (copy_property(fb, CFSTR("IOMFBSupportsGPLite")) != NULL) return bad("IOMFBSupportsGPLite", 1, 0);
    if (IORegistryEntryCreateCFProperty(s, CFSTR("VRRIdleEnabled"), NULL, 0) != NULL) return bad("VRRIdleEnabled", 1, 0);

    // QuartzCore's blocks: 77 (0x62c bytes), 74 (0x808) and 72 (0xc5c), none
    // of which the pipe registers a handler for.
    kern_return_t (*get_block)(Framebuffer, uint32_t, void *, uint32_t, const uint32_t *, uint32_t) = dlsym(h, "IOMobileFramebufferGetBlock");
    if (!get_block) return bad("IOMobileFramebufferGetBlock", 0, 1);
    static uint8_t block[0xc5c];
    if ((kr = get_block(fb, 0x4d, block, 0x62c, NULL, 0)) != kIOReturnUnsupported) return bad("GetBlock 77", kr, kIOReturnUnsupported);
    if ((kr = get_block(fb, 0x4a, block, 0x808, NULL, 0)) != kIOReturnUnsupported) return bad("GetBlock 74", kr, kIOReturnUnsupported);
    if ((kr = get_block(fb, 0x48, block, 0xc5c, NULL, 0)) != kIOReturnUnsupported) return bad("GetBlock 72", kr, kIOReturnUnsupported);
    // The selector itself: fewer than two scalars, or a second one whose low
    // word is not zero, is kIOReturnBadArgument.
    io_connect_t c = IO_OBJECT_NULL;
    if ((kr = IOServiceOpen(clcd, mach_task_self(), 0, &c)) != KERN_SUCCESS) return bad("IOServiceOpen", kr, 0);
    uint64_t sc[2] = {0x4d, 0};
    size_t outsz = 0x62c;
    if ((kr = IOConnectCallMethod(c, 79, sc, 1, NULL, 0, NULL, NULL, block, &outsz)) != kIOReturnBadArgument) return bad("GetBlock with one scalar", kr, kIOReturnBadArgument);
    sc[1] = 1;
    outsz = 0x62c;
    if ((kr = IOConnectCallMethod(c, 79, sc, 2, NULL, 0, NULL, NULL, block, &outsz)) != kIOReturnBadArgument) return bad("GetBlock with a second scalar", kr, kIOReturnBadArgument);
    sc[1] = 1ull << 32;
    outsz = 0x62c;
    if ((kr = IOConnectCallMethod(c, 79, sc, 2, NULL, 0, NULL, NULL, block, &outsz)) != kIOReturnUnsupported) return bad("GetBlock with a second scalar's high word", kr, kIOReturnUnsupported);
    IOServiceClose(c);

    // No other display: kIOReturnNoDevice.
    Framebuffer other = NULL;
    if ((kr = get_secondary(&other)) != kIOReturnNoDevice) return bad("IOMobileFramebufferGetSecondaryDisplay", kr, kIOReturnNoDevice);

    printf("iomfbmain ok\n");
    return 0;
}
