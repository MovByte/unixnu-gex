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

    // No other display: kIOReturnNoDevice.
    Framebuffer other = NULL;
    if ((kr = get_secondary(&other)) != kIOReturnNoDevice) return bad("IOMobileFramebufferGetSecondaryDisplay", kr, kIOReturnNoDevice);

    printf("iomfbmain ok\n");
    return 0;
}
