// The display's framebuffer as QuartzCore's display server reaches it, and
// a swap of a filled IOSurface.
//
// - The service: AppleCLCD, an IOMobileFramebuffer, on disp0's nub, opened
//   through IOMobileFramebuffer.framework (IOMobileFramebufferOpen reads
//   the nub's canvas size and the service's gain map version, neither of
//   which the device has).
// - The panel's size is the mode the device tree's display-timing-info
//   gives (its first and fifth words).
// - A surface of the panel's size, filled with a pattern, swapped onto
//   layer 0 and waited for until it is on the glass. The test embedder
//   records the frame; run.sh checks its bytes and geometry
//   (frame-check.py).
// - On a connection of its own, the user client's refusals: the selector
//   range, the dispatch counts, reserved and empty entries, unknown swaps,
//   a source rectangle outside its surface, the debug flags a production
//   device refuses, the notification types, and memory of no type.

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <IOSurface/IOSurfaceRef.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <stdio.h>
#include <string.h>

typedef struct { double x, y, w, h; } FbRect;
typedef struct { double w, h; } FbSize;
typedef void *Framebuffer;

static int bad(const char *what, long got, long want) {
    printf("iomfb: %s: %#lx, want %#lx\n", what, got, want);
    return 1;
}

// The pattern run.sh's checker expects: blue, green and red from the
// pixel's place, opaque.
static void fill(uint8_t *base, size_t bpr, uint32_t w, uint32_t h) {
    for (uint32_t y = 0; y < h; y++) {
        uint8_t *row = base + y * bpr;
        for (uint32_t x = 0; x < w; x++) {
            row[4 * x + 0] = (uint8_t)(x * 7 + y);
            row[4 * x + 1] = (uint8_t)(y * 3);
            row[4 * x + 2] = (uint8_t)(x ^ y);
            row[4 * x + 3] = 0xff;
        }
    }
}

static CFNumberRef num(int v) {
    return CFNumberCreate(NULL, kCFNumberIntType, &v);
}

// The transaction swap_submit reads (1288 bytes): the swap id at 0x98,
// layer 0's surface at 0x9c, source and destination at 0xac and 0x10c,
// the enabled layers at 0x14c.
static kern_return_t submit(io_connect_t c, uint32_t id, uint32_t surface, int sx, int sy, int sw, int sh) {
    uint8_t rec[1288];
    memset(rec, 0, sizeof rec);
    int32_t src[4] = {sx, sy, sw, sh};
    memcpy(rec + 0x98, &id, 4);
    memcpy(rec + 0x9c, &surface, 4);
    memcpy(rec + 0xac, src, 16);
    memcpy(rec + 0x10c, src, 16);
    uint32_t enabled = 1;
    memcpy(rec + 0x14c, &enabled, 4);
    return IOConnectCallStructMethod(c, 5, rec, sizeof rec, NULL, NULL);
}

int main(void) {
    io_service_t clcd = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("AppleCLCD"));
    if (clcd == IO_OBJECT_NULL) return bad("the AppleCLCD", 0, 1);
    io_name_t cls;
    if (IOObjectGetClass(clcd, cls) != KERN_SUCCESS || strcmp(cls, "AppleCLCD") != 0) return bad("its class", 0, 1);
    if (!IOObjectConformsTo(clcd, "IOMobileFramebuffer") || !IOObjectConformsTo(clcd, "UnifiedPipeline")) return bad("its superclasses", 0, 1);
    io_registry_entry_t nub = IO_OBJECT_NULL;
    if (IORegistryEntryGetParentEntry(clcd, kIOServicePlane, &nub) != KERN_SUCCESS) return bad("its provider", 0, 1);
    if (IOObjectGetClass(nub, cls) != KERN_SUCCESS || strcmp(cls, "AppleARMIODevice") != 0) return bad("its provider's class", 0, 1);

    // The mode the device tree gives.
    io_registry_entry_t disp0 = IORegistryEntryFromPath(kIOMainPortDefault, "IODeviceTree:/arm-io/disp0");
    CFDataRef timing = disp0 ? IORegistryEntryCreateCFProperty(disp0, CFSTR("display-timing-info"), NULL, 0) : NULL;
    if (timing == NULL || CFDataGetLength(timing) != 32) return bad("disp0's display-timing-info", 0, 1);
    uint32_t words[8];
    CFDataGetBytes(timing, CFRangeMake(0, 32), (UInt8 *)words);
    uint32_t pw = words[0] & 0xffff, ph = words[4] & 0xffff;

    void *h = dlopen("/System/Library/PrivateFrameworks/IOMobileFramebuffer.framework/IOMobileFramebuffer", RTLD_NOW);
    if (h == NULL) return bad("loading IOMobileFramebuffer.framework", 0, 1);
    kern_return_t (*fb_open)(io_service_t, task_port_t, uint32_t, Framebuffer *) = dlsym(h, "IOMobileFramebufferOpen");
    kern_return_t (*display_size)(Framebuffer, FbSize *) = dlsym(h, "IOMobileFramebufferGetDisplaySize");
    kern_return_t (*swap_begin)(Framebuffer, int *) = dlsym(h, "IOMobileFramebufferSwapBegin");
    kern_return_t (*swap_set_layer)(Framebuffer, int, IOSurfaceRef, FbRect, FbRect, int) = dlsym(h, "IOMobileFramebufferSwapSetLayer");
    kern_return_t (*swap_end)(Framebuffer) = dlsym(h, "IOMobileFramebufferSwapEnd");
    kern_return_t (*swap_wait)(Framebuffer, int, int) = dlsym(h, "IOMobileFramebufferSwapWait");
    if (!fb_open || !display_size || !swap_begin || !swap_set_layer || !swap_end || !swap_wait) return bad("the framework's functions", 0, 1);

    Framebuffer fb = NULL;
    kern_return_t kr = fb_open(clcd, mach_task_self(), 0, &fb);
    if (kr != KERN_SUCCESS || fb == NULL) return bad("IOMobileFramebufferOpen", kr, 0);
    FbSize size = {0, 0};
    kr = display_size(fb, &size);
    if (kr != KERN_SUCCESS || size.w != pw || size.h != ph) return bad("the display size", (long)size.w << 16 | (long)size.h, (long)pw << 16 | ph);

    // A surface of the panel's size, filled.
    int bpe = 4, fmt = 'BGRA';
    const void *keys[] = {kIOSurfaceWidth, kIOSurfaceHeight, kIOSurfaceBytesPerElement, kIOSurfacePixelFormat};
    const void *vals[] = {num((int)pw), num((int)ph), num(bpe), num(fmt)};
    CFDictionaryRef props = CFDictionaryCreate(NULL, keys, vals, 4, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    IOSurfaceRef s = IOSurfaceCreate(props);
    if (s == NULL) return bad("IOSurfaceCreate", 0, 1);
    if (IOSurfaceLock(s, 0, NULL) != KERN_SUCCESS) return bad("locking the surface", 0, 1);
    fill(IOSurfaceGetBaseAddress(s), IOSurfaceGetBytesPerRow(s), pw, ph);
    if (IOSurfaceUnlock(s, 0, NULL) != KERN_SUCCESS) return bad("unlocking the surface", 0, 1);

    // The swap: begun, layer 0 the whole surface onto the whole panel,
    // ended, and waited for until it is displayed (option 1).
    int token = 0;
    kr = swap_begin(fb, &token);
    if (kr != KERN_SUCCESS || token != 1) return bad("SwapBegin's first swap id", token, 1);
    FbRect whole = {0, 0, pw, ph};
    kr = swap_set_layer(fb, 0, s, whole, whole, 0);
    if (kr != KERN_SUCCESS) return bad("SwapSetLayer", kr, 0);
    kr = swap_end(fb);
    if (kr != KERN_SUCCESS) return bad("SwapEnd", kr, 0);
    kr = swap_wait(fb, token, 1);
    if (kr != KERN_SUCCESS) return bad("SwapWait until displayed", kr, 0);
    // Displayed now: waiting until it is no longer pending or queued again
    // returns at once, and so does a wait for an idle queue.
    if ((kr = swap_wait(fb, token, 1)) != KERN_SUCCESS) return bad("SwapWait of a displayed swap", kr, 0);
    if ((kr = swap_wait(fb, token, 2)) != KERN_SUCCESS) return bad("SwapWait for an idle queue", kr, 0);
    // Options 3 and 4 ask whether the display is enabled; bit 31 never
    // waits (kIOReturnBusy where it would: the displayed swap stays until
    // another replaces it).
    if ((kr = swap_wait(fb, token, 3)) != KERN_SUCCESS) return bad("SwapWait option 3", kr, 0);
    if ((kr = swap_wait(fb, token, 4)) != kIOReturnBadArgument) return bad("SwapWait option 4", kr, kIOReturnBadArgument);
    if ((kr = swap_wait(fb, token, 0x80000000)) != kIOReturnBusy) return bad("a SwapWait that would wait, not blocking", kr, kIOReturnBusy);

    // A connection of its own for the user client's refusals.
    io_connect_t c = IO_OBJECT_NULL;
    if ((kr = IOServiceOpen(clcd, mach_task_self(), 7, &c)) != KERN_SUCCESS) return bad("IOServiceOpen of any type", kr, 0);
    uint64_t in[4] = {0, 0, 0, 0}, out[2] = {0, 0};
    uint32_t outn = 1;
    if ((kr = IOConnectCallScalarMethod(c, 90, NULL, 0, NULL, NULL)) != (kern_return_t)0xe0000001) return bad("selector 90", kr, 0xe0000001);
    if ((kr = IOConnectCallScalarMethod(c, 6, in, 2, NULL, NULL)) != kIOReturnBadArgument) return bad("selector 6 with two scalars", kr, kIOReturnBadArgument);
    uint8_t shortrec[1287] = {0};
    if ((kr = IOConnectCallStructMethod(c, 5, shortrec, sizeof shortrec, NULL, NULL)) != kIOReturnBadArgument) return bad("selector 5 of 1287 bytes", kr, kIOReturnBadArgument);
    if ((kr = IOConnectCallScalarMethod(c, 1, NULL, 0, NULL, NULL)) != kIOReturnUnsupported) return bad("reserved selector 1", kr, kIOReturnUnsupported);
    if ((kr = IOConnectCallScalarMethod(c, 59, NULL, 0, NULL, NULL)) != (kern_return_t)0xe00002ea) return bad("selector 59, no method", kr, 0xe00002ea);
    // An unknown swap: lost by swap_submit (kIOReturnError); cancelled,
    // unknown (kIOReturnBadArgument).
    if ((kr = submit(c, 0x1234, 0, 0, 0, 0, 0)) != kIOReturnError) return bad("submitting an unknown swap", kr, kIOReturnError);
    in[0] = 0x1234;
    if ((kr = IOConnectCallScalarMethod(c, 52, in, 1, NULL, NULL)) != kIOReturnBadArgument) return bad("cancelling an unknown swap", kr, kIOReturnBadArgument);
    // A source rectangle outside its surface: kIOReturnBadArgument, the
    // swap left begun and handed over; submitting it again is lost, and it
    // cancels.
    outn = 1;
    if ((kr = IOConnectCallScalarMethod(c, 4, NULL, 0, out, &outn)) != KERN_SUCCESS || out[0] != 2) return bad("the second swap id", out[0], 2);
    uint32_t sid = IOSurfaceGetID(s), id2 = (uint32_t)out[0];
    if ((kr = submit(c, id2, sid, 1, 0, (int)pw, (int)ph)) != kIOReturnBadArgument) return bad("a source rectangle past its surface", kr, kIOReturnBadArgument);
    if ((kr = submit(c, id2, sid, 0, 0, (int)pw, (int)ph)) != kIOReturnError) return bad("submitting a swap twice", kr, kIOReturnError);
    in[0] = id2;
    if ((kr = IOConnectCallScalarMethod(c, 52, in, 1, NULL, NULL)) != KERN_SUCCESS) return bad("cancelling the refused swap", kr, 0);
    // A surface that does not exist: kIOReturnBadArgument.
    outn = 1;
    if ((kr = IOConnectCallScalarMethod(c, 4, NULL, 0, out, &outn)) != KERN_SUCCESS || out[0] != 3) return bad("the third swap id", out[0], 3);
    if ((kr = submit(c, (uint32_t)out[0], 0xfff0, 0, 0, 32, 32)) != kIOReturnBadArgument) return bad("a layer of no surface", kr, kIOReturnBadArgument);
    in[0] = 0;
    in[1] = 0;
    if ((kr = IOConnectCallScalarMethod(c, 81, in, 2, NULL, NULL)) != KERN_SUCCESS) return bad("SwapCancelAll", kr, 0);
    // The debug flags: refused without the debugger, and an error's reply
    // carries no output.
    out[0] = 5;
    outn = 1;
    if ((kr = IOConnectCallScalarMethod(c, 15, in, 2, out, &outn)) != kIOReturnError) return bad("SetDebugFlags", kr, kIOReturnError);
    if (out[0] != 5) return bad("SetDebugFlags' output", out[0], 5);
    outn = 1;
    if ((kr = IOConnectCallScalarMethod(c, 18, NULL, 0, out, &outn)) != KERN_SUCCESS || out[0] != 1) return bad("IsMainDisplay", out[0], 1);
    outn = 1;
    if ((kr = IOConnectCallScalarMethod(c, 7, NULL, 0, out, &outn)) != KERN_SUCCESS || out[0] != 0xffffffff) return bad("GetID", out[0], 0xffffffff);
    outn = 2;
    if ((kr = IOConnectCallScalarMethod(c, 8, NULL, 0, out, &outn)) != KERN_SUCCESS || out[0] != pw || out[1] != ph) return bad("GetDisplaySize", out[0], pw);
    // Notifications: a type past the six (kIOReturnBadArgument) for the
    // selector and for the port; a port registered twice.
    in[0] = 1;
    in[1] = 2;
    in[2] = 6;
    in[3] = 0;
    if ((kr = IOConnectCallScalarMethod(c, 72, in, 4, NULL, NULL)) != kIOReturnBadArgument) return bad("notifications of type 6", kr, kIOReturnBadArgument);
    mach_port_t p;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &p);
    if ((kr = IOConnectSetNotificationPort(c, 6, p, 0)) != kIOReturnBadArgument) return bad("a port of type 6", kr, kIOReturnBadArgument);
    if ((kr = IOConnectSetNotificationPort(c, 0, p, 0)) != KERN_SUCCESS) return bad("a hot plug port", kr, 0);
    if ((kr = IOConnectSetNotificationPort(c, 0, p, 0)) != (kern_return_t)0xe00002dd) return bad("a second hot plug port", kr, 0xe00002dd);
    // Hot plug turned on: listed, and a built-in panel tells nothing; a
    // second time is kIOReturnError; off again.
    in[2] = 0;
    if ((kr = IOConnectCallScalarMethod(c, 72, in, 4, NULL, NULL)) != KERN_SUCCESS) return bad("hot plug notifications", kr, 0);
    if ((kr = IOConnectCallScalarMethod(c, 72, in, 4, NULL, NULL)) != kIOReturnError) return bad("hot plug notifications again", kr, kIOReturnError);
    in[0] = 0;
    if ((kr = IOConnectCallScalarMethod(c, 72, in, 4, NULL, NULL)) != KERN_SUCCESS) return bad("hot plug notifications off", kr, 0);
    mach_vm_address_t addr = 0;
    mach_vm_size_t len = 0;
    if ((kr = IOConnectMapMemory64(c, 0, mach_task_self(), &addr, &len, kIOMapAnywhere)) != kIOReturnBadArgument) return bad("memory of type 0", kr, kIOReturnBadArgument);
    if ((kr = IOConnectMapMemory64(c, 3, mach_task_self(), &addr, &len, kIOMapAnywhere)) != kIOReturnBadArgument) return bad("memory of type 3", kr, kIOReturnBadArgument);
    IOServiceClose(c);

    printf("iomfb ok\n");
    return 0;
}
