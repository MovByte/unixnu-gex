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
//   device refuses, the parameters SetParameter does not take (a power
//   assertion among them) and the gain map's without its entitlement,
//   three QuartzCore sets (3 and 6, taken; 7, unsupported), the
//   frame information the pipe names and the options only it takes, the
//   notification types, and memory of no type.
// - The glass, on that connection (selector 83, with backboardd's graphics
//   priority entitlement): layer 0 holds the swapped surface and layer 1
//   nothing; a second swap that sets only layer 1 leaves layer 0 as it
//   was, and the test embedder records both layers (frame-check.py).
// - A swap that changes nothing on the glass completes at once, with no
//   new frame; swap signals (selector 20) for a begun swap, a queued one,
//   a layer it does not enable, and none.
// - The console mode: SystemConsoleMode is not on the service until the
//   first swap client comes, which turns it off.
// - Power, on that connection: power notifications asked for (an option
//   for them refused), the display turned off (selector 12), its
//   notification (the time, and state 0), the swap waits a display that is
//   off answers, a swap made while it is off, the display turned on again
//   (state 3: controller and panel), and that swap gone with the queue's
//   flush, never shown. The controller going off blanked the glass with the
//   kernel's request for its last frame. The test embedder records the
//   panel going dark, that blank frame, and the panel lighting again
//   (frame-check.py).
// - A swap whose completed layers are not all of those it enables waits at
//   the queue's head until it is cancelled; a swap wait for another such
//   one, interrupted by a signal, is kIOReturnAborted and clears the swaps.
// - The last swap client's close waits for the kernel's swap that blanks
//   the glass, a frame with no layers.

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <IOSurface/IOSurfaceRef.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

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

// A power notification: IOUserClient's async result (kOSNotificationMessageID,
// an OSNotificationHeader64 of kIOAsyncCompletionNotificationType with the
// reference the enable set, the result, and the time and state).
static int power_note(mach_port_t p, uint64_t callout, uint64_t refcon, uint64_t want_state) {
    // The header, then at 24 the notification header's size and type, at
    // 32 its eight-word reference, at 96 the result and at 100 the
    // arguments (packed).
    uint64_t buf[64];
    memset(buf, 0, sizeof buf);
    mach_msg_header_t *h = (mach_msg_header_t *)buf;
    kern_return_t kr = mach_msg(h, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof buf, p, 5000, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) return bad("receiving a power notification", kr, 0);
    if (h->msgh_id != 53 || h->msgh_size != 120) return bad("the power notification's id and size", (long)h->msgh_id << 16 | h->msgh_size, 53 << 16 | 120);
    const uint8_t *b = (const uint8_t *)buf;
    uint32_t size, type;
    uint64_t reference[8], args[2];
    int32_t result;
    memcpy(&size, b + 24, 4);
    memcpy(&type, b + 28, 4);
    memcpy(reference, b + 32, 64);
    memcpy(&result, b + 96, 4);
    memcpy(args, b + 100, 16);
    if (size != 4 + 16 || type != 150) return bad("its header's size and type", (long)size << 16 | type, 20 << 16 | 150);
    if (reference[0] != 0 || reference[1] != callout || reference[2] != refcon || reference[3] != 0) return bad("its reference", (long)reference[1], (long)callout);
    if (result != 0 || args[0] == 0 || args[1] != want_state) return bad("its result, time and state", (long)args[1], (long)want_state);
    return 0;
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

// A raw transaction of `enabled` layers and the `completed` mask, layer 0
// showing the whole of `surface`.
static kern_return_t submit_masks(io_connect_t c, uint32_t id, uint32_t surface, int w, int h, uint32_t enabled, uint32_t completed) {
    uint8_t rec[1288];
    memset(rec, 0, sizeof rec);
    int32_t src[4] = {0, 0, w, h};
    memcpy(rec + 0x98, &id, 4);
    memcpy(rec + 0x9c, &surface, 4);
    memcpy(rec + 0xac, src, 16);
    memcpy(rec + 0x10c, src, 16);
    memcpy(rec + 0x14c, &enabled, 4);
    memcpy(rec + 0x150, &completed, 4);
    return IOConnectCallStructMethod(c, 5, rec, sizeof rec, NULL, NULL);
}

static volatile sig_atomic_t alarmed;

static void on_alarm(int sig) {
    (void)sig;
    alarmed = 1;
}

static int console_mode(io_service_t clcd, int want) {
    CFTypeRef v = IORegistryEntryCreateCFProperty(clcd, CFSTR("SystemConsoleMode"), NULL, 0);
    int got = v == NULL ? -1 : v == kCFBooleanTrue ? 1 : v == kCFBooleanFalse ? 0 : 2;
    if (v) CFRelease(v);
    return got == want ? 0 : bad("SystemConsoleMode", got, want);
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
    // No swap client yet: no console mode set.
    if (console_mode(clcd, -1)) return 1;
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
    // The first swap client turned the console mode off.
    if (console_mode(clcd, 0)) return 1;
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
    // SetParameter: a power assertion (11), which the framebuffer does not
    // take, an unknown parameter, values of the wrong count or range, and
    // the gain map's (16) without its entitlement.
    uint64_t sp[4] = {1, 0, 0, 0};
    in[0] = 11;
    if ((kr = IOConnectCallMethod(c, 68, in, 1, sp, 8, NULL, NULL, NULL, NULL)) != kIOReturnBadArgument) return bad("SetParameter 11", kr, kIOReturnBadArgument);
    in[0] = 8;
    if ((kr = IOConnectCallMethod(c, 68, in, 1, sp, 8, NULL, NULL, NULL, NULL)) != kIOReturnBadArgument) return bad("SetParameter 8", kr, kIOReturnBadArgument);
    // QuartzCore's: 3 goes to the pipe's block that takes it, 6 is the EDR
    // scale; 7 needs a block the pipe never makes.
    in[0] = 3;
    if ((kr = IOConnectCallMethod(c, 68, in, 1, sp, 8, NULL, NULL, NULL, NULL)) != KERN_SUCCESS) return bad("SetParameter 3", kr, 0);
    in[0] = 6;
    if ((kr = IOConnectCallMethod(c, 68, in, 1, sp, 8, NULL, NULL, NULL, NULL)) != KERN_SUCCESS) return bad("SetParameter 6", kr, 0);
    in[0] = 7;
    if ((kr = IOConnectCallMethod(c, 68, in, 1, sp, 8, NULL, NULL, NULL, NULL)) != kIOReturnUnsupported) return bad("SetParameter 7", kr, kIOReturnUnsupported);
    in[0] = 0;
    if ((kr = IOConnectCallMethod(c, 68, in, 1, sp, 24, NULL, NULL, NULL, NULL)) != kIOReturnBadArgument) return bad("SetParameter 0 with three values", kr, kIOReturnBadArgument);
    in[0] = 4;
    sp[0] = 101;
    if ((kr = IOConnectCallMethod(c, 68, in, 1, sp, 8, NULL, NULL, NULL, NULL)) != kIOReturnBadArgument) return bad("SetParameter 4 of 101", kr, kIOReturnBadArgument);
    in[0] = 16;
    if ((kr = IOConnectCallMethod(c, 68, in, 1, sp, 8, NULL, NULL, NULL, NULL)) != kIOReturnNotPrivileged) return bad("SetParameter 16", kr, kIOReturnNotPrivileged);
    // Frame information: the pipe names 14 items of one word each; there is
    // no item 14; options go only to frame information's record.
    char item[64];
    size_t itemsz = sizeof item;
    in[0] = 0;
    outn = 2;
    if ((kr = IOConnectCallMethod(c, 74, in, 1, NULL, 0, out, &outn, item, &itemsz)) != KERN_SUCCESS || out[0] != 14 || out[1] != 1 || strcmp(item, "Layer_0_CRC") != 0) return bad("SupportedFrameInfo 0", kr ? kr : (long)out[0], 14);
    in[0] = 13;
    outn = 2;
    itemsz = sizeof item;
    if ((kr = IOConnectCallMethod(c, 74, in, 1, NULL, 0, out, &outn, item, &itemsz)) != KERN_SUCCESS || strcmp(item, "CA_mode") != 0) return bad("SupportedFrameInfo 13", kr, 0);
    in[0] = 14;
    outn = 2;
    itemsz = sizeof item;
    if ((kr = IOConnectCallMethod(c, 74, in, 1, NULL, 0, out, &outn, item, &itemsz)) != kIOReturnBadArgument) return bad("SupportedFrameInfo 14", kr, kIOReturnBadArgument);
    in[0] = 0;
    in[1] = 1;
    if ((kr = IOConnectCallScalarMethod(c, 73, in, 2, NULL, NULL)) != kIOReturnBadArgument) return bad("ChangeFrameInfo of hot plug", kr, kIOReturnBadArgument);
    in[0] = 6;
    if ((kr = IOConnectCallScalarMethod(c, 73, in, 2, NULL, NULL)) != kIOReturnBadArgument) return bad("ChangeFrameInfo of type 6", kr, kIOReturnBadArgument);
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

    // The glass: layer 0's surface is the swapped one, as a send right;
    // layer 1 has none (kIOReturnError); there is no layer 4.
    in[0] = 0;
    outn = 1;
    if ((kr = IOConnectCallScalarMethod(c, 83, in, 1, out, &outn)) != KERN_SUCCESS) return bad("CopyLayerDisplayedSurface of layer 0", kr, 0);
    IOSurfaceRef shown = IOSurfaceLookupFromMachPort((mach_port_t)out[0]);
    if (shown == NULL || IOSurfaceGetID(shown) != IOSurfaceGetID(s)) return bad("layer 0's surface", shown ? IOSurfaceGetID(shown) : 0, IOSurfaceGetID(s));
    CFRelease(shown);
    mach_port_deallocate(mach_task_self(), (mach_port_t)out[0]);
    in[0] = 1;
    outn = 1;
    if ((kr = IOConnectCallScalarMethod(c, 83, in, 1, out, &outn)) != kIOReturnError) return bad("CopyLayerDisplayedSurface of an empty layer", kr, kIOReturnError);
    in[0] = 4;
    outn = 1;
    if ((kr = IOConnectCallScalarMethod(c, 83, in, 1, out, &outn)) != kIOReturnBadArgument) return bad("CopyLayerDisplayedSurface of layer 4", kr, kIOReturnBadArgument);
    // A swap that sets only layer 1, a small surface of its own: layer 0
    // stays as the first swap left it.
    const void *vals2[] = {num(64), num(64), num(bpe), num(fmt)};
    CFDictionaryRef props2 = CFDictionaryCreate(NULL, keys, vals2, 4, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    IOSurfaceRef s2 = IOSurfaceCreate(props2);
    if (s2 == NULL) return bad("IOSurfaceCreate of the small surface", 0, 1);
    if (IOSurfaceLock(s2, 0, NULL) != KERN_SUCCESS) return bad("locking the small surface", 0, 1);
    memset(IOSurfaceGetBaseAddress(s2), 0x40, IOSurfaceGetAllocSize(s2));
    if (IOSurfaceUnlock(s2, 0, NULL) != KERN_SUCCESS) return bad("unlocking the small surface", 0, 1);
    int second = 0;
    if ((kr = swap_begin(fb, &second)) != KERN_SUCCESS) return bad("SwapBegin of layer 1", kr, 0);
    FbRect small = {0, 0, 64, 64};
    if ((kr = swap_set_layer(fb, 1, s2, small, small, 0)) != KERN_SUCCESS) return bad("SwapSetLayer of layer 1", kr, 0);
    if ((kr = swap_end(fb)) != KERN_SUCCESS) return bad("SwapEnd of layer 1", kr, 0);
    if ((kr = swap_wait(fb, second, 1)) != KERN_SUCCESS) return bad("SwapWait until layer 1 is displayed", kr, 0);
    for (int layer = 0; layer < 2; layer++) {
        in[0] = layer;
        outn = 1;
        if ((kr = IOConnectCallScalarMethod(c, 83, in, 1, out, &outn)) != KERN_SUCCESS) return bad("CopyLayerDisplayedSurface after layer 1's swap", kr, 0);
        IOSurfaceRef on = IOSurfaceLookupFromMachPort((mach_port_t)out[0]);
        IOSurfaceRef want = layer == 0 ? s : s2;
        if (on == NULL || IOSurfaceGetID(on) != IOSurfaceGetID(want)) return bad("a layer's surface after layer 1's swap", on ? IOSurfaceGetID(on) : 0, IOSurfaceGetID(want));
        CFRelease(on);
        mach_port_deallocate(mach_task_self(), (mach_port_t)out[0]);
    }

    // A swap of layer 0 with the surface and rectangles it has on the glass
    // changes nothing: it completes at once, no blank waited for, and no
    // frame is recorded for it.
    int same = 0;
    if ((kr = swap_begin(fb, &same)) != KERN_SUCCESS) return bad("SwapBegin of a no-op swap", kr, 0);
    if ((kr = swap_set_layer(fb, 0, s, whole, whole, 0)) != KERN_SUCCESS) return bad("SwapSetLayer of a no-op swap", kr, 0);
    if ((kr = swap_end(fb)) != KERN_SUCCESS) return bad("SwapEnd of a no-op swap", kr, 0);
    if ((kr = swap_wait(fb, same, 0x80000001)) != KERN_SUCCESS) return bad("a no-op swap, done at once", kr, 0);
    // Swap signals: a begun swap takes one for any layer; an unknown swap
    // is kIOReturnError, and a layer past 3 kIOReturnBadArgument.
    outn = 1;
    if ((kr = IOConnectCallScalarMethod(c, 4, NULL, 0, out, &outn)) != KERN_SUCCESS) return bad("SwapBegin to signal", kr, 0);
    uint32_t signalled = (uint32_t)out[0];
    in[0] = signalled;
    in[1] = 2;
    if ((kr = IOConnectCallScalarMethod(c, 20, in, 2, NULL, NULL)) != KERN_SUCCESS) return bad("SwapSignal of a begun swap", kr, 0);
    in[1] = 4;
    if ((kr = IOConnectCallScalarMethod(c, 20, in, 2, NULL, NULL)) != kIOReturnBadArgument) return bad("SwapSignal of layer 4", kr, kIOReturnBadArgument);
    in[0] = 0x7777;
    in[1] = 0;
    if ((kr = IOConnectCallScalarMethod(c, 20, in, 2, NULL, NULL)) != kIOReturnError) return bad("SwapSignal of no swap", kr, kIOReturnError);
    in[0] = signalled;
    if ((kr = IOConnectCallScalarMethod(c, 52, in, 1, NULL, NULL)) != KERN_SUCCESS) return bad("cancelling the signalled swap", kr, 0);

    // Power notifications (type 1) to a port of their own: an option for
    // them is refused, the record staying listed.
    mach_port_t pp;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &pp);
    mach_port_insert_right(mach_task_self(), pp, pp, MACH_MSG_TYPE_MAKE_SEND);
    if ((kr = IOConnectSetNotificationPort(c, 1, pp, 0)) != KERN_SUCCESS) return bad("a power port", kr, 0);
    in[0] = 0x1234;
    in[1] = 0x5678;
    in[2] = 1;
    in[3] = 1;
    if ((kr = IOConnectCallScalarMethod(c, 72, in, 4, NULL, NULL)) != kIOReturnBadArgument) return bad("power notifications with an option", kr, kIOReturnBadArgument);
    in[3] = 0;
    if ((kr = IOConnectCallScalarMethod(c, 72, in, 4, NULL, NULL)) != kIOReturnError) return bad("power notifications listed already", kr, kIOReturnError);
    // Off: the request succeeds, the scheduler sets the soft state (no swap
    // is pending), the controller and panel go off, and the client is told.
    in[0] = 0;
    if ((kr = IOConnectCallScalarMethod(c, 12, in, 1, NULL, NULL)) != KERN_SUCCESS) return bad("RequestPowerChange off", kr, 0);
    if (power_note(pp, 0x1234, 0x5678, 0)) return 1;
    // Off: option 4 is so and option 3 is not, at once or not; a wait on a
    // swap is kIOReturnOffline.
    if ((kr = swap_wait(fb, token, 4)) != KERN_SUCCESS) return bad("SwapWait option 4 while off", kr, 0);
    if ((kr = swap_wait(fb, token, 3)) != kIOReturnBadArgument) return bad("SwapWait option 3 while off", kr, kIOReturnBadArgument);
    if ((kr = swap_wait(fb, token, 0x80000004)) != KERN_SUCCESS) return bad("SwapWait option 4 while off, not blocking", kr, 0);
    if ((kr = swap_wait(fb, token, 0x80000003)) != kIOReturnBusy) return bad("SwapWait option 3 while off, not blocking", kr, kIOReturnBusy);
    if ((kr = swap_wait(fb, token, 1)) != (kern_return_t)0xe00002e3) return bad("SwapWait while off", kr, 0xe00002e3);
    // A swap while off is queued, not shown.
    int off = 0;
    if ((kr = swap_begin(fb, &off)) != KERN_SUCCESS) return bad("SwapBegin while off", kr, 0);
    if ((kr = swap_set_layer(fb, 0, s, whole, whole, 0)) != KERN_SUCCESS) return bad("SwapSetLayer while off", kr, 0);
    if ((kr = swap_end(fb)) != KERN_SUCCESS) return bad("SwapEnd while off", kr, 0);
    if ((kr = swap_wait(fb, off, 1)) != (kern_return_t)0xe00002e3) return bad("SwapWait on a swap made while off", kr, 0xe00002e3);
    // Queued while off: a signal for the layer it enables is taken, one
    // for a layer it does not is kIOReturnBadArgument.
    in[0] = off;
    in[1] = 0;
    if ((kr = IOConnectCallScalarMethod(c, 20, in, 2, NULL, NULL)) != KERN_SUCCESS) return bad("SwapSignal of a queued swap", kr, 0);
    in[1] = 1;
    if ((kr = IOConnectCallScalarMethod(c, 20, in, 2, NULL, NULL)) != kIOReturnBadArgument) return bad("SwapSignal of a layer not enabled", kr, kIOReturnBadArgument);
    // On again: the controller's change flushes the queue (the swap is gone
    // and never shown), the panel lights, and the client is told.
    in[0] = 1;
    if ((kr = IOConnectCallScalarMethod(c, 12, in, 1, NULL, NULL)) != KERN_SUCCESS) return bad("RequestPowerChange on", kr, 0);
    if (power_note(pp, 0x1234, 0x5678, 3)) return 1;
    if ((kr = swap_wait(fb, off, 1)) != KERN_SUCCESS) return bad("SwapWait on the flushed swap", kr, 0);
    if ((kr = swap_wait(fb, off, 2)) != KERN_SUCCESS) return bad("SwapWait for an idle queue after the flush", kr, 0);
    if ((kr = swap_wait(fb, off, 3)) != KERN_SUCCESS) return bad("SwapWait option 3 when on again", kr, 0);
    // The kernel's request for the controller's last frame as it went off
    // was shown: the glass is empty.
    in[0] = 0;
    outn = 1;
    if ((kr = IOConnectCallScalarMethod(c, 83, in, 1, out, &outn)) != kIOReturnError) return bad("CopyLayerDisplayedSurface after the power cycle", kr, kIOReturnError);
    // A swap that enables a layer past 3, which no signal completes, waits
    // at the queue's head; cancelled, the next kick drops it.
    int stuck = 0;
    if ((kr = swap_begin(fb, &stuck)) != KERN_SUCCESS) return bad("SwapBegin of an incomplete swap", kr, 0);
    if ((kr = submit_masks(c, (uint32_t)stuck, sid, (int)pw, (int)ph, 0x11, 0)) != KERN_SUCCESS) return bad("submitting an incomplete swap", kr, 0);
    if ((kr = swap_wait(fb, stuck, 0x80000001)) != kIOReturnBusy) return bad("an incomplete swap, still queued", kr, kIOReturnBusy);
    usleep(50000);
    if ((kr = swap_wait(fb, stuck, 0x80000001)) != kIOReturnBusy) return bad("an incomplete swap, still queued after blanks", kr, kIOReturnBusy);
    in[0] = stuck;
    if ((kr = IOConnectCallScalarMethod(c, 52, in, 1, NULL, NULL)) != KERN_SUCCESS) return bad("cancelling the incomplete swap", kr, 0);
    usleep(50000);
    if ((kr = swap_wait(fb, stuck, 0x80000001)) != KERN_SUCCESS) return bad("the cancelled swap, dropped", kr, 0);
    // Another, waited for: a signal ends the wait's sleep (kIOReturnAborted)
    // after its handler ran, and the swaps are cleared, the swap with them.
    if ((kr = swap_begin(fb, &stuck)) != KERN_SUCCESS) return bad("SwapBegin of a second incomplete swap", kr, 0);
    if ((kr = submit_masks(c, (uint32_t)stuck, sid, (int)pw, (int)ph, 0x11, 0)) != KERN_SUCCESS) return bad("submitting a second incomplete swap", kr, 0);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_alarm;
    sigaction(SIGALRM, &sa, NULL);
    ualarm(100000, 0);
    if ((kr = swap_wait(fb, stuck, 1)) != kIOReturnAborted || !alarmed) return bad("a swap wait a signal interrupts", kr, kIOReturnAborted);
    if ((kr = swap_wait(fb, stuck, 0x80000001)) != KERN_SUCCESS) return bad("the swap the interrupted wait cleared", kr, 0);
    in[0] = 0;
    if ((kr = IOConnectCallScalarMethod(c, 72, in, 4, NULL, NULL)) != KERN_SUCCESS) return bad("power notifications off", kr, 0);
    IOServiceClose(c);
    // The last swap client's close: its io_service_close returns once the
    // kernel's swap that blanks the glass is shown; the console mode stays
    // as the first swap client left it, the glass having no surface for it.
    CFRelease(fb);
    if (console_mode(clcd, 0)) return 1;

    printf("iomfb ok\n");
    return 0;
}
