// IOGPU.framework's IOGPUDeviceCreate, as RunningBoard calls it: the first
// IOGPU service, a device made over it. The create asks the device client
// for its stamps, its configuration and its trace object (selector 4: the
// graphics comm page IOSurfaceRoot shares, mapped into this task, and the
// device's client-shared block), then finds the comm page through
// IOSurface.framework, which maps the same page and hands back the mapping
// IOGPU made. Tracing is off, so the page's word is 0.
//
// It runs as an app does, in the container profile's sandbox, as accel
// does: unsandboxed, the platform profile would admit neither user client
// to this program, which it neither names nor entitles.

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <stdio.h>
#include <string.h>

extern void *IOSurfaceGetGraphicsCommPageAddress(void);

#define SANDBOX_NAMED_BUILTIN 2

int sandbox_init(const char *profile, uint64_t flags, char **errorbuf);

static int bad(const char *what, long got, long want) {
    printf("iogpudev: %s: %#lx, want %#lx\n", what, got, want);
    return 1;
}

int main(void) {
    char *err = NULL;
    if (sandbox_init("container", SANDBOX_NAMED_BUILTIN, &err) != 0) return bad("the container sandbox", 0, 1);
    void *h = dlopen("/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU", RTLD_NOW);
    if (h == NULL) return bad("loading IOGPU.framework", 0, 1);
    void *(*create)(io_service_t) = dlsym(h, "IOGPUDeviceCreate");
    uint64_t (*trace_object)(void *) = dlsym(h, "IOGPUDeviceGetGlobalTraceObjectID");
    kern_return_t (*allocated)(void *, uint64_t *) = dlsym(h, "IOGPUDeviceGetAllocatedSize");
    kern_return_t (*filter)(void *) = dlsym(h, "IOGPUDeviceGetCurrentTraceFilter");
    void (*release)(void *) = dlsym(h, "IOGPUDeviceRelease");
    if (!create || !trace_object || !allocated || !filter || !release) return bad("IOGPU.framework's functions", 0, 1);

    io_service_t gpu = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOGPU"));
    if (gpu == IO_OBJECT_NULL) return bad("the IOGPU", 0, 1);
    void *dev = create(gpu);
    if (dev == NULL) return bad("IOGPUDeviceCreate", 0, 1);
    if (trace_object(dev) == 0) return bad("the trace object id", 0, 1);
    // The allocated size, from the client-shared block: nothing allocated.
    uint64_t size = 1;
    if (allocated(dev, &size) != KERN_SUCCESS || size != 0) return bad("the allocated size", (long)size, 0);
    if (filter(dev) != KERN_SUCCESS) return bad("the trace filter", 1, 0);
    // The device kept selector 4's mapping of the comm page (its +0x60);
    // IOSurface's is the same mapping.
    uint64_t mapped;
    memcpy(&mapped, (char *)dev + 0x60, 8);
    volatile uint32_t *page = IOSurfaceGetGraphicsCommPageAddress();
    if (page == NULL || (uint64_t)page != mapped) return bad("the comm page's mapping", (long)page, (long)mapped);
    if (page[0] != 0) return bad("the comm page's word", page[0], 0);
    release(dev);
    IOObjectRelease(gpu);
    printf("iogpudev ok\n");
    return 0;
}
