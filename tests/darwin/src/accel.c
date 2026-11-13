// The GPU's accelerator service: found by class as Metal.framework finds it
// (IOAcceleratorES) and as RunningBoard does (IOGPU), its registry
// properties, its providers up the IOService plane to the registry's root,
// and its user clients: the WebMetal connection (type 0), the
// IOGPU device client (type 1), the memory information client (type 33),
// and the types it refuses. For each client: its class and properties,
// method argument checks as IOUserClient makes them, the asynchronous
// method and notification port calls, memory mapping, traps, closing, and
// the client going with its connection's last send right.

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <mach/mach.h>
#include <mach/mig.h>
#include <mach/mig_errors.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// IOConnectTrap's own call (libsystem_kernel's mach trap), which the iOS
// SDK's IOKitLib does not declare for applications.
extern kern_return_t iokit_user_client_trap(mach_port_t connect, unsigned int index, uintptr_t p1, uintptr_t p2, uintptr_t p3, uintptr_t p4, uintptr_t p5, uintptr_t p6);

static kern_return_t trap0(io_connect_t conn, unsigned int index) {
    return iokit_user_client_trap(conn, index, 0, 0, 0, 0, 0, 0);
}

static void port_free(mach_port_t port) {
    mach_port_mod_refs(mach_task_self(), port, MACH_PORT_RIGHT_RECEIVE, -1);
}

static int bad(const char *what, long got, long want) {
    printf("accel: %s: %#lx, want %#lx\n", what, got, want);
    return 1;
}

static int string_prop(io_registry_entry_t e, const char *key, const char *want) {
    CFStringRef k = CFStringCreateWithCString(NULL, key, kCFStringEncodingUTF8);
    CFTypeRef v = IORegistryEntryCreateCFProperty(e, k, kCFAllocatorDefault, 0);
    CFRelease(k);
    if (v == NULL || CFGetTypeID(v) != CFStringGetTypeID()) {
        printf("accel: %s: not a string\n", key);
        return 1;
    }
    char buf[256];
    CFStringGetCString(v, buf, sizeof buf, kCFStringEncodingUTF8);
    CFRelease(v);
    if (strcmp(buf, want) != 0) {
        printf("accel: %s: %s, want %s\n", key, buf, want);
        return 1;
    }
    return 0;
}

static int num_prop(io_registry_entry_t e, CFStringRef key, long long want) {
    CFTypeRef v = IORegistryEntryCreateCFProperty(e, key, kCFAllocatorDefault, 0);
    long long got = -1;
    if (v == NULL || CFGetTypeID(v) != CFNumberGetTypeID() || !CFNumberGetValue(v, kCFNumberLongLongType, &got) || got != want) {
        char k[64];
        CFStringGetCString(key, k, sizeof k, kCFStringEncodingUTF8);
        return bad(k, (long)got, (long)want);
    }
    CFRelease(v);
    return 0;
}

// An entry's class and its registry name.
static int is(io_registry_entry_t e, const char *class_name, const char *name) {
    io_name_t cls = "", n = "";
    if (IOObjectGetClass(e, cls) != KERN_SUCCESS || strcmp(cls, class_name) != 0 || IORegistryEntryGetName(e, n) != KERN_SUCCESS || strcmp(n, name) != 0) {
        printf("accel: an ancestor: %s %s, want %s %s\n", cls, n, class_name, name);
        return 1;
    }
    return 0;
}

// The accelerator's providers, as the device's kexts publish them: the GPU's
// nub (AppleARMIODevice, which AppleT8011IO made of arm-io's sgx), arm-io's
// driver, arm-io's nub (an IOPlatformDevice the platform expert made), the
// platform expert, the platform expert device and the registry's root; and
// what matching set on the drivers.
static int ancestors(io_service_t accel) {
    static const struct { const char *cls, *name; } want[] = {
        {"AppleARMIODevice", "sgx"}, {"AppleT8011IO", "AppleT8011IO"}, {"IOPlatformDevice", "arm-io"},
        {"AppleARMPE", "AppleARMPE"}, {"IOPlatformExpertDevice", "J120AP"}, {"IORegistryEntry", "Root"},
    };
    io_registry_entry_t e = accel, up[6];
    IOObjectRetain(e);
    for (int i = 0; i < 6; i++) {
        if (IORegistryEntryGetParentEntry(e, kIOServicePlane, &up[i]) != KERN_SUCCESS) return bad("a provider", i, 6);
        IOObjectRelease(e);
        e = up[i];
        IOObjectRetain(e);
        if (is(e, want[i].cls, want[i].name)) return 1;
    }
    io_registry_entry_t none = IO_OBJECT_NULL;
    if (IORegistryEntryGetParentEntry(e, kIOServicePlane, &none) != kIOReturnNoDevice) return bad("a parent of the root", 0, 1);
    IOObjectRelease(e);
    // Their superclasses, from the kexts' metaclasses.
    if (!IOObjectConformsTo(up[0], "IOService") || !IOObjectConformsTo(up[1], "AppleT801xIO") || !IOObjectConformsTo(up[1], "AppleARMIO") || !IOObjectConformsTo(up[1], "IOPlatformIO") || !IOObjectConformsTo(up[3], "IODTPlatformExpert") || !IOObjectConformsTo(up[3], "IOPlatformExpert")) return bad("the providers' superclasses", 0, 1);
    // The drivers' properties from their personalities and matching.
    if (string_prop(up[1], "IONameMatched", "arm-io,t8011") || string_prop(up[1], "CFBundleIdentifier", "com.apple.driver.AppleT8011") || string_prop(up[1], "IOMatchCategory", "IODefaultMatchCategory") || num_prop(up[1], CFSTR("IOProbeScore"), 0) || num_prop(up[1], CFSTR("IOPlatformActiveAction"), 80000)) return 1;
    if (string_prop(up[3], "IONameMatched", "AppleARM") || string_prop(up[3], "IOProviderClass", "IOPlatformExpertDevice") || num_prop(up[3], CFSTR("IOProbeScore"), 1000)) return 1;
    if (IORegistryEntryCreateCFProperty(up[3], CFSTR("IOMatchedAtBoot"), kCFAllocatorDefault, 0) != kCFBooleanTrue) return bad("the platform expert matched at boot", 0, 1);
    // The nubs keep their device tree entries' properties.
    CFTypeRef compat = IORegistryEntryCreateCFProperty(up[0], CFSTR("compatible"), kCFAllocatorDefault, 0);
    if (compat == NULL || CFGetTypeID(compat) != CFDataGetTypeID() || CFDataGetLength(compat) != 10 || memcmp(CFDataGetBytePtr(compat), "gpu,t8011", 10) != 0) return bad("the GPU nub's compatible", 0, 1);
    CFRelease(compat);
    for (int i = 0; i < 6; i++) IOObjectRelease(up[i]);
    return 0;
}

extern mach_msg_return_t mach_msg2_internal(void *data, uint64_t option64, uint64_t bits_and_send_size,
    uint64_t remote_and_local_port, uint64_t voucher_and_id, uint64_t desc_count_and_rcv_name,
    uint64_t rcv_size_and_priority, uint64_t timeout);

// io_connect_method sent by hand with an out-of-line input no larger than
// an inband one, which is_io_connect_method refuses (kIOReturnIPCError)
// before the client sees it.
static kern_return_t method_small_ool(mach_port_t conn) {
#pragma pack(push, 4)
    struct request {
        mach_msg_header_t head;
        NDR_record_t ndr;
        uint32_t selector;
        mach_msg_type_number_t scalar_count;
        mach_msg_type_number_t inband_count;
        mach_vm_address_t ool_input;
        mach_vm_size_t ool_input_size;
        mach_msg_type_number_t inband_output_count;
        mach_msg_type_number_t scalar_output_count;
        mach_vm_address_t ool_output;
        mach_vm_size_t ool_output_size;
    };
#pragma pack(pop)
    union {
        struct request req;
        mig_reply_error_t error;
        char room[8192];
    } m;
    static char data[16];
    memset(&m, 0, sizeof m);
    mach_port_t reply = mig_get_reply_port();
    m.req.head.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    m.req.head.msgh_size = sizeof m.req;
    m.req.head.msgh_remote_port = conn;
    m.req.head.msgh_local_port = reply;
    m.req.head.msgh_id = 2865;
    m.req.ndr = NDR_record;
    m.req.ool_input = (mach_vm_address_t)data;
    m.req.ool_input_size = sizeof data;
    // Sent as the MIG stubs send a kernel object's calls.
    const uint64_t send_msg = 1, rcv_msg = 2, kobject_call = 0x200000000ull;
    uint32_t bits = m.req.head.msgh_bits;
    kern_return_t kr = mach_msg2_internal(&m, send_msg | rcv_msg | kobject_call, (uint64_t)sizeof m.req << 32 | bits,
        (uint64_t)reply << 32 | conn, (uint64_t)2865 << 32, (uint64_t)reply << 32, sizeof m, 0);
    if (kr != KERN_SUCCESS) return kr;
    if (m.error.Head.msgh_id != 2965) return MIG_REPLY_MISMATCH;
    return m.error.RetCode;
}

static int wire_client(io_service_t accel, uint64_t accel_id) {
    io_connect_t conn = IO_OBJECT_NULL;
    kern_return_t kr = IOServiceOpen(accel, mach_task_self(), 0, &conn);
    if (kr != KERN_SUCCESS || conn == IO_OBJECT_NULL) return bad("opening type 0", kr, 0);
    io_name_t cls;
    if (IOObjectGetClass(conn, cls) != KERN_SUCCESS || strcmp(cls, "WebMetalUserClient") != 0) return bad("the WebMetal client's class", 0, 1);
    if (!IOObjectConformsTo(conn, "IOUserClient") || IOObjectConformsTo(conn, "IOGPU")) return bad("the WebMetal client's superclasses", 0, 1);
    uint64_t id = 0;
    if (IORegistryEntryGetRegistryEntryID(conn, &id) != KERN_SUCCESS || id <= accel_id) return bad("the client's registry entry id", (long)id, (long)accel_id);
    char creator[64];
    snprintf(creator, sizeof creator, "pid %d, %.16s", getpid(), getprogname());
    if (string_prop(conn, "IOUserClientCreator", creator)) return 1;
    CFTypeRef locking = IORegistryEntryCreateCFProperty(conn, CFSTR("IOUserClientDefaultLocking"), kCFAllocatorDefault, 0);
    if (locking != kCFBooleanTrue) return bad("IOUserClientDefaultLocking", 0, 1);

    // The checks of each selector's counts, and a selector it has none of.
    uint64_t in[4] = {0, 0, 0, 0}, out[2] = {0, 0};
    uint32_t nout = 1;
    kr = IOConnectCallScalarMethod(conn, 0, in, 3, out, &nout);
    if (kr != kIOReturnBadArgument) return bad("control with three scalars", kr, kIOReturnBadArgument);
    nout = 2;
    kr = IOConnectCallScalarMethod(conn, 0, in, 4, out, &nout);
    if (kr != kIOReturnBadArgument) return bad("control with room for two outputs", kr, kIOReturnBadArgument);
    nout = 1;
    kr = IOConnectCallMethod(conn, 1, in, 2, "x", 1, out, &nout, NULL, NULL);
    if (kr != kIOReturnBadArgument) return bad("fetch_reply with a structure", kr, kIOReturnBadArgument);
    nout = 0;
    kr = IOConnectCallScalarMethod(conn, 3, in, 1, out, &nout);
    if (kr != kIOReturnUnsupported) return bad("selector 3", kr, kIOReturnUnsupported);
    if (method_small_ool(conn) != kIOReturnIPCError) return bad("a small out-of-line input", method_small_ool(conn), kIOReturnIPCError);

    // register_event_port, asynchronously, for a queue and for the device;
    // again for the device.
    mach_port_t port = MACH_PORT_NULL;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port) != KERN_SUCCESS) return bad("a port", 0, 1);
    uint64_t ref[8] = {0}, queue = 0x1234;
    kr = IOConnectCallAsyncScalarMethod(conn, 2, port, ref, 8, &queue, 1, NULL, NULL);
    if (kr != KERN_SUCCESS) return bad("register_event_port for a queue", kr, 0);
    queue = 0;
    kr = IOConnectCallAsyncScalarMethod(conn, 2, port, ref, 8, &queue, 1, NULL, NULL);
    if (kr != KERN_SUCCESS) return bad("register_event_port for the device", kr, 0);
    kr = IOConnectCallAsyncScalarMethod(conn, 2, port, ref, 8, &queue, 1, NULL, NULL);
    if (kr != KERN_SUCCESS) return bad("register_event_port again", kr, 0);
    mach_port_type_t type;

    // Not the client's: its service, memory, a notification port, a trap.
    io_service_t svc = IO_OBJECT_NULL;
    kr = IOConnectGetService(conn, &svc);
    if (kr != kIOReturnUnsupported) return bad("the client's service", kr, kIOReturnUnsupported);
    mach_vm_address_t addr = 0;
    mach_vm_size_t size = 0;
    kr = IOConnectMapMemory64(conn, 0, mach_task_self(), &addr, &size, kIOMapAnywhere);
    if (kr != kIOReturnBadArgument) return bad("mapping its memory", kr, kIOReturnBadArgument);
    kr = IOConnectUnmapMemory64(conn, 0, mach_task_self(), 0x1000);
    if (kr != kIOReturnUnsupported) return bad("unmapping its memory", kr, kIOReturnUnsupported);
    kr = IOConnectSetNotificationPort(conn, 0, port, 0);
    if (kr != kIOReturnUnsupported) return bad("a notification port", kr, kIOReturnUnsupported);
    kr = trap0(conn, 0);
    if (kr != KERN_SUCCESS) return bad("a trap it has none of", kr, 0);

    // Closed (a second close is ignored); the client stays until its last
    // send right goes, which ends it: its registrations' rights go too.
    // (IOServiceClose lets one right go after closing; two more are kept.)
    mach_port_mod_refs(mach_task_self(), conn, MACH_PORT_RIGHT_SEND, 2);
    if (IOServiceClose(conn) != KERN_SUCCESS) return bad("closing", 0, 1);
    if (IOServiceClose(conn) != KERN_SUCCESS) return bad("closing again", 0, 1);
    nout = 0;
    kr = IOConnectCallScalarMethod(conn, 3, in, 1, out, &nout);
    if (kr != kIOReturnUnsupported) return bad("a method after closing", kr, kIOReturnUnsupported);
    mach_port_t keep = conn;
    mach_port_deallocate(mach_task_self(), conn);
    if (mach_port_type(mach_task_self(), keep, &type) == KERN_SUCCESS) return bad("the connection's name after its last right", type, 0);
    port_free(port);
    return 0;
}

static int memory_info_client(io_service_t accel) {
    io_connect_t conn = IO_OBJECT_NULL;
    kern_return_t kr = IOServiceOpen(accel, mach_task_self(), 33, &conn);
    if (kr != KERN_SUCCESS) return bad("opening type 33", kr, 0);
    io_name_t cls;
    if (IOObjectGetClass(conn, cls) != KERN_SUCCESS || strcmp(cls, "IOGPUMemoryInfoUserClient") != 0) return bad("the memory information client's class", 0, 1);
    // IOGPUFamily depends on IOSurface: no default locking property.
    if (IORegistryEntryCreateCFProperty(conn, CFSTR("IOUserClientDefaultLocking"), kCFAllocatorDefault, 0) != NULL) return bad("IOUserClientDefaultLocking", 1, 0);
    uint64_t out = 0;
    uint32_t nout = 1;
    kr = IOConnectCallScalarMethod(conn, 3, NULL, 0, &out, &nout);
    if (kr != kIOReturnBadArgument) return bad("memory information selector 3", kr, kIOReturnBadArgument);
    nout = 0;
    kr = IOConnectCallScalarMethod(conn, 2, &out, 1, NULL, &nout);
    if (kr != kIOReturnBadArgument) return bad("memory information selector 2 with a scalar", kr, kIOReturnBadArgument);
    if (trap0(conn, 0) != KERN_SUCCESS) return bad("a memory information trap", 1, 0);
    IOServiceClose(conn);
    return 0;
}

// IOGPU's device client: open with IOGPU.framework's type (1, the options in
// the high 16 bits), its class, its method gate (a selector past its table,
// an asynchronous call, a count its table does not take), its notification
// port (only type 0, and only for a notification queue it has), its traps,
// its memory, and the stamp memory its start maps read-only.
static int device_client(io_service_t accel) {
    io_connect_t conn = IO_OBJECT_NULL;
    kern_return_t kr = IOServiceOpen(accel, mach_task_self(), 1, &conn);
    if (kr != KERN_SUCCESS) return bad("opening type 1", kr, 0);
    io_name_t cls;
    if (IOObjectGetClass(conn, cls) != KERN_SUCCESS || strcmp(cls, "IOGPUDeviceUserClient") != 0) return bad("the device client's class", 0, 1);
    if (IORegistryEntryCreateCFProperty(conn, CFSTR("IOUserClientDefaultLocking"), kCFAllocatorDefault, 0) != NULL) return bad("IOUserClientDefaultLocking", 1, 0);

    uint64_t in[4] = {0}, out[2] = {0};
    uint32_t nout = 0;
    kr = IOConnectCallScalarMethod(conn, 50, in, 0, out, &nout);
    if (kr != kIOReturnUnsupported) return bad("selector 50", kr, kIOReturnUnsupported);
    char big[8192];
    size_t nbig = sizeof big;
    kr = IOConnectCallStructMethod(conn, 50, NULL, 0, big, &nbig);
    if (kr != kIOReturnIPCError) return bad("selector 50 with an out-of-line output", kr, kIOReturnIPCError);
    mach_port_t port = MACH_PORT_NULL;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    uint64_t ref[8] = {0};
    char cfg[64];
    size_t ncfg = sizeof cfg;
    kr = IOConnectCallAsyncStructMethod(conn, 0, port, ref, 8, NULL, 0, cfg, &ncfg);
    if (kr != kIOReturnBadArgument) return bad("an asynchronous call", kr, kIOReturnBadArgument);
    ncfg = 63;
    kr = IOConnectCallStructMethod(conn, 0, NULL, 0, cfg, &ncfg);
    if (kr != kIOReturnBadArgument) return bad("get config with 63 bytes of room", kr, kIOReturnBadArgument);
    nout = 0;
    kr = IOConnectCallScalarMethod(conn, 8, in, 2, out, &nout);
    if (kr != kIOReturnBadArgument) return bad("destroy command queue with two scalars", kr, kIOReturnBadArgument);

    kr = IOConnectSetNotificationPort(conn, 1, port, 0);
    if (kr != kIOReturnUnsupported) return bad("a notification port of type 1", kr, kIOReturnUnsupported);
    kr = IOConnectSetNotificationPort(conn, 0, port, 7);
    if (kr != kIOReturnBadArgument) return bad("a notification port for no queue", kr, kIOReturnBadArgument);
    if (trap0(conn, 4) != KERN_SUCCESS) return bad("trap 4", 1, 0);
    mach_vm_address_t addr = 0;
    mach_vm_size_t size = 0;
    kr = IOConnectMapMemory64(conn, 0, mach_task_self(), &addr, &size, kIOMapAnywhere);
    if (kr != kIOReturnBadArgument) return bad("mapping the device client's memory", kr, kIOReturnBadArgument);

    // What IOGPU.framework's IOGPUDeviceCreate asks for: the API (whose
    // method answers setProperty's 1), the stamps, the configuration.
    char api[16] = "Metal";
    kr = IOConnectCallStructMethod(conn, 6, api, sizeof api, NULL, NULL);
    if (kr != 1) return bad("setting the API", kr, 1);
    if (string_prop(conn, "API", "Metal")) return 1;
    unsigned char st[536];
    size_t nst = sizeof st;
    kr = IOConnectCallStructMethod(conn, 2, NULL, 0, st, &nst);
    if (kr != KERN_SUCCESS || nst != sizeof st) return bad("the stamps", kr, 0);
    uint64_t stamps;
    uint32_t sw[4];
    memcpy(&stamps, st, 8);
    memcpy(sw, st + 8, 16);
    if (sw[0] != 8 || sw[1] != 8 || sw[2] != 0 || sw[3] != 0) return bad("the stamp information", sw[0], 8);
    vm_address_t raddr = stamps;
    vm_size_t rsize = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t icount = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t obj = MACH_PORT_NULL;
    kr = vm_region_64(mach_task_self(), &raddr, &rsize, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &icount, &obj);
    if (kr != KERN_SUCCESS || raddr != stamps || rsize != 0x4000) return bad("the stamp mapping", (long)rsize, 0x4000);
    if (info.protection != VM_PROT_READ || info.max_protection != VM_PROT_READ || info.inheritance != VM_INHERIT_NONE) return bad("the stamp mapping's protection", info.protection, VM_PROT_READ);
    if (*(volatile uint64_t *)stamps != 0) return bad("the stamp memory", 1, 0);
    ncfg = sizeof cfg;
    kr = IOConnectCallStructMethod(conn, 0, NULL, 0, cfg, &ncfg);
    if (kr != KERN_SUCCESS || ncfg != 64) return bad("the configuration", kr, 0);
    uint32_t bits, accel_id;
    uint64_t shared, maxres, vram;
    memcpy(&bits, cfg, 4);
    memcpy(&vram, cfg + 16, 8);
    memcpy(&accel_id, cfg + 24, 4);
    memcpy(&shared, cfg + 32, 8);
    memcpy(&maxres, cfg + 40, 8);
    if (bits != 0x4340) return bad("the configuration bits", bits, 0x4340);
    if (vram != 0 || accel_id != 1) return bad("video memory and accelerator id", (long)vram, 0);
    // 4 GiB: two thirds wired, a quarter for one resource.
    if (shared != 0xaaaac000ull) return bad("the shared memory size", (long)shared, 0xaaaac000l);
    if (maxres != 0x40000000ull) return bad("the largest resource", (long)maxres, 0x40000000l);
    char gname[64];
    size_t nname = sizeof gname;
    kr = IOConnectCallStructMethod(conn, 1, NULL, 0, gname, &nname);
    if (kr != KERN_SUCCESS || strcmp(gname, "AGXG9G_A0") != 0) return bad("the name", kr, 0);
    uint64_t ids[2], ids2[2];
    size_t nids = sizeof ids;
    if (IOConnectCallStructMethod(conn, 5, NULL, 0, ids, &nids) != KERN_SUCCESS) return bad("trace ids", 1, 0);
    nids = sizeof ids2;
    if (IOConnectCallStructMethod(conn, 5, NULL, 0, ids2, &nids) != KERN_SUCCESS) return bad("more trace ids", 1, 0);
    if (ids[1] != ids[0] + 0x1000000 || ids2[0] != ids[1]) return bad("the trace id ranges", (long)ids2[0], (long)ids[1]);

    // What describes the device's use, and what the device keeps none of.
    unsigned char mem[48];
    size_t nmem = sizeof mem;
    memset(mem, 0xff, sizeof mem);
    kr = IOConnectCallStructMethod(conn, 22, NULL, 0, mem, &nmem);
    for (int i = 0; i < 48; i++)
        if (mem[i] != 0) return bad("the memory data", mem[i], 0);
    if (kr != KERN_SUCCESS) return bad("the memory data", kr, 0);
    nmem = sizeof mem;
    kr = IOConnectCallStructMethod(conn, 23, NULL, 0, mem, &nmem);
    if (kr != kIOReturnUnsupported) return bad("selector 23", kr, kIOReturnUnsupported);
    nout = 1;
    kr = IOConnectCallScalarMethod(conn, 24, NULL, 0, out, &nout);
    if (kr != KERN_SUCCESS || nout != 1 || out[0] != 0) return bad("the allocated size", kr, 0);
    uint64_t role[2] = {(uint64_t)getpid(), 2};
    kr = IOConnectCallScalarMethod(conn, 34, role, 2, NULL, NULL);
    if (kr != kIOReturnUnsupported) return bad("setting the app GPU role", kr, kIOReturnUnsupported);
    nout = 1;
    kr = IOConnectCallScalarMethod(conn, 35, role, 1, out, &nout);
    if (kr != kIOReturnUnsupported) return bad("getting the app GPU role", kr, kIOReturnUnsupported);
    kr = IOConnectCallScalarMethod(conn, 33, role, 2, NULL, NULL);
    if (kr != kIOReturnUnsupported) return bad("display parameters", kr, kIOReturnUnsupported);

    mach_port_mod_refs(mach_task_self(), conn, MACH_PORT_RIGHT_SEND, 1);
    IOServiceClose(conn);
    // Stopped: the stamps unmapped.
    raddr = stamps;
    icount = VM_REGION_BASIC_INFO_COUNT_64;
    kr = vm_region_64(mach_task_self(), &raddr, &rsize, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &icount, &obj);
    if (kr == KERN_SUCCESS && raddr == stamps) return bad("the stamp mapping after closing", (long)raddr, 0);
    // Closed, the client is stopped: its methods are not ready.
    ncfg = sizeof cfg;
    kr = IOConnectCallStructMethod(conn, 0, NULL, 0, cfg, &ncfg);
    if (kr != kIOReturnNotReady) return bad("a method after closing", kr, kIOReturnNotReady);
    mach_port_deallocate(mach_task_self(), conn);
    port_free(port);
    return 0;
}

// A client whose task is entitled to be restricted: its refused
// selectors (kIOReturnNotPermitted), the others still answered.
static int restricted_client(io_service_t accel) {
    io_connect_t conn = IO_OBJECT_NULL;
    kern_return_t kr = IOServiceOpen(accel, mach_task_self(), 1, &conn);
    if (kr != KERN_SUCCESS) return bad("opening type 1, restricted", kr, 0);
    uint64_t role[2] = {(uint64_t)getpid(), 2}, out = 0;
    kr = IOConnectCallScalarMethod(conn, 34, role, 2, NULL, NULL);
    if (kr != kIOReturnNotPermitted) return bad("a restricted app GPU role", kr, kIOReturnNotPermitted);
    unsigned char mem[48];
    size_t nmem = sizeof mem;
    kr = IOConnectCallStructMethod(conn, 22, NULL, 0, mem, &nmem);
    if (kr != kIOReturnNotPermitted) return bad("restricted memory data", kr, kIOReturnNotPermitted);
    uint32_t nout = 1;
    kr = IOConnectCallScalarMethod(conn, 24, NULL, 0, &out, &nout);
    if (kr != KERN_SUCCESS) return bad("a restricted client's allocated size", kr, 0);
    IOServiceClose(conn);
    return 0;
}

int main(int argc, char **argv) {
    // Metal.framework's _MTLRegisterDevices: every IOAcceleratorES.
    io_iterator_t it = IO_OBJECT_NULL;
    kern_return_t kr = IOServiceGetMatchingServices(kIOMainPortDefault, IOServiceMatching("IOAcceleratorES"), &it);
    if (kr != KERN_SUCCESS) return bad("matching IOAcceleratorES", kr, 0);
    io_service_t accel = IOIteratorNext(it);
    if (accel == IO_OBJECT_NULL) return bad("an accelerator", 0, 1);
    if (IOIteratorNext(it) != IO_OBJECT_NULL) return bad("one accelerator", 2, 1);
    IOObjectRelease(it);
    io_name_t cls;
    if (IOObjectGetClass(accel, cls) != KERN_SUCCESS || strcmp(cls, "WebMetalAccelerator") != 0) return bad("the accelerator's class", 0, 1);
    if (!IOObjectConformsTo(accel, "IOGPU") || !IOObjectConformsTo(accel, "IOAcceleratorES") || !IOObjectConformsTo(accel, "IOService")) return bad("the accelerator's superclasses", 0, 1);
    uint64_t accel_id = 0;
    IORegistryEntryGetRegistryEntryID(accel, &accel_id);

    // RunningBoard's: the first IOGPU, the same service.
    io_service_t gpu = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOGPU"));
    uint64_t gpu_id = 0;
    IORegistryEntryGetRegistryEntryID(gpu, &gpu_id);
    if (gpu == IO_OBJECT_NULL || gpu_id != accel_id) return bad("the IOGPU", (long)gpu_id, (long)accel_id);
    IOObjectRelease(gpu);

    // What Metal.framework reads, and what IOGPU::start sets.
    if (string_prop(accel, "MetalPluginName", "WebMetal") || string_prop(accel, "MetalPluginClassName", "WebMetalDevice") || string_prop(accel, "IOMatchCategory", "IOAcceleratorES") || string_prop(accel, "IOClass", "WebMetalAccelerator")) return 1;
    CFTypeRef kdebug = IORegistryEntryCreateCFProperty(accel, CFSTR("KDebugVersion"), kCFAllocatorDefault, 0);
    long long v = 0;
    if (kdebug == NULL || CFGetTypeID(kdebug) != CFNumberGetTypeID() || !CFNumberGetValue(kdebug, kCFNumberLongLongType, &v) || v != 0x100000000ll) return bad("KDebugVersion", v, 0x100000000ll);
    CFRelease(kdebug);

    // The types it does not make: IOGPU refuses them, and the service has
    // no IOUserClientClass.
    io_connect_t conn = IO_OBJECT_NULL;
    kr = IOServiceOpen(accel, mach_task_self(), 2, &conn);
    if (kr != kIOReturnUnsupported || conn != IO_OBJECT_NULL) return bad("opening type 2", kr, kIOReturnUnsupported);
    kr = IOServiceOpen(accel, mach_task_self(), 0x10000, &conn);
    if (kr != kIOReturnUnsupported) return bad("opening type 0x10000", kr, kIOReturnUnsupported);

    if (ancestors(accel)) return 1;

    if (argc > 1 && strcmp(argv[1], "restricted") == 0) {
        if (restricted_client(accel)) return 1;
    } else if (wire_client(accel, accel_id) || memory_info_client(accel) || device_client(accel)) {
        return 1;
    }

    IOObjectRelease(accel);
    printf("accel ok\n");
    return 0;
}
