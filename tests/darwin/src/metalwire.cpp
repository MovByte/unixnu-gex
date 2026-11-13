// The WebMetal connection's three channels (WebMetal wire/README.md,
// "Channels" and "Transport"), through the accelerator's user client of
// type 0 and the host executor behind it, with the records WebMetal's own
// header encodes:
// - control: Open, whose reply does not fit a small buffer and is fetched
//   with fetch_reply; CreateCommandQueue and CreateBuffer;
// - the command stream: a blit encoder filling part of a buffer in this
//   task's memory, committed with one call;
// - events: register_event_port's async completion (the message
//   IOUserClient::sendAsyncResult64 sends for a 64-bit task, with the queue
//   handle its argument), then FetchEvents' records: the command buffer
//   scheduled and completed, and the GPU's write in this task's memory.
#include <IOKit/IOKitLib.h>
#include <mach/mach.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <vector>

#include "WebMetalWire.h"

namespace wire = webmetal::wire;

static io_connect_t conn;

static int bad(const char *what, unsigned long long got, unsigned long long want) {
    printf("metalwire: %s: %#llx (want %#llx)\n", what, got, want);
    return 1;
}

template <class R>
static std::vector<uint8_t> encode(const R &r) {
    wire::Writer w;
    if (!wire::encode(w, r)) return {};
    return w.out;
}

// One control request; its reply in `out`, through fetch_reply when it is
// longer than `cap`.
static kern_return_t control(const std::vector<uint8_t> &req, std::vector<uint8_t> &out, size_t cap, bool *fetched) {
    std::vector<uint8_t> buf(cap ? cap : 1);
    uint64_t in[4] = {(uint64_t)req.data(), req.size(), (uint64_t)buf.data(), cap};
    uint64_t len = 0;
    uint32_t n = 1;
    kern_return_t kr = IOConnectCallScalarMethod(conn, 0, in, 4, &len, &n);
    if (kr != KERN_SUCCESS) return kr;
    *fetched = len > cap;
    if (len > cap) {
        buf.assign(len, 0);
        uint64_t f[2] = {(uint64_t)buf.data(), len};
        n = 1;
        kr = IOConnectCallScalarMethod(conn, 1, f, 2, &len, &n);
        if (kr != KERN_SUCCESS) return kr;
    }
    out.assign(buf.begin(), buf.begin() + len);
    return KERN_SUCCESS;
}

template <class Request, class ReplyFields>
static int call(const char *what, const Request &r, wire::Reply<ReplyFields> &reply) {
    std::vector<uint8_t> out;
    bool fetched = false;
    kern_return_t kr = control(encode(r), out, 4096, &fetched);
    if (kr != KERN_SUCCESS) return bad(what, kr, 0);
    if (!wire::decodeReply(out.data(), out.size(), reply)) return bad(what, out.size(), 0);
    if (!reply.ok) return bad(what, reply.failure.status, 0);
    return 0;
}

int main(void) {
    io_service_t accel = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOAcceleratorES"));
    if (!accel) return bad("the accelerator", 0, 1);
    kern_return_t kr = IOServiceOpen(accel, mach_task_self(), 0, &conn);
    if (kr != KERN_SUCCESS) return bad("opening type 0", kr, 0);

    // Open, with 16 bytes of room: the reply waits for fetch_reply.
    wire::Open open;
    memcpy(open.schemaHash.bytes.data(), wire::kSchemaHash.data(), 32);
    open.pid = getpid();
    std::vector<uint8_t> out;
    bool fetched = false;
    kr = control(encode(open), out, 16, &fetched);
    if (kr != KERN_SUCCESS) return bad("Open", kr, 0);
    if (!fetched) return bad("Open's reply fitting 16 bytes", out.size(), 0);
    wire::Reply<wire::OpenReply> opened;
    if (!wire::decodeReply(out.data(), out.size(), opened) || !opened.ok) return bad("Open's reply", out.size(), 0);
    if (memcmp(opened.value.schemaHash.bytes.data(), wire::kSchemaHash.data(), 32) != 0) return bad("the host's schema hash", 0, 1);

    const uint64_t queue = 1, buffer = 2, cb = 3, encoder = 4;
    wire::CreateCommandQueue cq;
    cq.queue = queue;
    wire::Reply<wire::CreateCommandQueueReply> cqr;
    if (call("CreateCommandQueue", cq, cqr)) return 1;

    // The queue's doorbell: a receive right of ours, a reference to see back.
    mach_port_t port = MACH_PORT_NULL;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port) != KERN_SUCCESS) return bad("a port", 0, 1);
    uint64_t ref[8] = {0, 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777};
    uint64_t qh = queue;
    kr = IOConnectCallAsyncScalarMethod(conn, 2, port, ref, 8, &qh, 1, NULL, NULL);
    if (kr != KERN_SUCCESS) return bad("register_event_port", kr, 0);

    // A shared buffer over a page of ours.
    vm_address_t page = 0;
    if (vm_allocate(mach_task_self(), &page, 0x4000, VM_FLAGS_ANYWHERE) != KERN_SUCCESS) return bad("a page", 0, 1);
    uint8_t *bytes = (uint8_t *)page;
    memset(bytes, 0x11, 256);
    wire::CreateBuffer cbuf;
    cbuf.buffer = buffer;
    cbuf.length = 256;
    cbuf.options = 0;
    cbuf.contents = page;
    wire::Reply<wire::CreateBufferReply> cbr;
    if (call("CreateBuffer", cbuf, cbr)) return 1;

    // The stream: fill bytes 16 to 47 with 0xab.
    wire::Writer s;
    wire::BeginBlit begin;
    begin.encoder = encoder;
    wire::BlitFillBuffer fill;
    fill.buffer = buffer;
    fill.range.location = 16;
    fill.range.length = 32;
    fill.value = 0xab;
    if (!wire::encode(s, begin) || !wire::encode(s, fill) || !wire::encode(s, wire::EncoderEndEncoding{})) return bad("the stream", 0, 1);
    wire::Commit commit;
    commit.commandBuffer = cb;
    commit.queue = queue;
    commit.retainedReferences = true;
    commit.stream = (uint64_t)s.out.data();
    commit.streamLength = s.out.size();
    uint64_t resources[1] = {buffer};
    commit.resources = {resources, 1};
    wire::Reply<wire::CommitReply> cr;
    if (call("Commit", commit, cr)) return 1;

    // The doorbell rings, and the queue's events are collected, until the
    // command buffer has completed.
    bool scheduled = false, completed = false;
    for (int rings = 0; !completed; rings++) {
        // The message: its header, then OSNotificationHeader64 (size, type,
        // the reference), the result and the one argument at 4-byte
        // alignment, 4 bytes of the structure's padding, and the trailer.
        union {
            mach_msg_header_t h;
            uint8_t raw[256];
        } msg;
        memset(&msg, 0, sizeof msg);
        kr = mach_msg(&msg.h, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof msg, port, 120000, MACH_PORT_NULL);
        if (kr != KERN_SUCCESS) return bad("the doorbell", kr, 0);
        if (msg.h.msgh_id != 53 || msg.h.msgh_size != 112) return bad("the doorbell's id and size", ((uint64_t)msg.h.msgh_id << 32) | msg.h.msgh_size, (53ull << 32) | 112);
        uint32_t size, type;
        uint64_t reference[8], arg;
        int32_t result;
        memcpy(&size, msg.raw + 24, 4);
        memcpy(&type, msg.raw + 28, 4);
        memcpy(reference, msg.raw + 32, 64);
        memcpy(&result, msg.raw + 96, 4);
        memcpy(&arg, msg.raw + 100, 8);
        if (type != 150 || size != 12 || result != 0 || arg != queue) return bad("the async completion", type, 150);
        if (reference[0] != 0 || reference[1] != 0x1111 || reference[7] != 0x7777) return bad("the async reference", reference[1], 0x1111);
        wire::FetchEvents fe;
        fe.queue = queue;
        wire::Reply<wire::FetchEventsReply> fr;
        if (call("FetchEvents", fe, fr)) return 1;
        size_t at = 0;
        const std::vector<uint8_t> &ev = fr.value.events;
        while (at < ev.size()) {
            wire::Event e;
            size_t used = 0;
            if (!wire::decodeEvent(ev.data() + at, ev.size() - at, e, &used)) return bad("an event record", at, 0);
            at += used;
            if (auto *x = std::get_if<wire::CommandBufferScheduled>(&e)) {
                if (x->commandBuffer != cb || x->failure.status != 0) return bad("the scheduled event", x->failure.status, 0);
                scheduled = true;
            } else if (auto *x = std::get_if<wire::CommandBufferCompleted>(&e)) {
                // MTLCommandBufferStatusCompleted.
                if (x->commandBuffer != cb || x->status != 4 || x->failure.status != 0) return bad("the completed event", x->status, 4);
                if (!scheduled) return bad("completed before scheduled", 0, 1);
                completed = true;
            } else {
                return bad("an unexpected event", e.index(), 0);
            }
        }
        if (rings > 8) return bad("rings without completion", rings, 0);
    }
    for (int i = 0; i < 256; i++) {
        uint8_t want = (i >= 16 && i < 48) ? 0xab : 0x11;
        if (bytes[i] != want) return bad("the buffer's bytes after the fill", ((uint64_t)i << 8) | bytes[i], ((uint64_t)i << 8) | want);
    }
    IOServiceClose(conn);
    printf("metalwire ok\n");
    return 0;
}
