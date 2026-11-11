// host_set_atm_diagnostic_flag (routine 225): refused without its
// entitlement; with it, the flag every process's commpage carries, read
// back through host_get_atm_diagnostic_flag. And host_create_mach_voucher
// is routine 222: an empty recipe makes no voucher.

#include <mach/mach.h>
#include <mach/mig_errors.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

extern mach_msg_return_t mach_msg2_internal(void *data, uint64_t option64, uint64_t bits_and_send_size,
    uint64_t remote_and_local_port, uint64_t voucher_and_id, uint64_t desc_count_and_rcv_name,
    uint64_t rcv_size_and_priority, uint64_t timeout);

static int bad(const char *what, long got, long want) {
    printf("atmflag: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

// host_create_mach_voucher by hand, as its MIG stub sends it (a kernel
// object's call): no recipes. Its reply's code, and the voucher if any.
static kern_return_t create_voucher_raw(mach_port_t host, mach_port_t *voucher) {
    const uint64_t send_msg = 1, rcv_msg = 2, kobject_call = 0x200000000ull;
    union {
        struct {
            mach_msg_header_t head;
            NDR_record_t ndr;
            mach_msg_type_number_t count;
        } req;
        struct {
            mach_msg_header_t head;
            mach_msg_body_t body;
            mach_msg_port_descriptor_t port;
        } ok;
        mig_reply_error_t error;
        char room[512];
    } m;
    memset(&m, 0, sizeof m);
    mach_port_t reply = mig_get_reply_port();
    uint32_t bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    m.req.head.msgh_bits = bits;
    m.req.head.msgh_size = sizeof m.req;
    m.req.head.msgh_remote_port = host;
    m.req.head.msgh_local_port = reply;
    m.req.head.msgh_id = 222;
    m.req.ndr = NDR_record;
    m.req.count = 0;
    kern_return_t kr = mach_msg2_internal(&m, send_msg | rcv_msg | kobject_call,
        (uint64_t)sizeof m.req << 32 | bits, (uint64_t)reply << 32 | host,
        (uint64_t)222 << 32, (uint64_t)reply << 32, sizeof m, 0);
    if (kr != KERN_SUCCESS) return kr;
    if (m.ok.head.msgh_id != 322) return -(int)m.ok.head.msgh_id;
    if (m.ok.head.msgh_bits & MACH_MSGH_BITS_COMPLEX) {
        *voucher = m.ok.port.name;
        return KERN_SUCCESS;
    }
    return m.error.RetCode;
}

int main(int argc, char **argv) {
    int entitled = argc > 1 && !strcmp(argv[1], "entitled");
    host_t host = mach_host_self();
    uint32_t flag = 0xffffffff;
    kern_return_t kr = host_get_atm_diagnostic_flag(host, &flag);
    if (kr != KERN_SUCCESS) return bad("reading the flag", kr, 0);
    // Zero at boot, with no boot argument or default for it (a system
    // already up may have had it set).
    if (entitled && flag != 0) return bad("the flag at boot", flag, 0);
    kr = host_set_atm_diagnostic_flag(host, 5);
    if (!entitled) {
        if (kr != KERN_NO_ACCESS) return bad("setting it unentitled", kr, KERN_NO_ACCESS);
    } else {
        if (kr != KERN_SUCCESS) return bad("setting it", kr, 0);
        // The commpage has it within a scheduler tick or so.
        for (int i = 0; i < 100 && flag != 5; i++) {
            host_get_atm_diagnostic_flag(host, &flag);
            if (flag != 5) usleep(10000);
        }
        if (flag != 5) return bad("the flag read back", flag, 5);
        host_set_atm_diagnostic_flag(host, 0);
    }

    mach_port_t v = 1;
    kr = create_voucher_raw(host, &v);
    if (kr != KERN_SUCCESS) return bad("host_create_mach_voucher with no recipes", kr, 0);
    if (v != MACH_PORT_NULL) return bad("its voucher", v, 0);

    printf("atmflag ok\n");
    return 0;
}
