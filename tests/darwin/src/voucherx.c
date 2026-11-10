// Vouchers between processes: a child's voucher sent to its parent and
// back, each received with MACH_RCV_VOUCHER, the bank accounts the sends
// and receives make (holder, merchant, originator and proximate process),
// what they say of themselves, and who may redeem them. A platform binary
// passes the originator it was given on; another sends as the originator
// itself.

#include <mach/mach.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

kern_return_t mach_voucher_extract_attr_content(mach_port_t, uint32_t, uint8_t *, mach_msg_type_number_t *);
kern_return_t mach_voucher_attr_command(mach_port_t, uint32_t, uint32_t, uint8_t *, mach_msg_type_number_t, uint8_t *, mach_msg_type_number_t *);
int csops(pid_t, unsigned int, void *, size_t);

#define BANK_CREATE 610
#define BANK_ORIGINATOR_PID 1
#define BANK_PERSONA_TOKEN 2
#define BANK_PERSONA_ID 3
#define BANK_ORIGINATOR_PROXIMATE_PID 5
#define PERSONA_ID_NONE 0xffffffffu
#define CS_OPS_STATUS 0
#define CS_PLATFORM_BINARY 0x04000000

static int bad(const char *who, const char *what, long got, long want) {
    printf("voucherx: %s: %s: %ld, want %ld\n", who, what, got, want);
    fflush(stdout);
    return 1;
}

typedef struct {
    mach_msg_header_t h;
    mach_msg_trailer_t t;
    char pad[64];
} rmsg;

static kern_return_t send(mach_port_t to, mach_port_t reply, mach_port_t voucher, int id) {
    mach_msg_header_t h = {0};
    h.msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND, reply ? MACH_MSG_TYPE_MAKE_SEND : 0, voucher ? MACH_MSG_TYPE_COPY_SEND : 0, 0);
    h.msgh_remote_port = to;
    h.msgh_local_port = reply;
    h.msgh_voucher_port = voucher;
    h.msgh_size = sizeof h;
    h.msgh_id = id;
    return mach_msg(&h, MACH_SEND_MSG, sizeof h, 0, 0, 0, 0);
}

static int command(mach_port_t v, uint32_t cmd, uint8_t *out, mach_msg_type_number_t *n) {
    return mach_voucher_attr_command(v, MACH_VOUCHER_ATTR_KEY_BANK, cmd, NULL, 0, out, n);
}

// The voucher's bank account as the holder, merchant, originator and
// proximate pids say it, and as the redeeming process may take it.
static int check_account(const char *who, mach_port_t v, int holder, int merchant, int originator, int proximate) {
    int fail = 0;
    uint8_t buf[512];
    mach_msg_type_number_t n = sizeof buf;
    kern_return_t kr = mach_voucher_extract_attr_content(v, MACH_VOUCHER_ATTR_KEY_BANK, buf, &n);
    char want[256];
    snprintf(want, sizeof want, " Bank Account linking holder pid %d with merchant pid %d, originator PID/persona: %d, %u and proximate PID/persona: %d, %u\n", holder, merchant, originator, PERSONA_ID_NONE, proximate, PERSONA_ID_NONE);
    if (kr != KERN_SUCCESS || n != strlen(want) + 1 || strcmp((char *)buf, want)) {
        printf("voucherx: %s: content (%d, %u) \"%s\"\n", who, kr, n, kr ? "" : (char *)buf);
        fflush(stdout);
        fail = 1;
    }
    int32_t pids[2] = {0, 0};
    n = sizeof pids;
    kr = command(v, BANK_ORIGINATOR_PID, (uint8_t *)pids, &n);
    fail |= kr != KERN_SUCCESS || n != 4 || pids[0] != holder ? bad(who, "originator pid", pids[0], holder) : 0;
    n = sizeof pids;
    kr = command(v, BANK_ORIGINATOR_PROXIMATE_PID, (uint8_t *)pids, &n);
    fail |= kr != KERN_SUCCESS || n != 8 || pids[0] != holder || pids[1] != proximate ? bad(who, "proximate pid", pids[1], proximate) : 0;
    uint32_t id = 0;
    n = sizeof id;
    kr = command(v, BANK_PERSONA_ID, (uint8_t *)&id, &n);
    fail |= kr != KERN_SUCCESS || id != PERSONA_ID_NONE ? bad(who, "persona id", id, PERSONA_ID_NONE) : 0;
    // struct persona_token: the originator's proc_persona_info, then the
    // proximate process's (unique_pid, pid, flags, pidversion, persona_id,
    // uid, gid, macho_uuid).
    uint8_t token[96];
    n = sizeof token;
    kr = command(v, BANK_PERSONA_TOKEN, token, &n);
    if (kr != KERN_SUCCESS || n != 96) {
        fail |= bad(who, "persona token", kr, 0);
    } else {
        for (int i = 0; i < 2; i++) {
            int32_t pid;
            uint32_t persona, uid, gid;
            memcpy(&pid, token + 48 * i + 8, 4);
            memcpy(&persona, token + 48 * i + 20, 4);
            memcpy(&uid, token + 48 * i + 24, 4);
            memcpy(&gid, token + 48 * i + 28, 4);
            int want_pid = i ? proximate : originator;
            fail |= pid != want_pid ? bad(who, "token pid", pid, want_pid) : 0;
            fail |= persona != PERSONA_ID_NONE ? bad(who, "token persona", persona, PERSONA_ID_NONE) : 0;
            fail |= uid != getuid() || gid != getgid() ? bad(who, "token ids", uid, getuid()) : 0;
        }
    }
    // A redeem is the merchant's alone.
    mach_voucher_attr_recipe_data_t r = {MACH_VOUCHER_ATTR_KEY_BANK, MACH_VOUCHER_ATTR_REDEEM, v, 0};
    mach_port_t rv = MACH_PORT_NULL;
    kr = host_create_mach_voucher(mach_host_self(), (mach_voucher_attr_raw_recipe_array_t)&r, sizeof r, &rv);
    int want_kr = getpid() == merchant ? KERN_SUCCESS : KERN_INVALID_CAPABILITY;
    fail |= kr != want_kr ? bad(who, "redeem", kr, want_kr) : 0;
    if (kr == KERN_SUCCESS) {
        // The same account, deduplicated to the same voucher.
        fail |= rv != v ? bad(who, "redeemed voucher", rv, v) : 0;
        mach_port_deallocate(mach_task_self(), rv);
    }
    return fail;
}

int main(void) {
    int fail = 0;
    mach_port_t p;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &p);
    mach_port_insert_right(mach_task_self(), p, p, MACH_MSG_TYPE_MAKE_SEND);
    mach_port_t saved;
    task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &saved);
    task_set_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, p);
    int parent = getpid();
    pid_t c = fork();
    if (c == 0) {
        int child = getpid();
        mach_port_t bp, mine;
        task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &bp);
        mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &mine);
        // A voucher of the child's own bank context.
        mach_voucher_attr_recipe_data_t r[2] = {
            {MACH_VOUCHER_ATTR_KEY_IMPORTANCE, MACH_VOUCHER_ATTR_IMPORTANCE_SELF, 0, 0},
            {MACH_VOUCHER_ATTR_KEY_BANK, BANK_CREATE, 0, 0},
        };
        mach_port_t v = MACH_PORT_NULL;
        kern_return_t kr = host_create_mach_voucher(mach_host_self(), (mach_voucher_attr_raw_recipe_array_t)r, sizeof r, &v);
        if (kr != KERN_SUCCESS) _exit(bad("child", "create", kr, 0));
        uint8_t buf[512];
        mach_msg_type_number_t n = sizeof buf;
        kr = mach_voucher_extract_attr_content(v, MACH_VOUCHER_ATTR_KEY_IMPORTANCE, buf, &n);
        char want[64];
        snprintf(want, sizeof want, "Importance for pid %d", child);
        if (kr != KERN_SUCCESS || strcmp((char *)buf, want) || n != strlen(want) + 1) fail |= bad("child", "importance content", kr, 0);
        // The default task value names the child's own context.
        int32_t pid = 0;
        n = sizeof pid;
        kr = command(v, BANK_ORIGINATOR_PID, (uint8_t *)&pid, &n);
        fail |= kr != KERN_SUCCESS || pid != child ? bad("child", "own originator", pid, child) : 0;
        n = sizeof buf;
        kr = mach_voucher_extract_attr_content(v, MACH_VOUCHER_ATTR_KEY_BANK, buf, &n);
        snprintf(want, sizeof want, " Bank Context for a pid %d\n", child);
        if (kr != KERN_SUCCESS || strcmp((char *)buf, want)) fail |= bad("child", "bank content", kr, 0);
        fail |= (kr = send(bp, mine, v, 1)) != KERN_SUCCESS ? bad("child", "send", kr, 0) : 0;
        // The voucher comes back from the parent, which sent it on: an
        // account whose holder is this process, with the parent as
        // proximate process, and as originator unless it may pass the
        // child on as that (bank_task_is_propagate_entitled).
        uint32_t cs = 0;
        csops(parent, CS_OPS_STATUS, &cs, sizeof cs);
        int originator = cs & CS_PLATFORM_BINARY ? child : parent;
        rmsg m;
        kr = mach_msg(&m.h, MACH_RCV_MSG | MACH_RCV_VOUCHER, 0, sizeof m, mine, 0, 0);
        if (kr != KERN_SUCCESS) _exit(bad("child", "receive", kr, 0));
        fail |= MACH_MSGH_BITS_VOUCHER(m.h.msgh_bits) != MACH_MSG_TYPE_MOVE_SEND ? bad("child", "voucher bits", m.h.msgh_bits, 0) : 0;
        fail |= check_account("child", m.h.msgh_voucher_port, child, child, originator, parent);
        // Without MACH_RCV_VOUCHER the voucher is not received.
        fail |= (kr = send(bp, 0, v, 3)) != KERN_SUCCESS ? bad("child", "send 2", kr, 0) : 0;
        _exit(fail);
    }
    task_set_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, saved);
    rmsg m;
    kern_return_t kr = mach_msg(&m.h, MACH_RCV_MSG | MACH_RCV_VOUCHER, 0, sizeof m, p, 0, 0);
    if (kr != KERN_SUCCESS) return bad("parent", "receive", kr, 0);
    mach_port_t v = m.h.msgh_voucher_port, reply = m.h.msgh_remote_port;
    // Received: an account of the child's (holder, originator and
    // proximate process) with this process as merchant.
    fail |= MACH_MSGH_BITS_VOUCHER(m.h.msgh_bits) != MACH_MSG_TYPE_MOVE_SEND ? bad("parent", "voucher bits", m.h.msgh_bits, 0) : 0;
    fail |= check_account("parent", v, c, parent, c, c);
    // Importance the message did not carry is not in the voucher.
    uint8_t buf[64];
    mach_msg_type_number_t n = sizeof buf;
    kr = mach_voucher_extract_attr_content(v, MACH_VOUCHER_ATTR_KEY_IMPORTANCE, buf, &n);
    fail |= kr != KERN_SUCCESS || n != 0 ? bad("parent", "importance", n, 0) : 0;
    fail |= (kr = send(reply, 0, v, 2)) != KERN_SUCCESS ? bad("parent", "send back", kr, 0) : 0;
    kr = mach_msg(&m.h, MACH_RCV_MSG, 0, sizeof m, p, 0, 0);
    fail |= kr != KERN_SUCCESS || m.h.msgh_id != 3 ? bad("parent", "receive 2", kr, 0) : 0;
    fail |= m.h.msgh_voucher_port != MACH_PORT_NULL || MACH_MSGH_BITS_VOUCHER(m.h.msgh_bits) != 0 ? bad("parent", "no voucher", m.h.msgh_voucher_port, 0) : 0;
    int st;
    waitpid(c, &st, 0);
    fail |= !WIFEXITED(st) || WEXITSTATUS(st) ? bad("parent", "child", st, 0) : 0;
    if (!fail) printf("voucherx ok\n");
    return fail;
}
