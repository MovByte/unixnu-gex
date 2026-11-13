// priv_check_cred asks the MAC policies first: the platform profile's
// system-privilege denies PRIV_WORK_INTERVAL to a caller without
// com.apple.private.kernel.work-interval, root included, so this program
// (run as root, not entitled) is refused a work interval with EPERM, while
// the workinterval test, entitled, makes them.

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define SYS_WORK_INTERVAL_CTL 499
#define OP_CREATE2 4

struct create_params {
    uint64_t id;
    uint32_t port;
    uint32_t flags;
};

static long wi(uint32_t op, uint64_t id, void *arg, size_t len) {
    register long x0 __asm__("x0") = op, x1 __asm__("x1") = (long)id, x2 __asm__("x2") = (long)arg, x3 __asm__("x3") = (long)len;
    register long x16 __asm__("x16") = SYS_WORK_INTERVAL_CTL, cs __asm__("x9");
    __asm__ volatile("svc #0x80\n cset x9, cs" : "+r"(x0), "+r"(x1), "=r"(cs) : "r"(x2), "r"(x3), "r"(x16) : "x4", "x5", "x6", "x7", "x8", "x10", "x11", "x12", "x13", "x14", "x15", "x17", "memory", "cc");
    if (cs) {
        errno = (int)x0;
        return -1;
    }
    return x0;
}

int main(void) {
    struct create_params p;
    memset(&p, 0, sizeof p);
    errno = 0;
    long r = wi(OP_CREATE2, 0, &p, sizeof p);
    if (r != -1 || errno != EPERM) {
        printf("sbxpriv: CREATE2 as root, not entitled: %ld errno %d, want EPERM\n", r, errno);
        return 1;
    }
    printf("sbxpriv ok\n");
    return 0;
}
