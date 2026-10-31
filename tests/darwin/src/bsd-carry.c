// Darwin reports a failed system call with the carry flag set and the
// errno in x0, and a successful one with carry clear. A write to a closed
// descriptor must come back with carry set and EBADF (9); one to stdout
// with carry clear and the byte count.

#define SYS_exit 1
#define SYS_write 4
#define EBADF 9

struct ret {
    long x0;
    long carry;
};

static struct ret bsd(long nr, long a0, long a1, long a2) {
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x16 __asm__("x16") = nr;
    long carry;
    __asm__ volatile("svc #0x80\n\tcset %1, cs"
                     : "+r"(x0), "=r"(carry)
                     : "r"(x1), "r"(x2), "r"(x16)
                     : "memory", "cc");
    return (struct ret){x0, carry};
}

static const char ok[] = "carry ok\n";

void start(void) {
    struct ret bad = bsd(SYS_write, 99, (long)ok, 1);
    struct ret good = bsd(SYS_write, 1, (long)ok, sizeof ok - 1);
    long status = 0;
    if (!bad.carry || bad.x0 != EBADF) {
        status |= 1;
    }
    if (good.carry || good.x0 != (long)(sizeof ok - 1)) {
        status |= 2;
    }
    bsd(SYS_exit, status, 0, 0);
    for (;;) {
    }
}
