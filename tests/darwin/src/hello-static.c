// The smallest Darwin program: no dyld, no libSystem. BSD system calls are
// `svc #0x80` with the number in x16; the kernel sets the carry flag on an
// error, with the errno in x0.

#define SYS_exit 1
#define SYS_write 4

static long bsd(long nr, long a0, long a1, long a2) {
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x16 __asm__("x16") = nr;
    __asm__ volatile("svc #0x80" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x16) : "memory", "cc");
    return x0;
}

static const char msg[] = "hello from darwin\n";

void start(void) {
    bsd(SYS_write, 1, (long)msg, sizeof msg - 1);
    bsd(SYS_exit, 0, 0, 0);
    for (;;) {
    }
}
