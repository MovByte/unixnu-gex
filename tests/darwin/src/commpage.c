// libsystem reads the commpage at constant addresses: its signature, the
// CPU count and the page size must read back as the kernel wrote them.

#define SYS_exit 1
#define COMM_PAGE 0x0000000FFFFFC000UL
#define COMM_PAGE_RO 0x0000000FFFFF4000UL

static void bsd_exit(long status) {
    register long x0 __asm__("x0") = status;
    register long x16 __asm__("x16") = SYS_exit;
    __asm__ volatile("svc #0x80" : "+r"(x0) : "r"(x16) : "memory", "cc");
}

void start(void) {
    const volatile char *sig = (const volatile char *)COMM_PAGE;
    const char want[] = "commpage 64-bit";
    long status = 0;
    for (unsigned i = 0; i < sizeof want; i++) {
        if (sig[i] != want[i]) {
            status |= 1;
        }
    }
    if (*(const volatile unsigned char *)(COMM_PAGE + 0x22) == 0) {
        status |= 2;
    }
    if (*(const volatile unsigned char *)(COMM_PAGE_RO + 0x25) != 14) {
        status |= 4;
    }
    bsd_exit(status);
    for (;;) {
    }
}
