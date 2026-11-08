// ldxp/stxp on a W pair and an X pair: each loop reads both halves
// exclusively and writes them back incremented, as libsystem's 128-bit
// atomics do. The halves must come back as written. A store-exclusive
// whose monitor does not match (cleared, never set, or set for another
// address) reports failure and leaves memory as it was.

#define SYS_exit 1

static void bsd_exit(long status) {
    register long x0 __asm__("x0") = status;
    register long x16 __asm__("x16") = SYS_exit;
    __asm__ volatile("svc #0x80" : "+r"(x0) : "r"(x16) : "memory", "cc");
}

static unsigned long pair64[2] __attribute__((aligned(16))) = {1, 0x100000000UL};
static unsigned int pair32[2] __attribute__((aligned(8))) = {7, 9};
static unsigned long word = 5, other = 6;
static unsigned long pair_b[2] __attribute__((aligned(16))) = {11, 12};

void start(void) {
    for (int i = 0; i < 3; i++) {
        unsigned long lo, hi;
        unsigned int fail;
        do {
            __asm__ volatile("ldaxp %0, %1, [%3]\n\t"
                             "add %0, %0, #1\n\t"
                             "add %1, %1, #2\n\t"
                             "stlxp %w2, %0, %1, [%3]"
                             : "=&r"(lo), "=&r"(hi), "=&r"(fail)
                             : "r"(pair64)
                             : "memory");
        } while (fail);
        unsigned int a, b;
        do {
            __asm__ volatile("ldxp %w0, %w1, [%3]\n\t"
                             "add %w0, %w0, #1\n\t"
                             "add %w1, %w1, #1\n\t"
                             "stxp %w2, %w0, %w1, [%3]"
                             : "=&r"(a), "=&r"(b), "=&r"(fail)
                             : "r"(pair32)
                             : "memory");
        } while (fail);
    }
    long status = 0;
    unsigned int st;
    unsigned long v, w;
    // Cleared before the store.
    __asm__ volatile("clrex\n\tstxr %w0, %1, [%2]" : "=&r"(st) : "r"(7UL), "r"(&word) : "memory");
    if (st != 1 || word != 5) {
        status |= 4;
    }
    // Set for another address.
    __asm__ volatile("ldxr %1, [%3]\n\tstxr %w0, %2, [%4]" : "=&r"(st), "=&r"(v) : "r"(8UL), "r"(&other), "r"(&word) : "memory");
    if (st != 1 || word != 5 || other != 6) {
        status |= 8;
    }
    // A pair, cleared; a pair set for another address.
    __asm__ volatile("clrex\n\tstxp %w0, %1, %2, [%3]" : "=&r"(st) : "r"(1UL), "r"(2UL), "r"(pair_b) : "memory");
    if (st != 1 || pair_b[0] != 11 || pair_b[1] != 12) {
        status |= 16;
    }
    __asm__ volatile("ldxp %1, %2, [%5]\n\tstxp %w0, %3, %4, [%6]" : "=&r"(st), "=&r"(v), "=&r"(w) : "r"(1UL), "r"(2UL), "r"(pair64), "r"(pair_b) : "memory");
    if (st != 1 || pair_b[0] != 11 || pair_b[1] != 12) {
        status |= 32;
    }
    if (pair64[0] != 4 || pair64[1] != 0x100000006UL) {
        status |= 1;
    }
    if (pair32[0] != 10 || pair32[1] != 12) {
        status |= 2;
    }
    bsd_exit(status);
    for (;;) {
    }
}
