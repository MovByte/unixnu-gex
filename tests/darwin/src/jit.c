// MAP_JIT for a platform program holding dynamic-codesigning: the map's one
// JIT region, at a random address, writable and executable at once; code
// written there runs, and runs again rewritten; mprotect keeps both on it.
// A second JIT region, or one asked for fixed or shared, is EINVAL, and so
// is a new one after the first is unmapped (the map has had its region).
// Inherited by a fork's child (VM_INHERIT_COPY), its copy is no JIT region:
// it has its bytes but no execute access, nor may it be given it (EACCES).
// VM_FLAGS_RANDOM_ADDR places an allocation anywhere free.

#include <errno.h>
#include <libkern/OSCacheControl.h>
#include <mach/mach.h>
#include <stdint.h>
#include <stdio.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

static int bad(const char *what, long got, long want) {
    printf("jit: %s: %#lx, want %#lx\n", what, got, want);
    return 1;
}

// `mov w0, #imm`, then `ret`.
static int run(uint32_t *code, int imm) {
    code[0] = 0x52800000u | ((uint32_t)imm << 5);
    code[1] = 0xd65f03c0u;
    sys_icache_invalidate(code, 8);
    return ((int (*)(void))code)();
}

int main(void) {
    const size_t len = 4 * 16384;
    const int rwx = PROT_READ | PROT_WRITE | PROT_EXEC;
    uint32_t *p = mmap(NULL, len, rwx, MAP_ANON | MAP_PRIVATE | MAP_JIT, -1, 0);
    if (p == MAP_FAILED) return bad("MAP_JIT", errno, 0);
    if ((uintptr_t)p & 16383) return bad("its alignment", (long)p, 0);
    if (run(p, 42) != 42) return bad("its code", 0, 42);
    if (run(p, 7) != 7) return bad("its code rewritten", 0, 7);
    void *q = mmap(NULL, 16384, rwx, MAP_ANON | MAP_PRIVATE | MAP_JIT, -1, 0);
    if (q != MAP_FAILED || errno != EINVAL) return bad("a second JIT region", errno, EINVAL);
    q = mmap((void *)0x300000000, 16384, rwx, MAP_ANON | MAP_PRIVATE | MAP_JIT | MAP_FIXED, -1, 0);
    if (q != MAP_FAILED || errno != EINVAL) return bad("a fixed JIT region", errno, EINVAL);
    q = mmap(NULL, 16384, rwx, MAP_ANON | MAP_SHARED | MAP_JIT, -1, 0);
    if (q != MAP_FAILED || errno != EINVAL) return bad("a shared JIT region", errno, EINVAL);
    if (mprotect(p, len, PROT_READ | PROT_WRITE) || mprotect(p, len, rwx)) return bad("mprotect", errno, 0);
    if (run(p, 1) != 1) return bad("its code after mprotect", 0, 1);
    if (minherit(p, len, VM_INHERIT_COPY)) return bad("minherit", errno, 0);
    // The child's copy: its bytes, no execute access (running it faults),
    // and none to be had.
    for (int i = 0; i < 2; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            if (p[0] != (0x52800000u | (1u << 5))) _exit(12);
            if (mprotect(p, len, rwx) != -1 || errno != EACCES) _exit(13);
            if (i == 1) ((int (*)(void))p)();
            _exit(0);
        }
        int st;
        if (pid < 0 || waitpid(pid, &st, 0) != pid) return bad("fork", errno, 0);
        if (i == 0 && (!WIFEXITED(st) || WEXITSTATUS(st) != 0)) return bad("the child's copy", WIFEXITED(st) ? WEXITSTATUS(st) : -1, 0);
        if (i == 1 && (!WIFSIGNALED(st) || (WTERMSIG(st) != SIGBUS && WTERMSIG(st) != SIGSEGV))) return bad("running the child's copy", st, SIGBUS);
    }
    munmap(p, len);
    q = mmap(NULL, 16384, rwx, MAP_ANON | MAP_PRIVATE | MAP_JIT, -1, 0);
    if (q != MAP_FAILED || errno != EINVAL) return bad("a JIT region after the first", errno, EINVAL);
    vm_address_t a = 0, b = 0;
    kern_return_t kr = vm_allocate(mach_task_self(), &a, 16384, VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR);
    if (kr || (a & 16383) || a == 0) return bad("VM_FLAGS_RANDOM_ADDR", kr, 0);
    if ((kr = vm_allocate(mach_task_self(), &b, 16384, VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR)) || b == a) return bad("another", kr, 0);
    *(volatile int *)a = 1;
    *(volatile int *)b = 2;
    printf("jit ok\n");
    return 0;
}
