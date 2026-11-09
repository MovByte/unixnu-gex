// __PAGEZERO: every arm64 program has 4 GiB of it, below which the map has
// nothing (load_machfile refuses a program without it and raises the map's
// minimum past it), so an access there faults: a store through a null
// pointer and a read just under 4 GiB each end the process with SIGSEGV.

#include <errno.h>
#include <mach/mach.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

static int bad(const char *what, long got, long want) {
    printf("pagezero: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

static int ends(int which) {
    pid_t pid = fork();
    if (pid == 0) {
        if (which == 0) *(volatile int *)0 = 1;
        else (void)*(volatile uint64_t *)(uintptr_t)0xfffff000u;
        _exit(0);
    }
    int st;
    if (pid < 0 || waitpid(pid, &st, 0) != pid) return -1;
    return WIFSIGNALED(st) ? WTERMSIG(st) : 0x100 | WEXITSTATUS(st);
}

int main(void) {
    int s;
    if ((s = ends(0)) != SIGSEGV) return bad("a store through a null pointer", s, SIGSEGV);
    if ((s = ends(1)) != SIGSEGV) return bad("a read under 4 GiB", s, SIGSEGV);

    // The page zero is the map's floor: nothing is placed under it, by
    // choice or on request.
    void *low = mmap((void *)0x10000000, 0x4000, PROT_READ, MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0);
    if (low != MAP_FAILED || errno != ENOMEM) return bad("a fixed mapping under 4 GiB", errno, ENOMEM);
    vm_address_t at = 0x10000000;
    kern_return_t kr = vm_allocate(mach_task_self(), &at, 0x4000, VM_FLAGS_FIXED);
    if (kr != KERN_INVALID_ADDRESS) return bad("a fixed allocation under 4 GiB", kr, KERN_INVALID_ADDRESS);
    void *any = mmap(NULL, 0x4000, PROT_READ, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (any == MAP_FAILED || (uintptr_t)any < 0x100000000u) return bad("an anywhere mapping under 4 GiB", (long)(uintptr_t)any, 0x100000000);
    at = 0;
    if ((kr = vm_allocate(mach_task_self(), &at, 0x4000, VM_FLAGS_ANYWHERE)) != KERN_SUCCESS || at < 0x100000000u) return bad("an anywhere allocation under 4 GiB", (long)at, 0x100000000);
    printf("pagezero ok\n");
    return 0;
}
