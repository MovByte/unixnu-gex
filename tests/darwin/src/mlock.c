// mlock and munlock: a user wiring counted per entry and read back through
// vm_region_basic_info_64, clipping the entry, the limit RLIMIT_MEMLOCK puts
// on it, holes, a fork's child, and mlockall's absence.

#include <errno.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#define PAGE 0x4000UL

static int bad(const char *what, long got, long want) {
    printf("mlock: %s: %#lx, want %#lx\n", what, got, want);
    return 1;
}

static int expect(const char *what, long r, int e) {
    if (r != -1 || errno != e) return bad(what, r == -1 ? errno : r, e);
    return 0;
}

// The entry at `at`: its start, size and user wire count.
static int region(uintptr_t at, vm_address_t *start, vm_size_t *size, unsigned *wired) {
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object;
    *start = at;
    kern_return_t kr = vm_region_64(mach_task_self(), start, size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count, &object);
    if (kr) return kr;
    *wired = info.user_wired_count;
    return 0;
}

int main(void) {
    char *p = mmap(NULL, 4 * PAGE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (p == MAP_FAILED) return bad("mmap", errno, 0);
    vm_address_t start;
    vm_size_t size;
    unsigned wired;

    if (region((uintptr_t)p, &start, &size, &wired) || wired != 0) return bad("before", wired, 0);
    if (mlock(p + PAGE, 16) != 0) return bad("mlock", errno, 0);
    // The range is rounded out to pages and the entry clipped to it.
    if (region((uintptr_t)p, &start, &size, &wired) || wired != 0 || size != PAGE) return bad("the page before", size, PAGE);
    if (region((uintptr_t)p + PAGE, &start, &size, &wired) || wired != 1 || size != PAGE) return bad("the page wired", wired, 1);
    if (mlock(p + PAGE, PAGE) != 0 || region((uintptr_t)p + PAGE, &start, &size, &wired) || wired != 2) return bad("wired twice", wired, 2);
    if (munlock(p + PAGE, PAGE) != 0 || region((uintptr_t)p + PAGE, &start, &size, &wired) || wired != 1) return bad("one wiring off", wired, 1);
    if (munlock(p + PAGE, PAGE) != 0 || region((uintptr_t)p + PAGE, &start, &size, &wired) || wired != 0) return bad("none left", wired, 0);
    if (munlock(p + PAGE, PAGE) != 0) return bad("munlock of an unwired page", errno, 0);

    // Empty, overflowing and unmapped.
    if (mlock(p, 0) != 0) return bad("an empty mlock", errno, 0);
    if (expect("an overflowing mlock", mlock((void *)-PAGE, 2 * PAGE), EINVAL)) return 1;
    if (expect("an overflowing munlock", munlock((void *)-PAGE, 2 * PAGE), EINVAL)) return 1;
    char *hole = mmap(NULL, 3 * PAGE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    munmap(hole + PAGE, PAGE);
    if (expect("mlock over a hole", mlock(hole, 3 * PAGE), ENOMEM)) return 1;
    // What came before the hole is not left wired.
    if (region((uintptr_t)hole, &start, &size, &wired) || wired != 0) return bad("before the hole", wired, 0);
    if (expect("mlock of nothing", mlock(hole + PAGE, PAGE), ENOMEM)) return 1;
    if (expect("munlock of nothing", munlock(hole + PAGE, PAGE), ENOMEM)) return 1;
    if (munlock(hole, 3 * PAGE) != 0) return bad("munlock starting in an entry", errno, 0);

    // PROT_NONE memory wires: mlock asks for no access.
    char *none = mmap(NULL, PAGE, PROT_NONE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (mlock(none, PAGE) != 0 || region((uintptr_t)none, &start, &size, &wired) || wired != 1) return bad("no access", errno, 0);
    munlock(none, PAGE);

    // The limit, counted once however many wirings an entry has; unmapping
    // gives it back.
    struct rlimit rl;
    getrlimit(RLIMIT_MEMLOCK, &rl);
    struct rlimit small = {2 * PAGE, rl.rlim_max};
    if (setrlimit(RLIMIT_MEMLOCK, &small) != 0) return bad("setrlimit", errno, 0);
    char *q = mmap(NULL, 4 * PAGE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (mlock(q, 2 * PAGE) != 0) return bad("up to the limit", errno, 0);
    if (mlock(q, 2 * PAGE) != 0) return bad("the same pages again", errno, 0);
    if (expect("past the limit", mlock(q + 2 * PAGE, PAGE), EAGAIN)) return 1;
    if (munmap(q, 2 * PAGE) != 0) return bad("munmap", errno, 0);
    if (mlock(q + 2 * PAGE, PAGE) != 0) return bad("after the unmap", errno, 0);
    munlock(q + 2 * PAGE, PAGE);

    // A fork's child has no wirings of its own.
    if (mlock(p, PAGE) != 0) return bad("mlock", errno, 0);
    pid_t pid = fork();
    if (pid == 0) {
        if (region((uintptr_t)p, &start, &size, &wired) || wired != 0) _exit(11);
        if (munlock(p, PAGE) != 0) _exit(12);
        _exit(0);
    }
    int st;
    if (waitpid(pid, &st, 0) != pid || st != 0) return bad("the child", st, 0);
    if (region((uintptr_t)p, &start, &size, &wired) || wired != 1) return bad("the parent's still", wired, 1);
    setrlimit(RLIMIT_MEMLOCK, &rl);

    if (expect("mlockall", mlockall(MCL_CURRENT), ENOSYS)) return 1;
    if (expect("munlockall", munlockall(), ENOSYS)) return 1;
    puts("mlock ok");
    return 0;
}
