// vm_protect with VM_PROT_COPY: a read-only private mapping and one of a
// shared file become the task's own copy, writable, the file untouched; an
// executable copy is refused only where write and execute fail (not on
// iOS). Also a port's context read and set by the mach_port routines.

#include <TargetConditionals.h>
#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <mach/mach_port.h>
#include <mach/vm_map.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define PAGE 0x4000UL

static int bad(const char *what, long got, long want) {
    printf("vmcopy: %s: %#lx, want %#lx\n", what, got, want);
    return 1;
}

static int region(void *at, vm_prot_t *cur, vm_prot_t *max) {
    vm_address_t a = (vm_address_t)at;
    vm_size_t size;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object;
    kern_return_t kr = vm_region_64(mach_task_self(), &a, &size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count, &object);
    if (kr) return kr;
    *cur = info.protection;
    *max = info.max_protection;
    return 0;
}

int main(void) {
    char path[256];
    snprintf(path, sizeof path, "/private/var/tmp/vmcopy-%d", getpid());
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0 || ftruncate(fd, 2 * PAGE) != 0) return bad("file", errno, 0);
    if (pwrite(fd, "original", 8, 0) != 8) return bad("pwrite", errno, 0);

    // A read-only shared mapping cannot be written, and its maximum says so.
    int ro = open(path, O_RDONLY);
    char *m = mmap(NULL, 2 * PAGE, PROT_READ, MAP_FILE | MAP_SHARED, ro, 0);
    if (m == MAP_FAILED) return bad("mmap", errno, 0);
    vm_prot_t cur, max;
    if (region(m, &cur, &max) || cur != VM_PROT_READ) return bad("before", cur, VM_PROT_READ);
    if (max & VM_PROT_WRITE) return bad("the maximum before", max, 0);
    kern_return_t kr = vm_protect(mach_task_self(), (vm_address_t)m, PAGE, FALSE, VM_PROT_READ | VM_PROT_WRITE);
    if (kr != KERN_PROTECTION_FAILURE) return bad("write without a copy", kr, KERN_PROTECTION_FAILURE);

    // With VM_PROT_COPY: the task's own, writable, the page's data kept.
    kr = vm_protect(mach_task_self(), (vm_address_t)m, PAGE, FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) return bad("VM_PROT_COPY", kr, 0);
    if (memcmp(m, "original", 8)) return bad("the data kept", m[0], 'o');
    if (region(m, &cur, &max) || cur != (VM_PROT_READ | VM_PROT_WRITE) || !(max & VM_PROT_WRITE)) return bad("after", cur, 3);
    m[0] = 'X';
    m[PAGE - 1] = 'Y';

    // The rest of the mapping is still the shared one, read-only.
    if (region(m + PAGE, &cur, &max) || cur != VM_PROT_READ) return bad("the page beyond", cur, VM_PROT_READ);

    // The file did not see the write.
    msync(m, PAGE, MS_SYNC);
    char got[8] = {0};
    if (pread(fd, got, 8, 0) != 8 || memcmp(got, "original", 8)) return bad("the file", got[0], 'o');
    if (pread(fd, got, 1, PAGE - 1) != 1 || got[0] != 0) return bad("its last byte", got[0], 0);

    // An executable copy: refused where write and execute fail
    // (VM_MAP_POLICY_WX_FAIL, macOS's own maps), made on iOS.
    kr = vm_protect(mach_task_self(), (vm_address_t)m + PAGE, PAGE, FALSE, VM_PROT_READ | VM_PROT_EXECUTE | VM_PROT_COPY);
#if TARGET_OS_OSX
    if (kr != KERN_PROTECTION_FAILURE) return bad("an executable copy", kr, KERN_PROTECTION_FAILURE);
#else
    if (kr != KERN_SUCCESS) return bad("an executable copy", kr, KERN_SUCCESS);
#endif

    // Unmapped memory is refused.
    char *hole = mmap(NULL, PAGE, PROT_READ, MAP_ANON | MAP_PRIVATE, -1, 0);
    munmap(hole, PAGE);
    kr = vm_protect(mach_task_self(), (vm_address_t)hole, PAGE, FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_INVALID_ADDRESS) return bad("a hole", kr, KERN_INVALID_ADDRESS);

    // A port's context.
    mach_port_t port;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port)) return bad("allocate", 1, 0);
    mach_port_context_t ctx = 77;
    if (mach_port_get_context(mach_task_self(), port, &ctx) || ctx != 0) return bad("an empty context", ctx, 0);
    if (mach_port_set_context(mach_task_self(), port, 0x1234567890abcdefull)) return bad("set context", 1, 0);
    if (mach_port_get_context(mach_task_self(), port, &ctx) || ctx != 0x1234567890abcdefull) return bad("the context", ctx, 0);
    if (mach_port_get_context(mach_task_self(), 0x12345, &ctx) != KERN_INVALID_NAME) return bad("no such name", 1, 0);

    close(ro);
    close(fd);
    unlink(path);
    puts("vmcopy ok");
    return 0;
}
