// Mapping and protection rules of the VM map: a writable and executable
// mach_vm_map loses execute on iOS (VM_MAP_POLICY_WX_STRIP_X; macOS's own
// maps fail it); a fixed address that does not meet the mask is
// KERN_NO_SPACE; and mprotect walks entry by entry, so a protection the
// first entry's maximum forbids is EACCES even with a hole after it.

#include <TargetConditionals.h>
#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

// mach/mach_vm.h is not in the iOS SDK; the routines are libsystem's.
extern kern_return_t mach_vm_allocate(vm_map_t, mach_vm_address_t *, mach_vm_size_t, int);
extern kern_return_t mach_vm_deallocate(vm_map_t, mach_vm_address_t, mach_vm_size_t);
extern kern_return_t mach_vm_protect(vm_map_t, mach_vm_address_t, mach_vm_size_t, boolean_t, vm_prot_t);
extern kern_return_t mach_vm_map(vm_map_t, mach_vm_address_t *, mach_vm_size_t, mach_vm_offset_t, int, mem_entry_name_port_t,
    memory_object_offset_t, boolean_t, vm_prot_t, vm_prot_t, vm_inherit_t);
extern kern_return_t mach_vm_region(vm_map_t, mach_vm_address_t *, mach_vm_size_t *, vm_region_flavor_t, vm_region_info_t,
    mach_msg_type_number_t *, mach_port_t *);

static int bad(const char *what, long got, long want) {
    printf("vmwx: %s: %#lx, want %#lx\n", what, got, want);
    fflush(stdout);
    return 1;
}

__attribute__((unused)) static vm_prot_t prot_at(mach_vm_address_t a) {
    mach_vm_size_t sz;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t obj;
    if (mach_vm_region(mach_task_self(), &a, &sz, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &cnt, &obj)) return -1;
    return info.protection;
}

int main(void) {
    const mach_vm_size_t page = (mach_vm_size_t)getpagesize();
    mach_vm_address_t a = 0;
    kern_return_t kr = mach_vm_map(mach_task_self(), &a, page, 0, VM_FLAGS_ANYWHERE, MACH_PORT_NULL, 0, FALSE,
        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE, VM_PROT_ALL, VM_INHERIT_DEFAULT);
#if TARGET_OS_OSX
    if (kr != KERN_PROTECTION_FAILURE) return bad("write and execute on macOS", kr, KERN_PROTECTION_FAILURE);
#else
    if (kr) return bad("write and execute", kr, 0);
    if (prot_at(a) != (VM_PROT_READ | VM_PROT_WRITE)) return bad("its protection", prot_at(a), VM_PROT_READ | VM_PROT_WRITE);
    mach_vm_deallocate(mach_task_self(), a, page);
#endif

    // A fixed address against a mask it does not meet.
    a = 0;
    if ((kr = mach_vm_allocate(mach_task_self(), &a, 4 * page, VM_FLAGS_ANYWHERE))) return bad("room", kr, 0);
    mach_vm_deallocate(mach_task_self(), a, 4 * page);
    mach_vm_address_t odd = (a & ~(2 * page - 1)) + 2 * page + page;
    mach_vm_address_t f = odd;
    kr = mach_vm_map(mach_task_self(), &f, page, 2 * page - 1, VM_FLAGS_FIXED, MACH_PORT_NULL, 0, FALSE,
        VM_PROT_DEFAULT, VM_PROT_ALL, VM_INHERIT_DEFAULT);
    if (kr != KERN_NO_SPACE) return bad("a fixed address off its mask", kr, KERN_NO_SPACE);

    // A read-only file's shared mapping, then a hole: asking for write is
    // the mapping's refusal, not the hole's.
    char path[] = "/tmp/gex-vmwx-XXXXXX";
    int w = mkstemp(path);
    ftruncate(w, (off_t)page);
    int fd = open(path, O_RDONLY);
    char *m = mmap(NULL, 2 * page, PROT_READ, MAP_SHARED, fd, 0);
    if (m == MAP_FAILED) return bad("the mapping", errno, 0);
    munmap(m + page, page);
    int r = mprotect(m, 2 * page, PROT_READ | PROT_WRITE);
    if (r != -1 || errno != EACCES) return bad("write on a read-only mapping before a hole", r == -1 ? errno : r, EACCES);
    r = mprotect(m, 2 * page, PROT_READ);
    if (r != -1 || errno != ENOMEM) return bad("a hole alone", r == -1 ? errno : r, ENOMEM);
    munmap(m, page);
    unlink(path);

    printf("vmwx ok\n");
    return 0;
}
