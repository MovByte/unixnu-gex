// The map's entries as mach_vm_region reports them: one per vm_map_enter,
// nothing merged but realloc'd memory, big anonymous allocations cut into
// chunks, an entry clipped by protect and inherit and not put back, each
// entry's protections, inheritance, behavior and offset, what a fork leaves
// in the child, and what a walk off the end of the map and a bad request get.

#include <errno.h>
#include <fcntl.h>
#include <mach-o/ldsyms.h>
#include <mach/mach.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#define K ((mach_vm_size_t)0x4000)

// <mach/mach_vm.h> is refused on this platform; these are in libsystem.
extern kern_return_t mach_vm_allocate(vm_map_t, mach_vm_address_t *, mach_vm_size_t, int);
extern kern_return_t mach_vm_deallocate(vm_map_t, mach_vm_address_t, mach_vm_size_t);
extern kern_return_t mach_vm_protect(vm_map_t, mach_vm_address_t, mach_vm_size_t, boolean_t, vm_prot_t);
extern kern_return_t mach_vm_inherit(vm_map_t, mach_vm_address_t, mach_vm_size_t, vm_inherit_t);
extern kern_return_t mach_vm_behavior_set(vm_map_t, mach_vm_address_t, mach_vm_size_t, vm_behavior_t);
extern kern_return_t mach_vm_region(vm_map_t, mach_vm_address_t *, mach_vm_size_t *, vm_region_flavor_t, vm_region_info_t, mach_msg_type_number_t *, mach_port_t *);

static int bad(const char *what, long long got, long long want) {
    printf("vmregion: %s: %lld, want %lld\n", what, got, want);
    return 1;
}

static kern_return_t region(mach_vm_address_t *at, mach_vm_size_t *size, vm_region_basic_info_data_64_t *info) {
    mach_msg_type_number_t n = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t name = MACH_PORT_NULL;
    return mach_vm_region(mach_task_self(), at, size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)info, &n, &name);
}

static mach_vm_address_t alloc_at(mach_vm_size_t size) {
    mach_vm_address_t a = 0;
    if (mach_vm_allocate(mach_task_self(), &a, size, VM_FLAGS_ANYWHERE) != KERN_SUCCESS) return 0;
    return a;
}

int main(void) {
    mach_vm_address_t a, b;
    mach_vm_size_t size;
    vm_region_basic_info_data_64_t info;

    // A fresh allocation: what it was entered with.
    b = alloc_at(4 * K);
    if (!b) return bad("allocate", 0, 1);
    a = b;
    if (region(&a, &size, &info) != KERN_SUCCESS) return bad("region", 1, 0);
    if (a != b || size != 4 * K) return bad("the entry", (long long)size, (long long)(4 * K));
    if (info.protection != (VM_PROT_READ | VM_PROT_WRITE)) return bad("protection", info.protection, 3);
    if (info.max_protection != VM_PROT_ALL) return bad("max_protection", info.max_protection, VM_PROT_ALL);
    if (info.inheritance != VM_INHERIT_COPY) return bad("inheritance", info.inheritance, VM_INHERIT_COPY);
    if (info.shared || info.reserved || info.offset != 0 || info.behavior != VM_BEHAVIOR_DEFAULT || info.user_wired_count != 0) return bad("the rest of the info", (long long)info.offset, 0);

    // An address inside it, and in the hole below it, find the same entry.
    a = b + K + 12;
    if (region(&a, &size, &info) != KERN_SUCCESS || a != b || size != 4 * K) return bad("inside the entry", (long long)a, (long long)b);

    // Clipped by a protect, and not put back by another.
    if (mach_vm_protect(mach_task_self(), b + K, K, FALSE, VM_PROT_READ) != KERN_SUCCESS) return bad("protect", 1, 0);
    a = b;
    if (region(&a, &size, &info) != KERN_SUCCESS || a != b || size != K) return bad("below the clip", (long long)size, (long long)K);
    a = b + K;
    if (region(&a, &size, &info) != KERN_SUCCESS || size != K || info.protection != VM_PROT_READ) return bad("the clipped piece", info.protection, VM_PROT_READ);
    if (info.offset != K) return bad("a clipped entry's offset", (long long)info.offset, (long long)K);
    mach_vm_protect(mach_task_self(), b + K, K, FALSE, VM_PROT_READ | VM_PROT_WRITE);
    a = b;
    if (region(&a, &size, &info) != KERN_SUCCESS || size != K) return bad("a clip undone", (long long)size, (long long)K);

    // Inheritance clips too, and reads back.
    if (mach_vm_inherit(mach_task_self(), b + 2 * K, K, VM_INHERIT_NONE) != KERN_SUCCESS) return bad("inherit", 1, 0);
    a = b + 2 * K;
    if (region(&a, &size, &info) != KERN_SUCCESS || size != K || info.inheritance != VM_INHERIT_NONE) return bad("VM_INHERIT_NONE", info.inheritance, VM_INHERIT_NONE);

    // A behavior reads back the same way.
    if (mach_vm_behavior_set(mach_task_self(), b + 3 * K, K, VM_BEHAVIOR_RANDOM) != KERN_SUCCESS) return bad("behavior_set", 1, 0);
    a = b + 3 * K;
    if (region(&a, &size, &info) != KERN_SUCCESS || size != K || info.behavior != VM_BEHAVIOR_RANDOM) return bad("VM_BEHAVIOR_RANDOM", info.behavior, VM_BEHAVIOR_RANDOM);

    // Two allocations next to each other stay two entries.
    b = alloc_at(16 * K);
    if (!b) return bad("allocate 2", 0, 1);
    mach_vm_deallocate(mach_task_self(), b, 16 * K);
    a = b;
    if (mach_vm_allocate(mach_task_self(), &a, 2 * K, VM_FLAGS_FIXED) != KERN_SUCCESS) return bad("fixed", 1, 0);
    a = b + 2 * K;
    if (mach_vm_allocate(mach_task_self(), &a, 2 * K, VM_FLAGS_FIXED) != KERN_SUCCESS) return bad("fixed 2", 1, 0);
    a = b;
    if (region(&a, &size, &info) != KERN_SUCCESS || size != 2 * K) return bad("neighbours merged", (long long)size, (long long)(2 * K));

    // Tagged VM_MEMORY_REALLOC they do extend the entry below.
    a = b + 8 * K;
    if (mach_vm_allocate(mach_task_self(), &a, 2 * K, VM_FLAGS_FIXED | VM_MAKE_TAG(VM_MEMORY_REALLOC)) != KERN_SUCCESS) return bad("realloc", 1, 0);
    a = b + 10 * K;
    if (mach_vm_allocate(mach_task_self(), &a, 2 * K, VM_FLAGS_FIXED | VM_MAKE_TAG(VM_MEMORY_REALLOC)) != KERN_SUCCESS) return bad("realloc 2", 1, 0);
    a = b + 8 * K;
    if (region(&a, &size, &info) != KERN_SUCCESS || size != 4 * K) return bad("realloc'd memory not merged", (long long)size, (long long)(4 * K));

    // A big anonymous allocation comes in chunks of 128 MB.
    const mach_vm_size_t chunk = (mach_vm_size_t)128 << 20;
    b = alloc_at(2 * chunk + K);
    if (!b) return bad("allocate big", 0, 1);
    a = b;
    if (region(&a, &size, &info) != KERN_SUCCESS || a != b || size != chunk) return bad("the first chunk", (long long)size, (long long)chunk);
    a = b + chunk;
    if (region(&a, &size, &info) != KERN_SUCCESS || a != b + chunk || size != chunk) return bad("the second chunk", (long long)size, (long long)chunk);
    a = b + 2 * chunk;
    if (region(&a, &size, &info) != KERN_SUCCESS || size != K) return bad("the last chunk", (long long)size, (long long)K);
    mach_vm_deallocate(mach_task_self(), b, 2 * chunk + K);

    // A shared mapping of a file: its offset, shared only once inherited.
    char path[] = "/var/tmp/gex-vmregion-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) return bad("mkstemp", errno, 0);
    unlink(path);
    if (ftruncate(fd, (off_t)(8 * K)) != 0) return bad("ftruncate", errno, 0);
    char *p = mmap(NULL, 4 * K, PROT_READ | PROT_WRITE, MAP_FILE | MAP_SHARED, fd, (off_t)(2 * K));
    if (p == MAP_FAILED) return bad("mmap", errno, 0);
    a = (mach_vm_address_t)p;
    if (region(&a, &size, &info) != KERN_SUCCESS || size != 4 * K || info.offset != 2 * K) return bad("the file's offset", (long long)info.offset, (long long)(2 * K));
    if (info.shared) return bad("is_shared before any fork", 1, 0);

    // An entry below the map's end, and none past it.
    a = (mach_vm_address_t)0xfffffc000ull;
    kern_return_t kr = region(&a, &size, &info);
    if (kr != KERN_INVALID_ADDRESS) return bad("past the last entry", kr, KERN_INVALID_ADDRESS);

    // Bad requests.
    mach_msg_type_number_t n = VM_REGION_BASIC_INFO_COUNT_64 - 1;
    mach_port_t name;
    a = (mach_vm_address_t)p;
    kr = mach_vm_region(mach_task_self(), &a, &size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &n, &name);
    if (kr != KERN_INVALID_ARGUMENT) return bad("too small a count", kr, KERN_INVALID_ARGUMENT);
    n = VM_REGION_BASIC_INFO_COUNT_64;
    kr = mach_vm_region(mach_task_self(), &a, &size, 99, (vm_region_info_t)&info, &n, &name);
    if (kr != KERN_INVALID_ARGUMENT) return bad("no such flavor", kr, KERN_INVALID_ARGUMENT);

    // The legacy flavor answers as the 64-bit one, with its count.
    n = VM_REGION_BASIC_INFO_COUNT_64;
    a = (mach_vm_address_t)p;
    kr = mach_vm_region(mach_task_self(), &a, &size, VM_REGION_BASIC_INFO, (vm_region_info_t)&info, &n, &name);
    if (kr != KERN_SUCCESS || n != VM_REGION_BASIC_INFO_COUNT_64 || info.offset != 2 * K) return bad("the legacy flavor", (long long)n, VM_REGION_BASIC_INFO_COUNT_64);

    // What a fork leaves: shared where shared by inheritance, in both.
    mach_vm_inherit(mach_task_self(), (mach_vm_address_t)p, 4 * K, VM_INHERIT_SHARE);
    pid_t pid = fork();
    if (pid == 0) {
        a = (mach_vm_address_t)p;
        if (region(&a, &size, &info) != KERN_SUCCESS || !info.shared) _exit(2);
        _exit(0);
    }
    int st;
    waitpid(pid, &st, 0);
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) return bad("a child's shared entry", st, 0);
    a = (mach_vm_address_t)p;
    if (region(&a, &size, &info) != KERN_SUCCESS || !info.shared) return bad("the parent's shared entry", info.shared, 1);

    // The image's own text: an entry of the file, read and execute.
    a = (mach_vm_address_t)&_mh_execute_header;
    if (region(&a, &size, &info) != KERN_SUCCESS) return bad("the image", 1, 0);
    if (info.protection != (VM_PROT_READ | VM_PROT_EXECUTE)) return bad("the image's protection", info.protection, 5);
    printf("vmregion ok\n");
    return 0;
}
