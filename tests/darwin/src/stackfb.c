// create_unix_stack's fallback (bsd/kern/kern_exec.c): the main stack is
// allocated right below its top, USRSTACK64 (0x16fe00000) less the main
// image's slide, and where that cannot be had, anywhere, its top then the
// allocation's end. This program's LC_MAIN asks for a 1.75 GiB stack (the
// build writes it: ld caps arm64 at 512 MB, exec does not), which from its
// top would start under the map: the stack goes anywhere, the first room
// above the image and dyld, with one guard page at its bottom (a custom
// stack's), and kern.usrstack64 and the main thread say where.

#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach/mach.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/sysctl.h>

#define PAGE 0x4000ull
#define USRSTACK64 0x16fe00000ull
#define REGION_BASE 0x180000000ull
#define STACKSIZE 0x70000000ull

static int bad(const char *what, unsigned long long got) {
    printf("stackfb: %s (%llx)\n", what, got);
    return 1;
}

int main(void) {
    const struct mach_header_64 *mh = (const void *)_dyld_get_image_header(0);
    uint64_t slide = (uint64_t)_dyld_get_image_vmaddr_slide(0), stacksize = 0;
    const uint8_t *lc = (const uint8_t *)(mh + 1);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *c = (const void *)lc;
        if (c->cmd == LC_MAIN) stacksize = ((const struct entry_point_command *)c)->stacksize;
        lc += c->cmdsize;
    }
    if (stacksize != STACKSIZE) return bad("LC_MAIN's stack size", stacksize);

    uint64_t top = 0;
    size_t tn = sizeof top;
    if (sysctlbyname("kern.usrstack64", &top, &tn, NULL, 0)) return bad("kern.usrstack64", 0);
    if (top == USRSTACK64 - slide) return bad("the stack is at its default place", top);
    if ((uint64_t)(uintptr_t)pthread_get_stackaddr_np(pthread_self()) != top) return bad("the main thread's stack", (uintptr_t)pthread_get_stackaddr_np(pthread_self()));
    // The allocation: LC_MAIN's size and a page, below the top, above the
    // image, below the shared region.
    uint64_t base = top - (STACKSIZE + PAGE);
    if (base % PAGE || base <= (uintptr_t)mh || top > REGION_BASE) return bad("the stack's allocation", base);
    uintptr_t here = (uintptr_t)&top;
    if (here >= top || here < top - STACKSIZE) return bad("a local is not on the stack", here);

    // Its bottom page is the guard, then the stack is readable and writable.
    vm_address_t raddr = base;
    vm_size_t rsize = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t obj = MACH_PORT_NULL;
    kern_return_t kr = vm_region_64(mach_task_self(), &raddr, &rsize, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count, &obj);
    if (kr != KERN_SUCCESS || raddr != base || rsize != PAGE || info.protection != VM_PROT_NONE) return bad("the guard page", raddr ^ rsize);
    raddr = base + PAGE;
    count = VM_REGION_BASIC_INFO_COUNT_64;
    kr = vm_region_64(mach_task_self(), &raddr, &rsize, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count, &obj);
    if (kr != KERN_SUCCESS || raddr != base + PAGE || info.protection != (VM_PROT_READ | VM_PROT_WRITE)) return bad("the stack above its guard", raddr);
    printf("stackfb ok\n");
    return 0;
}
