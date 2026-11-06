// arm64 iOS's 16 KiB pages: what getpagesize, sysconf, vm_page_size,
// host_page_size and hw.pagesize say; a mapping is page-aligned and its
// length rounded up to whole pages (its last byte usable); munmap,
// mprotect and a fixed mmap refuse an address that is only 4 KiB aligned
// (EINVAL); vm_allocate rounds to whole pages too.

#include <errno.h>
#include <mach/mach.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <unistd.h>

static int bad(const char *what, long got, long want) {
    printf("pages: %s: %#lx, want %#lx\n", what, got, want);
    return 1;
}

int main(void) {
    const long page = 16384;
    if (getpagesize() != page) return bad("getpagesize", getpagesize(), page);
    if (sysconf(_SC_PAGESIZE) != page) return bad("sysconf", sysconf(_SC_PAGESIZE), page);
    if ((long)vm_page_size != page) return bad("vm_page_size", (long)vm_page_size, page);
    vm_size_t hp = 0;
    kern_return_t kr;
    if ((kr = host_page_size(mach_host_self(), &hp)) || (long)hp != page) return bad("host_page_size", kr ? kr : (long)hp, page);
    int hw = 0;
    size_t len = sizeof hw;
    if (sysctlbyname("hw.pagesize", &hw, &len, NULL, 0) || hw != page) return bad("hw.pagesize", hw, page);

    char *p = mmap(NULL, 1, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (p == MAP_FAILED || ((long)p & (page - 1))) return bad("a mapping's address", (long)p, 0);
    p[page - 1] = 1;
    if (munmap(p + 4096, 4096) != -1 || errno != EINVAL) return bad("munmap at 4 KiB", errno, EINVAL);
    if (mprotect(p + 4096, 4096, PROT_READ) != -1 || errno != EINVAL) return bad("mprotect at 4 KiB", errno, EINVAL);
    if (mmap(p + 4096, 4096, PROT_READ, MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0) != MAP_FAILED || errno != EINVAL) return bad("a fixed mmap at 4 KiB", errno, EINVAL);
    if (munmap(p, 1)) return bad("munmap", errno, 0);

    vm_address_t a = 0;
    if ((kr = vm_allocate(mach_task_self(), &a, 1, VM_FLAGS_ANYWHERE)) || (a & (page - 1))) return bad("vm_allocate", kr ? kr : (long)a, 0);
    // A second allocation is not inside the first one's page.
    vm_address_t b = 0;
    if ((kr = vm_allocate(mach_task_self(), &b, 1, VM_FLAGS_ANYWHERE)) || (b > a - page && b < a + page)) return bad("a second allocation", kr ? kr : (long)b, a + page);
    printf("pages ok\n");
    return 0;
}
