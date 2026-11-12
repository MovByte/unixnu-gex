// The address space exec gives a program, as XNU lays it out for the
// iPad7,1 (bsd/kern/mach_loader.c, kern_exec.c, osfmk/vm/vm_shared_region.c
// and the device's kernelcache), and libmalloc's nano allocator in it
// (libmalloc-521.120.7's nanov2):
//
// - load_machfile slides the main image by 1 to 1023 16 KiB pages
//   (vm_map_get_max_aslr_slide_pages: 16 MiB) and 0, 1 or 2 32 MiB sections
//   (vm_map_get_max_aslr_slide_section, ARM_TT_TWIG_SIZE); its __PAGEZERO is
//   extended to the slid image, which is the map's floor. dyld, linked at 0,
//   goes right after the main image's end by its own 1 to 255 pages
//   (vm_map_get_max_loader_aslr_slide_pages: 4 MiB). A release kernel
//   (SECURE_KERNEL) never disables either: posix_spawn ignores
//   _POSIX_SPAWN_DISABLE_ASLR.
// - load_main: the main stack's top is USRSTACK64 (0x16fe00000) less the
//   main image's slide (kern.usrstack64).
// - vm_shared_region_enter nests the whole shared region, from
//   SHARED_REGION_BASE_ARM64 (0x180000000) for SHARED_REGION_SIZE_ARM64
//   (0x180000000), as one read-only entry inherited by share. The cache in
//   it is slid once a boot: dyld passes the cache's maxSlide and
//   shared_region_map_and_slide_2_np picks the slide below it, on a 16 KiB
//   boundary; every task of the boot sees the same.
// - libmalloc's nano allocator follows the shared region: 512 MiB at
//   0x300000000 (NANOZONE_BASE_REGION_ADDRESS). It is engaged when exec
//   gives apple[] "MallocNanoZone=1" (a spawn with
//   _POSIX_SPAWN_NANO_ALLOCATOR, as an app's is) or the environment asks;
//   without either, as for this program run directly, it is not.
//
// dyld then moves into its copy in the shared cache and unmaps the one exec
// loaded (dyldMain.cpp's handleDyldInCache), unless the environment has
// DYLD_IN_CACHE=0. The program checks its own layout, dyld in the cache,
// and that nano is off; then it spawns itself with
// _POSIX_SPAWN_NANO_ALLOCATOR and _POSIX_SPAWN_DISABLE_ASLR, and
// DYLD_IN_CACHE=0: the child checks its layout again (still slid, and dyld
// where exec put it) and nano's allocations.

#include <errno.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>
#include <mach/mach.h>
#include <malloc/malloc.h>
#include <pthread.h>
#include <spawn.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

int syscall(int, ...);
extern char **environ;

// bsd/sys/spawn.h, private.
#define _POSIX_SPAWN_DISABLE_ASLR 0x0100
#define _POSIX_SPAWN_NANO_ALLOCATOR 0x0200
// shared_region_check_np.
#define SYS_shared_region_check_np 294

#define PAGE 0x4000ull
#define TWIG (32ull << 20)
#define LINKED_BASE 0x100000000ull
#define USRSTACK64 0x16fe00000ull
#define REGION_BASE 0x180000000ull
#define REGION_SIZE 0x180000000ull
#define NANO_BASE (REGION_BASE + REGION_SIZE)
#define NANO_SIZE 0x20000000ull

static const char *who = "layout";

static int bad(const char *what, unsigned long long got) {
    printf("%s: %s (%llx)\n", who, what, got);
    return 1;
}

static const char *apple_val(const char **apple, const char *key) {
    size_t n = strlen(key);
    for (int i = 0; apple[i]; i++)
        if (!strncmp(apple[i], key, n) && apple[i][n] == '=') return apple[i] + n + 1;
    return NULL;
}

static int in_nano(const void *p) {
    return (uintptr_t)p >= NANO_BASE && (uintptr_t)p < NANO_BASE + NANO_SIZE;
}

// The shared cache's slide, which check_layout finds.
static uint64_t cache_slide;

// The layout every process has, whatever its spawn asked for. dyld is where
// exec loaded it when `dyld_on_disk`, else its copy in the shared cache.
static int check_layout(int dyld_on_disk) {
    const struct mach_header_64 *mh = (const void *)_dyld_get_image_header(0);
    uint64_t slide = (uint64_t)_dyld_get_image_vmaddr_slide(0);
    uint64_t header = (uintptr_t)mh, end = 0, text = 0;
    const uint8_t *lc = (const uint8_t *)(mh + 1);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *c = (const void *)lc;
        if (c->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *s = (const void *)c;
            if (!strcmp(s->segname, "__TEXT")) text = s->vmaddr;
            if (strcmp(s->segname, "__PAGEZERO") && s->vmaddr + s->vmsize + slide > end) end = s->vmaddr + s->vmsize + slide;
        }
        lc += c->cmdsize;
    }
    end = (end + PAGE - 1) & ~(PAGE - 1);

    // The main image's slide: pages from the first, sections of a twig.
    if (text != LINKED_BASE) return bad("this program's __TEXT is not linked after a 4 GiB page zero", text);
    if (header != text + slide) return bad("the header is not at the linked base plus the slide", header);
    if (slide % PAGE) return bad("the slide is not a 16 KiB multiple", slide);
    if (slide / TWIG > 2) return bad("the slide's section is past the third", slide);
    if (slide % TWIG < PAGE || slide % TWIG > 1023 * PAGE) return bad("the slide's pages are not 1 to 1023", slide);

    // The page zero reaches the slid image: the map starts there.
    void *low = mmap((void *)(uintptr_t)(header - PAGE), PAGE, PROT_READ, MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0);
    if (low != MAP_FAILED || errno != ENOMEM) return bad("a fixed mapping just under the image", errno);
    vm_address_t at = LINKED_BASE;
    kern_return_t kr = vm_allocate(mach_task_self(), &at, PAGE, VM_FLAGS_FIXED);
    if (kr != KERN_INVALID_ADDRESS) return bad("a fixed allocation at the image's linked base", kr);
    vm_address_t raddr = 0;
    vm_size_t rsize = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t obj = MACH_PORT_NULL;
    kr = vm_region_64(mach_task_self(), &raddr, &rsize, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count, &obj);
    if (kr != KERN_SUCCESS || raddr != header) return bad("the map's first entry is not the image's header", raddr);

    // dyld: exec's after the main image's end by 1 to 255 pages, its
    // image list in it; or the shared cache's, with its own.
    task_dyld_info_data_t dinfo;
    count = TASK_DYLD_INFO_COUNT;
    if ((kr = task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&dinfo, &count)) != KERN_SUCCESS) return bad("TASK_DYLD_INFO", kr);
    const struct dyld_all_image_infos *ai = (const void *)(uintptr_t)dinfo.all_image_info_addr;
    if (dinfo.all_image_info_size < offsetof(struct dyld_all_image_infos, sharedCacheBaseAddress) + sizeof(uintptr_t)) return bad("TASK_DYLD_INFO's all_image_info_size", dinfo.all_image_info_size);
    uint64_t dyld = (uintptr_t)ai->dyldImageLoadAddress;
    if (dyld_on_disk) {
        if (dyld <= end || (dyld - end) % PAGE || dyld - end > 255 * PAGE) return bad("dyld is not 1 to 255 pages after the main image", dyld - end);
        if (dinfo.all_image_info_addr < dyld || dinfo.all_image_info_addr >= dyld + 0x100000) return bad("the image list is not in exec's dyld", dinfo.all_image_info_addr);
    } else {
        if (dyld < REGION_BASE || dyld >= REGION_BASE + REGION_SIZE) return bad("dyld is not the shared cache's", dyld);
        if (dinfo.all_image_info_addr < REGION_BASE || dinfo.all_image_info_addr >= REGION_BASE + REGION_SIZE) return bad("the image list is not in the shared cache", dinfo.all_image_info_addr);
    }

    // The main stack: USRSTACK64 less the slide.
    uint64_t top = 0;
    size_t tn = sizeof top;
    if (sysctlbyname("kern.usrstack64", &top, &tn, NULL, 0)) return bad("kern.usrstack64", errno);
    if (top != USRSTACK64 - slide) return bad("kern.usrstack64 is not USRSTACK64 less the slide", top);
    if ((uint64_t)(uintptr_t)pthread_get_stackaddr_np(pthread_self()) != top) return bad("the main thread's stack", (uintptr_t)pthread_get_stackaddr_np(pthread_self()));
    struct rlimit rl;
    getrlimit(RLIMIT_STACK, &rl);
    uintptr_t here = (uintptr_t)&rl;
    if (here >= top || here < top - rl.rlim_cur) return bad("a local is not on the main stack", here);

    // The shared region: one read-only entry over all of it, the cache
    // first in it, and nothing past it until something maps there.
    uint64_t start = 0;
    if (syscall(SYS_shared_region_check_np, &start) != 0) return bad("shared_region_check_np", errno);
    if (start < REGION_BASE || start >= REGION_BASE + REGION_SIZE || start != ai->sharedCacheBaseAddress) return bad("the shared cache's start", start);
    // Its header, at its start: linked at sharedRegionStart (0xe0), slid
    // below maxSlide (0xf0) on a 16 KiB boundary, as dyld says it is.
    const uint8_t *hdr = (const uint8_t *)(uintptr_t)start;
    uint64_t linked = *(const uint64_t *)(hdr + 0xe0), max_slide = *(const uint64_t *)(hdr + 0xf0);
    if (memcmp(hdr, "dyld_v1", 7) || linked != REGION_BASE) return bad("the shared cache's header", linked);
    cache_slide = start - linked;
    if (cache_slide % PAGE || cache_slide >= max_slide || cache_slide != ai->sharedCacheSlide) return bad("the shared cache's slide", cache_slide);
    raddr = REGION_BASE + 0x1000;
    count = VM_REGION_BASIC_INFO_COUNT_64;
    kr = vm_region_64(mach_task_self(), &raddr, &rsize, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count, &obj);
    if (kr != KERN_SUCCESS || raddr != REGION_BASE || rsize != REGION_SIZE) return bad("the shared region's entry", raddr ^ rsize);
    if (info.protection != VM_PROT_READ || info.max_protection != VM_PROT_READ || info.inheritance != VM_INHERIT_SHARE || !info.reserved || info.shared)
        return bad("the shared region's entry's attributes", info.protection | info.max_protection << 4 | info.inheritance << 8 | info.reserved << 12 | info.shared << 16);
    at = REGION_BASE + REGION_SIZE - PAGE;
    if ((kr = vm_allocate(mach_task_self(), &at, PAGE, VM_FLAGS_FIXED)) != KERN_NO_SPACE) return bad("a fixed allocation in the shared region's last page", kr);
    return 0;
}

// The region's submap entry is permanent: a range of it may be replaced or
// removed only where the region holds no permanent mapping (vm_map_delete,
// shared_region_make_permanent: one neither writable nor executable, as its
// dynamic data page is), else KERN_PROTECTION_FAILURE (EACCES from
// mmap(MAP_FIXED), EINVAL from munmap). Its holes may go.
static int check_region_permanence(void) {
    uint64_t start = 0;
    if (syscall(SYS_shared_region_check_np, &start) != 0) return bad("shared_region_check_np", errno);
    uint64_t dyn = start + *(const uint64_t *)(uintptr_t)(start + 0x1f0);
    if (memcmp((const void *)(uintptr_t)dyn, "dyld_data    v0", 16)) return bad("the shared cache's dynamic data page", dyn);
    void *p = mmap((void *)(uintptr_t)dyn, PAGE, PROT_READ, MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0);
    if (p != MAP_FAILED || errno != EACCES) return bad("a fixed mapping over the dynamic data page", errno);
    vm_address_t at = dyn;
    kern_return_t kr = vm_allocate(mach_task_self(), &at, PAGE, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE);
    if (kr != KERN_PROTECTION_FAILURE) return bad("an overwriting allocation over the dynamic data page", kr);
    if ((kr = vm_deallocate(mach_task_self(), dyn, PAGE)) != KERN_PROTECTION_FAILURE) return bad("vm_deallocate of the dynamic data page", kr);
    if (munmap((void *)(uintptr_t)dyn, PAGE) != -1 || errno != EINVAL) return bad("munmap of the dynamic data page", errno);
    if (memcmp((const void *)(uintptr_t)dyn, "dyld_data    v0", 16)) return bad("the dynamic data page after", dyn);

    vm_address_t hole = REGION_BASE + REGION_SIZE - PAGE, raddr = hole;
    p = mmap((void *)hole, PAGE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0);
    if (p != (void *)hole) return bad("a fixed mapping over a hole of the region", errno);
    vm_size_t rsize = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t obj = MACH_PORT_NULL;
    kr = vm_region_64(mach_task_self(), &raddr, &rsize, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count, &obj);
    if (kr != KERN_SUCCESS || raddr != hole || rsize != PAGE || info.reserved) return bad("the mapping that replaced part of the region", raddr);
    if (munmap(p, PAGE) != 0) return bad("munmap of that mapping", errno);
    at = hole;
    if ((kr = vm_allocate(mach_task_self(), &at, PAGE, VM_FLAGS_FIXED)) != KERN_SUCCESS) return bad("a fixed allocation where the region was", kr);
    vm_deallocate(mach_task_self(), at, PAGE);
    return 0;
}

static int check_nano_off(const char **apple) {
    if (getenv("MallocNanoZone")) return bad("MallocNanoZone is in the environment", 0);
    if (apple_val(apple, "MallocNanoZone")) return bad("exec gave MallocNanoZone without the spawn flag", 0);
    vm_address_t *zones = NULL;
    unsigned nzones = 0;
    if (malloc_get_all_zones(mach_task_self(), NULL, &zones, &nzones) != KERN_SUCCESS || nzones != 1 || strcmp(malloc_get_zone_name((malloc_zone_t *)zones[0]), "DefaultMallocZone"))
        return bad("the zones without nano", nzones);
    void *p = malloc(32);
    if (!p || in_nano(p)) return bad("a small allocation without nano", (uintptr_t)p);
    if (malloc_zone_from_ptr(p) != malloc_default_zone()) return bad("the default zone without nano", (uintptr_t)malloc_zone_from_ptr(p));
    free(p);
    // Nothing is placed where nano would be.
    vm_address_t at = NANO_BASE;
    kern_return_t kr = vm_allocate(mach_task_self(), &at, PAGE, VM_FLAGS_FIXED);
    if (kr != KERN_SUCCESS) return bad("a fixed allocation at nano's base", kr);
    vm_deallocate(mach_task_self(), at, PAGE);
    return 0;
}

static int check_nano(const char **apple) {
    const char *v = apple_val(apple, "MallocNanoZone");
    if (!v || strcmp(v, "1")) return bad("exec gave no MallocNanoZone=1 for the spawn flag", 0);
    if (getenv("MallocNanoZone")) return bad("MallocNanoZone is in the environment", 0);

    // Its region, reserved whole at its base.
    vm_address_t raddr = NANO_BASE;
    vm_size_t rsize = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t obj = MACH_PORT_NULL;
    kern_return_t kr = vm_region_64(mach_task_self(), &raddr, &rsize, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count, &obj);
    if (kr != KERN_SUCCESS || raddr != NANO_BASE) return bad("nano's region", raddr);

    // The zones: nano's, the default, and its helper.
    vm_address_t *zones = NULL;
    unsigned nzones = 0;
    if (malloc_get_all_zones(mach_task_self(), NULL, &zones, &nzones) != KERN_SUCCESS || nzones != 2) return bad("the zones with nano", nzones);
    malloc_zone_t *nano = (malloc_zone_t *)zones[0], *helper = (malloc_zone_t *)zones[1];
    if (strcmp(malloc_get_zone_name(nano), "DefaultMallocZone") || strcmp(malloc_get_zone_name(helper), "MallocHelperZone")) return bad("the zones' names", 0);

    // Every size up to 256 bytes comes from nano's region, rounded to 16;
    // anything bigger from the helper, whose blocks nano answers for too
    // (nanov2_size asks it). Either is the default zone's, as
    // malloc_zone_from_ptr names it.
    enum { N = 64 };
    void *p[N];
    for (int i = 0; i < N; i++) {
        size_t n = (size_t)i * 4 + 1;
        if (!(p[i] = malloc(n)) || !in_nano(p[i]) || (uintptr_t)p[i] % 16) return bad("a small allocation is not nano's", (uintptr_t)p[i]);
        if (malloc_size(p[i]) != ((n + 15) & ~(size_t)15)) return bad("malloc_size of a nano block", malloc_size(p[i]));
        if (malloc_zone_from_ptr(p[i]) != malloc_default_zone()) return bad("malloc_zone_from_ptr of a nano block", (uintptr_t)malloc_zone_from_ptr(p[i]));
        if (nano->size(nano, p[i]) != malloc_size(p[i]) || helper->size(helper, p[i]) != 0) return bad("a nano block's owner", (uintptr_t)p[i]);
        memset(p[i], 0xa5, n);
    }
    void *big = malloc(1024);
    if (!big || in_nano(big) || malloc_size(big) != 1024 || malloc_zone_from_ptr(big) != malloc_default_zone() || helper->size(helper, big) != 1024)
        return bad("a 1 KiB allocation is not the helper zone's", (uintptr_t)big);
    free(big);
    if (malloc_zone_from_ptr(&count)) return bad("malloc_zone_from_ptr of a stack address", (uintptr_t)&count);

    // A freed block is no one's, and the next of its size is the same.
    for (int i = 0; i < N; i += 7) {
        size_t n = (size_t)i * 4 + 1;
        void *was = p[i];
        free(was);
        if (malloc_size(was) != 0 || malloc_zone_from_ptr(was)) return bad("a freed nano block still has a size", malloc_size(was));
        if ((p[i] = malloc(n)) != was) return bad("a freed nano block is not reused", (uintptr_t)p[i]);
        if (malloc_size(p[i]) != ((n + 15) & ~(size_t)15) || nano->size(nano, p[i]) != malloc_size(p[i])) return bad("a reused nano block", (uintptr_t)p[i]);
    }
    // calloc and realloc stay in nano.
    uint8_t *c = calloc(3, 16);
    if (!in_nano(c)) return bad("calloc's block", (uintptr_t)c);
    for (int i = 0; i < 48; i++)
        if (c[i]) return bad("calloc's block is not zero", i);
    uint8_t *r = realloc(c, 200);
    if (!in_nano(r) || malloc_size(r) != 208) return bad("realloc's block", (uintptr_t)r);
    free(r);
    for (int i = 0; i < N; i++) free(p[i]);
    return 0;
}

int main(int argc, char **argv, char **envp, const char **apple) {
    (void)envp;
    if (argc > 2 && !strcmp(argv[1], "nano")) {
        who = "layout (nano)";
        if (check_layout(1) || check_nano(apple)) return 1;
        // One slide a boot: the parent's.
        if (cache_slide != strtoull(argv[2], NULL, 16)) return bad("the shared cache's slide differs from the parent's", cache_slide);
        return 0;
    }
    if (check_layout(0) || check_nano_off(apple) || check_region_permanence()) return 1;

    char path[1024];
    uint32_t n = sizeof path;
    if (_NSGetExecutablePath(path, &n)) return bad("_NSGetExecutablePath", 0);
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_setflags(&attr, _POSIX_SPAWN_NANO_ALLOCATOR | _POSIX_SPAWN_DISABLE_ASLR);
    char slide[32];
    snprintf(slide, sizeof slide, "%llx", (unsigned long long)cache_slide);
    char *args[] = {path, "nano", slide, NULL};
    int envc = 0;
    while (environ[envc]) envc++;
    char **env = calloc((size_t)envc + 2, sizeof *env);
    memcpy(env, environ, (size_t)envc * sizeof *env);
    env[envc] = "DYLD_IN_CACHE=0";
    pid_t pid;
    int e = posix_spawn(&pid, path, NULL, &attr, args, env);
    if (e) return bad("posix_spawn", e);
    int st;
    if (waitpid(pid, &st, 0) != pid) return bad("waitpid", errno);
    if (!WIFEXITED(st) || WEXITSTATUS(st)) return bad("the nano child's status", st);
    printf("layout ok\n");
    return 0;
}
