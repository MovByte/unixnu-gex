// madvise by vm_map_behavior_set (kern_mman.c, vm_map.c): an unknown
// advice and MADV_PAGEOUT are refused; MADV_FREE and MADV_FREE_REUSABLE at
// address 0 are EINVAL (FOURK_COMPAT); a range with a hole is EINVAL; a
// deactivated page keeps its contents and a zeroed one reads zero; a malloc
// region is reusable only in its first state (default protection, no
// zero_wired_pages), and a
// region that cannot be written cannot be made reusable (EPERM) or zeroed;
// a shared or private file mapping cannot be zeroed (EPERM, ENOTSUP).

#include <errno.h>
#include <fcntl.h>
#include <mach/vm_statistics.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static int bad(const char *what, long got, long want) {
    printf("madvise: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

static int adv(void *p, size_t n, int a) {
    return madvise(p, n, a) ? errno : 0;
}

int main(int argc, char **argv) {
    const size_t page = getpagesize();
    char *p = mmap(NULL, 4 * page, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, VM_MAKE_TAG(VM_MEMORY_MALLOC_LARGE), 0);
    if (p == MAP_FAILED) return bad("a malloc region", errno, 0);
    int e;
    if ((e = adv(p, page, 12)) != EINVAL) return bad("an unknown advice", e, EINVAL);
    if ((e = adv(p, page, -1)) != EINVAL) return bad("a negative advice", e, EINVAL);
    if ((e = adv(p, page, MADV_PAGEOUT)) != ENOTSUP) return bad("MADV_PAGEOUT", e, ENOTSUP);
    if ((e = adv(NULL, page, MADV_FREE)) != EINVAL) return bad("MADV_FREE at 0", e, EINVAL);
    if ((e = adv(NULL, page, MADV_FREE_REUSABLE)) != EINVAL) return bad("MADV_FREE_REUSABLE at 0", e, EINVAL);
    if ((e = adv((void *)-page, 2 * page, MADV_NORMAL)) != EINVAL) return bad("a range past the end", e, EINVAL);
    if ((e = adv(p, 0, MADV_WILLNEED))) return bad("an empty range", e, 0);
    if ((e = adv(p + 1, 1, MADV_RANDOM))) return bad("an unaligned range", e, 0);
    if ((e = adv(p, 4 * page, MADV_SEQUENTIAL)) || (e = adv(p, 4 * page, MADV_NORMAL))) return bad("a persistent behavior", e, 0);
    if ((e = adv(p, 4 * page, MADV_WILLNEED))) return bad("MADV_WILLNEED", e, 0);

    memset(p, 0x5a, 4 * page);
    if ((e = adv(p, 4 * page, MADV_DONTNEED)) || p[0] != 0x5a || p[4 * page - 1] != 0x5a) return bad("a deactivated page", e ? e : p[0], 0x5a);
    if ((e = adv(p + page, page, MADV_ZERO)) || p[page] || p[2 * page - 1]) return bad("a zeroed page", e ? e : p[page], 0);
    if (p[page - 1] != 0x5a || p[2 * page] != 0x5a) return bad("the pages beside it", p[page - 1], 0x5a);

    if ((e = adv(p, 4 * page, MADV_FREE_REUSABLE)) || (e = adv(p, 4 * page, MADV_FREE_REUSE)) || (e = adv(p, 4 * page, MADV_CAN_REUSE))) return bad("a malloc region made reusable", e, 0);
    if ((e = adv(p, 4 * page, MADV_FREE))) return bad("MADV_FREE", e, 0);

    // Its protection changed: no longer in a malloc region's first state.
    mprotect(p + 3 * page, page, PROT_READ);
    if ((e = adv(p, 4 * page, MADV_CAN_REUSE)) != EINVAL) return bad("a changed malloc region", e, EINVAL);
    if ((e = adv(p + 3 * page, page, MADV_FREE_REUSABLE)) != EINVAL) return bad("a changed malloc region made reusable", e, EINVAL);
    if ((e = adv(p + 3 * page, page, MADV_ZERO)) != EPERM) return bad("zeroing what cannot be written", e, EPERM);

    // A hole.
    munmap(p + 2 * page, page);
    if ((e = adv(p, 4 * page, MADV_WILLNEED)) != EINVAL) return bad("MADV_WILLNEED over a hole", e, EINVAL);
    if ((e = adv(p, 4 * page, MADV_RANDOM)) != EINVAL) return bad("MADV_RANDOM over a hole", e, EINVAL);
    if ((e = adv(p, 4 * page, MADV_DONTNEED)) != EINVAL) return bad("MADV_DONTNEED over a hole", e, EINVAL);
    if ((e = adv(p, 4 * page, MADV_FREE)) != EINVAL) return bad("MADV_FREE over a hole", e, EINVAL);
    if ((e = adv(p, 4 * page, MADV_FREE_REUSABLE)) != EINVAL) return bad("MADV_FREE_REUSABLE over a hole", e, EINVAL);
    if ((e = adv(p, 4 * page, MADV_ZERO)) != EINVAL) return bad("MADV_ZERO over a hole", e, EINVAL);
    if ((e = adv(p, 2 * page, MADV_CAN_REUSE))) return bad("before the hole", e, 0);

    // Zeroing wired pages at their unmapping is not a first state either.
    char *w = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, VM_MAKE_TAG(VM_MEMORY_MALLOC_SMALL), 0);
    if ((e = adv(w, page, MADV_ZERO_WIRED_PAGES))) return bad("MADV_ZERO_WIRED_PAGES", e, 0);
    if ((e = adv(w, page, MADV_FREE_REUSABLE)) != EINVAL) return bad("a malloc region to zero when wired", e, EINVAL);

    // Not a malloc region: reusable unless it cannot be written.
    char *q = mmap(NULL, page, PROT_READ, MAP_ANON | MAP_PRIVATE, -1, 0);
    if ((e = adv(q, page, MADV_CAN_REUSE))) return bad("a read-only region's reuse", e, 0);
    if ((e = adv(q, page, MADV_FREE_REUSABLE)) != EPERM) return bad("a read-only region made reusable", e, EPERM);

    // Files.
    char path[] = "/tmp/gex-madvise-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) return bad("a file", errno, 0);
    unlink(path);
    if (ftruncate(fd, page)) return bad("its size", errno, 0);
    char *s = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    char *v = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (s == MAP_FAILED || v == MAP_FAILED) return bad("mapping it", errno, 0);
    if ((e = adv(s, page, MADV_ZERO)) != EPERM) return bad("zeroing a shared file mapping", e, EPERM);
    if ((e = adv(v, page, MADV_ZERO)) != ENOTSUP) return bad("zeroing a private file mapping", e, ENOTSUP);
    v[0] = 1;
    if ((e = adv(v, page, MADV_ZERO)) != ENOTSUP) return bad("zeroing a written private file mapping", e, ENOTSUP);
    s[0] = 7;
    if ((e = adv(s, page, MADV_DONTNEED)) || (e = adv(s, page, MADV_FREE)) || s[0] != 7) return bad("a shared file mapping freed", e ? e : s[0], 7);
    printf("madvise ok\n");
    return 0;
}
