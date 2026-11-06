// mmap's checks by kern_mman.c: flags outside the known set are refused
// (a Fall 2020 SDK or later); MAP_JIT only with an anonymous, private,
// placed-anywhere mapping; MAP_RESILIENT_* only for a file and MAP_TPRO only
// writable and not executable; a hint rounded up to a page; an anonymous mapping's descriptor carries only
// VM flags (a superpage is not on arm64); the UNIX03 checks libsyscall asks
// for (an offset in a page, neither private nor shared, no length); a file's
// protections come from how it was opened; what is not a regular file cannot
// be mapped, a character device with ENODEV.

#include <TargetConditionals.h>
#include <errno.h>
#include <fcntl.h>
#include <mach/vm_statistics.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef MAP_RESILIENT_CODESIGN
#define MAP_RESILIENT_CODESIGN 0x2000
#endif
#ifndef MAP_RESILIENT_MEDIA
#define MAP_RESILIENT_MEDIA 0x4000
#endif
#ifndef MAP_TPRO
#define MAP_TPRO 0x80000
#endif

static int bad(const char *what, long got, long want) {
    printf("mmapflags: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

// The errno of a mapping that should fail, 0 if it was made.
static int fails(size_t len, int prot, int flags, int fd, off_t off) {
    void *p = mmap(NULL, len, prot, flags, fd, off);
    if (p != MAP_FAILED) {
        munmap(p, len);
        return 0;
    }
    return errno;
}

int main(void) {
    const size_t page = getpagesize();
    const int rw = PROT_READ | PROT_WRITE, anon = MAP_ANON | MAP_PRIVATE;
    int e;
    if ((e = fails(page, rw, anon | 0x100000, -1, 0)) != EINVAL) return bad("an unknown flag", e, EINVAL);
#if !TARGET_OS_OSX
    if ((e = fails(page, rw, anon | 0x8000, -1, 0)) != EINVAL) return bad("MAP_32BIT", e, EINVAL);
#endif
    if ((e = fails(page, rw, anon | MAP_NOCACHE | MAP_HASSEMAPHORE | MAP_NOEXTEND | 0x80, -1, 0))) return bad("the flags taken and ignored", e, 0);
    if ((e = fails(page, rw, anon | MAP_JIT | MAP_FIXED, -1, 0)) != EINVAL) return bad("a fixed JIT mapping", e, EINVAL);
    if ((e = fails(page, rw, MAP_ANON | MAP_SHARED | MAP_JIT, -1, 0)) != EINVAL) return bad("a shared JIT mapping", e, EINVAL);
    if ((e = fails(page, rw, anon | MAP_JIT | MAP_TPRO, -1, 0)) != EINVAL) return bad("a TPRO JIT mapping", e, EINVAL);
    if ((e = fails(page, PROT_READ, anon | MAP_RESILIENT_CODESIGN, -1, 0)) != EINVAL) return bad("anonymous MAP_RESILIENT_CODESIGN", e, EINVAL);
    if ((e = fails(page, PROT_READ, anon | MAP_RESILIENT_MEDIA, -1, 0)) != EINVAL) return bad("anonymous MAP_RESILIENT_MEDIA", e, EINVAL);
    if ((e = fails(page, PROT_READ, anon | MAP_TPRO, -1, 0)) != EPERM) return bad("read-only MAP_TPRO", e, EPERM);
    if ((e = fails(page, rw | PROT_EXEC, anon | MAP_TPRO, -1, 0)) != EPERM) return bad("executable MAP_TPRO", e, EPERM);

    // An anonymous mapping's descriptor: VM flags only.
    if ((e = fails(page, rw, anon, 1, 0)) != EINVAL) return bad("a descriptor that is not VM flags", e, EINVAL);
    if ((e = fails(page, rw, anon, VM_MAKE_TAG(VM_MEMORY_MALLOC), 0))) return bad("a tag", e, 0);
    if ((e = fails(page, rw, anon, VM_FLAGS_SUPERPAGE_SIZE_ANY, 0)) != EINVAL) return bad("a superpage", e, EINVAL);

    // UNIX03.
    if ((e = fails(page, rw, anon, -1, 1)) != EINVAL) return bad("an offset within a page", e, EINVAL);
    if ((e = fails(page, rw, anon, -1, page))) return bad("an anonymous mapping's offset", e, 0);
    if ((e = fails(page, rw, MAP_ANON, -1, 0)) != EINVAL) return bad("neither private nor shared", e, EINVAL);
    if ((e = fails(0, rw, anon, -1, 0)) != EINVAL) return bad("no length", e, EINVAL);

    // A hint is rounded up to a page.
    char *h = mmap(NULL, 2 * page, rw, anon, -1, 0);
    munmap(h, 2 * page);
    char *g = mmap(h + 1, page, rw, anon, -1, 0);
    if (g != h + page) return bad("a free hint", (long)g, (long)(h + page));
    munmap(g, page);

    // Files.
    char path[] = "/tmp/gex-mmapflags-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0 || ftruncate(fd, 2 * page)) return bad("a file", errno, 0);
    int ro = open(path, O_RDONLY), wo = open(path, O_WRONLY);
    unlink(path);
    if ((e = fails(page, PROT_READ | PROT_WRITE, MAP_SHARED, ro, 0)) != EACCES) return bad("a shared writable mapping of a read-only file", e, EACCES);
    if ((e = fails(page, PROT_READ | PROT_WRITE, MAP_PRIVATE, ro, 0))) return bad("a private writable mapping of a read-only file", e, 0);
    if ((e = fails(page, PROT_READ, MAP_SHARED, wo, 0)) != EACCES) return bad("a readable mapping of a write-only file", e, EACCES);
    if ((e = fails(page, PROT_READ, MAP_PRIVATE | MAP_JIT, fd, 0)) != EINVAL) return bad("a JIT file mapping", e, EINVAL);
    // A fixed mapping keeps the offset's place in its page.
    char *f = mmap(NULL, 2 * page, PROT_READ, MAP_SHARED, fd, 0);
    if (f == MAP_FAILED || mmap(f + 16, page - 16, PROT_READ, MAP_SHARED | MAP_FIXED, fd, page + 16) != MAP_FAILED || errno != EINVAL) return bad("an offset within a page, fixed", errno, EINVAL);
    int dir = open("/tmp", O_RDONLY), pfd[2];
    pipe(pfd);
    if ((e = fails(page, PROT_READ, MAP_SHARED, dir, 0)) != EINVAL) return bad("a directory", e, EINVAL);
    if ((e = fails(page, PROT_READ, MAP_SHARED, pfd[0], 0)) != EINVAL) return bad("a pipe", e, EINVAL);
    int null = open("/dev/null", O_RDWR);
    if ((e = fails(page, PROT_READ, MAP_SHARED, null, 0)) != ENODEV) return bad("a character device", e, ENODEV);
    if ((e = fails(page, PROT_READ, MAP_SHARED, 99, 0)) != EBADF) return bad("no descriptor", e, EBADF);
    printf("mmapflags ok\n");
    return 0;
}
