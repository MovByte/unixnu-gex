// A call's copies of the program's memory are held to its pages'
// protections, as copyin, copyout and copyinstr are: a buffer the call
// would write that is unmapped, read-only or inaccessible, or one it would
// read that is unmapped or inaccessible, is EFAULT, and nothing is written;
// a path that runs into an unmapped page before its end is EFAULT too.

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static int bad(const char *what, long got, long want) {
    printf("efault: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

int main(void) {
    size_t pg = (size_t)getpagesize();
    char *a = mmap(0, 3 * pg, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    memset(a, 'x', 3 * pg);
    int p[2];
    pipe(p);

    // Into memory the call may not write.
    write(p[1], "ab", 2);
    errno = 0;
    if (read(p[0], NULL, 2) != -1 || errno != EFAULT) return bad("a read to address 0", errno, EFAULT);
    mprotect(a, pg, PROT_READ);
    errno = 0;
    if (read(p[0], a, 2) != -1 || errno != EFAULT) return bad("a read into a read-only page", errno, EFAULT);
    if (a[0] != 'x') return bad("the read-only page's byte", a[0], 'x');
    mprotect(a, pg, PROT_NONE);
    struct stat st;
    errno = 0;
    if (fstat(p[0], (struct stat *)a) != -1 || errno != EFAULT) return bad("an fstat into a page with no access", errno, EFAULT);
    mprotect(a, pg, PROT_READ | PROT_WRITE);
    if (fstat(p[0], &st) != 0) return bad("an fstat into the stack", errno, 0);

    // From memory the call may not read.
    munmap(a + 2 * pg, pg);
    errno = 0;
    if (write(p[1], a + 2 * pg, 4) != -1 || errno != EFAULT) return bad("a write from an unmapped page", errno, EFAULT);
    mprotect(a + pg, pg, PROT_NONE);
    errno = 0;
    if (write(p[1], a + pg, 4) != -1 || errno != EFAULT) return bad("a write from a page with no access", errno, EFAULT);
    mprotect(a + pg, pg, PROT_READ | PROT_WRITE);

    // A path with no end before an unmapped page (well within MAXPATHLEN of
    // it, which would end the copy first with ENAMETOOLONG).
    memset(a + pg, 'p', pg);
    errno = 0;
    if (open(a + 2 * pg - 100, O_RDONLY) != -1 || errno != EFAULT) return bad("a path running into an unmapped page", errno, EFAULT);
    errno = 0;
    if (open(a + pg, O_RDONLY) != -1 || errno != ENAMETOOLONG) return bad("a path longer than MAXPATHLEN", errno, ENAMETOOLONG);
    a[2 * pg - 1] = 0;
    errno = 0;
    if (open(a + 2 * pg - 2, O_RDONLY) != -1 || errno != ENOENT) return bad("a path ending on its page", errno, ENOENT);
    printf("efault ok\n");
    return 0;
}
