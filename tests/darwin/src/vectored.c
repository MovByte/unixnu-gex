// readv, writev, preadv and pwritev (sys_generic.c), and a call made
// indirectly through syscall(): the count, the vector's address and its
// lengths, what is refused before them and after, and what is transferred.

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

int syscall(int, ...);

static int bad(const char *what, long got, long want) {
    printf("vectored: %s: %#lx, want %#lx\n", what, got, want);
    return 1;
}

static int expect(const char *what, long r, int e) {
    if (r != -1 || errno != e) return bad(what, r == -1 ? errno : r, e);
    return 0;
}

int main(void) {
    char file[256], in[16];
    snprintf(file, sizeof file, "/tmp/vectored-%d", getpid());
    int fd = open(file, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return bad("open", errno, 0);

    // A vector with an empty entry.
    struct iovec v[3] = {{"ab", 2}, {NULL, 0}, {"cde", 3}};
    if (writev(fd, v, 3) != 5) return bad("writev", errno, 0);
    if (lseek(fd, 0, SEEK_CUR) != 5) return bad("the offset after it", lseek(fd, 0, SEEK_CUR), 5);
    lseek(fd, 0, SEEK_SET);
    char a[3] = {0}, b[8] = {0};
    struct iovec r[2] = {{a, 2}, {b, 8}};
    if (readv(fd, r, 2) != 5 || memcmp(a, "ab", 2) || memcmp(b, "cde", 3)) return bad("readv", errno, 0);

    // The count, the address, the lengths: the descriptor is looked at
    // between the second and the third.
    if (expect("no vectors", readv(fd, r, 0), EINVAL)) return 1;
    if (expect("a negative count", writev(fd, v, -1), EINVAL)) return 1;
    if (expect("too many vectors", writev(fd, v, 1025), EINVAL)) return 1;
    if (expect("a vector at a bad address", writev(fd, (struct iovec *)8, 1), EFAULT)) return 1;
    if (expect("a bad count before a bad descriptor", writev(999, v, 0), EINVAL)) return 1;
    struct iovec huge[2] = {{"a", (size_t)INT64_MAX}, {"b", (size_t)INT64_MAX}};
    struct iovec over[1] = {{"a", (size_t)INT64_MAX + 1}};
    if (expect("a bad descriptor before bad lengths", writev(999, over, 1), EBADF)) return 1;
    if (expect("a length past the limit", writev(fd, over, 1), EINVAL)) return 1;
    if (expect("lengths past the limit together", writev(fd, huge, 2), EINVAL)) return 1;
    if (expect("the wrong access before bad lengths", writev(open(file, O_RDONLY), over, 1), EBADF)) return 1;

    // Positioned: the offset is the call's, and the file's is left alone.
    lseek(fd, 1, SEEK_SET);
    struct iovec w[2] = {{"XY", 2}, {"Z", 1}};
    if (pwritev(fd, w, 2, 8) != 3) return bad("pwritev", errno, 0);
    char c[2] = {0}, d[2] = {0};
    struct iovec p[2] = {{c, 2}, {d, 2}};
    if (preadv(fd, p, 2, 8) != 3 || memcmp(c, "XY", 2) || d[0] != 'Z') return bad("preadv", errno, 0);
    if (lseek(fd, 0, SEEK_CUR) != 1) return bad("the offset through them", lseek(fd, 0, SEEK_CUR), 1);
    if (expect("no vectors, positioned", preadv(fd, p, 0, 0), EINVAL)) return 1;

    // Not random access.
    int pp[2];
    pipe(pp);
    if (expect("preadv of a pipe", preadv(pp[0], p, 2, 0), ESPIPE)) return 1;
    if (expect("pwritev to a pipe", pwritev(pp[1], w, 2, 0), ESPIPE)) return 1;
    int ro = open(file, O_RDONLY);
    if (expect("pwritev to a read-only descriptor", pwritev(ro, w, 2, 0), EBADF)) return 1;
    if (expect("preadv of a closed descriptor", preadv(999, p, 2, 0), EBADF)) return 1;

    // A pipe's writev and readv are the same calls.
    if (writev(pp[1], v, 3) != 5) return bad("a pipe's writev", errno, 0);
    memset(in, 0, sizeof in);
    struct iovec pr[2] = {{in, 1}, {in + 1, 8}};
    if (readv(pp[0], pr, 2) != 5 || memcmp(in, "abcde", 5)) return bad("a pipe's readv", errno, 0);

    // An indirect call reaches what a direct one does.
    if (syscall(4 /* write */, fd, "ok", 2) != 2) return bad("an indirect write", errno, 0);
    lseek(fd, 1, SEEK_SET);
    memset(in, 0, sizeof in);
    if (syscall(3 /* read */, fd, in, 2) != 2 || memcmp(in, "ok", 2)) return bad("an indirect read", errno, 0);
    struct iovec iw[1] = {{"!", 1}};
    if (syscall(121 /* writev */, fd, iw, 1) != 1) return bad("an indirect writev", errno, 0);

    close(ro);
    close(fd);
    unlink(file);
    puts("vectored ok");
    return 0;
}
