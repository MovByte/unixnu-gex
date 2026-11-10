// stat, lstat, fstat and fstatat and their _extended forms: the struct stat
// with a 32-bit inode number, field for field what the 64 forms answer, its
// spare fields zero and nothing written past it.

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SYS_STAT 188
#define SYS_FSTAT 189
#define SYS_LSTAT 190
#define SYS_STAT_EXTENDED 279
#define SYS_LSTAT_EXTENDED 280
#define SYS_FSTAT_EXTENDED 281
#define SYS_STAT64 338
#define SYS_FSTAT64 339
#define SYS_LSTAT64 340
#define SYS_FSTATAT 469
#define SYS_FSTATAT64 470

static long sys4(long n, long a, long b, long c, long d) {
    register long x0 __asm__("x0") = a, x1 __asm__("x1") = b, x2 __asm__("x2") = c, x3 __asm__("x3") = d;
    register long x16 __asm__("x16") = n, cs __asm__("x9");
    __asm__ volatile("svc #0x80\n cset x9, cs" : "+r"(x0), "+r"(x1), "=r"(cs) : "r"(x2), "r"(x3), "r"(x16) : "x4", "x5", "x6", "x7", "x8", "x10", "x11", "x12", "x13", "x14", "x15", "x17", "memory", "cc");
    if (cs) {
        errno = (int)x0;
        return -1;
    }
    return x0;
}

// struct user64_stat.
struct stat32 {
    int32_t st_dev;
    uint32_t st_ino;
    uint16_t st_mode;
    uint16_t st_nlink;
    uint32_t st_uid;
    uint32_t st_gid;
    int32_t st_rdev;
    struct timespec st_atimespec, st_mtimespec, st_ctimespec;
    int64_t st_size;
    int64_t st_blocks;
    int32_t st_blksize;
    uint32_t st_flags;
    uint32_t st_gen;
    int32_t st_lspare;
    int64_t st_qspare[2];
};
_Static_assert(sizeof(struct stat32) == 120, "user64_stat");

static int bad(const char *what, long got, long want) {
    printf("statino: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

static int expect(const char *what, long r, int e) {
    if (r != -1 || errno != e) return bad(what, r == -1 ? errno : r, e);
    return 0;
}

// The buffer: the struct, then bytes that must stay as they were.
union buf {
    struct stat32 s;
    unsigned char b[160];
};

static int same(const char *what, const union buf *u, const struct stat *w) {
    const struct stat32 *s = &u->s;
    int f = 0;
    f |= s->st_dev != w->st_dev ? bad(what, s->st_dev, w->st_dev) : 0;
    f |= s->st_ino != (uint32_t)w->st_ino ? bad(what, s->st_ino, (uint32_t)w->st_ino) : 0;
    f |= s->st_mode != w->st_mode ? bad(what, s->st_mode, w->st_mode) : 0;
    f |= s->st_nlink != w->st_nlink ? bad(what, s->st_nlink, w->st_nlink) : 0;
    f |= s->st_uid != w->st_uid ? bad(what, s->st_uid, w->st_uid) : 0;
    f |= s->st_gid != w->st_gid ? bad(what, s->st_gid, w->st_gid) : 0;
    f |= s->st_rdev != w->st_rdev ? bad(what, s->st_rdev, w->st_rdev) : 0;
    f |= memcmp(&s->st_atimespec, &w->st_atimespec, 16) ? bad(what, s->st_atimespec.tv_sec, w->st_atimespec.tv_sec) : 0;
    f |= memcmp(&s->st_mtimespec, &w->st_mtimespec, 16) ? bad(what, s->st_mtimespec.tv_sec, w->st_mtimespec.tv_sec) : 0;
    f |= memcmp(&s->st_ctimespec, &w->st_ctimespec, 16) ? bad(what, s->st_ctimespec.tv_sec, w->st_ctimespec.tv_sec) : 0;
    f |= s->st_size != w->st_size ? bad(what, s->st_size, w->st_size) : 0;
    f |= s->st_blocks != w->st_blocks ? bad(what, s->st_blocks, w->st_blocks) : 0;
    f |= s->st_blksize != w->st_blksize ? bad(what, s->st_blksize, w->st_blksize) : 0;
    f |= s->st_flags != w->st_flags ? bad(what, s->st_flags, w->st_flags) : 0;
    f |= s->st_gen != w->st_gen ? bad(what, s->st_gen, w->st_gen) : 0;
    f |= s->st_lspare || s->st_qspare[0] || s->st_qspare[1] ? bad(what, 1, 0) : 0;
    for (int i = 120; i < 160; i++)
        if (u->b[i] != 0xa5) return bad(what, i, 160);
    return f;
}

static void fill(union buf *u) { memset(u, 0xa5, sizeof *u); }

int main(void) {
    int fail = 0;
    const char *file = "/tmp/statino-f", *link = "/tmp/statino-l";
    unlink(file);
    unlink(link);
    int fd = open(file, O_RDWR | O_CREAT | O_TRUNC, 0640);
    if (fd < 0 || write(fd, "hello", 5) != 5 || symlink(file, link)) return bad("setup", errno, 0);
    union buf u;
    struct stat w;

    fill(&u);
    if (sys4(SYS_STAT64, (long)file, (long)&w, 0, 0) || sys4(SYS_STAT, (long)file, (long)&u, 0, 0)) return bad("stat", errno, 0);
    fail |= same("stat", &u, &w);
    fail |= (u.s.st_mode & S_IFMT) != S_IFREG || u.s.st_size != 5 ? bad("stat kind", u.s.st_mode, S_IFREG | 0640) : 0;

    fill(&u);
    if (sys4(SYS_LSTAT64, (long)link, (long)&w, 0, 0) || sys4(SYS_LSTAT, (long)link, (long)&u, 0, 0)) return bad("lstat", errno, 0);
    fail |= same("lstat", &u, &w);
    fail |= (u.s.st_mode & S_IFMT) != S_IFLNK ? bad("lstat kind", u.s.st_mode, S_IFLNK) : 0;

    fill(&u);
    if (sys4(SYS_FSTAT64, fd, (long)&w, 0, 0) || sys4(SYS_FSTAT, fd, (long)&u, 0, 0)) return bad("fstat", errno, 0);
    fail |= same("fstat", &u, &w);

    // A pipe's: a FIFO, its size what is buffered.
    int p[2];
    if (pipe(p) || write(p[1], "abc", 3) != 3) return bad("pipe", errno, 0);
    fill(&u);
    if (sys4(SYS_FSTAT64, p[0], (long)&w, 0, 0) || sys4(SYS_FSTAT, p[0], (long)&u, 0, 0)) return bad("fstat pipe", errno, 0);
    fail |= same("fstat pipe", &u, &w);
    fail |= (u.s.st_mode & S_IFMT) != S_IFIFO || u.s.st_size != 3 ? bad("fstat pipe kind", u.s.st_mode, S_IFIFO) : 0;

    fill(&u);
    if (sys4(SYS_FSTATAT64, AT_FDCWD, (long)link, (long)&w, AT_SYMLINK_NOFOLLOW) || sys4(SYS_FSTATAT, AT_FDCWD, (long)link, (long)&u, AT_SYMLINK_NOFOLLOW)) return bad("fstatat", errno, 0);
    fail |= same("fstatat nofollow", &u, &w);
    fill(&u);
    if (sys4(SYS_FSTATAT64, AT_FDCWD, (long)link, (long)&w, 0) || sys4(SYS_FSTATAT, AT_FDCWD, (long)link, (long)&u, 0)) return bad("fstatat", errno, 0);
    fail |= same("fstatat", &u, &w);
    fail |= (u.s.st_mode & S_IFMT) != S_IFREG ? bad("fstatat kind", u.s.st_mode, S_IFREG) : 0;

    // The _extended forms: an APFS file's security, with no list.
    uint64_t xsize = 999;
    char xsec[128];
    fill(&u);
    if (sys4(SYS_STAT64, (long)file, (long)&w, 0, 0) || sys4(SYS_STAT_EXTENDED, (long)file, (long)&u, (long)xsec, (long)&xsize)) return bad("stat_extended", errno, 0);
    fail |= same("stat_extended", &u, &w) | (xsize != 44 ? bad("stat_extended size", (long)xsize, 44) : 0);
    xsize = 999;
    fill(&u);
    if (sys4(SYS_LSTAT64, (long)link, (long)&w, 0, 0) || sys4(SYS_LSTAT_EXTENDED, (long)link, (long)&u, (long)xsec, (long)&xsize)) return bad("lstat_extended", errno, 0);
    fail |= same("lstat_extended", &u, &w) | (xsize != 44 ? bad("lstat_extended size", (long)xsize, 44) : 0);
    xsize = 999;
    fill(&u);
    if (sys4(SYS_FSTAT64, fd, (long)&w, 0, 0) || sys4(SYS_FSTAT_EXTENDED, fd, (long)&u, (long)xsec, (long)&xsize)) return bad("fstat_extended", errno, 0);
    fail |= same("fstat_extended", &u, &w) | (xsize != 44 ? bad("fstat_extended size", (long)xsize, 44) : 0);

    // The errors are the 64 forms'.
    fail |= expect("stat missing", sys4(SYS_STAT, (long)"/tmp/statino-none", (long)&u, 0, 0), ENOENT);
    fail |= expect("fstat closed", sys4(SYS_FSTAT, 999, (long)&u, 0, 0), EBADF);
    fail |= expect("fstatat flag", sys4(SYS_FSTATAT, AT_FDCWD, (long)file, (long)&u, 0x1), EINVAL);
    fail |= expect("stat fault", sys4(SYS_STAT, (long)file, 8, 0, 0), EFAULT);

    close(fd);
    close(p[0]);
    close(p[1]);
    unlink(link);
    unlink(file);
    if (!fail) printf("statino ok\n");
    return fail;
}
