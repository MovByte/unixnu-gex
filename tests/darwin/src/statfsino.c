// statfs, fstatfs, getfsstat and __mac_getfsstat: the struct statfs of
// 32-bit inodes, field for field what the 64 forms answer, statfs's copy
// short of the last reserved fields; and the lookups both forms make.

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#define SYS_GETFSSTAT 18
#define SYS_STATFS 157
#define SYS_FSTATFS 158
#define SYS_STATFS64 345
#define SYS_FSTATFS64 346
#define SYS_GETFSSTAT64 347
#define SYS_MAC_GETFSSTAT 426

static long sys5(long n, long a, long b, long c, long d, long e) {
    register long x0 __asm__("x0") = a, x1 __asm__("x1") = b, x2 __asm__("x2") = c, x3 __asm__("x3") = d, x4 __asm__("x4") = e;
    register long x16 __asm__("x16") = n, cs __asm__("x9");
    __asm__ volatile("svc #0x80\n cset x9, cs" : "+r"(x0), "+r"(x1), "=r"(cs) : "r"(x2), "r"(x3), "r"(x4), "r"(x16) : "x5", "x6", "x7", "x8", "x10", "x11", "x12", "x13", "x14", "x15", "x17", "memory", "cc");
    if (cs) {
        errno = (int)x0;
        return -1;
    }
    return x0;
}

// struct user64_statfs.
struct statfs32 {
    short f_otype, f_oflags;
    long f_bsize, f_iosize, f_blocks, f_bfree, f_bavail, f_files, f_ffree;
    fsid_t f_fsid;
    uid_t f_owner;
    short f_reserved1, f_type;
    long f_flags;
    long f_reserved2[2];
    char f_fstypename[15];
    char f_mntonname[90];
    char f_mntfromname[90];
    char f_reserved3;
    long f_reserved4[4];
};
_Static_assert(sizeof(struct statfs32) == 336, "user64_statfs");

static int bad(const char *what, long got, long want) {
    printf("statfsino: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

static int expect(const char *what, long r, int e) {
    if (r != -1 || errno != e) return bad(what, r == -1 ? errno : r, e);
    return 0;
}

union buf {
    struct statfs32 s;
    unsigned char b[400];
};

static void fill(union buf *u) { memset(u, 0xa5, sizeof *u); }

// The fields against the 64 form's; `copied` bytes written, the rest kept.
static int same(const char *what, const union buf *u, const struct statfs *w, size_t copied) {
    const struct statfs32 *s = &u->s;
    int f = 0;
    f |= s->f_otype || s->f_oflags ? bad(what, s->f_otype, 0) : 0;
    f |= s->f_bsize != (long)w->f_bsize ? bad(what, s->f_bsize, w->f_bsize) : 0;
    f |= s->f_iosize != w->f_iosize ? bad(what, s->f_iosize, w->f_iosize) : 0;
    f |= s->f_blocks != (long)w->f_blocks ? bad(what, s->f_blocks, (long)w->f_blocks) : 0;
    f |= s->f_bfree != (long)w->f_bfree ? bad(what, s->f_bfree, (long)w->f_bfree) : 0;
    f |= s->f_bavail != (long)w->f_bavail ? bad(what, s->f_bavail, (long)w->f_bavail) : 0;
    f |= s->f_files != (long)w->f_files ? bad(what, s->f_files, (long)w->f_files) : 0;
    f |= s->f_ffree != (long)w->f_ffree ? bad(what, s->f_ffree, (long)w->f_ffree) : 0;
    f |= memcmp(&s->f_fsid, &w->f_fsid, sizeof s->f_fsid) ? bad(what, s->f_fsid.val[0], w->f_fsid.val[0]) : 0;
    f |= s->f_owner != w->f_owner ? bad(what, s->f_owner, w->f_owner) : 0;
    f |= s->f_reserved1 != (short)w->f_fssubtype ? bad(what, s->f_reserved1, w->f_fssubtype) : 0;
    f |= s->f_type != (short)w->f_type ? bad(what, s->f_type, w->f_type) : 0;
    f |= s->f_flags != (long)w->f_flags ? bad(what, s->f_flags, w->f_flags) : 0;
    f |= s->f_reserved2[0] || s->f_reserved2[1] ? bad(what, s->f_reserved2[0], 0) : 0;
    char want[90];
    snprintf(want, 15, "%s", w->f_fstypename);
    f |= strcmp(s->f_fstypename, want) ? bad(what, s->f_fstypename[0], want[0]) : 0;
    snprintf(want, 90, "%s", w->f_mntonname);
    f |= strcmp(s->f_mntonname, want) ? bad(what, s->f_mntonname[0], want[0]) : 0;
    snprintf(want, 90, "%s", w->f_mntfromname);
    f |= strcmp(s->f_mntfromname, want) ? bad(what, s->f_mntfromname[0], want[0]) : 0;
    for (size_t i = 0; i < sizeof u->b; i++)
        if (i < copied ? (i >= 104 + 15 + 90 + 90 && u->b[i] != 0) : u->b[i] != 0xa5) return bad(what, (long)i, (long)copied);
    return f;
}

int main(void) {
    int fail = 0;
    const char *file = "/private/var/tmp/statfsino-f";
    unlink(file);
    int fd = open(file, O_RDWR | O_CREAT | O_TRUNC, 0640);
    if (fd < 0) return bad("setup", errno, 0);
    union buf u;
    struct statfs w;

    fill(&u);
    if (sys5(SYS_STATFS64, (long)"/", (long)&w, 0, 0, 0) || sys5(SYS_STATFS, (long)"/", (long)&u, 0, 0, 0)) return bad("statfs /", errno, 0);
    fail |= same("statfs /", &u, &w, 303);

    fill(&u);
    if (sys5(SYS_STATFS64, (long)file, (long)&w, 0, 0, 0) || sys5(SYS_STATFS, (long)file, (long)&u, 0, 0, 0)) return bad("statfs file", errno, 0);
    fail |= same("statfs file", &u, &w, 303);

    // The descriptor's own mount, the same as its path's.
    struct statfs wf;
    fill(&u);
    if (sys5(SYS_FSTATFS64, fd, (long)&wf, 0, 0, 0) || sys5(SYS_FSTATFS, fd, (long)&u, 0, 0, 0)) return bad("fstatfs", errno, 0);
    fail |= same("fstatfs", &u, &wf, 303);
    fail |= memcmp(&wf.f_fsid, &w.f_fsid, sizeof w.f_fsid) || strcmp(wf.f_mntonname, w.f_mntonname) ? bad("fstatfs64 mount", wf.f_fsid.val[0], w.f_fsid.val[0]) : 0;

    // A relative path is the working directory's.
    if (chdir("/private/var/tmp")) return bad("chdir", errno, 0);
    struct statfs wr;
    if (sys5(SYS_STATFS64, (long)"statfsino-f", (long)&wr, 0, 0, 0)) return bad("statfs64 relative", errno, 0);
    fail |= memcmp(&wr.f_fsid, &w.f_fsid, sizeof w.f_fsid) ? bad("statfs64 relative", wr.f_fsid.val[0], w.f_fsid.val[0]) : 0;

    // The lookup's errors, and file_vnode's.
    int p[2];
    if (pipe(p)) return bad("pipe", errno, 0);
    fail |= expect("statfs missing", sys5(SYS_STATFS, (long)"/private/var/tmp/statfsino-none", (long)&u, 0, 0, 0), ENOENT);
    fail |= expect("statfs64 missing", sys5(SYS_STATFS64, (long)"/private/var/tmp/statfsino-none", (long)&w, 0, 0, 0), ENOENT);
    fail |= expect("statfs64 through a file", sys5(SYS_STATFS64, (long)"/private/var/tmp/statfsino-f/x", (long)&w, 0, 0, 0), ENOTDIR);
    fail |= expect("statfs empty", sys5(SYS_STATFS, (long)"", (long)&u, 0, 0, 0), ENOENT);
    fail |= expect("fstatfs pipe", sys5(SYS_FSTATFS, p[0], (long)&u, 0, 0, 0), EINVAL);
    fail |= expect("fstatfs64 pipe", sys5(SYS_FSTATFS64, p[0], (long)&w, 0, 0, 0), EINVAL);
    fail |= expect("fstatfs closed", sys5(SYS_FSTATFS, 999, (long)&u, 0, 0, 0), EBADF);
    fail |= expect("statfs fault", sys5(SYS_STATFS, (long)"/", 8, 0, 0, 0), EFAULT);

    // getfsstat: the count with no buffer, then whole structs where there
    // is room, each the 64 form's.
    long n = sys5(SYS_GETFSSTAT, 0, 0, MNT_NOWAIT, 0, 0);
    long n64 = sys5(SYS_GETFSSTAT64, 0, 0, MNT_NOWAIT, 0, 0);
    if (n < 1 || n != n64) return bad("getfsstat count", n, n64);
    struct statfs all64[64];
    union buf one;
    if (n > 64 || sys5(SYS_GETFSSTAT64, (long)all64, sizeof all64, MNT_NOWAIT, 0, 0) != n) return bad("getfsstat64", n, n);
    fill(&one);
    if (sys5(SYS_GETFSSTAT, (long)&one, 336, MNT_NOWAIT, 0, 0) != 1) return bad("getfsstat one", errno, 1);
    fail |= same("getfsstat", &one, &all64[0], 336);
    fail |= sys5(SYS_GETFSSTAT, (long)&one, 335, MNT_NOWAIT, 0, 0) != 0 ? bad("getfsstat no room", errno, 0) : 0;
    fail |= expect("getfsstat bufsize", sys5(SYS_GETFSSTAT, (long)&one, -1, MNT_NOWAIT, 0, 0), EINVAL);

    // __mac_getfsstat: as getfsstat with no labels; a label array of the
    // wrong count, and an empty one (whose allocation is a zone's smallest).
    fill(&one);
    if (sys5(SYS_MAC_GETFSSTAT, (long)&one, 336, 0, 0, MNT_NOWAIT) != 1) return bad("__mac_getfsstat", errno, 1);
    fail |= same("__mac_getfsstat", &one, &all64[0], 336);
    long labels[2];
    fail |= expect("__mac_getfsstat label count", sys5(SYS_MAC_GETFSSTAT, (long)&one, 336, (long)labels, 16, MNT_NOWAIT), EINVAL);
    fail |= sys5(SYS_MAC_GETFSSTAT, 0, 0, (long)labels, 0, MNT_NOWAIT) != n ? bad("__mac_getfsstat no labels", errno, n) : 0;
    fail |= sys5(SYS_MAC_GETFSSTAT, 0, 0, (long)labels, 7, MNT_NOWAIT) != n ? bad("__mac_getfsstat count", errno, n) : 0;

    close(p[0]);
    close(p[1]);
    close(fd);
    unlink(file);
    if (!fail) printf("statfsino ok\n");
    return fail;
}
