// getdirentries: the struct dirent of 32-bit inodes VNOP_READDIR fills, the
// entries getdirentries64 reads, the offset each read started at, and its
// errors.

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SYS_GETDIRENTRIES 196
#define SYS_GETDIRENTRIES64 344

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

// struct dirent of 32-bit inodes.
struct dirent32 {
    uint32_t d_ino;
    uint16_t d_reclen;
    uint8_t d_type;
    uint8_t d_namlen;
    char d_name[256];
};

// struct direntry.
struct direntry {
    uint64_t d_ino;
    uint64_t d_seekoff;
    uint16_t d_reclen;
    uint16_t d_namlen;
    uint8_t d_type;
    char d_name[1024];
};

static int bad(const char *what, long got, long want) {
    printf("dirino: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

static int expect(const char *what, long r, int e) {
    if (r != -1 || errno != e) return bad(what, r == -1 ? errno : r, e);
    return 0;
}

struct ent {
    uint64_t ino;
    uint8_t type;
    char name[256];
};

int main(void) {
    int fail = 0;
    char d[64], f[96];
    snprintf(d, sizeof d, "/private/var/tmp/dirino-%d", getpid());
    if (mkdir(d, 0755)) return bad("mkdir", errno, 0);
    const char *names[] = {"a", "bb", "ccc", "dddd", "a-much-longer-name-than-the-others", "sub"};
    for (int i = 0; i < 6; i++) {
        snprintf(f, sizeof f, "%s/%s", d, names[i]);
        if (i == 5 ? mkdir(f, 0755) : close(open(f, O_CREAT | O_WRONLY, 0644))) return bad("create", errno, i);
    }

    // The 64 form's entries, all at once.
    struct ent want[16];
    int nwant = 0;
    int fd = open(d, O_RDONLY | O_DIRECTORY);
    if (fd < 0) return bad("open", errno, 0);
    static char big[16384];
    long base;
    long n = sys4(SYS_GETDIRENTRIES64, fd, (long)big, sizeof big, (long)&base);
    if (n <= 0) return bad("getdirentries64", errno, 1);
    for (long at = 0; at < n;) {
        struct direntry *e = (struct direntry *)(big + at);
        if (nwant == 16) return bad("too many", nwant, 8);
        want[nwant].ino = e->d_ino;
        want[nwant].type = e->d_type;
        memcpy(want[nwant].name, e->d_name, e->d_namlen);
        want[nwant].name[e->d_namlen] = 0;
        nwant++;
        at += e->d_reclen;
    }
    if (nwant != 8) return bad("entries", nwant, 8);

    // The same, one small buffer at a time: each read from where the last
    // left the descriptor, which basep says.
    if (lseek(fd, 0, SEEK_SET) != 0) return bad("rewind", errno, 0);
    int got = 0;
    char small[64];
    for (;;) {
        off_t before = lseek(fd, 0, SEEK_CUR);
        memset(small, 0xa5, sizeof small);
        base = -7;
        n = sys4(SYS_GETDIRENTRIES, fd, (long)small, sizeof small, (long)&base);
        if (n < 0) return bad("getdirentries", errno, 0);
        if (base != before) fail |= bad("basep", base, (long)before);
        if (n == 0) break;
        for (long at = 0; at < n;) {
            struct dirent32 *e = (struct dirent32 *)(small + at);
            size_t want_len = (8 + e->d_namlen + 1 + 3) & ~3u;
            if (e->d_reclen != want_len) return bad("d_reclen", e->d_reclen, (long)want_len);
            if (e->d_name[e->d_namlen] != 0) return bad("terminator", e->d_name[e->d_namlen], 0);
            if (got == nwant) return bad("more than getdirentries64", got, nwant);
            struct ent *w = &want[got++];
            if (strcmp(e->d_name, w->name) || e->d_type != w->type || e->d_ino != (uint32_t)w->ino) fail |= bad(w->name, e->d_ino, (long)(uint32_t)w->ino);
            at += e->d_reclen;
        }
        if ((unsigned char)small[n] != 0xa5 && n < (long)sizeof small) fail |= bad("past the entries", n, 0);
    }
    if (got != nwant) fail |= bad("entries, small", got, nwant);

    // Too small a buffer for the next entry; a file; a closed descriptor.
    if (lseek(fd, 0, SEEK_SET) != 0) return bad("rewind", errno, 0);
    fail |= expect("a tiny buffer", sys4(SYS_GETDIRENTRIES, fd, (long)small, 8, (long)&base), EINVAL);
    if (lseek(fd, 0, SEEK_CUR) != 0) fail |= bad("offset after EINVAL", lseek(fd, 0, SEEK_CUR), 0);
    snprintf(f, sizeof f, "%s/a", d);
    int ffd = open(f, O_RDONLY);
    fail |= expect("a file", sys4(SYS_GETDIRENTRIES, ffd, (long)small, sizeof small, (long)&base), EINVAL);
    fail |= expect("closed", sys4(SYS_GETDIRENTRIES, 999, (long)small, sizeof small, (long)&base), EBADF);
    close(ffd);
    close(fd);

    for (int i = 0; i < 6; i++) {
        snprintf(f, sizeof f, "%s/%s", d, names[i]);
        if (i == 5) rmdir(f); else unlink(f);
    }
    rmdir(d);
    if (!fail) printf("dirino ok\n");
    return fail;
}
