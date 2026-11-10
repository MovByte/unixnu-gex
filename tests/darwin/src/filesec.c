// The calls with a file security argument, with no access control list, the
// answer for every file here (an APFS file's security says so);
// fsgetpath_ext and proc_info_extended_id.

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define NONE 0xffffff9bu
int proc_pidinfo(int, int, uint64_t, void *, int);

// Eight arguments in registers, with the carry as the result.
static long sys8(long n, long a, long b, long c, long d, long e, long f, long g, long h) {
    register long x0 __asm__("x0") = a, x1 __asm__("x1") = b, x2 __asm__("x2") = c, x3 __asm__("x3") = d;
    register long x4 __asm__("x4") = e, x5 __asm__("x5") = f, x6 __asm__("x6") = g, x7 __asm__("x7") = h;
    register long x16 __asm__("x16") = n, cs __asm__("x9");
    __asm__ volatile("svc #0x80\n cset x9, cs" : "+r"(x0), "+r"(x1), "=r"(cs) : "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x6), "r"(x7), "r"(x16) : "x8", "x10", "x11", "x12", "x13", "x14", "x15", "x17", "memory", "cc");
    if (cs) {
        errno = (int)x0;
        return -1;
    }
    return x0;
}

static int bad(const char *what, long got, long want) {
    printf("filesec: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

static int expect(const char *what, long r, int e) {
    if (r != -1 || errno != e) return bad(what, r == -1 ? errno : r, e);
    return 0;
}

enum { STAT = 341, LSTAT = 342, FSTAT = 343, OPEN = 277, UMASK = 278, CHMOD = 282, FCHMOD = 283, MKDIR = 292, GETPATH = 217, INFO = 545 };

int main(void) {
    char d[64], f[96];
    snprintf(d, sizeof d, "/private/var/tmp/filesec-%d", getpid());
    snprintf(f, sizeof f, "%s/f", d);
    unlink(f);
    rmdir(d);

    if (sys8(MKDIR, (long)d, NONE, NONE, 0755, 0, 0, 0, 0) != 0) return bad("mkdir_extended", errno, 0);
    int fd = (int)sys8(OPEN, (long)f, O_CREAT | O_RDWR, NONE, NONE, 0640, 0, 0, 0);
    if (fd < 0) return bad("open_extended", errno, 0);
    if (write(fd, "abc", 3) != 3) return bad("the file it opened", errno, 0);

    // An APFS file's security: no list, null owner and group GUIDs.
    static const unsigned char noacl[44] = {0x6d, 0xc1, 0x2c, 0x01, [36] = 0xff, 0xff, 0xff, 0xff};
    struct stat plain, st;
    if (stat(f, &plain) != 0) return bad("stat", errno, 0);
    size_t size = 1234;
    unsigned char sec[64];
    memset(sec, 0x5a, sizeof sec);
    if (sys8(STAT, (long)f, (long)&st, (long)sec, (long)&size, 0, 0, 0, 0) != 0) return bad("stat64_extended", errno, 0);
    if (st.st_ino != plain.st_ino || st.st_size != 3 || (st.st_mode & 07777) != 0640) return bad("what it saw", st.st_mode, 0640);
    if (size != 44) return bad("the security's size", (long)size, 44);
    if (memcmp(sec, noacl, 44) || sec[44] != 0x5a) return bad("the security", sec[0], noacl[0]);
    size = 77;
    if (sys8(STAT, (long)f, (long)&st, 0, (long)&size, 0, 0, 0, 0) != 0 || size != 77) return bad("no security wanted", (long)size, 77);
    // Too small a buffer: only the size.
    size = 43;
    memset(sec, 0x5a, sizeof sec);
    if (sys8(STAT, (long)f, (long)&st, (long)sec, (long)&size, 0, 0, 0, 0) != 0 || size != 44 || sec[0] != 0x5a) return bad("a small buffer", (long)size, 44);
    size = 1000;
    if (sys8(LSTAT, (long)f, (long)&st, (long)sec, (long)&size, 0, 0, 0, 0) != 0 || size != 44 || memcmp(sec, noacl, 44)) return bad("lstat64_extended", errno, 0);
    size = 1000;
    if (sys8(FSTAT, fd, (long)&st, (long)sec, (long)&size, 0, 0, 0, 0) != 0 || size != 44 || st.st_size != 3 || memcmp(sec, noacl, 44)) return bad("fstat64_extended", errno, 0);
    // devfs keeps none, and neither has a pipe.
    size = 1000;
    if (sys8(STAT, (long)"/dev/null", (long)&st, (long)sec, (long)&size, 0, 0, 0, 0) != 0 || size != 0) return bad("devfs", (long)size, 0);
    int p[2];
    if (pipe(p) != 0) return bad("pipe", errno, 0);
    size = 1000;
    if (sys8(FSTAT, p[0], (long)&st, (long)sec, (long)&size, 0, 0, 0, 0) != 0 || size != 0) return bad("a pipe", (long)size, 0);
    // fstat goes on past a struct it could not copy out, and the security's
    // copyout is the answer; the stat forms stop.
    size = 1000;
    if (sys8(FSTAT, fd, 8, (long)sec, (long)&size, 0, 0, 0, 0) != 0 || size != 44) return bad("fstat64_extended at a bad address", errno, 0);
    size = 1000;
    if (expect("fstat64_extended of a pipe at a bad address", sys8(FSTAT, p[0], 8, (long)sec, (long)&size, 0, 0, 0, 0), EFAULT) || size != 0) return 1;
    size = 1000;
    if (expect("stat64_extended at a bad address", sys8(STAT, (long)f, 8, (long)sec, (long)&size, 0, 0, 0, 0), EFAULT) || size != 1000) return 1;
    close(p[0]);
    close(p[1]);
    size = 1;
    if (expect("no such file", sys8(STAT, (long)"/nonexistent", (long)&st, (long)sec, (long)&size, 0, 0, 0, 0), ENOENT)) return 1;
    if (size != 1) return bad("the size after a failure", (long)size, 1);

    // chmod: a mode, none (-1), and no list to take away.
    if (sys8(CHMOD, (long)f, NONE, NONE, 0600, 0, 0, 0, 0) != 0) return bad("chmod_extended", errno, 0);
    stat(f, &st);
    if ((st.st_mode & 07777) != 0600) return bad("the mode", st.st_mode & 07777, 0600);
    if (sys8(CHMOD, (long)f, NONE, NONE, -1, 1, 0, 0, 0) != 0) return bad("removing no list", errno, 0);
    stat(f, &st);
    if ((st.st_mode & 07777) != 0600) return bad("the mode it left", st.st_mode & 07777, 0600);
    if (expect("no file to chmod", sys8(CHMOD, (long)"/nonexistent", NONE, NONE, -1, 0, 0, 0, 0), ENOENT)) return 1;
    if (sys8(FCHMOD, fd, NONE, NONE, 0644, 0, 0, 0, 0) != 0) return bad("fchmod_extended", errno, 0);
    fstat(fd, &st);
    if ((st.st_mode & 07777) != 0644) return bad("the mode by descriptor", st.st_mode & 07777, 0644);
    if (expect("no descriptor", sys8(FCHMOD, 987, NONE, NONE, -1, 0, 0, 0, 0), EBADF)) return 1;

    mode_t was = umask(022);
    if (sys8(UMASK, 027, 0, 0, 0, 0, 0, 0, 0) != 022) return bad("umask_extended", errno, 022);
    if (umask(was) != 027) return bad("the umask it set", 0, 027);

    // fsgetpath_ext: a volume's root, by the number every root has.
    char path[128];
    int32_t fsid[2];
    stat("/", &st);
    fsid[0] = st.st_dev;
    fsid[1] = 0;
    long n = sys8(GETPATH, (long)path, sizeof path, (long)fsid, 2, 0x80, 0, 0, 0);
    if (n != 2 || strcmp(path, "/")) return bad("the root's path", n, 2);
    if (sys8(GETPATH, (long)path, sizeof path, (long)fsid, 2, 0x200, 0, 0, 0) != 2) return bad("a real fsid", errno, 0);
    if (expect("an option it does not have", sys8(GETPATH, (long)path, sizeof path, (long)fsid, 2, 0x100, 0, 0, 0), EINVAL)) return 1;
    if (expect("no buffer space", sys8(GETPATH, (long)path, 0, (long)fsid, 2, 0, 0, 0, 0), EINVAL)) return 1;
    if (expect("too much buffer", sys8(GETPATH, (long)path, 8193, (long)fsid, 2, 0, 0, 0, 0), EINVAL)) return 1;
    int32_t none[2] = {0x7654321, 0};
    if (expect("no such volume", sys8(GETPATH, (long)path, sizeof path, (long)none, 2, 0, 0, 0, 0), ENOTSUP)) return 1;

    // proc_info_extended_id: as proc_pidinfo, with its flags checked.
    char info[1024], plain_info[1024];
    long got = sys8(INFO, 2, getpid(), 3, 0, 0, 0, (long)info, sizeof info);
    int want = proc_pidinfo(getpid(), 3, 0, plain_info, sizeof plain_info);
    if (got != want || got <= 16) return bad("proc_info_extended_id", got, want);
    if (*(uint32_t *)(info + 12) != (uint32_t)getpid()) return bad("the pid", *(uint32_t *)(info + 12), getpid());
    if (expect("both comparisons", sys8(INFO, 2, getpid(), 3, 3, 0, 0, (long)info, sizeof info), EINVAL)) return 1;

    close(fd);
    unlink(f);
    rmdir(d);
    puts("filesec ok");
    return 0;
}
