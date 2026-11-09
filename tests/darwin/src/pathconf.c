// pathconf and fpathconf by the kind of vnode they ask about, what a
// descriptor that is no vnode answers, getdtablesize, an O_SYMLINK open and
// freadlink, and O_NOFOLLOW_ANY.

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/event.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define PC_MIN_HOLE 27
#define PC_XATTR_BITS 26
#ifndef O_SYMLINK
#define O_SYMLINK 0x00200000
#endif
#define O_NOFOLLOW_ANY_ 0x20000000

ssize_t freadlink(int fd, char *buf, size_t size);

static int bad(const char *what, long got, long want) {
    printf("pathconf: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

static int expect(const char *what, long r, int e) {
    if (r != -1 || errno != e) return bad(what, r == -1 ? errno : r, e);
    return 0;
}

// The answers for names 1 to 27; -1 for EINVAL.
static const long apfs[] = {32767, -1, -1, 255, 1024, 512, 200112, 200112, -1, 255, 1, 1, 1, 0, 1, 1, 1, 56, 0, 4096, 65536, 4096, 4096, 255, 0, 56, 4096};
static const long spec[] = {32767, 1024, 1024, -1, -1, 512, 200112, -1, 255, -1, -1, -1, 0, 0, 1, 1, 1, -1, 0, 4096, 65536, 4096, 4096, 255, 0, 31, -1};
static const long devd[] = {32767, -1, -1, 31, 127, -1, 200112, 0, -1, -1, 1, 1, 0, 0, 1, 1, 1, -1, 0, 4096, 65536, 4096, 4096, 255, 0, 31, -1};

static int table(const char *what, const char *path, int fd, const long *want) {
    for (int n = 1; n <= 27; n++) {
        errno = 0;
        long got = path ? pathconf(path, n) : fpathconf(fd, n);
        if (want[n - 1] < 0) {
            if (got != -1 || errno != EINVAL) {
                printf("pathconf: %s name %d: %ld errno %d, want EINVAL\n", what, n, got, errno);
                return 1;
            }
        } else if (got != want[n - 1]) {
            printf("pathconf: %s name %d: %ld errno %d, want %ld\n", what, n, got, errno, want[n - 1]);
            return 1;
        }
    }
    return 0;
}

int main(void) {
    char dir[256], file[300], link[300], buf[32];
    snprintf(dir, sizeof dir, "/private/var/tmp/pc-%d", getpid());
    snprintf(file, sizeof file, "%s/f", dir);
    snprintf(link, sizeof link, "%s/l", dir);
    unlink(link);
    unlink(file);
    rmdir(dir);
    if (mkdir(dir, 0755) != 0) return bad("mkdir", errno, 0);
    close(open(file, O_RDWR | O_CREAT, 0644));
    if (symlink("target-name", link) != 0) return bad("symlink", errno, 0);

    if (table("a directory", dir, -1, apfs)) return 1;
    if (table("a file", file, -1, apfs)) return 1;
    if (table("a device", "/dev/null", -1, spec)) return 1;
    if (table("/dev", "/dev", -1, devd)) return 1;
    if (expect("no such file", pathconf("/private/var/tmp/pc-none/x", 1), ENOENT)) return 1;
    if (expect("a bad address", pathconf((char *)8, 1), EFAULT)) return 1;
    if (expect("an unknown name", pathconf(file, 99), EINVAL)) return 1;

    int fd = open(file, O_RDONLY);
    if (table("a file by descriptor", NULL, fd, apfs)) return 1;
    int nullfd = open("/dev/null", O_RDONLY);
    if (table("a device by descriptor", NULL, nullfd, spec)) return 1;

    int pp[2], sv[2];
    pipe(pp);
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    if (fpathconf(pp[0], _PC_PIPE_BUF) != 512) return bad("a pipe's PIPE_BUF", errno, 0);
    if (expect("a pipe's other name", fpathconf(pp[0], _PC_LINK_MAX), EINVAL)) return 1;
    if (fpathconf(sv[0], _PC_PIPE_BUF) != 512) return bad("a socket's PIPE_BUF", errno, 0);
    if (expect("a socket's other name", fpathconf(sv[0], _PC_NAME_MAX), EINVAL)) return 1;
    int kq = kqueue();
    if (expect("a kqueue", fpathconf(kq, _PC_PIPE_BUF), EINVAL)) return 1;
    if (expect("a closed descriptor", fpathconf(999, 1), EBADF)) return 1;

    struct rlimit rl;
    getrlimit(RLIMIT_NOFILE, &rl);
    if (getdtablesize() != (int)rl.rlim_cur) return bad("getdtablesize", getdtablesize(), (long)rl.rlim_cur);

    // O_SYMLINK holds the link; freadlink reads it.
    int ln = open(link, O_RDONLY | O_SYMLINK);
    if (ln < 0) return bad("an O_SYMLINK open", errno, 0);
    struct stat st;
    if (fstat(ln, &st) != 0 || !S_ISLNK(st.st_mode)) return bad("its fstat", st.st_mode, 0);
    memset(buf, 0, sizeof buf);
    if (freadlink(ln, buf, sizeof buf) != 11 || strcmp(buf, "target-name")) return bad("freadlink", errno, 0);
    if (freadlink(ln, buf, 3) != 3 || memcmp(buf, "tar", 3)) return bad("a short freadlink", errno, 0);
    if (freadlink(ln, buf, 0) != 0) return bad("an empty freadlink", errno, 0);
    if (expect("freadlink of a file", freadlink(fd, buf, sizeof buf), EINVAL)) return 1;
    if (expect("freadlink of a pipe", freadlink(pp[0], buf, sizeof buf), EINVAL)) return 1;
    if (expect("freadlink of a closed descriptor", freadlink(999, buf, sizeof buf), EBADF)) return 1;
    close(ln);
    // O_SYMLINK of what is no link is an open.
    int plain = open(file, O_RDWR | O_SYMLINK);
    if (plain < 0 || write(plain, "x", 1) != 1) return bad("O_SYMLINK of a file", errno, 0);
    close(plain);

    // O_NOFOLLOW_ANY: the first link in the path ends it.
    if (expect("O_NOFOLLOW_ANY through a link", open(link, O_RDONLY | O_NOFOLLOW_ANY_), ELOOP)) return 1;
    char dl[300], viadl[320];
    snprintf(dl, sizeof dl, "%s/dl", dir);
    snprintf(viadl, sizeof viadl, "%s/f", dl);
    unlink(dl);
    if (symlink(dir, dl) != 0) return bad("a directory's link", errno, 0);
    int thru = open(viadl, O_RDONLY);
    if (thru < 0) return bad("an open through a link", errno, 0);
    close(thru);
    if (expect("O_NOFOLLOW_ANY through a directory's link", open(viadl, O_RDONLY | O_NOFOLLOW_ANY_), ELOOP)) return 1;
    unlink(dl);
    if (expect("O_NOFOLLOW_ANY and O_SYMLINK", open(file, O_RDONLY | O_NOFOLLOW_ANY_ | O_SYMLINK), EINVAL)) return 1;
    if (expect("O_NOFOLLOW_ANY and O_NOFOLLOW", open(file, O_RDONLY | O_NOFOLLOW_ANY_ | O_NOFOLLOW), EINVAL)) return 1;
    plain = open(file, O_RDONLY | O_NOFOLLOW_ANY_);
    if (plain < 0) return bad("O_NOFOLLOW_ANY of a plain path", errno, 0);
    close(plain);

    unlink(link);
    unlink(file);
    rmdir(dir);
    puts("pathconf ok");
    return 0;
}
