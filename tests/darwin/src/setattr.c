// setattrlist, fsetattrlist and setattrlistat: the masks refused, an empty
// request, buffers too short or too long, times, the mode, Finder Info and
// the ignored change time.

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/attr.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

int setattrlist(const char *, void *, void *, size_t, unsigned int);
int fsetattrlist(int, void *, void *, size_t, unsigned int);
int setattrlistat(int, const char *, void *, void *, size_t, uint32_t);

static int bad(const char *what, long got, long want) {
    printf("setattr: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

static int expect(const char *what, long r, int e) {
    if (r != -1 || errno != e) return bad(what, r == -1 ? errno : r, e);
    return 0;
}

int main(void) {
    char path[256], dir[256], name[32] = "t";
    snprintf(dir, sizeof dir, "/private/var/tmp/setattr-%d", getpid());
    snprintf(path, sizeof path, "%s/t", dir);
    char link[280];
    snprintf(link, sizeof link, "%s/l", dir);
    unlink(link);
    unlink(path);
    rmdir(dir);
    if (mkdir(dir, 0755) != 0) return bad("mkdir", errno, 0);
    int fd = open(path, O_RDWR | O_CREAT, 0644);
    if (fd < 0) return bad("open", errno, 0);

    struct attrlist al = {ATTR_BIT_MAP_COUNT, 0, 0, 0, 0, 0, 0};
    char buf[128] = {0};

    // What is refused or does nothing.
    al.bitmapcount = 1;
    if (expect("a bad bitmap count", setattrlist(path, &al, buf, sizeof buf, 0), EINVAL)) return 1;
    al.bitmapcount = ATTR_BIT_MAP_COUNT;
    if (setattrlist(path, &al, (void *)8, 0, 0) != 0) return bad("nothing to set", errno, 0);
    al.commonattr = ATTR_CMN_NAME;
    if (expect("a read-only attribute", setattrlist(path, &al, buf, sizeof buf, 0), EINVAL)) return 1;
    al.commonattr = ATTR_CMN_MODTIME;
    if (expect("a buffer too long", setattrlist(path, &al, buf, 8193, 0), ENOMEM)) return 1;
    if (expect("a buffer too short", setattrlist(path, &al, buf, 8, 0), EINVAL)) return 1;
    if (expect("no such file", setattrlist("/private/var/tmp/setattr-none/x", &al, buf, sizeof buf, 0), ENOENT)) return 1;
    if (expect("a closed descriptor", fsetattrlist(987, &al, buf, sizeof buf, 0), EBADF)) return 1;
    int pp[2];
    pipe(pp);
    if (expect("a pipe", fsetattrlist(pp[0], &al, buf, sizeof buf, 0), EINVAL)) return 1;

    // The times, in attribute order: modify, change (ignored), access.
    al.commonattr = ATTR_CMN_MODTIME | ATTR_CMN_CHGTIME | ATTR_CMN_ACCTIME;
    struct timespec *t = (struct timespec *)buf;
    t[0].tv_sec = 1000000000;
    t[0].tv_nsec = 123456000;
    t[1].tv_sec = 5;
    t[2].tv_sec = 1100000000;
    t[2].tv_nsec = 7000;
    if (setattrlist(path, &al, buf, 3 * sizeof *t, 0) != 0) return bad("the times", errno, 0);
    struct stat st;
    if (stat(path, &st) != 0) return bad("stat", errno, 0);
    if (st.st_mtimespec.tv_sec != 1000000000 || st.st_mtimespec.tv_nsec != 123456000) return bad("mtime", st.st_mtimespec.tv_sec, 1000000000);
    if (st.st_atimespec.tv_sec != 1100000000 || st.st_atimespec.tv_nsec != 7000) return bad("atime", st.st_atimespec.tv_sec, 1100000000);
    if (st.st_ctimespec.tv_sec == 5) return bad("ctime was set", st.st_ctimespec.tv_sec, 0);

    // By descriptor and relative to a directory, the mode with them.
    al.commonattr = ATTR_CMN_MODTIME | ATTR_CMN_ACCESSMASK;
    t[0].tv_sec = 1200000000;
    t[0].tv_nsec = 0;
    *(uint32_t *)(t + 1) = 0600;
    if (fsetattrlist(fd, &al, buf, sizeof *t + 4, 0) != 0) return bad("by descriptor", errno, 0);
    if (fstat(fd, &st) != 0 || (st.st_mode & 07777) != 0600 || st.st_mtimespec.tv_sec != 1200000000) return bad("its result", st.st_mode & 07777, 0600);
    int dfd = open(dir, O_RDONLY);
    t[0].tv_sec = 1300000000;
    *(uint32_t *)(t + 1) = 0644;
    if (setattrlistat(dfd, name, &al, buf, sizeof *t + 4, 0) != 0) return bad("relative to a directory", errno, 0);
    if (stat(path, &st) != 0 || (st.st_mode & 07777) != 0644 || st.st_mtimespec.tv_sec != 1300000000) return bad("its result", st.st_mode & 07777, 0644);

    // Finder Info is the attribute of that name.
    al.commonattr = ATTR_CMN_FNDRINFO;
    memset(buf, 0, sizeof buf);
    memcpy(buf, "TEXTttxt", 8);
    if (setattrlist(path, &al, buf, 32, 0) != 0) return bad("Finder Info", errno, 0);
    char got[32] = {0};
    if (getxattr(path, "com.apple.FinderInfo", got, sizeof got, 0, 0) != 32 || memcmp(got, "TEXTttxt", 8)) return bad("its attribute", errno, 0);
    if (expect("Finder Info too short", setattrlist(path, &al, buf, 31, 0), EINVAL)) return 1;

    // A symbolic link: FSOPT_NOFOLLOW sets the link's time.
    if (symlink(path, link) != 0) return bad("symlink", errno, 0);
    al.commonattr = ATTR_CMN_MODTIME;
    t[0].tv_sec = 1400000000;
    t[0].tv_nsec = 0;
    if (setattrlist(link, &al, buf, sizeof *t, FSOPT_NOFOLLOW) != 0) return bad("a link's own time", errno, 0);
    struct stat st2;
    if (lstat(link, &st) != 0 || st.st_mtimespec.tv_sec != 1400000000) return bad("the link's time", st.st_mtimespec.tv_sec, 1400000000);
    if (stat(link, &st2) != 0 || st2.st_mtimespec.tv_sec != 1300000000) return bad("its target's time", st2.st_mtimespec.tv_sec, 1300000000);
    if (setattrlist(link, &al, buf, sizeof *t, 0) != 0) return bad("through the link", errno, 0);
    if (stat(path, &st2) != 0 || st2.st_mtimespec.tv_sec != 1400000000) return bad("the target through it", st2.st_mtimespec.tv_sec, 1400000000);

    unlink(link);
    unlink(path);
    rmdir(dir);
    puts("setattr ok");
    return 0;
}
