// clonefile, fclonefileat and exchangedata: what a clone of a file, link
// and directory keeps, and each refusal.

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/clonefile.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/xattr.h>
#include <unistd.h>

int exchangedata(const char *, const char *, unsigned int);

static int bad(const char *what, long got, long want) {
    printf("clone: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

static int expect(const char *what, long r, int e) {
    if (r != -1 || errno != e) return bad(what, r == -1 ? errno : r, e);
    return 0;
}

static char d[128], p[8][200];

static const char *at(int i, const char *name) {
    snprintf(p[i], sizeof p[i], "%s/%s", d, name);
    return p[i];
}

static void clean(void) {
    static const char *names[] = {"f", "c", "l", "lc", "lf", "s/g", "s2/g", "s", "s2", "w", "rr", "n", 0};
    for (int i = 0; names[i]; i++) {
        unlink(at(0, names[i]));
        rmdir(at(0, names[i]));
    }
    rmdir(d);
}

int main(void) {
    snprintf(d, sizeof d, "/private/var/tmp/clone-%d", getpid());
    clean();
    if (mkdir(d, 0755) != 0) return bad("mkdir", errno, 0);
    int f = open(at(0, "f"), O_RDWR | O_CREAT, 0640);
    if (write(f, "hello", 5) != 5) return bad("write", errno, 0);
    close(f);
    if (setxattr(at(0, "f"), "x.y", "val", 3, 0, 0) != 0) return bad("setxattr", errno, 0);
    struct timeval tv[2] = {{1000000, 5}, {2000000, 7}};
    utimes(at(0, "f"), tv);

    if (clonefile(at(0, "f"), at(1, "c"), 0) != 0) return bad("clonefile", errno, 0);
    struct stat a, b;
    stat(at(0, "f"), &a);
    stat(at(1, "c"), &b);
    if (b.st_ino == a.st_ino) return bad("the file number", (long)b.st_ino, 0);
    if (b.st_mode != a.st_mode || b.st_size != 5) return bad("the mode", b.st_mode, a.st_mode);
    if (b.st_mtimespec.tv_sec != 2000000 || b.st_mtimespec.tv_nsec != 7000) return bad("the mtime", b.st_mtimespec.tv_sec, 2000000);
    if (b.st_atimespec.tv_sec != 1000000 || b.st_atimespec.tv_nsec != 5000) return bad("the atime", b.st_atimespec.tv_sec, 1000000);
    char buf[16] = {0};
    if (getxattr(at(1, "c"), "x.y", buf, sizeof buf, 0, 0) != 3 || memcmp(buf, "val", 3)) return bad("the attribute", errno, 0);
    int c = open(at(1, "c"), O_RDWR);
    if (read(c, buf, 5) != 5 || memcmp(buf, "hello", 5)) return bad("the data", buf[0], 'h');
    // It is its own file now.
    pwrite(c, "J", 1, 0);
    close(c);
    int o = open(at(0, "f"), O_RDONLY);
    read(o, buf, 1);
    close(o);
    if (buf[0] != 'h') return bad("the source changed", buf[0], 'h');

    // Links: CLONE_NOFOLLOW clones the link, otherwise what it names.
    symlink("f", at(2, "l"));
    if (clonefile(at(2, "l"), at(3, "lc"), CLONE_NOFOLLOW) != 0) return bad("a link's clone", errno, 0);
    if (lstat(at(3, "lc"), &b) != 0 || !S_ISLNK(b.st_mode)) return bad("is a link", b.st_mode, 0);
    char tgt[8] = {0};
    if (readlink(at(3, "lc"), tgt, sizeof tgt) != 1 || tgt[0] != 'f') return bad("its target", tgt[0], 'f');
    if (clonefile(at(2, "l"), at(4, "lf"), 0) != 0) return bad("a followed link", errno, 0);
    if (lstat(at(4, "lf"), &b) != 0 || !S_ISREG(b.st_mode)) return bad("is a file", b.st_mode, 0);

    // A directory, with what is in it; its own modification is new.
    mkdir(at(5, "s"), 0700);
    close(open(at(6, "s/g"), O_CREAT | O_WRONLY, 0600));
    struct timeval old[2] = {{3000000, 0}, {4000000, 0}};
    utimes(at(5, "s"), old);
    if (clonefile(at(5, "s"), at(7, "s2"), 0) != 0) return bad("a directory's clone", errno, 0);
    if (stat(at(7, "s2"), &b) != 0 || !S_ISDIR(b.st_mode) || (b.st_mode & 0777) != 0700) return bad("is a directory", b.st_mode, 0);
    if (b.st_atimespec.tv_sec != 3000000) return bad("its atime", b.st_atimespec.tv_sec, 3000000);
    if (b.st_mtimespec.tv_sec == 4000000) return bad("its mtime kept", b.st_mtimespec.tv_sec, 0);
    if (stat(at(6, "s2/g"), &b) != 0 || !S_ISREG(b.st_mode) || (b.st_mode & 0777) != 0600) return bad("its entry", b.st_mode, 0);

    // Refusals.
    if (expect("the name in use", clonefile(at(0, "f"), at(1, "c"), 0), EEXIST)) return 1;
    if (expect("no source", clonefile(at(0, "none"), at(1, "n"), 0), ENOENT)) return 1;
    if (expect("no directory for it", clonefile(at(0, "f"), at(1, "nodir/x"), 0), ENOENT)) return 1;
    if (expect("a bad flag", clonefile(at(0, "f"), at(1, "n"), 8), EINVAL)) return 1;
    if (expect("a device", clonefile("/dev/null", at(1, "n"), 0), EINVAL)) return 1;
    if (expect("across volumes", clonefile(at(0, "f"), "/System/Cryptexes/OS/n", 0), EXDEV)) return 1;
    int wr = open(at(0, "f"), O_WRONLY);
    if (expect("a write-only descriptor", fclonefileat(wr, AT_FDCWD, at(1, "w"), 0), EBADF)) return 1;
    close(wr);
    int pp[2];
    pipe(pp);
    if (expect("a pipe", fclonefileat(pp[0], AT_FDCWD, at(1, "n"), 0), ENOTSUP)) return 1;
    int rd = open(at(0, "f"), O_RDONLY);
    if (fclonefileat(rd, AT_FDCWD, at(1, "rr"), 0) != 0) return bad("by descriptor", errno, 0);
    close(rd);
    if (stat(at(1, "rr"), &b) != 0 || b.st_size != 5) return bad("its size", b.st_size, 5);

    // exchangedata: its checks, then no such operation on APFS.
    if (expect("exchange with itself", exchangedata(at(0, "f"), at(1, "f"), 0), EINVAL)) return 1;
    if (expect("exchange of a directory", exchangedata(at(0, "f"), at(1, "s"), 0), EINVAL)) return 1;
    if (expect("exchange of nothing", exchangedata(at(0, "f"), at(1, "none"), 0), ENOENT)) return 1;
    if (expect("exchange", exchangedata(at(0, "f"), at(1, "c"), 0), ENOTSUP)) return 1;

    clean();
    puts("clone ok");
    return 0;
}
