// fstatat's AT_REALDEV (VA_REALFSID): the device is the vnode's own
// mount's (f_fsid.val[0]) even where its filesystem would give another
// (VA_USEFSID); the rest of the stat is the same.

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

static int bad(const char *what, const char *p, long got, long want) {
    printf("realdev: %s of %s: %ld, want %ld\n", what, p, got, want);
    fflush(stdout);
    return 1;
}

int main(void) {
    const char *paths[] = {"/", "/dev", "/dev/null", "/private/var", "/usr/lib/dyld", "/dev/ptmx"};
    for (int i = 0; i < 6; i++) {
        const char *p = paths[i];
        struct stat a, b;
        struct statfs f;
        if (fstatat(AT_FDCWD, p, &a, 0) || statfs(p, &f)) return bad("stat", p, errno, 0);
        if (fstatat(AT_FDCWD, p, &b, AT_REALDEV)) return bad("AT_REALDEV", p, errno, 0);
        if (b.st_dev != (dev_t)f.f_fsid.val[0]) return bad("the real device", p, b.st_dev, f.f_fsid.val[0]);
        b.st_dev = a.st_dev;
        // (the times of a node read between the two may move)
        b.st_atimespec = a.st_atimespec;
        if (memcmp(&a, &b, sizeof a)) return bad("the rest", p, (long)b.st_ino, (long)a.st_ino);
    }
    // With AT_SYMLINK_NOFOLLOW, the link's own.
    struct stat a, b;
    if (fstatat(AT_FDCWD, "/var", &a, AT_SYMLINK_NOFOLLOW) || fstatat(AT_FDCWD, "/var", &b, AT_SYMLINK_NOFOLLOW | AT_REALDEV)) return bad("the link", "/var", errno, 0);
    if (!S_ISLNK(b.st_mode) || b.st_ino != a.st_ino) return bad("the link", "/var", b.st_mode, a.st_mode);
    printf("realdev ok\n");
    return 0;
}
