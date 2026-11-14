// Files' owners, groups, modes and flags, and who may change them, as the
// device has them (run as a user other than root):
//
// - the system volume's files are its image's: stat and getattrlist give
//   their owners, groups, modes (set-id bits too) and flags (UF_COMPRESSED
//   for a compressed one), and the volume is read-only (EROFS);
// - the Data volume's first files are the system image's /private/var;
// - a file made is the maker's, in the group of the directory it is made
//   in (BSD semantics), with the mode asked for under the umask and no
//   flags; a directory and a symbolic link likewise;
// - chmod, chown and chflags are vnode_authattr's: the owner may change
//   the mode but not set the set-group-id bit of a group it is not in,
//   nor give the file away, nor set a superuser flag; chown clears the
//   set-user-id bit; an immutable file refuses a write;
// - access is vnode_authorize's, by the real ids.

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/attr.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>

int syscall(int, ...);

#define DIR "/private/var/tmp/gex-darwin-owners.d"

static int fails;

static void bad(const char *what, long long got, long long want) {
    printf("owners: %s: %lld (want %lld)\n", what, got, want);
    fails++;
}

#define EXPECT(what, got, want)                                    \
    do {                                                           \
        long long g_ = (long long)(got), w_ = (long long)(want);   \
        if (g_ != w_) bad(what, g_, w_);                           \
    } while (0)

#define REFUSED(what, call, e)                                       \
    do {                                                             \
        errno = 0;                                                   \
        long r_ = (long)(call);                                      \
        if (r_ != -1 || errno != (e)) bad(what, r_ == -1 ? errno : r_, e); \
    } while (0)

static void owned(const char *path, int follow, uid_t uid, gid_t gid, mode_t mode, uint32_t flags) {
    struct stat st;
    char w[256];
    int r = follow ? stat(path, &st) : lstat(path, &st);
    if (r != 0) {
        snprintf(w, sizeof w, "stat %s", path);
        bad(w, errno, 0);
        return;
    }
    snprintf(w, sizeof w, "%s: st_uid", path);
    EXPECT(w, st.st_uid, uid);
    snprintf(w, sizeof w, "%s: st_gid", path);
    EXPECT(w, st.st_gid, gid);
    snprintf(w, sizeof w, "%s: st_mode", path);
    EXPECT(w, st.st_mode, mode);
    snprintf(w, sizeof w, "%s: st_flags", path);
    EXPECT(w, st.st_flags, flags);
}

struct cmn {
    uint32_t len;
    uid_t uid;
    gid_t gid;
    uint32_t mask;
    uint32_t flags;
    uint32_t access;
} __attribute__((packed));

int main(void) {
    uid_t me = geteuid();
    gid_t mygid = getegid();
    if (me == 0) {
        printf("owners: run as root\n");
        return 1;
    }
    umask(022);

    // The system volume's.
    owned("/sbin/launchd", 1, 0, 0, S_IFREG | 0755, UF_COMPRESSED);
    owned("/bin/ps", 1, 0, 0, S_IFREG | 04755, UF_COMPRESSED);
    owned("/var", 0, 0, 80, S_IFLNK | 0755, 0);
    owned("/System/Library", 1, 0, 0, S_IFDIR | 0755, 0);
    // The Data volume's, the image's /private/var.
    owned("/private/var/mobile", 1, 501, 501, S_IFDIR | 0711, 0);
    owned("/private/var/tmp", 1, 0, 0, S_IFDIR | 01777, 0);

    struct attrlist al = {.bitmapcount = ATTR_BIT_MAP_COUNT, .commonattr = ATTR_CMN_OWNERID | ATTR_CMN_GRPID | ATTR_CMN_ACCESSMASK | ATTR_CMN_FLAGS | ATTR_CMN_USERACCESS};
    struct cmn c;
    if (getattrlist("/bin/ps", &al, &c, sizeof c, 0) != 0) {
        bad("getattrlist /bin/ps", errno, 0);
    } else {
        EXPECT("getattrlist /bin/ps: ATTR_CMN_OWNERID", c.uid, 0);
        EXPECT("getattrlist /bin/ps: ATTR_CMN_GRPID", c.gid, 0);
        EXPECT("getattrlist /bin/ps: ATTR_CMN_ACCESSMASK", c.mask, S_IFREG | 04755);
        EXPECT("getattrlist /bin/ps: ATTR_CMN_FLAGS", c.flags, UF_COMPRESSED);
        // Others may read and run it; nobody may write a read-only volume.
        EXPECT("getattrlist /bin/ps: ATTR_CMN_USERACCESS", c.access, R_OK | X_OK);
    }

    // The read-only volume.
    REFUSED("access W_OK of the system volume's file", access("/sbin/launchd", W_OK), EROFS);
    REFUSED("chmod of the system volume's file", chmod("/sbin/launchd", 0700), EROFS);
    REFUSED("utimes of the system volume's file", utimes("/sbin/launchd", NULL), EROFS);
    if (access("/sbin/launchd", R_OK | X_OK) != 0) bad("access R_OK|X_OK of launchd", errno, 0);
    // Another user's directory: the other bits.
    REFUSED("access R_OK of root's 0750 directory", access("/private/var/root", R_OK), EACCES);

    // What one makes (what an earlier run left gone first).
    unlink(DIR "/link");
    unlink(DIR "/file");
    rmdir(DIR);
    mkdir(DIR, 0777);
    owned(DIR, 1, me, 0, S_IFDIR | 0755, 0);
    int fd = open(DIR "/file", O_RDWR | O_CREAT | O_TRUNC, 0666);
    if (fd < 0) {
        bad("open O_CREAT", errno, 0);
        return 1;
    }
    owned(DIR "/file", 1, me, 0, S_IFREG | 0644, 0);
    if (symlink("file", DIR "/link") != 0) bad("symlink", errno, 0);
    owned(DIR "/link", 0, me, 0, S_IFLNK | 0755, 0);
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_uid != me || st.st_gid != 0) bad("fstat of what one made", st.st_uid, me);

    // Its mode, by its owner: not the set-group-id bit of a group one is
    // not in.
    if (chmod(DIR "/file", 0600) != 0) bad("chmod by the owner", errno, 0);
    owned(DIR "/file", 1, me, 0, S_IFREG | 0600, 0);
    // (the kernel's call: Libsyscall's chmod tries again without the bit)
    REFUSED("chmod g+s of wheel's file", syscall(SYS_chmod, DIR "/file", 02600), EPERM);
    if (fchmod(fd, 04755) != 0) bad("fchmod u+s by the owner", errno, 0);
    owned(DIR "/file", 1, me, 0, S_IFREG | 04755, 0);

    // Its owner and group: not given away, its group one of one's own;
    // chown clears the set-user-id bit.
    REFUSED("chown to another user", chown(DIR "/file", me + 1, -1), EPERM);
    REFUSED("chown to a group one is not in", chown(DIR "/file", -1, 80), EPERM);
    if (chown(DIR "/file", -1, mygid) != 0) bad("chown to one's own group", errno, 0);
    owned(DIR "/file", 1, me, mygid, S_IFREG | 0755, 0);
    if (lchown(DIR "/link", me, -1) != 0) bad("lchown of one's own link", errno, 0);

    // Its flags: a user's, not a superuser's; an immutable file refuses a
    // write, and its flag can be taken off.
    if (chflags(DIR "/file", UF_HIDDEN) != 0) bad("chflags UF_HIDDEN", errno, 0);
    owned(DIR "/file", 1, me, mygid, S_IFREG | 0755, UF_HIDDEN);
    REFUSED("chflags SF_IMMUTABLE as a user", chflags(DIR "/file", SF_IMMUTABLE), EPERM);
    if (fchflags(fd, UF_IMMUTABLE) != 0) bad("fchflags UF_IMMUTABLE", errno, 0);
    REFUSED("open for writing of an immutable file", open(DIR "/file", O_WRONLY), EPERM);
    REFUSED("chmod of an immutable file", chmod(DIR "/file", 0700), EPERM);
    if (chflags(DIR "/file", 0) != 0) bad("chflags 0 of an immutable file", errno, 0);
    owned(DIR "/file", 1, me, mygid, S_IFREG | 0755, 0);
    // UF_COMPRESSED does not stick to a file with no compressed data.
    if (chflags(DIR "/file", UF_COMPRESSED) != 0) bad("chflags UF_COMPRESSED", errno, 0);
    owned(DIR "/file", 1, me, mygid, S_IFREG | 0755, 0);

    // access by the owner's bits alone.
    if (chmod(DIR "/file", 0077) != 0) bad("chmod 0077", errno, 0);
    REFUSED("access R_OK of one's own 0077 file", access(DIR "/file", R_OK), EACCES);
    REFUSED("open of one's own 0077 file", open(DIR "/file", O_RDONLY), EACCES);

    close(fd);
    unlink(DIR "/link");
    unlink(DIR "/file");
    rmdir(DIR);
    if (fails) return 1;
    printf("owners ok\n");
    return 0;
}
