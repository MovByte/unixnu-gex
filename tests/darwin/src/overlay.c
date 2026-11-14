// An overlay laid over the root (`gexc run --overlay`) is part of the
// root's volume, and its files cannot be told from the volume's own: what
// stat, fstat, statfs, getattrlist and getattrlistbulk say of an overlay
// file and of a file of the root beside it; the merged listing of their
// directory; a directory the overlay shadows, whose own entries are gone;
// the mount table; a lookup by object id, F_GETPATH and realpath; the
// extended attributes; mmap; exec of an overlay program; and the
// read-only volume's refusals.
//
// The runner's check overlay holds, in /System/Library/Extensions:
// AGXMetalA10.bundle, opaque, with the root's own Info.plist and a program
// (overlayexe, hello's source) as its executable, which the real bundle
// does not have on disk; and GexOverlay.bundle, which the root has no
// bundle of that name beside, holding an Info.plist. Nothing here writes
// to the root.

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/attr.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

#define EXT "/System/Library/Extensions"
#define SHADOW EXT "/AGXMetalA10.bundle"
#define NEW EXT "/GexOverlay.bundle"
// A bundle of the root's beside them, and a directory of the root's.
#define REAL EXT "/AGXGPURawCounterBundle.bundle"
#define REALDIR EXT "/AppleMetalGLRenderer.bundle"

ssize_t fsgetpath(char *buf, size_t bufsize, fsid_t *fsid, uint64_t objid);
extern char **environ;

static int fails;

static void bad(const char *what, long long got, long long want) {
    printf("overlay: %s: %lld (want %lld)\n", what, got, want);
    fails++;
}

#define EXPECT(what, got, want)                                \
    do {                                                       \
        long long g_ = (long long)(got), w_ = (long long)(want); \
        if (g_ != w_) bad(what, g_, w_);                       \
    } while (0)

// A call that must fail with `e`.
#define REFUSED(what, call, e)                                   \
    do {                                                         \
        errno = 0;                                               \
        long r_ = (long)(call);                                  \
        if (r_ != -1 || errno != (e)) bad(what, r_ == -1 ? errno : r_, e); \
    } while (0)

static struct stat st(const char *path) {
    struct stat s;
    memset(&s, 0, sizeof s);
    if (lstat(path, &s) != 0) {
        printf("overlay: lstat %s: errno %d\n", path, errno);
        fails++;
    }
    return s;
}

// What two files of one volume share, as stat says it.
static void same_kind(const char *what, const struct stat *a, const struct stat *b) {
    char w[160];
    snprintf(w, sizeof w, "%s: st_dev", what);
    EXPECT(w, a->st_dev, b->st_dev);
    snprintf(w, sizeof w, "%s: st_mode", what);
    EXPECT(w, a->st_mode, b->st_mode);
    snprintf(w, sizeof w, "%s: st_uid", what);
    EXPECT(w, a->st_uid, b->st_uid);
    snprintf(w, sizeof w, "%s: st_gid", what);
    EXPECT(w, a->st_gid, b->st_gid);
    snprintf(w, sizeof w, "%s: st_flags", what);
    EXPECT(w, a->st_flags, b->st_flags);
    snprintf(w, sizeof w, "%s: st_blksize", what);
    EXPECT(w, a->st_blksize, b->st_blksize);
    snprintf(w, sizeof w, "%s: st_gen", what);
    EXPECT(w, a->st_gen, b->st_gen);
    if (a->st_ino == b->st_ino) bad("two files with one inode number", (long long)a->st_ino, 0);
}

// A directory's link count and size against its listing, as a directory
// of the root's has them: what the volume counts (every entry, or the
// subdirectories), and its size per link.
struct dirshape {
    long long nlink, size, entries, subdirs;
};

static struct dirshape shape(const char *dir) {
    struct dirshape d = {0, 0, 0, 0};
    struct stat s = st(dir);
    d.nlink = s.st_nlink;
    d.size = s.st_size;
    DIR *dp = opendir(dir);
    if (!dp) {
        bad("opendir", errno, 0);
        return d;
    }
    struct dirent *e;
    while ((e = readdir(dp))) {
        d.entries++;
        if (e->d_type == DT_DIR) d.subdirs++;
    }
    closedir(dp);
    return d;
}

static void shaped_as(const char *what, struct dirshape d, struct dirshape real) {
    char w[160];
    snprintf(w, sizeof w, "%s: st_nlink against its listing", what);
    if (real.nlink == real.entries) EXPECT(w, d.nlink, d.entries);
    else if (real.nlink == real.subdirs) EXPECT(w, d.nlink, d.subdirs);
    snprintf(w, sizeof w, "%s: st_size against st_nlink", what);
    if (real.nlink && real.size % real.nlink == 0 && d.nlink) EXPECT(w, d.size, real.size / real.nlink * d.nlink);
}

// getattrlist's common attributes, in the order of their bits.
struct cmn {
    uint32_t len;
    attrreference_t name;
    dev_t dev;
    fsid_t fsid;
    fsobj_type_t type;
    fsobj_tag_t tag;
    uid_t uid;
    gid_t gid;
    uint32_t mask;
    uint32_t flags;
    uint32_t useraccess;
    uint64_t fileid;
    uint64_t parentid;
    char rest[1024];
} __attribute__((packed, aligned(4)));

#define CMN (ATTR_CMN_NAME | ATTR_CMN_DEVID | ATTR_CMN_FSID | ATTR_CMN_OBJTYPE | ATTR_CMN_OBJTAG | ATTR_CMN_OWNERID | ATTR_CMN_GRPID | ATTR_CMN_ACCESSMASK | ATTR_CMN_FLAGS | ATTR_CMN_USERACCESS | ATTR_CMN_FILEID | ATTR_CMN_PARENTID)

static struct cmn attrs(const char *path) {
    struct cmn c;
    memset(&c, 0, sizeof c);
    struct attrlist al = {.bitmapcount = ATTR_BIT_MAP_COUNT, .commonattr = CMN};
    if (getattrlist(path, &al, &c, sizeof c, FSOPT_NOFOLLOW) != 0) {
        printf("overlay: getattrlist %s: errno %d\n", path, errno);
        fails++;
    }
    return c;
}

static const char *name_of(const struct cmn *c) {
    return (const char *)&c->name + c->name.attr_dataoffset;
}

// (`flags`: the file's own flags, or -1 for the real file's)
static void attrs_as(const char *what, const char *path, const char *real, const char *parent, long long flags) {
    struct cmn a = attrs(path), b = attrs(real);
    struct stat s = st(path), p = st(parent);
    char w[160];
    snprintf(w, sizeof w, "%s: ATTR_CMN_DEVID", what);
    EXPECT(w, a.dev, b.dev);
    snprintf(w, sizeof w, "%s: ATTR_CMN_FSID", what);
    EXPECT(w, a.fsid.val[0], b.fsid.val[0]);
    EXPECT(w, a.fsid.val[1], b.fsid.val[1]);
    snprintf(w, sizeof w, "%s: ATTR_CMN_OBJTYPE", what);
    EXPECT(w, a.type, b.type);
    snprintf(w, sizeof w, "%s: ATTR_CMN_OBJTAG", what);
    EXPECT(w, a.tag, b.tag);
    snprintf(w, sizeof w, "%s: ATTR_CMN_OWNERID", what);
    EXPECT(w, a.uid, b.uid);
    snprintf(w, sizeof w, "%s: ATTR_CMN_GRPID", what);
    EXPECT(w, a.gid, b.gid);
    snprintf(w, sizeof w, "%s: ATTR_CMN_ACCESSMASK", what);
    EXPECT(w, a.mask, b.mask);
    snprintf(w, sizeof w, "%s: ATTR_CMN_FLAGS", what);
    EXPECT(w, a.flags, flags < 0 ? (long long)b.flags : flags);
    snprintf(w, sizeof w, "%s: ATTR_CMN_USERACCESS", what);
    EXPECT(w, a.useraccess, b.useraccess);
    snprintf(w, sizeof w, "%s: ATTR_CMN_FILEID against st_ino", what);
    EXPECT(w, a.fileid, s.st_ino);
    snprintf(w, sizeof w, "%s: ATTR_CMN_PARENTID against its directory's st_ino", what);
    EXPECT(w, a.parentid, p.st_ino);
    snprintf(w, sizeof w, "%s: ATTR_CMN_DEVID against st_dev", what);
    EXPECT(w, a.dev, s.st_dev);
    const char *slash = strrchr(path, '/');
    if (strcmp(name_of(&a), slash + 1) != 0) {
        printf("overlay: %s: ATTR_CMN_NAME %s\n", what, name_of(&a));
        fails++;
    }
}

// A directory's listing: each name once, each entry's d_ino its st_ino
// and on the volume's device. Whether `want` is among the names, and
// (when given) whether `gone` is not.
static int listing(const char *dir, const char *want, const char *gone, dev_t dev) {
    DIR *dp = opendir(dir);
    if (!dp) {
        bad("opendir", errno, 0);
        return 0;
    }
    char names[128][NAME_MAX + 1];
    ino_t inos[128];
    int n = 0, found = 0;
    struct dirent *e;
    while ((e = readdir(dp)) && n < 128) {
        for (int i = 0; i < n; i++) {
            if (strcmp(names[i], e->d_name) == 0) {
                printf("overlay: %s lists %s twice\n", dir, e->d_name);
                fails++;
            }
            if (inos[i] == e->d_ino && strcmp(e->d_name, "..") && strcmp(names[i], "..")) {
                printf("overlay: %s lists %s and %s as one inode\n", dir, names[i], e->d_name);
                fails++;
            }
        }
        snprintf(names[n], sizeof names[n], "%s", e->d_name);
        inos[n++] = e->d_ino;
        if (!strcmp(e->d_name, "..")) continue;
        if (want && !strcmp(e->d_name, want)) found = 1;
        if (gone && !strcmp(e->d_name, gone)) {
            printf("overlay: %s lists %s\n", dir, gone);
            fails++;
        }
        char p[PATH_MAX];
        snprintf(p, sizeof p, "%s/%s", dir, e->d_name);
        struct stat s = st(p);
        if (s.st_ino != e->d_ino) {
            printf("overlay: %s: d_ino %llu, st_ino %llu\n", p, (unsigned long long)e->d_ino, (unsigned long long)s.st_ino);
            fails++;
        }
        if (s.st_dev != dev) bad(p, s.st_dev, dev);
    }
    closedir(dp);
    return found;
}

// getattrlistbulk's names and file ids, against readdir's.
static void bulk(const char *dir) {
    int fd = open(dir, O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
        bad("open the directory", errno, 0);
        return;
    }
    struct attrlist al = {.bitmapcount = ATTR_BIT_MAP_COUNT, .commonattr = ATTR_CMN_RETURNED_ATTRS | ATTR_CMN_NAME | ATTR_CMN_FILEID};
    char buf[16384];
    int seen = 0;
    for (;;) {
        int n = getattrlistbulk(fd, &al, buf, sizeof buf, 0);
        if (n < 0) {
            bad("getattrlistbulk", errno, 0);
            break;
        }
        if (n == 0) break;
        char *at = buf;
        for (int i = 0; i < n; i++) {
            uint32_t len = *(uint32_t *)at;
            char *f = at + 4 + sizeof(attribute_set_t);
            attrreference_t *nr = (attrreference_t *)f;
            const char *name = (const char *)nr + nr->attr_dataoffset;
            uint64_t fileid;
            memcpy(&fileid, f + sizeof(attrreference_t), 8);
            char p[PATH_MAX];
            snprintf(p, sizeof p, "%s/%s", dir, name);
            struct stat s = st(p);
            if (s.st_ino != fileid) {
                printf("overlay: getattrlistbulk %s: file id %llu, st_ino %llu\n", p, (unsigned long long)fileid, (unsigned long long)s.st_ino);
                fails++;
            }
            seen++;
            at += len;
        }
    }
    close(fd);
    // readdir's count, without . and ..
    int count = 0;
    DIR *dp = opendir(dir);
    struct dirent *e;
    while (dp && (e = readdir(dp)))
        if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) count++;
    if (dp) closedir(dp);
    EXPECT("getattrlistbulk's count against readdir's", seen, count);
}

// What a program the overlay holds prints when spawned.
static void spawned(const char *path) {
    int p[2];
    if (pipe(p) != 0) {
        bad("pipe", errno, 0);
        return;
    }
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, p[1], 1);
    posix_spawn_file_actions_addclose(&fa, p[0]);
    char *argv[] = {(char *)path, "x", NULL};
    pid_t pid;
    int r = posix_spawn(&pid, path, &fa, NULL, argv, environ);
    posix_spawn_file_actions_destroy(&fa);
    close(p[1]);
    if (r != 0) {
        bad("posix_spawn of the overlay's program", r, 0);
        close(p[0]);
        return;
    }
    char out[256] = {0};
    size_t got = 0;
    ssize_t k;
    while (got < sizeof out - 1 && (k = read(p[0], out + got, sizeof out - 1 - got)) > 0) got += (size_t)k;
    close(p[0]);
    int status;
    waitpid(pid, &status, 0);
    char want[256];
    snprintf(want, sizeof want, "hello from %s with 1 argument\n", path);
    if (strcmp(out, want) != 0) {
        printf("overlay: the overlay's program printed %s", out);
        fails++;
    }
    EXPECT("the overlay's program's status", status, 0);
}

int main(void) {
    struct stat ext = st(EXT);
    const char *plist = SHADOW "/Info.plist";

    // One volume: an overlay file and its directory against the root's.
    struct stat o = st(plist), r = st(REAL "/Info.plist");
    same_kind("an overlay file against the root's", &o, &r);
    struct stat od = st(SHADOW), nd = st(NEW), rd = st(REALDIR);
    same_kind("the shadowing directory against the root's", &od, &rd);
    same_kind("the overlay's new directory against the root's", &nd, &rd);
    EXPECT("st_dev of the overlay's file against its directory's", o.st_dev, ext.st_dev);

    // fstat of an open overlay file and directory is their stat.
    int fd = open(plist, O_RDONLY);
    if (fd < 0) {
        bad("open the overlay's file", errno, 0);
        return 1;
    }
    struct stat f;
    fstat(fd, &f);
    EXPECT("fstat st_dev", f.st_dev, o.st_dev);
    EXPECT("fstat st_ino", f.st_ino, o.st_ino);
    EXPECT("fstat st_mode", f.st_mode, o.st_mode);
    EXPECT("fstat st_nlink", f.st_nlink, o.st_nlink);
    EXPECT("fstat st_size", f.st_size, o.st_size);
    EXPECT("fstat st_mtime", f.st_mtimespec.tv_sec, o.st_mtimespec.tv_sec);
    int dfd = open(SHADOW, O_RDONLY | O_DIRECTORY);
    struct stat fd2;
    fstat(dfd, &fd2);
    EXPECT("fstat of the shadowing directory: st_ino", fd2.st_ino, od.st_ino);
    EXPECT("fstat of the shadowing directory: st_nlink", fd2.st_nlink, od.st_nlink);
    close(dfd);

    // statfs: the root's volume, by path and by descriptor.
    struct statfs so, sr, sf;
    statfs(plist, &so);
    statfs(REAL "/Info.plist", &sr);
    fstatfs(fd, &sf);
    if (memcmp(&so, &sr, sizeof so) != 0) bad("statfs of the overlay's file against the root's", 1, 0);
    if (memcmp(&sf, &sr, sizeof sf) != 0) bad("fstatfs of the overlay's file against statfs of the root's", 1, 0);
    if (strcmp(so.f_mntonname, "/") != 0) bad("the overlay file's f_mntonname is /", 1, 0);
    EXPECT("f_fsid against st_dev", so.f_fsid.val[0], o.st_dev);

    // No mount of its own.
    int nm = getfsstat(NULL, 0, MNT_NOWAIT);
    struct statfs mounts[16];
    int got = getfsstat(mounts, (int)sizeof mounts, MNT_NOWAIT);
    EXPECT("getfsstat's count", got, nm);
    for (int i = 0; i < got; i++) {
        if (strncmp(mounts[i].f_mntonname, "/System/Library", 15) == 0) {
            printf("overlay: a mount on %s\n", mounts[i].f_mntonname);
            fails++;
        }
    }

    // getattrlist: the root's answers.
    // A file the root's volume has at its path has that file's flags; one
    // where it has none is stored as the overlay holds it, uncompressed,
    // with none.
    attrs_as("an overlay file in the shadowing directory", plist, REAL "/Info.plist", SHADOW, -1);
    attrs_as("an overlay file in the new directory", NEW "/Info.plist", REAL "/Info.plist", NEW, 0);
    attrs_as("the shadowing directory", SHADOW, REALDIR, EXT, -1);
    attrs_as("the new directory", NEW, REALDIR, EXT, -1);

    // The merged listing, counted and sized as the root's directories are;
    // the shadowing directory's, the overlay's alone.
    if (!listing(EXT, "GexOverlay.bundle", NULL, ext.st_dev)) bad("the merged listing has GexOverlay.bundle", 0, 1);
    if (!listing(EXT, "AGXMetalA10.bundle", NULL, ext.st_dev)) bad("the merged listing has AGXMetalA10.bundle", 0, 1);
    if (!listing(SHADOW, "AGXMetalA10", "0_0.bin", ext.st_dev)) bad("the shadowing directory lists its program", 0, 1);
    struct dirshape real = shape(REAL);
    shaped_as(EXT, shape(EXT), real);
    shaped_as(SHADOW, shape(SHADOW), real);
    shaped_as(NEW, shape(NEW), real);
    bulk(EXT);
    bulk(SHADOW);
    struct stat gone;
    REFUSED("lstat of the shadowed bundle's own file", lstat(SHADOW "/0_0.bin", &gone), ENOENT);
    REFUSED("lstat of the shadowed bundle's own signature", lstat(SHADOW "/_CodeSignature", &gone), ENOENT);

    // By object id, F_GETPATH and realpath: where it is.
    char path[PATH_MAX];
    ssize_t n = fsgetpath(path, sizeof path, &so.f_fsid, o.st_ino);
    if (n <= 0 || strcmp(path, plist) != 0) {
        printf("overlay: fsgetpath: %zd %s\n", n, n > 0 ? path : "");
        fails++;
    }
    n = fsgetpath(path, sizeof path, &so.f_fsid, nd.st_ino);
    if (n <= 0 || strcmp(path, NEW) != 0) {
        printf("overlay: fsgetpath of the new directory: %zd %s\n", n, n > 0 ? path : "");
        fails++;
    }
    if (fcntl(fd, F_GETPATH, path) != 0 || strcmp(path, plist) != 0) bad("F_GETPATH", errno, 0);
    if (!realpath(EXT "/../Extensions/./AGXMetalA10.bundle/Info.plist", path) || strcmp(path, plist) != 0) bad("realpath", errno, 0);

    // Extended attributes: the root's file's (none seen), and not the
    // overlay's marks.
    EXPECT("listxattr of the overlay's file against the root's", listxattr(plist, NULL, 0, 0), listxattr(REAL "/Info.plist", NULL, 0, 0));
    EXPECT("listxattr of the shadowing directory against the root's", listxattr(SHADOW, NULL, 0, 0), listxattr(REALDIR, NULL, 0, 0));
    REFUSED("getxattr of the overlay's mark", getxattr(SHADOW, "overlay.opaque", NULL, 0, 0, 0), ENOATTR);

    // mmap reads what read does.
    char a[4096], *m;
    ssize_t len = pread(fd, a, sizeof a, 0);
    m = mmap(NULL, (size_t)o.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (m == MAP_FAILED || len != o.st_size || memcmp(m, a, (size_t)len) != 0) bad("mmap of the overlay's file", errno, 0);
    if (m != MAP_FAILED) munmap(m, (size_t)o.st_size);

    // The volume is read-only.
    EXPECT("access R_OK", access(plist, R_OK), 0);
    REFUSED("access W_OK", access(plist, W_OK), EROFS);
    REFUSED("open to write", open(plist, O_RDWR), EROFS);
    REFUSED("open to create in the shadowing directory", open(SHADOW "/made", O_WRONLY | O_CREAT, 0644), EROFS);
    REFUSED("unlink", unlink(plist), EROFS);
    REFUSED("rename", rename(plist, SHADOW "/moved"), EROFS);
    REFUSED("mkdir in the shadowing directory", mkdir(SHADOW "/d", 0755), EROFS);
    REFUSED("rmdir", rmdir(NEW), EROFS);
    REFUSED("chmod", chmod(plist, 0600), EROFS);
    REFUSED("utimes", utimes(plist, NULL), EROFS);
    REFUSED("setxattr", setxattr(plist, "com.example.x", "1", 1, 0, 0), EROFS);
    close(fd);

    // A program of the overlay's runs.
    spawned(SHADOW "/AGXMetalA10");

    if (fails) return 1;
    printf("overlay ok\n");
    return 0;
}
