// /dev as devfs keeps it: its mount (devfs_statfs: 512-byte blocks of its
// bookkeeping, nothing free, f_files its devnodes), its root (mode 0555,
// hidden, owned by root, its size 8 and the name for each entry, its
// links "." its name ".." and its subdirectories' ".."), its nodes as
// devfs_init made them, numbered in the order they were made, with no
// birth time and MAXPHYSIO for their block size, and their times kept
// lazily (devfs_consider_time_update: an update within a second of the
// last is put off, then made at most a second on). A replica's node is
// numbered after the boot's.

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static int bad(const char *what, long got, long want) {
    printf("devfs: %s: %ld, want %ld\n", what, got, want);
    fflush(stdout);
    return 1;
}

static ino_t ino(const char *p) {
    struct stat st;
    return stat(p, &st) ? 0 : st.st_ino;
}

// The root's entries: their names' bytes plus 8 each, their count, its
// subdirectories, and the first names.
static int scan(long *len, long *n, long *dirs, char first[5][32], ino_t *dot, ino_t *dotdot) {
    DIR *d = opendir("/dev");
    if (!d) return -1;
    struct dirent *e;
    int i = 0;
    *len = *n = *dirs = 0;
    while ((e = readdir(d))) {
        if (!strcmp(e->d_name, ".")) { *dot = e->d_ino; continue; }
        if (!strcmp(e->d_name, "..")) { *dotdot = e->d_ino; continue; }
        *len += (long)strlen(e->d_name) + 8;
        (*n)++;
        if (e->d_type == DT_DIR) (*dirs)++;
        if (i < 5) strlcpy(first[i++], e->d_name, 32);
    }
    closedir(d);
    return 0;
}

int main(void) {
    struct statfs fs;
    if (statfs("/dev", &fs)) return bad("statfs", errno, 0);
    if (strcmp(fs.f_fstypename, "devfs") || strcmp(fs.f_mntonname, "/dev") || strcmp(fs.f_mntfromname, "devfs")) return bad("the mount's names", 0, 1);
    if (fs.f_type != 19 || (unsigned)fs.f_fsid.val[1] != 19) return bad("f_type", fs.f_type, 19);
    if (fs.f_bsize != 512 || fs.f_iosize != 512) return bad("f_bsize", fs.f_bsize, 512);
    if (fs.f_bfree || fs.f_bavail || fs.f_ffree) return bad("free space", (long)fs.f_bfree, 0);
    if (fs.f_flags != (MNT_LOCAL | MNT_DONTBROWSE | MNT_MULTILABEL)) return bad("f_flags", fs.f_flags, MNT_LOCAL | MNT_DONTBROWSE | MNT_MULTILABEL);
    // The blocks are what the devnodes, their entries (no more than the
    // devnodes: a removed node stays until its vnode is reclaimed), the
    // mount record and any symlink names hold.
    long want = (16 + (long)fs.f_files * 216 + (long)fs.f_files * 80) / 512;
    if ((long)fs.f_blocks > want + 1 || (long)fs.f_blocks < (16 + (long)fs.f_files * 216) / 512) return bad("f_blocks", (long)fs.f_blocks, want);
    struct statfs *all;
    int nm = getmntinfo(&all, MNT_NOWAIT), at = -1;
    for (int i = 0; i < nm; i++)
        if (!strcmp(all[i].f_mntonname, "/dev")) at = i;
    if (at != 1) return bad("devfs's place in the mount list", at, 1);

    struct stat st;
    long len = 0, n = 0, dirs = 0;
    char first[5][32];
    ino_t dot = 0, dotdot = 0;
    // A terminal made between the two looks is tried again.
    for (int tries = 0;; tries++) {
        if (scan(&len, &n, &dirs, first, &dot, &dotdot)) return bad("opendir", errno, 0);
        if (lstat("/dev", &st)) return bad("lstat /dev", errno, 0);
        if (st.st_size == len || tries == 5) break;
    }
    if (st.st_mode != (S_IFDIR | 0555) || st.st_uid || st.st_gid) return bad("/dev's mode", st.st_mode, S_IFDIR | 0555);
    if (st.st_flags != UF_HIDDEN) return bad("/dev's flags", st.st_flags, UF_HIDDEN);
    if (st.st_size != len) return bad("/dev's size", (long)st.st_size, len);
    if (st.st_nlink != 3 + dirs) return bad("/dev's links", st.st_nlink, 3 + dirs);
    if (st.st_blksize != 512 || st.st_blocks != (st.st_size + 511) / 512) return bad("/dev's blocks", (long)st.st_blocks, (long)(st.st_size + 511) / 512);
    if (st.st_birthtimespec.tv_sec || st.st_birthtimespec.tv_nsec) return bad("/dev's birth time", st.st_birthtimespec.tv_sec, 0);
    if (st.st_dev != (dev_t)fs.f_fsid.val[0]) return bad("/dev's device", st.st_dev, fs.f_fsid.val[0]);
    if (dot != st.st_ino || dotdot != st.st_ino) return bad("the root's . and ..", (long)dotdot, (long)st.st_ino);
    const char *order[] = {"console", "tty", "null", "zero", "klog"};
    for (int i = 0; i < 5; i++)
        if (strcmp(first[i], order[i])) return bad(order[i], i, 0);

    // The nodes devfs_init makes, numbered in turn after the mount's root.
    struct { const char *p; int maj, min, mode; } nodes[] = {
        {"/dev/tty", 2, 0, 0666}, {"/dev/null", 3, 2, 0666}, {"/dev/zero", 3, 3, 0666}, {"/dev/klog", 6, 0, 0600},
    };
    for (int i = 0; i < 4; i++) {
        if (stat(nodes[i].p, &st)) return bad(nodes[i].p, errno, 0);
        if (major(st.st_rdev) != nodes[i].maj || minor(st.st_rdev) != nodes[i].min) return bad(nodes[i].p, (long)st.st_rdev, makedev(nodes[i].maj, nodes[i].min));
        if (st.st_mode != (S_IFCHR | nodes[i].mode) || st.st_uid || st.st_gid || st.st_nlink != 1) return bad("a node's mode", st.st_mode, S_IFCHR | nodes[i].mode);
        if (st.st_blksize != 64 * 1024 || st.st_blocks || st.st_size) return bad("a node's block size", st.st_blksize, 64 * 1024);
        if (st.st_birthtimespec.tv_sec) return bad("a node's birth time", st.st_birthtimespec.tv_sec, 0);
        if (st.st_dev != (dev_t)fs.f_fsid.val[0]) return bad("a node's device", st.st_dev, fs.f_fsid.val[0]);
    }
    ino_t root = ino("/dev"), console = ino("/dev/console");
    if (console != root + 1 || ino("/dev/tty") != root + 2 || ino("/dev/null") != root + 3 || ino("/dev/zero") != root + 4) return bad("the nodes' numbers", (long)ino("/dev/null"), (long)root + 3);
    if (ino("/dev/ptyp0") != ino("/dev/ttyp0") + 1 || ino("/dev/bpf0") != ino("/dev/ptmx") + 1) return bad("the ptys' numbers", (long)ino("/dev/ptyp0"), (long)ino("/dev/ttyp0") + 1);

    // A replica's node, made after the boot's.
    int m = posix_openpt(O_RDWR | O_NOCTTY);
    if (m < 0 || grantpt(m) || unlockpt(m)) return bad("a pty", errno, 0);
    char pname[128];
    strlcpy(pname, ptsname(m), sizeof pname);
    int s = open(pname, O_RDWR | O_NOCTTY);
    if (s < 0) return bad("the replica", errno, 0);
    if (fstat(s, &st) || st.st_ino <= ino("/dev/bpf0")) return bad("the replica's number", (long)st.st_ino, 0);
    // A write a second after the last change moves the times now; one
    // within the second is put off, and then made a second on.
    // (on the replica, a node no one else writes)
    int fd = s;
    usleep(1100000);
    time_t t0 = time(NULL);
    write(fd, "x", 1);
    fstat(fd, &st);
    if (st.st_mtimespec.tv_sec < t0 || st.st_ctimespec.tv_sec < t0) return bad("the write's time", st.st_mtimespec.tv_sec, t0);
    time_t m1 = st.st_mtimespec.tv_sec;
    // Within the same second: put off.
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    if (ts.tv_sec == m1) {
        write(fd, "x", 1);
        usleep(2500000);
        fstat(fd, &st);
        if (st.st_mtimespec.tv_sec != m1 + 1) return bad("a put-off write's time", st.st_mtimespec.tv_sec, m1 + 1);
    }

    close(s);
    close(m);
    printf("devfs ok\n");
    return 0;
}
