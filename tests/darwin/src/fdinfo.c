// proc_pidfdinfo of a vnode: the file's flags and offset, the descriptor's
// close-on and guard flags, the vnode's stat as fstat has it, its path, and
// what a call that does not fit is told.

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define PROC_PIDFDVNODEINFO 1
#define PROC_PIDFDVNODEPATHINFO 2
#define SYS_change_fdguard_np 444
#define GUARD_CLOSE 1u
#define GUARD_DUP 2u
#define GUARD_FILEPORT 8u
#define O_CLOFORK_ 0x08000000

int proc_pidfdinfo(int pid, int fd, int flavor, void *buffer, int buffersize);
int syscall(int, ...);

struct fileinfo {
    uint32_t openflags, status;
    int64_t offset;
    int32_t type;
    uint32_t guardflags;
};

struct vinfo_stat {
    uint32_t dev;
    uint16_t mode, nlink;
    uint64_t ino;
    uint32_t uid, gid;
    int64_t atime, atimensec, mtime, mtimensec, ctime, ctimensec, birthtime, birthtimensec;
    int64_t size, blocks;
    int32_t blksize;
    uint32_t flags, gen, rdev;
    int64_t qspare[2];
};

struct vnode_info {
    struct vinfo_stat st;
    int type, pad;
    int32_t fsid[2];
};

struct vnode_fdinfo {
    struct fileinfo pfi;
    struct vnode_info pvi;
};

struct vnode_fdinfowithpath {
    struct fileinfo pfi;
    struct vnode_info pvi;
    char path[1024];
};

static int bad(const char *what, long got, long want) {
    printf("fdinfo: %s: %#lx, want %#lx\n", what, got, want);
    return 1;
}

static const uint64_t G = 0x55aa55aa55aa55aaull;

int main(void) {
    if (sizeof(struct vnode_fdinfo) != 176 || sizeof(struct vnode_fdinfowithpath) != 1200) return bad("this test's layout", sizeof(struct vnode_fdinfo), 176);
    char path[256];
    snprintf(path, sizeof path, "/private/var/tmp/fdinfo-%d", getpid());
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC | O_APPEND | O_CLOFORK_, 0644);
    if (fd < 0) return bad("open", errno, 0);
    if (write(fd, "hello", 5) != 5) return bad("write", errno, 0);

    struct vnode_fdinfowithpath i;
    memset(&i, 0xee, sizeof i);
    if (proc_pidfdinfo(getpid(), fd, PROC_PIDFDVNODEPATHINFO, &i, sizeof i) != sizeof i) return bad("path info", errno, 0);
    struct stat st;
    fstat(fd, &st);
    if (i.pfi.openflags != ((O_RDWR | O_APPEND) + 1)) return bad("openflags", i.pfi.openflags, (O_RDWR | O_APPEND) + 1);
    if (i.pfi.status != 8) return bad("status, close-on-fork", i.pfi.status, 8);
    if (i.pfi.offset != 5) return bad("offset", i.pfi.offset, 5);
    if (i.pfi.type != 1) return bad("type", i.pfi.type, 1);
    if (i.pfi.guardflags != 0) return bad("guard flags", i.pfi.guardflags, 0);
    if (strcmp(i.path, path)) return bad("path", i.path[0], path[0]);
    if (i.pvi.st.dev != (uint32_t)st.st_dev) return bad("dev", i.pvi.st.dev, st.st_dev);
    if (i.pvi.st.mode != st.st_mode) return bad("mode", i.pvi.st.mode, st.st_mode);
    if (i.pvi.st.nlink != st.st_nlink) return bad("nlink", i.pvi.st.nlink, st.st_nlink);
    if (i.pvi.st.ino != st.st_ino) return bad("ino", (long)i.pvi.st.ino, (long)st.st_ino);
    if (i.pvi.st.uid != st.st_uid || i.pvi.st.gid != st.st_gid) return bad("owner", i.pvi.st.uid, st.st_uid);
    if (i.pvi.st.mtime != st.st_mtimespec.tv_sec || i.pvi.st.mtimensec != st.st_mtimespec.tv_nsec) return bad("mtime", i.pvi.st.mtime, st.st_mtimespec.tv_sec);
    if (i.pvi.st.atime != st.st_atimespec.tv_sec) return bad("atime", i.pvi.st.atime, st.st_atimespec.tv_sec);
    if (i.pvi.st.ctime != st.st_ctimespec.tv_sec) return bad("ctime", i.pvi.st.ctime, st.st_ctimespec.tv_sec);
    if (i.pvi.st.birthtime != st.st_birthtimespec.tv_sec) return bad("birthtime", i.pvi.st.birthtime, st.st_birthtimespec.tv_sec);
    if (i.pvi.st.size != 5 || i.pvi.st.size != st.st_size) return bad("size", i.pvi.st.size, st.st_size);
    if (i.pvi.st.blocks != st.st_blocks) return bad("blocks", i.pvi.st.blocks, st.st_blocks);
    if (i.pvi.st.blksize != st.st_blksize) return bad("blksize", i.pvi.st.blksize, st.st_blksize);
    if (i.pvi.st.rdev != (uint32_t)st.st_rdev) return bad("rdev", i.pvi.st.rdev, st.st_rdev);
    if (i.pvi.type != 1) return bad("vi_type", i.pvi.type, 1);
    if ((uint32_t)i.pvi.fsid[0] != (uint32_t)st.st_dev) return bad("fsid", i.pvi.fsid[0], st.st_dev);

    // The vnode info alone, and a buffer short of it.
    struct vnode_fdinfo v;
    if (proc_pidfdinfo(getpid(), fd, PROC_PIDFDVNODEINFO, &v, sizeof v) != sizeof v) return bad("vnode info", errno, 0);
    if (v.pvi.st.ino != st.st_ino) return bad("its ino", (long)v.pvi.st.ino, (long)st.st_ino);
    errno = 0;
    if (proc_pidfdinfo(getpid(), fd, PROC_PIDFDVNODEINFO, &v, sizeof v - 1) != 0 || errno != ENOMEM) return bad("a small buffer", errno, ENOMEM);

    // A guarded descriptor says so; a dup'd one is shared; close-on-exec.
    if (syscall(SYS_change_fdguard_np, fd, NULL, 0, &G, GUARD_CLOSE | GUARD_DUP | GUARD_FILEPORT, NULL) != 0) return bad("change_fdguard_np", errno, 0);
    if (proc_pidfdinfo(getpid(), fd, PROC_PIDFDVNODEINFO, &v, sizeof v) != sizeof v) return bad("guarded info", errno, 0);
    if (v.pfi.status != (2 | 4 | 8)) return bad("guarded status", v.pfi.status, 2 | 4 | 8);
    if (v.pfi.guardflags != (1 | 2 | 8)) return bad("its guard flags", v.pfi.guardflags, 1 | 2 | 8);
    int plain = open(path, O_RDONLY);
    int two = dup(plain);
    if (proc_pidfdinfo(getpid(), plain, PROC_PIDFDVNODEINFO, &v, sizeof v) != sizeof v) return bad("a dup's info", errno, 0);
    if (!(v.pfi.status & 1)) return bad("PROC_FP_SHARED", v.pfi.status, 1);
    close(two);
    if (proc_pidfdinfo(getpid(), plain, PROC_PIDFDVNODEINFO, &v, sizeof v) != sizeof v) return bad("after the dup's close", errno, 0);
    if (v.pfi.status & 1) return bad("not shared now", v.pfi.status, 0);
    close(plain);

    // Not a vnode, not open, no such process.
    int pp[2];
    pipe(pp);
    errno = 0;
    if (proc_pidfdinfo(getpid(), pp[0], PROC_PIDFDVNODEINFO, &v, sizeof v) != 0 || errno != EBADF) return bad("a pipe", errno, EBADF);
    errno = 0;
    if (proc_pidfdinfo(getpid(), 987, PROC_PIDFDVNODEINFO, &v, sizeof v) != 0 || errno != EBADF) return bad("a closed descriptor", errno, EBADF);
    errno = 0;
    if (proc_pidfdinfo(99999, 0, PROC_PIDFDVNODEINFO, &v, sizeof v) != 0 || errno != ESRCH) return bad("no such process", errno, ESRCH);
    unlink(path);
    puts("fdinfo ok");
    return 0;
}
