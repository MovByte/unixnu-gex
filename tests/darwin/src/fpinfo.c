// proc_pidfileportinfo: a file port's file described with no descriptor
// (no close-on-exec), a shared memory object's and a vnode's, in the
// caller's space and in another process's; a flavor of another type, a
// name that is no file port, and a short buffer are refused. A process that
// has exited is not found; the kernel's holds no descriptor.

#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#define PIDFDINFO 3
#define PIDFILEPORTINFO 6
#define VNODEPATHINFO 2
#define SOCKETINFO 3
#define PSHMINFO 5
#define PIPEINFO 6

int __proc_info(int callnum, int pid, int flavor, uint64_t arg, void *buffer, int buffersize);
int fileport_makeport(int fd, mach_port_t *port);

struct fileinfo {
    uint32_t openflags, status;
    int64_t offset;
    int32_t type;
    uint32_t guardflags;
};

struct pshm_fdinfo {
    struct fileinfo pfi;
    uint8_t st[136];
    uint64_t mappaddr;
    char name[1024];
};

struct vnode_fdinfowithpath {
    struct fileinfo pfi;
    uint8_t vi[152];
    char path[1024];
};

static int bad(const char *what, long got, long want) {
    printf("fpinfo: %s: %#lx, want %#lx\n", what, got, want);
    fflush(stdout);
    return 1;
}

static int info(pid_t pid, int flavor, mach_port_t name, void *b, int size) {
    return __proc_info(PIDFILEPORTINFO, pid, flavor, name, b, size);
}

// The call's error (0: it succeeded with the whole buffer).
static int err_of(int r, int size) {
    return r == size ? 0 : r == -1 ? errno : -r;
}

int main(void) {
    int fail = 0, e;
    char path[64], mname[32];
    snprintf(path, sizeof path, "/private/var/tmp/fpinfo-%d", getpid());
    snprintf(mname, sizeof mname, "/fpinfo-%d", getpid());

    // A shared memory object's file port, the descriptor close-on-exec.
    int mfd = shm_open(mname, O_CREAT | O_EXCL | O_RDWR, 0600);
    if (mfd < 0) return bad("shm_open", errno, 0);
    if (ftruncate(mfd, 65536)) return bad("ftruncate", errno, 0);
    void *a = mmap(NULL, 65536, PROT_READ, MAP_SHARED, mfd, 0);
    mach_port_t mp;
    if (fileport_makeport(mfd, &mp)) return bad("makeport", errno, 0);
    struct pshm_fdinfo mi;
    memset(&mi, 0xee, sizeof mi);
    if ((e = err_of(info(getpid(), PSHMINFO, mp, &mi, sizeof mi), sizeof mi))) return bad("shared memory", e, 0);
    fail |= mi.pfi.type != 3 || mi.pfi.openflags != 3 ? bad("its type and flags", mi.pfi.type, 3) : 0;
    // Held by the descriptor and the port: shared, and no descriptor's state.
    fail |= mi.pfi.status != 1 || mi.pfi.guardflags ? bad("its status", mi.pfi.status, 1) : 0;
    fail |= mi.mappaddr != (uint64_t)(uintptr_t)a || strcmp(mi.name, mname) ? bad("its mapping", mi.mappaddr, (long)a) : 0;
    // Its descriptor gone: the port's alone.
    close(mfd);
    info(getpid(), PSHMINFO, mp, &mi, sizeof mi);
    fail |= mi.pfi.status != 0 ? bad("port's alone", mi.pfi.status, 0) : 0;
    // Another type's flavor, each as its own lookup refuses it.
    char big[1200];
    fail |= (e = err_of(info(getpid(), VNODEPATHINFO, mp, big, sizeof big), sizeof big)) != ENOTSUP ? bad("not a vnode", e, ENOTSUP) : 0;
    fail |= (e = err_of(info(getpid(), SOCKETINFO, mp, big, 792), 792)) != EOPNOTSUPP ? bad("not a socket", e, EOPNOTSUPP) : 0;
    fail |= (e = err_of(info(getpid(), PIPEINFO, mp, big, 184), 184)) != EBADF ? bad("not a pipe", e, EBADF) : 0;
    fail |= (e = err_of(info(getpid(), 4, mp, big, sizeof big), sizeof big)) != EINVAL ? bad("no such flavor", e, EINVAL) : 0;
    fail |= (e = err_of(info(getpid(), PSHMINFO, mp, &mi, sizeof mi - 1), sizeof mi)) != ENOMEM ? bad("short buffer", e, ENOMEM) : 0;
    // A send right of something else, and no right at all.
    fail |= (e = err_of(info(getpid(), PSHMINFO, mach_task_self(), &mi, sizeof mi), sizeof mi)) != EINVAL ? bad("not a file port", e, EINVAL) : 0;
    fail |= (e = err_of(info(getpid(), PSHMINFO, 0x1234567, &mi, sizeof mi), sizeof mi)) != EINVAL ? bad("no right", e, EINVAL) : 0;

    // A vnode's, from another process's space.
    int fds[2], back[2];
    pipe(fds);
    pipe(back);
    pid_t c = fork();
    if (c == 0) {
        int fd = open(path, O_RDWR | O_CREAT | O_APPEND, 0644);
        mach_port_t p = MACH_PORT_NULL;
        if (fd < 0 || fileport_makeport(fd, &p)) _exit(2);
        close(fd);
        write(back[1], &p, sizeof p);
        char ch;
        read(fds[0], &ch, 1);
        _exit(0);
    }
    mach_port_t theirs = 0;
    if (read(back[0], &theirs, sizeof theirs) != sizeof theirs) return bad("child's port", 0, 1);
    struct vnode_fdinfowithpath vi;
    memset(&vi, 0xee, sizeof vi);
    if ((e = err_of(info(c, VNODEPATHINFO, theirs, &vi, sizeof vi), sizeof vi))) {
        fail |= bad("child's vnode", e, 0);
    } else {
        // FFLAGS(O_RDWR | O_APPEND): FREAD, FWRITE and FAPPEND.
        fail |= vi.pfi.type != 1 || vi.pfi.openflags != (3 | O_APPEND) || vi.pfi.status ? bad("its type, flags and status", vi.pfi.openflags, 3 | O_APPEND) : 0;
        fail |= strcmp(vi.path, path) ? bad("its path", vi.path[1], path[1]) : 0;
    }
    // The name means nothing in this space.
    fail |= (e = err_of(info(getpid(), VNODEPATHINFO, theirs, &vi, sizeof vi), sizeof vi)) != EINVAL && theirs != mp ? bad("not in mine", e, EINVAL) : 0;
    write(fds[1], "x", 1);
    // Exited and not yet reaped: no such process.
    siginfo_t si;
    waitid(P_PID, c, &si, WEXITED | WNOWAIT);
    fail |= (e = err_of(info(c, VNODEPATHINFO, theirs, &vi, sizeof vi), sizeof vi)) != ESRCH ? bad("exited", e, ESRCH) : 0;
    fail |= (e = err_of(__proc_info(PIDFDINFO, c, VNODEPATHINFO, 0, &vi, sizeof vi), sizeof vi)) != ESRCH ? bad("exited's descriptor", e, ESRCH) : 0;
    int st;
    waitpid(c, &st, 0);
    fail |= !WIFEXITED(st) || WEXITSTATUS(st) ? bad("child", st, 0) : 0;
    // The kernel's process: root's, with no descriptor.
    e = err_of(__proc_info(PIDFDINFO, 0, VNODEPATHINFO, 0, &vi, sizeof vi), sizeof vi);
    fail |= e != (getuid() ? EPERM : EBADF) ? bad("kernel's descriptor", e, getuid() ? EPERM : EBADF) : 0;
    e = err_of(info(0, PSHMINFO, mp, &mi, sizeof mi), sizeof mi);
    fail |= e != (getuid() ? EPERM : EINVAL) ? bad("kernel's file port", e, getuid() ? EPERM : EINVAL) : 0;

    mach_port_deallocate(mach_task_self(), mp);
    munmap(a, 65536);
    shm_unlink(mname);
    unlink(path);
    if (!fail) printf("fpinfo ok\n");
    return fail;
}
