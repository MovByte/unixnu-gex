// proc_pidfdinfo of a POSIX semaphore and a shared memory object: the
// file's flags as the open kept them, its type, the object's mode, owner,
// group, use count or length and name, the mapping an open last made, and
// a flavor of another type's refused; F_GETFL and the descriptor list
// agree.

#include <errno.h>
#include <fcntl.h>
#include <semaphore.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define PROC_PIDLISTFDS 1
#define PROC_PIDFDVNODEINFO 1
#define PROC_PIDFDPSEMINFO 4
#define PROC_PIDFDPSHMINFO 5
#define DTYPE_PSXSHM 3
#define DTYPE_PSXSEM 4

int proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int buffersize);
int proc_pidfdinfo(int pid, int fd, int flavor, void *buffer, int buffersize);
int __proc_info(int callnum, int pid, int flavor, uint64_t arg, void *buffer, int buffersize);

// The call itself, which says -1 on failure where libproc says 0.
static int fdinfo(int fd, int flavor, void *buffer, int size) {
    return __proc_info(3, getpid(), flavor, (uint64_t)fd, buffer, size);
}

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
    int64_t times[8];
    int64_t size, blocks;
    int32_t blksize;
    uint32_t flags, gen, rdev;
    int64_t qspare[2];
};

struct psem_fdinfo {
    struct fileinfo pfi;
    struct vinfo_stat st;
    char name[1024];
};

struct pshm_fdinfo {
    struct fileinfo pfi;
    struct vinfo_stat st;
    uint64_t mappaddr;
    char name[1024];
};

static int bad(const char *what, long got, long want) {
    printf("ipcfd: %s: %#lx, want %#lx\n", what, got, want);
    fflush(stdout);
    return 1;
}

// The type the descriptor list gives `fd` (-1: not listed).
static int listed(int fd) {
    struct {
        int32_t fd;
        uint32_t type;
    } l[256];
    int n = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, l, sizeof l);
    for (int i = 0; i < n / (int)sizeof l[0]; i++) {
        if (l[i].fd == fd) return (int)l[i].type;
    }
    return -1;
}

// The vinfo_stat fields neither object has: zero.
static int rest_zero(const struct vinfo_stat *st) {
    struct vinfo_stat z = *st;
    z.mode = 0;
    z.uid = z.gid = 0;
    z.size = 0;
    static const struct vinfo_stat zero;
    return !memcmp(&z, &zero, sizeof z);
}

int main(void) {
    if (sizeof(struct psem_fdinfo) != 1184 || sizeof(struct pshm_fdinfo) != 1192) return bad("this test's layout", sizeof(struct psem_fdinfo), 1184);
    int fail = 0;
    char sname[32], mname[32];
    snprintf(sname, sizeof sname, "/ipcfd-s%d", getpid());
    snprintf(mname, sizeof mname, "/ipcfd-m%d", getpid());

    // A semaphore: its descriptor is the number sem_open returns.
    sem_t *s = sem_open(sname, O_CREAT | O_EXCL | O_RDWR, 0640, 1);
    if (s == SEM_FAILED) return bad("sem_open", errno, 0);
    int sfd = (int)(intptr_t)s;
    struct psem_fdinfo si;
    memset(&si, 0xee, sizeof si);
    int r = proc_pidfdinfo(getpid(), sfd, PROC_PIDFDPSEMINFO, &si, sizeof si);
    if (r != sizeof si) return bad("semaphore info", r < 0 ? errno : r, sizeof si);
    fail |= si.pfi.type != DTYPE_PSXSEM ? bad("semaphore type", si.pfi.type, DTYPE_PSXSEM) : 0;
    // FFLAGS(O_RDWR) & FMASK: read and write, not O_CREAT or O_EXCL.
    fail |= si.pfi.openflags != 3 ? bad("semaphore flags", si.pfi.openflags, 3) : 0;
    fail |= fcntl(sfd, F_GETFL) != O_RDWR ? bad("semaphore F_GETFL", fcntl(sfd, F_GETFL), O_RDWR) : 0;
    fail |= si.pfi.offset != 0 || si.pfi.guardflags != 0 ? bad("semaphore offset", si.pfi.offset, 0) : 0;
    fail |= (si.pfi.status & 2) != (fcntl(sfd, F_GETFD) & FD_CLOEXEC ? 2u : 0u) ? bad("semaphore close-on-exec", si.pfi.status, 0) : 0;
    fail |= si.st.mode != 0640 ? bad("semaphore mode", si.st.mode, 0640) : 0;
    fail |= si.st.uid != geteuid() || si.st.gid != getegid() ? bad("semaphore owner", si.st.uid, geteuid()) : 0;
    // The name's reference and the open's.
    fail |= si.st.size != 2 ? bad("semaphore use count", si.st.size, 2) : 0;
    fail |= !rest_zero(&si.st) ? bad("semaphore stat's rest", si.st.dev, 0) : 0;
    fail |= strcmp(si.name, sname) ? bad("semaphore name", si.name[1], sname[1]) : 0;
    for (size_t i = strlen(sname); i < sizeof si.name; i++) {
        if (si.name[i]) {
            fail |= bad("semaphore name's tail", i, 0);
            break;
        }
    }
    fail |= listed(sfd) != DTYPE_PSXSEM ? bad("semaphore listed", listed(sfd), DTYPE_PSXSEM) : 0;
    // Another open counts; the unlink takes the name's away.
    sem_t *s2 = sem_open(sname, 0);
    if (s2 == SEM_FAILED) return bad("sem_open again", errno, 0);
    proc_pidfdinfo(getpid(), sfd, PROC_PIDFDPSEMINFO, &si, sizeof si);
    fail |= si.st.size != 3 ? bad("two opens", si.st.size, 3) : 0;
    fail |= fcntl((int)(intptr_t)s2, F_GETFL) != O_RDONLY ? bad("second open's F_GETFL", fcntl((int)(intptr_t)s2, F_GETFL), O_RDONLY) : 0;
    sem_unlink(sname);
    proc_pidfdinfo(getpid(), sfd, PROC_PIDFDPSEMINFO, &si, sizeof si);
    fail |= si.st.size != 2 ? bad("unlinked", si.st.size, 2) : 0;
    // Too small a buffer, and a flavor of another type.
    r = fdinfo(sfd, PROC_PIDFDPSEMINFO, &si, sizeof si - 1);
    fail |= r != -1 || errno != ENOMEM ? bad("small buffer", errno, ENOMEM) : 0;
    struct pshm_fdinfo mi;
    r = fdinfo(sfd, PROC_PIDFDPSHMINFO, &mi, sizeof mi);
    fail |= r != -1 || errno != EBADF ? bad("semaphore as shared memory", errno, EBADF) : 0;
    char vbuf[176];
    r = fdinfo(sfd, PROC_PIDFDVNODEINFO, vbuf, sizeof vbuf);
    fail |= r != -1 || errno != EBADF ? bad("semaphore as a vnode", errno, EBADF) : 0;

    // A shared memory object, sized and mapped.
    int mfd = shm_open(mname, O_CREAT | O_EXCL | O_RDWR, 0600);
    if (mfd < 0) return bad("shm_open", errno, 0);
    const size_t len = 65536;
    if (ftruncate(mfd, len)) return bad("ftruncate", errno, 0);
    memset(&mi, 0xee, sizeof mi);
    r = proc_pidfdinfo(getpid(), mfd, PROC_PIDFDPSHMINFO, &mi, sizeof mi);
    if (r != sizeof mi) return bad("shared memory info", r < 0 ? errno : r, sizeof mi);
    fail |= mi.pfi.type != DTYPE_PSXSHM ? bad("shared memory type", mi.pfi.type, DTYPE_PSXSHM) : 0;
    // FREAD and FWRITE kept, not O_CREAT or O_EXCL.
    fail |= mi.pfi.openflags != 3 ? bad("shared memory flags", mi.pfi.openflags, 3) : 0;
    fail |= fcntl(mfd, F_GETFL) != O_RDWR ? bad("shared memory F_GETFL", fcntl(mfd, F_GETFL), O_RDWR) : 0;
    fail |= !(mi.pfi.status & 2) ? bad("shared memory close-on-exec", mi.pfi.status, 2) : 0;
    fail |= mi.st.mode != 0600 ? bad("shared memory mode", mi.st.mode, 0600) : 0;
    fail |= mi.st.uid != geteuid() || mi.st.gid != getegid() ? bad("shared memory owner", mi.st.uid, geteuid()) : 0;
    fail |= mi.st.size != (int64_t)len ? bad("shared memory length", mi.st.size, len) : 0;
    fail |= !rest_zero(&mi.st) ? bad("shared memory stat's rest", mi.st.dev, 0) : 0;
    fail |= mi.mappaddr != 0 ? bad("not yet mapped", mi.mappaddr, 0) : 0;
    fail |= strcmp(mi.name, mname) ? bad("shared memory name", mi.name[1], mname[1]) : 0;
    fail |= listed(mfd) != DTYPE_PSXSHM ? bad("shared memory listed", listed(mfd), DTYPE_PSXSHM) : 0;
    void *a = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, mfd, 0);
    if (a == MAP_FAILED) return bad("mmap", errno, 0);
    proc_pidfdinfo(getpid(), mfd, PROC_PIDFDPSHMINFO, &mi, sizeof mi);
    fail |= mi.mappaddr != (uint64_t)(uintptr_t)a ? bad("mapped at", mi.mappaddr, (long)a) : 0;
    // Each open keeps its own; the next mapping replaces it.
    int mfd2 = shm_open(mname, O_RDONLY);
    proc_pidfdinfo(getpid(), mfd2, PROC_PIDFDPSHMINFO, &mi, sizeof mi);
    fail |= mi.mappaddr != 0 || mi.pfi.openflags != 1 ? bad("another open's", mi.mappaddr, 0) : 0;
    void *b = mmap(NULL, len / 2, PROT_READ, MAP_SHARED, mfd, 0);
    proc_pidfdinfo(getpid(), mfd, PROC_PIDFDPSHMINFO, &mi, sizeof mi);
    fail |= mi.mappaddr != (uint64_t)(uintptr_t)b ? bad("mapped again at", mi.mappaddr, (long)b) : 0;
    r = fdinfo(mfd, PROC_PIDFDPSEMINFO, &si, sizeof si);
    fail |= r != -1 || errno != EBADF ? bad("shared memory as a semaphore", errno, EBADF) : 0;
    munmap(a, len);
    munmap(b, len / 2);
    close(mfd2);
    close(mfd);
    shm_unlink(mname);
    sem_close(s2);
    sem_close(s);
    if (!fail) printf("ipcfd ok\n");
    return fail;
}
