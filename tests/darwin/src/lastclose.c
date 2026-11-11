// An open file's flock goes with its last descriptor (vn_closefile at
// fg_count's end), though a shared mapping of it stays; a duplicate, a
// file port or a message in flight keeps the file, and its lock, open.

#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

int fileport_makeport(int fd, mach_port_t *port);
int fileport_makefd(mach_port_t port);

static int bad(const char *what, long got, long want) {
    printf("lastclose: %s: %ld, want %ld\n", what, got, want);
    fflush(stdout);
    return 1;
}

static char path[64];

// Whether another open of the file can take its lock now.
static int lockable(void) {
    int fd = open(path, O_RDONLY);
    int r = flock(fd, LOCK_EX | LOCK_NB);
    close(fd);
    return r == 0;
}

static int locked_open(void) {
    int fd = open(path, O_RDWR | O_CREAT, 0644);
    flock(fd, LOCK_EX);
    return fd;
}

static void send_fd(int sock, int fd) {
    char b = 'x';
    struct iovec iov = {&b, 1};
    char cbuf[CMSG_SPACE(sizeof(int))];
    struct msghdr mh = {0};
    mh.msg_iov = &iov;
    mh.msg_iovlen = 1;
    mh.msg_control = cbuf;
    mh.msg_controllen = sizeof cbuf;
    struct cmsghdr *c = CMSG_FIRSTHDR(&mh);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c), &fd, sizeof fd);
    sendmsg(sock, &mh, 0);
}

static int recv_fd(int sock) {
    char b;
    struct iovec iov = {&b, 1};
    char cbuf[CMSG_SPACE(sizeof(int))];
    struct msghdr mh = {0};
    mh.msg_iov = &iov;
    mh.msg_iovlen = 1;
    mh.msg_control = cbuf;
    mh.msg_controllen = sizeof cbuf;
    if (recvmsg(sock, &mh, 0) != 1) return -1;
    struct cmsghdr *c = CMSG_FIRSTHDR(&mh);
    int fd = -1;
    if (c && c->cmsg_type == SCM_RIGHTS) memcpy(&fd, CMSG_DATA(c), sizeof fd);
    return fd;
}

int main(void) {
    int fail = 0;
    snprintf(path, sizeof path, "/private/var/tmp/lastclose-%d", getpid());
    int fd = locked_open();
    ftruncate(fd, 16384);
    fail |= lockable() ? bad("held", 1, 0) : 0;

    // Mapped, then closed: the lock goes though the mapping stays.
    void *a = mmap(NULL, 16384, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (a == MAP_FAILED) return bad("mmap", errno, 0);
    close(fd);
    fail |= !lockable() ? bad("released at the last close, mapped", 0, 1) : 0;
    munmap(a, 16384);

    // A duplicate keeps it.
    fd = locked_open();
    int d = dup(fd);
    close(fd);
    fail |= lockable() ? bad("kept by a duplicate", 1, 0) : 0;
    close(d);
    fail |= !lockable() ? bad("released with the duplicate", 0, 1) : 0;

    // A file port keeps it, and a descriptor made from it.
    fd = locked_open();
    mach_port_t p;
    if (fileport_makeport(fd, &p)) return bad("makeport", errno, 0);
    close(fd);
    fail |= lockable() ? bad("kept by a file port", 1, 0) : 0;
    int f = fileport_makefd(p);
    mach_port_deallocate(mach_task_self(), p);
    fail |= lockable() ? bad("kept by the descriptor made from it", 1, 0) : 0;
    close(f);
    fail |= !lockable() ? bad("released with the port and descriptor", 0, 1) : 0;

    // A message in flight keeps it; its receipt hands it on.
    int sv[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    fd = locked_open();
    send_fd(sv[0], fd);
    close(fd);
    fail |= lockable() ? bad("kept in flight", 1, 0) : 0;
    int r = recv_fd(sv[1]);
    fail |= r < 0 ? bad("received", r, 0) : 0;
    fail |= lockable() ? bad("kept by the received descriptor", 1, 0) : 0;
    close(r);
    fail |= !lockable() ? bad("released with the received descriptor", 0, 1) : 0;
    // One never received goes with the socket.
    fd = locked_open();
    send_fd(sv[0], fd);
    close(fd);
    close(sv[0]);
    close(sv[1]);
    fail |= !lockable() ? bad("released with the socket", 0, 1) : 0;

    unlink(path);
    if (!fail) printf("lastclose ok\n");
    return fail;
}
