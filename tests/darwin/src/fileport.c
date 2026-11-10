// File ports: a descriptor to a port and back, what is not sendable, and
// the kdebug calls with tracing off.

#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/event.h>
#include <unistd.h>

// In libsystem; the headers are private.
typedef mach_port_t fileport_t;
extern int fileport_makeport(int, fileport_t *);
extern int fileport_makefd(fileport_t);

static int bad(const char *what, long got, long want) {
    printf("fileport: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

int main(void) {
    int ends[2];
    if (pipe(ends) != 0) return bad("pipe", errno, 0);
    fileport_t port = MACH_PORT_NULL;
    if (fileport_makeport(ends[0], &port) != 0 || port == MACH_PORT_NULL) return bad("fileport_makeport", errno, 0);

    // The same open file, close-on-exec, from the original descriptor's port.
    int fd = fileport_makefd(port);
    if (fd < 0 || fd == ends[0]) return bad("fileport_makefd", fd, 3);
    if (fcntl(fd, F_GETFD) != FD_CLOEXEC) return bad("the new descriptor's flags", fcntl(fd, F_GETFD), FD_CLOEXEC);
    if (write(ends[1], "hi", 2) != 2) return bad("write", errno, 0);
    char buf[4] = {0};
    if (read(fd, buf, 2) != 2 || memcmp(buf, "hi", 2) != 0) return bad("reading through it", errno, 0);
    close(fd);

    // The port holds the file open: with the write end's descriptor closed
    // the reader sees no end of file until the port's last send right goes.
    fileport_t wport = MACH_PORT_NULL;
    if (fileport_makeport(ends[1], &wport) != 0) return bad("fileport_makeport of the write end", errno, 0);
    int w2 = dup(ends[1]);
    close(ends[1]);
    if (fcntl(ends[0], F_SETFL, O_NONBLOCK) != 0) return bad("O_NONBLOCK", errno, 0);
    errno = 0;
    if (read(ends[0], buf, 1) != -1 || errno != EAGAIN) return bad("reading while the port holds it", errno, EAGAIN);
    close(w2);
    errno = 0;
    if (read(ends[0], buf, 1) != -1 || errno != EAGAIN) return bad("reading while only the port holds it", errno, EAGAIN);
    if (mach_port_deallocate(mach_task_self(), wport) != KERN_SUCCESS) return bad("mach_port_deallocate", 1, 0);
    if (read(ends[0], buf, 1) != 0) return bad("end of file after the port went", errno, 0);
    ends[1] = -1;

    // What is not a file port; a descriptor that cannot go in one.
    errno = 0;
    if (fileport_makefd(mach_task_self()) != -1 || errno != EINVAL) return bad("the task's port", errno, EINVAL);
    errno = 0;
    if (fileport_makefd(MACH_PORT_DEAD) != -1 || errno != EINVAL) return bad("a dead name", errno, EINVAL);
    errno = 0;
    if (fileport_makeport(-1, &port) != -1 || errno != EBADF) return bad("no descriptor", errno, EBADF);
    int kq = kqueue();
    errno = 0;
    fileport_t none = MACH_PORT_NULL;
    if (fileport_makeport(kq, &none) != -1 || errno != EINVAL) return bad("a kqueue", errno, EINVAL);
    close(kq);

    // kdebug with tracing off: quiet successes, and a page of zeros.
    if (syscall(180, 0x12340000, 1, 2, 3, 4) != 0) return bad("kdebug_trace", errno, 0);
    uint64_t at = 0, size = 0;
    if (syscall(177, &at, &size) != 0 || at == 0) return bad("kdebug_typefilter", errno, 0);
    if (*(volatile uint8_t *)(uintptr_t)at != 0) return bad("its contents", 1, 0);
    errno = 0;
    if (syscall(177, NULL, NULL) != -1 || errno != EINVAL) return bad("kdebug_typefilter of nothing", errno, EINVAL);

    close(ends[0]);
    printf("fileport ok\n");
    return 0;
}
