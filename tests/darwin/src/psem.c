// POSIX semaphores by posix_sem.c: creating and opening by name, the
// limits, trywait, a wait another process ends, a signal ending one, a
// name unlinked while open, what the descriptor is not, and psem_access,
// which shared memory's pshm_access is too.

#include <errno.h>
#include <fcntl.h>
#include <semaphore.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

static int bad(const char *what, long got, long want) {
    printf("psem: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

static int expect(const char *what, int r, int e) {
    if (r != -1 || errno != e) return bad(what, r == -1 ? errno : r, e);
    return 0;
}

static void on_alarm(int s) {
    (void)s;
}

int main(void) {
    char name[32], other[32];
    snprintf(name, sizeof name, "/gexpsem.%d", getpid());
    snprintf(other, sizeof other, "/gexpsem.o.%d", getpid());
    sem_unlink(name);
    sem_unlink(other);

    sem_t *s = sem_open(name, O_CREAT | O_EXCL, 0600, 0);
    if (s == SEM_FAILED) return bad("sem_open", errno, 0);
    if (sem_open(name, O_CREAT | O_EXCL, 0600, 0) != SEM_FAILED || errno != EEXIST) return bad("O_EXCL", errno, EEXIST);
    if (sem_open(other, 0) != SEM_FAILED || errno != ENOENT) return bad("no such name", errno, ENOENT);
    if (sem_open(other, O_CREAT, 0600, 32768) != SEM_FAILED || errno != EINVAL) return bad("SEM_VALUE_MAX", errno, EINVAL);
    // The value is checked even when the name exists.
    if (sem_open(name, O_CREAT, 0600, 40000) != SEM_FAILED || errno != EINVAL) return bad("the value of one there", errno, EINVAL);
    if (sem_open("/abcdefghijklmnopqrstuvwxyz1234", O_CREAT, 0600, 0) != SEM_FAILED || errno != ENAMETOOLONG) return bad("31 bytes", errno, ENAMETOOLONG);
    sem_t *longest = sem_open("/abcdefghijklmnopqrstuvwxyz123", O_CREAT, 0600, 0);
    if (longest == SEM_FAILED) return bad("30 bytes", errno, 0);
    sem_close(longest);
    sem_unlink("/abcdefghijklmnopqrstuvwxyz123");

    // trywait, post.
    if (expect("trywait at zero", sem_trywait(s), EAGAIN)) return 1;
    if (sem_post(s) || sem_post(s)) return bad("sem_post", errno, 0);
    if (sem_trywait(s) || sem_wait(s)) return bad("taking two", errno, 0);
    if (expect("trywait after", sem_trywait(s), EAGAIN)) return 1;

    // O_CREAT on one that exists opens it: the same semaphore.
    sem_t *again = sem_open(name, O_CREAT, 0600, 5);
    if (again == SEM_FAILED || again == s) return bad("a second open", errno, 0);
    sem_post(again);
    if (sem_trywait(s)) return bad("the same semaphore", errno, 0);

    // Another process ends a wait.
    pid_t c = fork();
    if (c == 0) {
        sem_t *mine = sem_open(name, 0);
        if (mine == SEM_FAILED) _exit(2);
        usleep(30000);
        _exit(sem_post(mine) ? 3 : 0);
    }
    if (sem_wait(s)) return bad("woken by another process", errno, 0);
    int st;
    if (waitpid(c, &st, 0) != c || st != 0) return bad("the poster", st, 0);

    // A signal ends one, and the wakeup is not lost.
    struct sigaction sa = {0};
    sa.sa_handler = on_alarm;
    sigaction(SIGALRM, &sa, NULL);
    struct itimerval it = {{0, 0}, {0, 30000}};
    setitimer(ITIMER_REAL, &it, NULL);
    if (expect("a signal", sem_wait(s), EINTR)) return 1;
    sem_post(s);
    if (sem_trywait(s)) return bad("the count after a signal", errno, 0);

    // Unlinked while open: the name goes, the semaphore stays.
    if (sem_unlink(name)) return bad("sem_unlink", errno, 0);
    if (sem_open(name, 0) != SEM_FAILED || errno != ENOENT) return bad("the unlinked name", errno, ENOENT);
    if (expect("unlinking twice", sem_unlink(name), ENOENT)) return 1;
    sem_post(s);
    if (sem_trywait(again)) return bad("still one semaphore", errno, 0);

    // The descriptor is not a file, and other descriptors are not it.
    int fd = (int)(long)s;
    char b;
    struct stat sb;
    if (expect("read", (int)read(fd, &b, 1), ENXIO)) return 1;
    if (expect("fstat", fstat(fd, &sb), EBADF)) return 1;
    int p[2];
    pipe(p);
    if (expect("a pipe", sem_post((sem_t *)(long)p[0]), EBADF)) return 1;
    if (sem_close(s) || sem_close(again)) return bad("sem_close", errno, 0);
    if (expect("closed", sem_post(s), EBADF)) return 1;
    if (expect("closing twice", sem_close(s), EBADF)) return 1;

    // psem_access: the owner with no owner bits falls to the group's,
    // where a member is refused.
    sem_t *none = sem_open(other, O_CREAT | O_EXCL, 0, 1);
    if (none == SEM_FAILED) return bad("a mode of 0", errno, 0);
    if (geteuid() != 0 && (sem_open(other, 0) != SEM_FAILED || errno != EACCES)) return bad("no access", errno, EACCES);
    if (sem_unlink(other)) return bad("unlinking it anyway", errno, 0);
    sem_close(none);
    // With group and world allowed, the owner is let in through them.
    sem_t *through = sem_open(other, O_CREAT | O_EXCL, 0044, 1);
    if (through == SEM_FAILED) return bad("a mode of 044", errno, 0);
    sem_t *opened = sem_open(other, 0);
    if (opened == SEM_FAILED) return bad("the owner through the group and world bits", errno, 0);
    sem_close(opened);
    sem_close(through);
    sem_unlink(other);

    // pshm_access: the same rule; shm_unlink lets the owner by anyway.
    char shm[32];
    snprintf(shm, sizeof shm, "/gexpshm.%d", getpid());
    shm_unlink(shm);
    int o = shm_open(shm, O_CREAT | O_EXCL | O_RDWR, 0);
    if (o < 0) return bad("shm_open with a mode of 0", errno, 0);
    if (geteuid() != 0 && (shm_open(shm, O_RDONLY) != -1 || errno != EACCES)) return bad("shm_open with no access", errno, EACCES);
    if (shm_unlink(shm)) return bad("shm_unlink by its owner", errno, 0);
    close(o);
    o = shm_open(shm, O_CREAT | O_EXCL | O_RDWR, 0044);
    int r = shm_open(shm, O_RDONLY);
    if (o < 0 || r < 0) return bad("shm_open through the group and world bits", errno, 0);
    close(r);
    close(o);
    shm_unlink(shm);

    puts("psem ok");
    return 0;
}
