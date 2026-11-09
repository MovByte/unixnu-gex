// __pthread_chdir and __pthread_fchdir: one thread's working directory, the
// others' left alone, going back to the process's, a fork inheriting the
// caller's, and the errors.

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

int __pthread_chdir(const char *);
int __pthread_fchdir(int);

static char a[128], b[128], here[1024];
static int result;

static int bad(const char *what, long got, long want) {
    printf("thcwd: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

static int in(const char *dir) {
    char got[1024];
    return getcwd(got, sizeof got) && !strcmp(got, dir);
}

static void *other(void *arg) {
    (void)arg;
    result = 1;
    // The process's directory: the first thread's own is not seen here.
    if (!in(here)) return NULL;
    if (__pthread_chdir(b) != 0 || !in(b)) return NULL;
    result = 0;
    return NULL;
}

int main(void) {
    snprintf(a, sizeof a, "/private/var/tmp/thcwd-a-%d", getpid());
    snprintf(b, sizeof b, "/private/var/tmp/thcwd-b-%d", getpid());
    rmdir(a);
    rmdir(b);
    mkdir(a, 0755);
    mkdir(b, 0755);
    getcwd(here, sizeof here);

    // Nothing to go back from yet.
    if (__pthread_fchdir(-1) != -1 || errno != EBADF) return bad("no thread directory", errno, EBADF);

    if (__pthread_chdir(a) != 0) return bad("__pthread_chdir", errno, 0);
    if (!in(a)) return bad("this thread's directory", 0, 1);

    // Relative paths are this thread's.
    int f = open("x", O_RDWR | O_CREAT, 0644);
    if (f < 0) return bad("a relative create", errno, 0);
    close(f);
    char full[300];
    snprintf(full, sizeof full, "%s/x", a);
    struct stat st;
    if (stat(full, &st) != 0) return bad("where it went", errno, 0);
    unlink(full);

    pthread_t t;
    pthread_create(&t, NULL, other, NULL);
    pthread_join(t, NULL);
    if (result) return bad("another thread's", result, 0);
    if (!in(a)) return bad("mine, after it", 0, 1);

    // A fork starts in the calling thread's directory.
    pid_t pid = fork();
    if (pid == 0) _exit(in(a) ? 0 : 7);
    int s;
    if (waitpid(pid, &s, 0) != pid || s != 0) return bad("a fork's", s, 0);

    // By descriptor, and back to the process's.
    int d = open(b, O_RDONLY);
    if (__pthread_fchdir(d) != 0 || !in(b)) return bad("__pthread_fchdir", errno, 0);
    if (__pthread_fchdir(-1) != 0) return bad("going back", errno, 0);
    if (!in(here)) return bad("the process's again", 0, 1);
    if (__pthread_fchdir(-1) != -1 || errno != EBADF) return bad("going back twice", errno, EBADF);

    // The errors, which leave none.
    if (__pthread_chdir("/private/var/tmp/thcwd-none") != -1 || errno != ENOENT) return bad("no such directory", errno, ENOENT);
    if (__pthread_fchdir(-1) != -1 || errno != EBADF) return bad("a failed chdir set one", errno, EBADF);
    int file = open("/private/var/tmp", O_RDONLY);
    int plain = open(full, O_RDWR | O_CREAT, 0644);
    if (__pthread_fchdir(plain) != -1 || errno != ENOTDIR) return bad("a file", errno, ENOTDIR);
    if (__pthread_fchdir(987) != -1 || errno != EBADF) return bad("a closed descriptor", errno, EBADF);
    if (__pthread_fchdir(-1) != -1 || errno != EBADF) return bad("a failed fchdir set one", errno, EBADF);
    close(file);
    close(plain);
    unlink(full);
    rmdir(a);
    rmdir(b);
    puts("thcwd ok");
    return 0;
}
