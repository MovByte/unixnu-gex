// Sandbox's file checks. Under the container profile, a file outside the
// container (here, under /private/var/tmp) may not be read, written, made,
// removed or have its attributes changed, each refused at its own hook:
// the open's (read or write), the create's (O_CREAT, mkdir, symlink), the
// stat's and the attributes', the unlink's and rename's, the xattrs'. Its
// lookups are allowed (a missing name is ENOENT, not EPERM), and so is
// what the profile lets any process read: a symbolic link's own metadata
// and contents, the root's attributes, /dev/null. A descriptor opened
// before the sandbox stats (its file's credential lets it through) but
// does not change the file's mode (the setmode check is the vnode's).
//
// sbxscrub: under the wifiFirmwareLoader profile, a process that is not
// Apple's own (it may run any cdhash) has a directory's times taken out
// of what stat and getattrlist give it (the getattr check's flag 0x20).
//
// A semaphore another process made and holds open is its maker's, which
// the container profile does not let a sandboxed process open; one that
// nothing holds open becomes the opener's, which then may open it and
// post it (ipc-posix-sem-open and -post of a semaphore the caller made).
//
// The checks run in a child, which the sandbox ends with; the parent
// removes what it made (a directory and semaphores of its own, by its
// pid).

#include <errno.h>
#include <fcntl.h>
#include <semaphore.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/attr.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

#define SANDBOX_NAMED_BUILTIN 2

int sandbox_init(const char *profile, uint64_t flags, char **errorbuf);

static const char *me = "sbxfile";

static int fail(const char *what, long got) {
    printf("%s: %s: %ld\n", me, what, got);
    return 1;
}

// The directory, its file and a link to it, and paths under it.
static char dir[64], file[96], link_[96];

static const char *in(const char *name) {
    static char p[4][96];
    static int i;
    i = (i + 1) % 4;
    snprintf(p[i], sizeof p[i], "%s/%s", dir, name);
    return p[i];
}

static int refused(const char *what, long r) {
    if (r != -1 || errno != EPERM) return fail(what, r == -1 ? errno : r);
    return 0;
}

static char held[32], left[32];

static int container(int fd) {
    char *err = NULL;
    if (sandbox_init("container", SANDBOX_NAMED_BUILTIN, &err) != 0) return fail("sandbox_init", errno);
    struct stat st;
    char buf[64];
    char dotdot[160];
    snprintf(dotdot, sizeof dotdot, "%s/../%s/file", dir, strrchr(dir, '/') + 1);
    if (refused("stat", stat(file, &st))) return 1;
    if (refused("stat by a path with ..", stat(dotdot, &st))) return 1;
    if (lstat(link_, &st) != 0 || !S_ISLNK(st.st_mode)) return fail("lstat of the link", errno);
    if (readlink(link_, buf, sizeof buf) != 4) return fail("readlink", errno);
    if (refused("open to read", open(file, O_RDONLY))) return 1;
    if (refused("open to write", open(file, O_WRONLY))) return 1;
    if (refused("open through the link", open(link_, O_RDONLY))) return 1;
    if (open(in("missing"), O_RDONLY) != -1 || errno != ENOENT) return fail("open of a missing file", errno);
    if (refused("open to make", open(in("new"), O_CREAT | O_WRONLY, 0644))) return 1;
    if (refused("access", access(file, R_OK))) return 1;
    if (refused("mkdir", mkdir(in("sub"), 0755))) return 1;
    if (refused("symlink", symlink("file", in("link2")))) return 1;
    if (refused("unlink", unlink(file))) return 1;
    if (refused("rename", rename(file, in("moved")))) return 1;
    if (refused("chmod", chmod(file, 0600))) return 1;
    if (refused("utimes", utimes(file, NULL))) return 1;
    if (refused("truncate", truncate(file, 1))) return 1;
    if (refused("setxattr", setxattr(file, "user.x", "v", 1, 0, 0))) return 1;
    if (refused("getxattr", getxattr(file, "user.x", buf, sizeof buf, 0, 0))) return 1;
    if (refused("listxattr", listxattr(file, buf, sizeof buf, 0))) return 1;
    if (fstat(fd, &st) != 0 || st.st_size != 3) return fail("fstat", errno);
    if (refused("fchmod", fchmod(fd, 0600))) return 1;
    if (sem_open(held, 0) != SEM_FAILED || errno != EPERM) return fail("sem_open of another's semaphore", errno);
    sem_t *s = sem_open(left, 0);
    if (s == SEM_FAILED) return fail("sem_open of a semaphore nothing holds", errno);
    if (sem_post(s) != 0) return fail("sem_post", errno);
    if (stat("/", &st) != 0) return fail("stat /", errno);
    int n = open("/dev/null", O_RDWR);
    if (n < 0) return fail("open /dev/null", errno);
    close(n);
    return 0;
}

static int scrub(void) {
    struct stat st;
    if (stat(dir, &st) != 0 || st.st_mtime == 0) return fail("stat before", errno);
    char *err = NULL;
    if (sandbox_init("wifiFirmwareLoader", SANDBOX_NAMED_BUILTIN, &err) != 0) return fail("sandbox_init", errno);
    memset(&st, 0xff, sizeof st);
    if (stat(dir, &st) != 0) return fail("stat", errno);
    if (st.st_mtime || st.st_mtimespec.tv_nsec || st.st_atime || st.st_ctime || st.st_birthtime) return fail("stat's times", st.st_mtime);
    if (st.st_size == 0 || !S_ISDIR(st.st_mode)) return fail("stat's other attributes", st.st_mode);
    struct attrlist al = {.bitmapcount = ATTR_BIT_MAP_COUNT, .commonattr = ATTR_CMN_MODTIME | ATTR_CMN_CRTIME};
    struct {
        uint32_t len;
        struct timespec crtime, modtime;
    } __attribute__((packed)) ab;
    memset(&ab, 0xff, sizeof ab);
    if (getattrlist(dir, &al, &ab, sizeof ab, 0) != 0) return fail("getattrlist", errno);
    if (ab.crtime.tv_sec || ab.modtime.tv_sec || ab.modtime.tv_nsec) return fail("getattrlist's times", ab.modtime.tv_sec);
    return 0;
}

int main(int argc, char **argv) {
    (void)argc;
    int scrubbing = strstr(argv[0], "sbxscrub") != NULL;
    if (scrubbing) me = "sbxscrub";
    snprintf(dir, sizeof dir, "/private/var/tmp/gex-%s.%d", me, (int)getpid());
    snprintf(file, sizeof file, "%s/file", dir);
    snprintf(link_, sizeof link_, "%s/link", dir);
    if (mkdir(dir, 0755) != 0) return fail("the directory", errno);
    int fd = open(file, O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (fd < 0 || write(fd, "abc", 3) != 3) return fail("the file", errno);
    if (symlink("file", link_) != 0) return fail("the link", errno);
    snprintf(held, sizeof held, "/gex-sbxfile-h.%d", (int)getpid());
    snprintf(left, sizeof left, "/gex-sbxfile-l.%d", (int)getpid());
    sem_t *h = SEM_FAILED, *l = SEM_FAILED;
    if (!scrubbing) {
        h = sem_open(held, O_CREAT | O_EXCL, 0600, 0);
        l = sem_open(left, O_CREAT | O_EXCL, 0600, 0);
        if (h == SEM_FAILED || l == SEM_FAILED || sem_close(l) != 0) return fail("the semaphores", errno);
    }
    pid_t pid = fork();
    if (pid < 0) return fail("fork", errno);
    if (pid == 0) _exit(scrubbing ? scrub() : container(fd));
    int status = 0;
    if (waitpid(pid, &status, 0) != pid) return fail("waitpid", errno);
    close(fd);
    if (!scrubbing) {
        sem_close(h);
        sem_unlink(held);
        sem_unlink(left);
    }
    unlink(link_);
    unlink(file);
    rmdir(dir);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) return 1;
    printf("%s ok\n", me);
    return 0;
}
