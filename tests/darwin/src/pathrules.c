// Path rules as XNU's namei and the calls apply them: a path longer than
// MAXPATHLEN (1024 bytes with its NUL) is ENAMETOOLONG; a mount point is busy to rmdir and
// unlink; "file/." is ENOTDIR to rmdir; a name made with a trailing slash
// that is not to be a directory, where nothing is, is ENOENT; and chown
// with an owner and group of -1 changes nothing and succeeds.

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int bad(const char *what, long got, long want) {
    printf("pathrules: %s: %ld, want %ld\n", what, got, want);
    fflush(stdout);
    return 1;
}

static int err(int r) { return r == -1 ? errno : 0; }

int main(void) {
    char dir[] = "/tmp/gex-pathrules-XXXXXX";
    if (!mkdtemp(dir)) return bad("a directory", errno, 0);
    char file[128], p[2048];
    snprintf(file, sizeof file, "%s/f", dir);
    close(open(file, O_CREAT | O_WRONLY, 0644));

    // MAXPATHLEN: 1024 characters and no room for the NUL is too long, in
    // components of 99 (NAME_MAX is a limit of its own).
    memset(p, 'a', sizeof p);
    for (int i = 0; i < (int)sizeof p; i += 100) p[i] = '/';
    p[1024] = 0;
    int e;
    if ((e = err(access(p, F_OK))) != ENAMETOOLONG) return bad("1024 characters", e, ENAMETOOLONG);

    // A mount point.
    if ((e = err(rmdir("/dev"))) != EBUSY) return bad("rmdir of a mount point", e, EBUSY);
    if ((e = err(unlink("/dev"))) != EBUSY) return bad("unlink of a mount point", e, EBUSY);

    // "file/." and a directory's own unlink.
    snprintf(p, sizeof p, "%s/.", file);
    if ((e = err(rmdir(p))) != ENOTDIR) return bad("rmdir of file/.", e, ENOTDIR);
    if ((e = err(unlink(dir))) != EPERM) return bad("unlink of a directory", e, EPERM);

    // Trailing slashes on names being made.
    snprintf(p, sizeof p, "%s/new/", dir);
    if ((e = err(open(p, O_CREAT | O_WRONLY, 0644))) != ENOENT) return bad("open(O_CREAT) of new/", e, ENOENT);
    if ((e = err(symlink("x", p))) != ENOENT) return bad("symlink to new/", e, ENOENT);
    if ((e = err(link(file, p))) != ENOENT) return bad("link to new/", e, ENOENT);
    if ((e = err(rename(file, p))) != ENOENT) return bad("rename of a file to new/", e, ENOENT);
    char sub[160];
    snprintf(sub, sizeof sub, "%s/sub", dir);
    mkdir(sub, 0755);
    if ((e = err(rename(sub, p)))) return bad("rename of a directory to new/", e, 0);
    rmdir(p);

    // chown with nothing to change.
    if ((e = err(chown(file, (uid_t)-1, (gid_t)-1)))) return bad("chown -1 -1", e, 0);
    int fd = open(file, O_RDONLY);
    if ((e = err(fchown(fd, (uid_t)-1, (gid_t)-1)))) return bad("fchown -1 -1", e, 0);
    snprintf(p, sizeof p, "%s/none", dir);
    if ((e = err(lchown(p, (uid_t)-1, (gid_t)-1))) != ENOENT) return bad("lchown of nothing", e, ENOENT);
    close(fd);
    unlink(file);
    rmdir(dir);
    printf("pathrules ok\n");
    return 0;
}
