// The filesystem calls by vfs_syscalls.c's rules: mkdir's ACCESSPERMS under
// the umask, link following a symlink, renameatx_np's RENAME_EXCL, unlink of a directory (EPERM), truncate, utimes, chmod,
// and getdirentries64 through readdir and rewinddir. AT_SYMLINK_NOFOLLOW_ANY
// and FSOPT_NOFOLLOW_ANY refuse a link the lookup traverses (ELOOP), not a
// last component left unfollowed (getattrlist then reports the link
// itself), unless a trailing slash follows it: fstatat, faccessat,
// unlinkat and renameatx_np too, whose flags are checked; fstatat's
// AT_FDONLY stats the descriptor, a vnode's.

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/attr.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#define D "/tmp/gex-fsops"

static int bad(const char *what, long v) {
    printf("fsops: %s (%ld)\n", what, v);
    return 1;
}

static void put(const char *p, const char *s) {
    int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    write(fd, s, strlen(s));
    close(fd);
}

int main(void) {
    struct stat st;
    umask(022);
    if (umask(022) != 022) return bad("umask", 0);
    if (mkdir(D, 07777) || stat(D, &st) || (st.st_mode & 07777) != 0755) return bad("mkdir's mode", st.st_mode & 07777);
    if (chdir(D)) return bad("chdir", errno);
    put("a", "aaaa");
    put("b", "bb");
    if (symlink("a", "s")) return bad("symlink", errno);
    // link follows the symlink: the new name is the file, not the link.
    if (link("s", "h") || lstat("h", &st) || !S_ISREG(st.st_mode) || st.st_size != 4) return bad("link through a symlink", st.st_mode);
    if (renameatx_np(AT_FDCWD, "a", AT_FDCWD, "b", RENAME_EXCL) != -1 || errno != EEXIST) return bad("RENAME_EXCL", errno);
    if (rename("b", "c") || access("b", F_OK) == 0) return bad("rename", errno);
    if (mkdir("sub", 0700) || unlink("sub") != -1 || errno != EPERM) return bad("unlink of a directory", errno);
    if (rmdir("sub")) return bad("rmdir", errno);
    if (truncate("c", 1) || stat("c", &st) || st.st_size != 1) return bad("truncate", st.st_size);
    if (truncate("c", -1) != -1 || errno != EINVAL) return bad("truncate below zero", errno);
    struct timeval tv[2] = {{1000000000, 5}, {1100000000, 7}};
    if (utimes("c", tv) || stat("c", &st) || st.st_mtimespec.tv_sec != 1100000000) return bad("utimes", st.st_mtimespec.tv_sec);
    if (chmod("c", 0604) || stat("c", &st) || (st.st_mode & 07777) != 0604) return bad("chmod", st.st_mode & 07777);
    if (mkdir("dd", 0755)) return bad("mkdir dd", errno);
    put("dd/f", "f");
    if (symlink("dd", "dl")) return bad("symlink dl", errno);
    if (fchmodat(AT_FDCWD, "dl/f", 0600, AT_SYMLINK_NOFOLLOW_ANY) != -1 || errno != ELOOP) return bad("fchmodat through a link", errno);
    if (fchmodat(AT_FDCWD, "dd/f", 0640, AT_SYMLINK_NOFOLLOW_ANY) || stat("dd/f", &st) || (st.st_mode & 07777) != 0640) return bad("fchmodat with no link", st.st_mode & 07777);
    struct attrlist al = {ATTR_BIT_MAP_COUNT, 0, ATTR_CMN_OBJTYPE, 0, 0, 0, 0};
    struct {
        uint32_t len;
        fsobj_type_t type;
    } __attribute__((packed)) ab;
    // VLNK (sys/vnode.h's enum vtype).
    if (getattrlist("dl", &al, &ab, sizeof ab, FSOPT_NOFOLLOW_ANY) || ab.type != 5) return bad("getattrlist of the link itself", ab.type);
    if (getattrlist("dl/f", &al, &ab, sizeof ab, FSOPT_NOFOLLOW_ANY) != -1 || errno != ELOOP) return bad("getattrlist through a link", errno);
    if (getattrlist("dl/", &al, &ab, sizeof ab, FSOPT_NOFOLLOW_ANY) != -1 || errno != ELOOP) return bad("getattrlist of a link with a slash", errno);
    if (fstatat(AT_FDCWD, "dl/f", &st, AT_SYMLINK_NOFOLLOW_ANY) != -1 || errno != ELOOP) return bad("fstatat through a link", errno);
    if (fstatat(AT_FDCWD, "dl", &st, AT_SYMLINK_NOFOLLOW_ANY) || !S_ISLNK(st.st_mode)) return bad("fstatat of the link", st.st_mode);
    if (fstatat(AT_FDCWD, "dd/f", &st, 0x1000) != -1 || errno != EINVAL) return bad("fstatat's flags", errno);
    // AT_FDONLY (0x400).
    int fdd = open("dd/f", O_RDONLY), pp[2];
    if (fdd < 0 || fstatat(fdd, "nowhere", &st, 0x400) || !S_ISREG(st.st_mode)) return bad("AT_FDONLY", errno);
    close(fdd);
    pipe(pp);
    if (fstatat(pp[0], "", &st, 0x400) != -1 || errno != ENOTSUP) return bad("AT_FDONLY of a pipe", errno);
    close(pp[0]);
    close(pp[1]);
    if (faccessat(AT_FDCWD, "dl/f", R_OK, AT_SYMLINK_NOFOLLOW_ANY) != -1 || errno != ELOOP) return bad("faccessat through a link", errno);
    if (faccessat(AT_FDCWD, "dd/f", R_OK, AT_SYMLINK_NOFOLLOW_ANY)) return bad("faccessat with no link", errno);
    if (faccessat(AT_FDCWD, "dd/f", R_OK, 0x1000) != -1 || errno != EINVAL) return bad("faccessat's flags", errno);
    if (unlinkat(AT_FDCWD, "dl/f", AT_SYMLINK_NOFOLLOW_ANY) != -1 || errno != ELOOP) return bad("unlinkat through a link", errno);
    if (renameatx_np(AT_FDCWD, "dl/f", AT_FDCWD, "dd/g", RENAME_NOFOLLOW_ANY) != -1 || errno != ELOOP) return bad("renameatx_np through a link", errno);
    if (renameatx_np(AT_FDCWD, "dd/f", AT_FDCWD, "dd/g", RENAME_NOFOLLOW_ANY) || rename("dd/g", "dd/f")) return bad("renameatx_np with no link", errno);
    if (unlinkat(AT_FDCWD, "dl", AT_SYMLINK_NOFOLLOW_ANY) || lstat("dl", &st) == 0) return bad("unlinkat of the link itself", errno);
    unlink("dd/f");
    rmdir("dd");

    // readdir through getdirentries64, twice over with rewinddir.
    DIR *dir = opendir(".");
    int n = 0, again = 0;
    struct dirent *e;
    while ((e = readdir(dir))) n++;
    rewinddir(dir);
    while ((e = readdir(dir))) again++;
    closedir(dir);
    // ".", "..", a, c, s, h
    if (n != 6 || again != 6) return bad("readdir", n * 100 + again);

    unlink("a");
    unlink("c");
    unlink("s");
    unlink("h");
    chdir("/");
    if (rmdir(D)) return bad("rmdir of the emptied directory", errno);
    printf("fsops ok\n");
    return 0;
}
