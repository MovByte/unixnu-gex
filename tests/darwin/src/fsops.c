// The filesystem calls by vfs_syscalls.c's rules: mkdir's ACCESSPERMS under
// the umask, link following a symlink, renameatx_np's RENAME_EXCL, unlink of a directory (EPERM), truncate, utimes, chmod,
// and getdirentries64 through readdir and rewinddir.

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
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
