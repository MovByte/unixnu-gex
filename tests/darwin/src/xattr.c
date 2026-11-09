// Extended attributes: set, get, list and remove, by path and descriptor;
// size queries, what a missing attribute gets, CREATE and REPLACE, a name
// too long, the attributes a task needs an entitlement for, and what a
// descriptor that is not a file gets.

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/xattr.h>
#include <unistd.h>

static int bad(const char *what, long got, long want) {
    printf("xattr: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

int main(void) {
    char path[] = "/tmp/xattr.XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) return bad("the file", errno, 0);

    if (setxattr(path, "org.gex.one", "hello", 5, 0, 0) != 0) return bad("setxattr", errno, 0);
    char buf[32];
    ssize_t n = getxattr(path, "org.gex.one", buf, sizeof buf, 0, 0);
    if (n != 5 || memcmp(buf, "hello", 5) != 0) return bad("getxattr", n, 5);
    if ((n = getxattr(path, "org.gex.one", NULL, 0, 0, 0)) != 5) return bad("getxattr's size", n, 5);
    errno = 0;
    if (getxattr(path, "org.gex.one", buf, 2, 0, 0) != -1 || errno != ERANGE) return bad("a short buffer", errno, ERANGE);
    errno = 0;
    if (getxattr(path, "org.gex.none", buf, sizeof buf, 0, 0) != -1 || errno != ENOATTR) return bad("a missing attribute", errno, ENOATTR);

    // CREATE and REPLACE.
    errno = 0;
    if (setxattr(path, "org.gex.one", "x", 1, 0, XATTR_CREATE) != -1 || errno != EEXIST) return bad("XATTR_CREATE over one", errno, EEXIST);
    errno = 0;
    if (setxattr(path, "org.gex.two", "x", 1, 0, XATTR_REPLACE) != -1 || errno != ENOATTR) return bad("XATTR_REPLACE of none", errno, ENOATTR);
    if (fsetxattr(fd, "org.gex.two", "yy", 2, 0, XATTR_CREATE) != 0) return bad("fsetxattr", errno, 0);
    if ((n = fgetxattr(fd, "org.gex.two", buf, sizeof buf, 0, 0)) != 2) return bad("fgetxattr", n, 2);

    // Listing, without the prefix they are kept under.
    char names[64];
    if ((n = listxattr(path, names, sizeof names, 0)) != 24) return bad("listxattr", n, 24);
    if (memmem(names, n, "org.gex.one\0", 12) == NULL || memmem(names, n, "org.gex.two\0", 12) == NULL) return bad("the names", 0, 1);
    if ((n = flistxattr(fd, NULL, 0, 0)) != 24) return bad("flistxattr's size", n, 24);
    errno = 0;
    if (listxattr(path, names, 4, 0) != -1 || errno != ERANGE) return bad("a short list", errno, ERANGE);

    // Options that are the kernel's, a name too long, and no name.
    errno = 0;
    if (getxattr(path, "org.gex.one", buf, sizeof buf, 0, XATTR_NOSECURITY) != -1 || errno != EINVAL) return bad("XATTR_NOSECURITY", errno, EINVAL);
    char lng[200];
    memset(lng, 'a', sizeof lng);
    lng[199] = 0;
    errno = 0;
    if (setxattr(path, lng, "x", 1, 0, 0) != -1 || errno != ENAMETOOLONG) return bad("a long name", errno, ENAMETOOLONG);
    errno = 0;
    if (setxattr(path, "", "x", 1, 0, 0) != -1 || errno != EINVAL) return bad("no name", errno, EINVAL);

    // What the system keeps for itself.
    errno = 0;
    if (setxattr(path, "com.apple.system.other", "x", 1, 0, 0) != -1 || errno != EPERM) return bad("a protected name", errno, EPERM);

    // Removal.
    if (removexattr(path, "org.gex.one", 0) != 0) return bad("removexattr", errno, 0);
    errno = 0;
    if (removexattr(path, "org.gex.one", 0) != -1 || errno != ENOATTR) return bad("removing it again", errno, ENOATTR);
    if (fremovexattr(fd, "org.gex.two", 0) != 0) return bad("fremovexattr", errno, 0);
    if ((n = listxattr(path, names, sizeof names, 0)) != 0) return bad("nothing left", n, 0);

    // What is not a vnode.
    int ends[2];
    if (pipe(ends) != 0) return bad("pipe", errno, 0);
    errno = 0;
    if (fgetxattr(ends[0], "org.gex.one", buf, sizeof buf, 0, 0) != -1 || errno != EINVAL) return bad("a pipe", errno, EINVAL);
    close(ends[0]);
    close(ends[1]);
    close(fd);
    unlink(path);
    printf("xattr ok\n");
    return 0;
}
