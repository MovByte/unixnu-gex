// renameatx_np with RENAME_SWAP: two names exchanged, a file and a directory
// each keeping its own contents, and what it refuses.

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef RENAME_SWAP
#define RENAME_SWAP 0x2
#define RENAME_EXCL 0x4
#endif

int renamex_np(const char *, const char *, unsigned int);
int renameatx_np(int, const char *, int, const char *, unsigned int);

static int bad(const char *what, long got, long want) {
    printf("renameswap: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

static int expect(const char *what, long r, int e) {
    if (r != -1 || errno != e) return bad(what, r == -1 ? errno : r, e);
    return 0;
}

static char d[128], p[6][200];

static const char *at(int i, const char *n) {
    snprintf(p[i], sizeof p[i], "%s/%s", d, n);
    return p[i];
}

static void put(const char *path, const char *s) {
    int f = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    write(f, s, strlen(s));
    close(f);
}

static int has(const char *path, const char *s) {
    char b[32] = {0};
    int f = open(path, O_RDONLY);
    if (f < 0) return 0;
    read(f, b, sizeof b - 1);
    close(f);
    return !strcmp(b, s);
}

int main(void) {
    snprintf(d, sizeof d, "/private/var/tmp/renameswap-%d", getpid());
    static const char *names[] = {"a", "b", "s/in", "s", "z", 0};
    for (int i = 0; names[i]; i++) {
        unlink(at(0, names[i]));
        rmdir(at(0, names[i]));
    }
    rmdir(d);
    if (mkdir(d, 0755) != 0) return bad("mkdir", errno, 0);

    put(at(0, "a"), "first");
    put(at(1, "b"), "second");
    struct stat sa, sb, after;
    stat(at(0, "a"), &sa);
    stat(at(1, "b"), &sb);
    if (renamex_np(at(0, "a"), at(1, "b"), RENAME_SWAP) != 0) return bad("swap", errno, 0);
    if (!has(at(0, "a"), "second") || !has(at(1, "b"), "first")) return bad("the contents", 0, 1);
    stat(at(0, "a"), &after);
    if (after.st_ino != sb.st_ino) return bad("the file numbers", (long)after.st_ino, (long)sb.st_ino);

    // A file for a directory.
    mkdir(at(2, "s"), 0755);
    put(at(3, "s/in"), "inside");
    int dfd = open(d, O_RDONLY);
    if (renameatx_np(dfd, "a", dfd, "s", RENAME_SWAP) != 0) return bad("file and directory", errno, 0);
    if (!has(at(0, "s"), "second")) return bad("the file moved", 0, 1);
    if (!has(at(1, "a/in"), "inside")) return bad("the directory moved", 0, 1);
    if (renameatx_np(dfd, "a", dfd, "s", RENAME_SWAP) != 0) return bad("back", errno, 0);

    // Refusals: a name missing on either side, both flags, another volume.
    if (expect("no target", renamex_np(at(0, "a"), at(1, "z"), RENAME_SWAP), ENOENT)) return 1;
    if (expect("no source", renamex_np(at(0, "z"), at(1, "a"), RENAME_SWAP), ENOENT)) return 1;
    if (expect("both flags", renamex_np(at(0, "a"), at(1, "b"), RENAME_SWAP | RENAME_EXCL), EINVAL)) return 1;
    if (expect("a bad flag", renamex_np(at(0, "a"), at(1, "b"), 0x100), EINVAL)) return 1;

    for (int i = 0; names[i]; i++) {
        unlink(at(0, names[i]));
        rmdir(at(0, names[i]));
    }
    rmdir(d);
    puts("renameswap ok");
    return 0;
}
