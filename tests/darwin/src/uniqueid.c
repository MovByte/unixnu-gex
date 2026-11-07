// A process's unique identifiers (proc_pidinfo PROC_PIDUNIQIDENTIFIERINFO,
// 56 bytes): its main image's UUID, its unique id, its parent's unique id,
// its pidversion. A child spawned from it has a unique id of its own and
// this process's as its parent's; a buffer too small is ENOMEM.

#include <errno.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

// libproc's (no header in the iOS SDK).
int proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int buffersize);

struct uniq {
    uint8_t uuid[16];
    uint64_t uniqueid;
    uint64_t puniqueid;
    int32_t idversion;
    uint32_t reserve2;
    uint64_t reserve3;
    uint64_t reserve4;
};

static int bad(const char *what, long got, long want) {
    printf("uniqueid: %s: %#lx, want %#lx\n", what, got, want);
    return 1;
}

int main(int argc, char **argv) {
    struct uniq u;
    memset(&u, 0, sizeof u);
    int n = proc_pidinfo(getpid(), 17, 0, &u, sizeof u);
    if (n != (int)sizeof u) return bad("PROC_PIDUNIQIDENTIFIERINFO", n, sizeof u);
    if (argc > 1) {
        // The child: its parent's unique id is the one it was given.
        return u.puniqueid == strtoull(argv[1], NULL, 0) && u.uniqueid != u.puniqueid ? 0 : 3;
    }
    // The UUID is the main image's.
    const struct mach_header_64 *mh = (const struct mach_header_64 *)_dyld_get_image_header(0);
    const struct load_command *lc = (const struct load_command *)(mh + 1);
    const uint8_t *want = NULL;
    for (uint32_t i = 0; i < mh->ncmds; i++, lc = (const struct load_command *)((const char *)lc + lc->cmdsize))
        if (lc->cmd == LC_UUID) want = ((const struct uuid_command *)lc)->uuid;
    if (!want || memcmp(u.uuid, want, 16)) return bad("its UUID", u.uuid[0], want ? want[0] : 0);
    if (u.uniqueid == 0) return bad("its unique id", 0, 1);
    char small[40];
    if (proc_pidinfo(getpid(), 17, 0, small, sizeof small) != 0 || errno != ENOMEM) return bad("a short buffer", errno, ENOMEM);
    char id[32];
    snprintf(id, sizeof id, "%llu", (unsigned long long)u.uniqueid);
    char *args[] = {argv[0], id, NULL};
    pid_t pid;
    if (posix_spawn(&pid, argv[0], NULL, NULL, args, environ)) return bad("spawn", errno, 0);
    int st = 0;
    if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st) || WEXITSTATUS(st) != 0) return bad("the child's ids", st, 0);
    printf("uniqueid ok\n");
    return 0;
}
