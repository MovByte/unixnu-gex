// Personas: the persona manager allocates them (ids from 501 in steps of
// 10, or the one asked for; the name and the id unused), finds them by
// name, id or type, reads their info (a version 1 structure has no uid),
// and deallocates them, after which they are gone to lookups and spawns.
// A process in none has no current persona. A spawn into a persona takes
// it (and the uid and gid the spawn gives) through its exec; another's
// persona info is root's, and so are a spawn's POSIX credentials.
// Without the manager's entitlement (HOST_UNENTITLED, for a run outside
// gex) only the refusals are checked.

#include <errno.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;
int posix_spawnattr_set_persona_np(const posix_spawnattr_t *attr, uid_t persona_id, uint32_t flags);
int posix_spawnattr_set_persona_uid_np(const posix_spawnattr_t *attr, uid_t uid);
int posix_spawnattr_set_persona_gid_np(const posix_spawnattr_t *attr, gid_t gid);
int posix_spawnattr_set_uid_np(const posix_spawnattr_t *attr, uid_t uid);

struct kpersona_info {
    uint32_t version;
    uid_t id;
    int type;
    gid_t gid;
    uint32_t ngroups;
    gid_t groups[16];
    uid_t gmuid;
    char name[256];
    uid_t uid;
} __attribute__((packed));

enum { OP_ALLOC = 1, OP_DEALLOC = 3, OP_GET = 4, OP_INFO = 5, OP_PIDINFO = 6, OP_FIND = 7, OP_FIND_BY_TYPE = 9 };

static int persona(int op, struct kpersona_info *info, uid_t *id, size_t *idlen) {
    return syscall(494, op, 0, info, id, idlen, NULL);
}

static int bad(const char *what, long got, long want) {
    printf("persona: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

static struct kpersona_info info(int version, uid_t id, int type, const char *name, uid_t uid) {
    struct kpersona_info k;
    memset(&k, 0, sizeof k);
    k.version = version;
    k.id = id;
    k.type = type;
    k.uid = uid;
    if (name) strncpy(k.name, name, sizeof k.name - 1);
    return k;
}

// The spawned child: its persona and ids.
static int child(void) {
    uid_t id = 0;
    struct kpersona_info k = info(2, 0, 0, NULL, 0);
    pid_t me = getpid();
    if (persona(OP_GET, NULL, &id, NULL) != 0) return 10;
    if (syscall(494, OP_PIDINFO, 0, &k, &me, NULL, NULL) != 0 || k.id != id) return 11;
    printf("%u %u %u %s\n", id, getuid(), getgid(), k.name);
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1) return child();
    uid_t id = 0, none = (uid_t)-1;
    struct kpersona_info k = info(2, none, 4, "gex-system", 1000);
    pid_t me = getpid();
#ifdef HOST_UNENTITLED
    if (persona(OP_ALLOC, &k, &id, NULL) != -1 || errno != EPERM) return bad("an unentitled alloc", errno, EPERM);
    if (persona(OP_DEALLOC, NULL, &id, NULL) != -1 || errno != EPERM) return bad("an unentitled dealloc", errno, EPERM);
#else
    size_t n;
    // Allocation: the next free id, then the name taken.
    if (persona(OP_ALLOC, &k, &id, NULL) != 0 || id < 501 || (id - 501) % 10 != 0 || k.id != id || k.version != 2) return bad("alloc", errno, 0);
    uid_t again = 0;
    struct kpersona_info dup = info(2, none, 2, "gex-system", 0);
    if (persona(OP_ALLOC, &dup, &again, NULL) != -1 || errno != EEXIST) return bad("a used name", errno, EEXIST);
    uid_t asked = 0;
    struct kpersona_info mk = info(1, 7001, 2, "gex-managed", 0);
    if (persona(OP_ALLOC, &mk, &asked, NULL) != 0 || asked != 7001) return bad("an asked id", asked, 7001);
    struct kpersona_info clash = info(2, 7001, 2, "gex-other", 0);
    if (persona(OP_ALLOC, &clash, &again, NULL) != -1 || errno != EEXIST) return bad("a used id", errno, EEXIST);
    struct kpersona_info badtype = info(2, none, 9, "gex-bad", 0);
    if (persona(OP_ALLOC, &badtype, &again, NULL) != -1 || errno != EINVAL) return bad("a bad type", errno, EINVAL);
    struct kpersona_info noname = info(2, none, 4, NULL, 0);
    if (persona(OP_ALLOC, &noname, &again, NULL) != -1 || errno != EINVAL) return bad("no name", errno, EINVAL);
    struct kpersona_info badv = info(3, none, 4, "gex-v3", 0);
    if (persona(OP_ALLOC, &badv, &again, NULL) != -1 || errno != EINVAL) return bad("a bad version", errno, EINVAL);
    // Its info, as version 2 and version 1 (no uid: left as it was).
    struct kpersona_info got = info(2, 0, 0, NULL, 0);
    if (persona(OP_INFO, &got, &id, NULL) != 0 || got.id != id || got.type != 4 || got.uid != 1000 || strcmp(got.name, "gex-system") || got.version != 2) return bad("its info", got.type, 4);
    struct kpersona_info v1 = info(1, 0, 0, NULL, 4242);
    if (persona(OP_INFO, &v1, &asked, NULL) != 0 || v1.version != 1 || v1.type != 2 || v1.uid != 4242 || strcmp(v1.name, "gex-managed")) return bad("version 1 info", v1.uid, 4242);
    // Finding: by name, by type, by nothing, and none.
    uid_t ids[8];
    struct kpersona_info q = info(1, none, 0, "gex-system", 0);
    n = 8;
    if (persona(OP_FIND, &q, ids, &n) != 0 || n != 1 || ids[0] != id) return bad("by name", (long)n, 1);
    q = info(1, none, 2, NULL, 0);
    n = 8;
    if (persona(OP_FIND_BY_TYPE, &q, ids, &n) != 0 || n < 1) return bad("by type", (long)n, 1);
    int seen = 0;
    for (size_t i = 0; i < n && i < 8; i++) seen |= ids[i] == 7001;
    if (!seen) return bad("by type: the managed one", (long)n, 1);
    q = info(1, none, 0, NULL, 0);
    n = 8;
    if (persona(OP_FIND, &q, ids, &n) != -1 || errno != EINVAL || n != 8) return bad("by nothing", errno, EINVAL);
    q = info(1, none, 0, "gex-nobody", 0);
    n = 8;
    if (persona(OP_FIND, &q, ids, &n) != -1 || errno != ESRCH || n != 0) return bad("none found", errno, ESRCH);
    // A spawn into the system persona, as uid and gid 1000.
    posix_spawnattr_t sa;
    posix_spawnattr_init(&sa);
    posix_spawnattr_set_persona_np(&sa, id, 1);
    posix_spawnattr_set_persona_uid_np(&sa, 1000);
    posix_spawnattr_set_persona_gid_np(&sa, 1000);
    int p[2];
    pipe(p);
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, p[1], 1);
    char *args[] = {argv[0], "child", NULL};
    pid_t pid;
    int e = posix_spawn(&pid, argv[0], &fa, &sa, args, environ);
    if (e) return bad("a spawn into it", e, 0);
    close(p[1]);
    char out[512] = {0}, want[512];
    int st;
    read(p[0], out, sizeof out - 1);
    waitpid(pid, &st, 0);
    snprintf(want, sizeof want, "%u 1000 1000 gex-system\n", id);
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0 || strcmp(out, want)) {
        printf("persona: the child: %s (status %d)\n", out, WIFEXITED(st) ? WEXITSTATUS(st) : -1);
        return 1;
    }
    // Gone: deallocated, it is found by no lookup and spawned into no more.
    if (persona(OP_DEALLOC, NULL, &asked, NULL) != 0) return bad("dealloc", errno, 0);
    if (persona(OP_INFO, &got, &asked, NULL) != -1 || errno != ESRCH) return bad("info of the gone", errno, ESRCH);
    if (persona(OP_DEALLOC, NULL, &asked, NULL) != -1 || errno != ESRCH) return bad("dealloc again", errno, ESRCH);
    posix_spawnattr_t sb;
    posix_spawnattr_init(&sb);
    posix_spawnattr_set_persona_np(&sb, asked, 1);
    if ((e = posix_spawn(&pid, argv[0], NULL, &sb, args, environ)) != ESRCH) return bad("a spawn into the gone", e, ESRCH);
    if (persona(OP_DEALLOC, NULL, &id, NULL) != 0) return bad("dealloc", errno, 0);
#endif
    // In none: no current persona, nor its own.
    if (persona(OP_GET, NULL, &id, NULL) != -1 || errno != ESRCH) return bad("no current persona", errno, ESRCH);
    struct kpersona_info mine = info(2, 0, 0, NULL, 0);
    if (syscall(494, OP_PIDINFO, 0, &mine, &me, NULL, NULL) != -1 || errno != ESRCH) return bad("its own persona", errno, ESRCH);
    // Root's: another's persona info, a spawn's POSIX credentials.
    if (geteuid() != 0) {
        pid_t parent = getppid();
        if (syscall(494, OP_PIDINFO, 0, &mine, &parent, NULL, NULL) != -1 || errno != EPERM) return bad("another's persona", errno, EPERM);
        posix_spawnattr_t sc;
        posix_spawnattr_init(&sc);
        posix_spawnattr_set_uid_np(&sc, 1234);
        char *cargs[] = {argv[0], "child", NULL};
        pid_t c;
        int r = posix_spawn(&c, argv[0], NULL, &sc, cargs, environ);
        if (r != EPERM) return bad("a spawn's POSIX credentials", r, EPERM);
    }
    printf("persona ok\n");
    return 0;
}
