// Coalitions: a member of a privileged coalition makes resource and
// jetsam coalitions, spawns a child into them (the jetsam one's leader),
// asks them to terminate and reaps them once the child is gone; their
// ids, task counts and the child's place show in proc_info; a coalition
// asked to terminate takes no new task, and a member of an unprivileged
// one may not make coalitions. A process outside privileged coalitions
// (macOS's, under launchd) is refused. A process leading no coalition may
// use foreground hardware by the voucher it adopted, and only root may ask
// of another.

#include <errno.h>
#include <mach/mach.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

int coalition_create(uint64_t *cid_out, uint32_t flags);
int coalition_terminate(uint64_t cid, uint32_t flags);
int coalition_reap(uint64_t cid, uint32_t flags);
int coalition_info_set_name(uint64_t cid, const char *name, size_t size);
int coalition_info_set_efficiency(uint64_t cid, uint64_t flags);
int coalition_ledger_set_logical_writes_limit(uint64_t cid, int64_t limit);
int posix_spawnattr_setcoalition_np(const posix_spawnattr_t *, uint64_t, int, int);
int __proc_info(int callnum, int pid, int flavor, uint64_t arg, void *buffer, int buffersize);
int memorystatus_control(uint32_t command, int32_t pid, uint32_t flags, void *buffer, size_t buffersize);

#define TYPE_RESOURCE 0
#define TYPE_JETSAM 1
#define ROLE_ADAPTIVE 3
#define TASKROLE_UNDEF 0
#define TASKROLE_LEADER 1
#define FLAGS(type, role, priv) (((type) << 4) | ((role) << 8) | (priv))
#define PROC_PIDCOALITIONINFO 20
#define LISTCOALITIONS_SINGLE_TYPE 2
#define MEMORYSTATUS_CMD_GET_PROCESS_COALITION_IS_SWAPPABLE 26

extern char **environ;

static int bad(const char *what, long got, long want) {
    printf("coalition: %s: %ld, want %ld\n", what, got, want);
    fflush(stdout);
    return 1;
}

static int err(int r) {
    return r ? errno : 0;
}

struct coalinfo {
    uint64_t id;
    uint32_t type, tasks;
};

// The coalition `id` of `type` in the list, and its task count (-1: none).
static long tasks_of(uint64_t id, int type) {
    struct coalinfo list[256];
    int n = __proc_info(11, LISTCOALITIONS_SINGLE_TYPE, type, 0, list, sizeof list);
    for (int i = 0; i < n / (int)sizeof list[0]; i++) {
        if (list[i].id == id) return list[i].type == (uint32_t)type ? list[i].tasks : -2;
    }
    return -1;
}

static int ids_of(pid_t pid, uint64_t ids[2]) {
    uint64_t b[5];
    if (__proc_info(2, pid, PROC_PIDCOALITIONINFO, 0, b, sizeof b) != sizeof b) return errno;
    ids[0] = b[0];
    ids[1] = b[1];
    return 0;
}

static pid_t spawn_in(const char *path, const char *arg, uint64_t rc, uint64_t jc, int jrole, int *e) {
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    if (rc) posix_spawnattr_setcoalition_np(&attr, rc, TYPE_RESOURCE, TASKROLE_UNDEF);
    if (jc) posix_spawnattr_setcoalition_np(&attr, jc, TYPE_JETSAM, jrole);
    char *args[] = {(char *)path, (char *)arg, NULL};
    pid_t c = -1;
    *e = posix_spawn(&c, path, NULL, &attr, args, environ);
    posix_spawnattr_destroy(&attr);
    return c;
}

int main(int argc, char **argv) {
    if (argc > 1) {
        // The child, in an unprivileged coalition: it may not make one.
        uint64_t cid;
        int e = err(coalition_create(&cid, FLAGS(TYPE_RESOURCE, 0, 0)));
        if (!strcmp(argv[1], "wait")) {
            char c;
            read(0, &c, 1);
        }
        return e == EPERM ? 0 : (bad("child create", e, EPERM), 1);
    }
    int fail = 0;
    // proc_can_use_foreground_hw (PROC_INFO_CALL_CANUSEFGHW).
    uint32_t reason = 0;
    int r = __proc_info(12, getpid(), 0, 0, &reason, sizeof reason);
    // With no voucher: no; with one whose originator is in the foreground
    // (as a process launched from an app's session may have): yes.
    fail |= !((r == 0 && reason == 13) || (r == 1 && reason == 1)) ? bad("foreground hw", r, 0) | bad("its reason", reason, 13) : 0;
    if (getuid() != 0) {
        reason = 0;
        r = __proc_info(12, getppid(), 0, 0, &reason, sizeof reason);
        fail |= r != -1 || errno != EPERM || reason != 99 ? bad("another's foreground hw", errno, EPERM) | bad("its reason", reason, 99) : 0;
    }
    uint64_t mine[2];
    if (ids_of(getpid(), mine)) return bad("own coalitions", errno, 0);
    fail |= !mine[0] || !mine[1] ? bad("own ids", mine[0], 1) : 0;
    fail |= tasks_of(mine[0], TYPE_RESOURCE) < 1 ? bad("own coalition listed", tasks_of(mine[0], TYPE_RESOURCE), 1) : 0;
    uint64_t rc = 0, jc = 0;
    int e = err(coalition_create(&rc, FLAGS(TYPE_RESOURCE, 0, 0)));
    if (e == EPERM) {
        // Not in a privileged coalition.
        fail |= err(coalition_terminate(mine[0], 0)) != EPERM ? bad("terminate unprivileged", errno, EPERM) : 0;
        if (!fail) printf("coalition ok\n");
        return fail;
    }
    if (e) return bad("create", e, 0);
    fail |= (e = err(coalition_create(&jc, FLAGS(TYPE_JETSAM, ROLE_ADAPTIVE, 0)))) ? bad("create jetsam", e, 0) : 0;
    fail |= rc <= mine[1] || jc != rc + 1 ? bad("ids in order", jc, rc + 1) : 0;
    fail |= (e = err(coalition_create(&rc, 0x1000))) != EINVAL ? bad("bad flags", e, EINVAL) : 0;
    fail |= tasks_of(rc, TYPE_RESOURCE) != 0 || tasks_of(jc, TYPE_JETSAM) != 0 ? bad("new and empty", tasks_of(rc, TYPE_RESOURCE), 0) : 0;
    // Name and efficiency: a jetsam coalition's; efficiency at creation.
    fail |= (e = err(coalition_info_set_name(jc, "test", 5))) ? bad("name", e, 0) : 0;
    fail |= (e = err(coalition_info_set_name(rc, "test", 5))) != EINVAL ? bad("name resource", e, EINVAL) : 0;
    fail |= (e = err(coalition_info_set_efficiency(jc, 1))) != ENOTSUP ? bad("efficiency", e, ENOTSUP) : 0;
    fail |= (e = err(coalition_info_set_efficiency(jc, 0))) != EINVAL ? bad("no efficiency", e, EINVAL) : 0;
    if (getuid() != 0) fail |= (e = err(coalition_ledger_set_logical_writes_limit(rc, 1))) != EPERM ? bad("ledger", e, EPERM) : 0;
    fail |= (e = err(memorystatus_control(MEMORYSTATUS_CMD_GET_PROCESS_COALITION_IS_SWAPPABLE, getpid(), 0, NULL, 0))) != ENOTSUP && e != EPERM ? bad("swappable", e, ENOTSUP) : 0;

    // A child spawned into them, the jetsam one's leader.
    int fds[2];
    pipe(fds);
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, fds[0], 0);
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_setcoalition_np(&attr, rc, TYPE_RESOURCE, TASKROLE_UNDEF);
    posix_spawnattr_setcoalition_np(&attr, jc, TYPE_JETSAM, TASKROLE_LEADER);
    char *args[] = {argv[0], "wait", NULL};
    pid_t c;
    if ((e = posix_spawn(&c, argv[0], &fa, &attr, args, environ))) return bad("spawn", e, 0);
    close(fds[0]);
    uint64_t theirs[2];
    fail |= ids_of(c, theirs) || theirs[0] != rc || theirs[1] != jc ? bad("child's coalitions", theirs[1], jc) : 0;
    fail |= tasks_of(rc, TYPE_RESOURCE) != 1 || tasks_of(jc, TYPE_JETSAM) != 1 ? bad("one task each", tasks_of(jc, TYPE_JETSAM), 1) : 0;
    fail |= tasks_of(rc, TYPE_JETSAM) != -1 ? bad("by type", tasks_of(rc, TYPE_JETSAM), -1) : 0;
    // Asked to terminate while the child is in it: not yet reaped, and no
    // new task taken.
    fail |= (e = err(coalition_terminate(rc, 0))) ? bad("terminate", e, 0) : 0;
    fail |= (e = err(coalition_terminate(rc, 0))) != EALREADY ? bad("terminate again", e, EALREADY) : 0;
    fail |= (e = err(coalition_reap(rc, 0))) != EBUSY ? bad("reap busy", e, EBUSY) : 0;
    fail |= (e = err(coalition_terminate(mine[0], 0))) != EPERM ? bad("terminate default", e, EPERM) : 0;
    // A spawn into a jetsam coalition alone needs a resource one.
    spawn_in(argv[0], "go", 0, jc, TASKROLE_UNDEF, &e);
    fail |= e != EINVAL ? bad("jetsam alone", e, EINVAL) : 0;
    spawn_in(argv[0], "go", 0xdead, jc, TASKROLE_UNDEF, &e);
    fail |= e != ESRCH ? bad("no such coalition", e, ESRCH) : 0;
    spawn_in(argv[0], "go", jc, jc, TASKROLE_UNDEF, &e);
    fail |= e != ESRCH ? bad("wrong type", e, ESRCH) : 0;
    // The child goes: the coalition is terminated, then reaped.
    write(fds[1], "x", 1);
    int st;
    waitpid(c, &st, 0);
    fail |= !WIFEXITED(st) || WEXITSTATUS(st) ? bad("child", st, 0) : 0;
    spawn_in(argv[0], "go", rc, 0, 0, &e);
    fail |= e != ESRCH ? bad("spawn into terminated", e, ESRCH) : 0;
    fail |= tasks_of(rc, TYPE_RESOURCE) != 0 ? bad("emptied", tasks_of(rc, TYPE_RESOURCE), 0) : 0;
    fail |= (e = err(coalition_reap(rc, 0))) ? bad("reap", e, 0) : 0;
    fail |= (e = err(coalition_reap(rc, 0))) != ESRCH ? bad("reap again", e, ESRCH) : 0;
    fail |= tasks_of(rc, TYPE_RESOURCE) != -1 ? bad("reaped is gone", tasks_of(rc, TYPE_RESOURCE), -1) : 0;
    // Not asked to terminate: an empty coalition is not reaped.
    fail |= (e = err(coalition_reap(jc, 0))) != EBUSY ? bad("reap unterminated", e, EBUSY) : 0;
    fail |= (e = err(coalition_terminate(jc, 0))) || (e = err(coalition_reap(jc, 0))) ? bad("terminate and reap", e, 0) : 0;
    if (!fail) printf("coalition ok\n");
    return fail;
}
