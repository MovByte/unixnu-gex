// A spawn's task policy by task_policy.c: the main thread starts at the QoS
// task_compute_main_thread_qos gives its app type (an app user-interactive,
// a standard daemon at the legacy tier, a background daemon background;
// none, legacy as libpthread sets it), within the QoS clamp; the clamp and
// the app type pass to a child spawned without attributes
// (task_policy_create); and a role is taken.

#include <limits.h>
#include <mach-o/dyld.h>
#include <pthread.h>
#include <pthread/qos.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern int posix_spawnattr_setprocesstype_np(posix_spawnattr_t *, int);
extern int posix_spawnattr_set_qos_clamp_np(posix_spawnattr_t *, uint64_t);
extern int posix_spawnattr_set_darwin_role_np(posix_spawnattr_t *, uint64_t);

#define PROC_TYPE_APP_DEFAULT 0x100
#define PROC_TYPE_DAEMON_STANDARD 0x300
#define PROC_TYPE_DAEMON_BACKGROUND 0x500
#define CLAMP_UTILITY 1
#define CLAMP_BACKGROUND 2
#define ROLE_UI_FOCAL 1

static char self[PATH_MAX];

// A child that exits with its main thread's QoS class, or, as "parent" with
// the class it should have, with its own child's (one spawned with no
// attributes), 1 if its own is not that.
static int run(const char *mode, const char *want, int type, uint64_t clamp, uint64_t role) {
    posix_spawnattr_t at;
    posix_spawnattr_init(&at);
    if (type) posix_spawnattr_setprocesstype_np(&at, type);
    if (clamp) posix_spawnattr_set_qos_clamp_np(&at, clamp);
    if (role) posix_spawnattr_set_darwin_role_np(&at, role);
    char *args[] = {self, (char *)mode, (char *)want, NULL};
    char *env[] = {"MallocNanoZone=0", NULL};
    pid_t pid;
    if (posix_spawn(&pid, self, NULL, &at, args, env)) return -1;
    int st;
    if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st)) return -2;
    return WEXITSTATUS(st);
}

static int bad(const char *what, long got, long want) {
    printf("taskpolicy: %s: %#lx, want %#lx\n", what, got, want);
    return 1;
}

int main(int argc, char **argv) {
    uint32_t n = sizeof self;
    _NSGetExecutablePath(self, &n);
    if (argc > 2 && !strcmp(argv[1], "parent")) {
        if (qos_class_main() != (int)strtol(argv[2], NULL, 0)) return 1;
        return run("qos", "", 0, 0, 0);
    }
    if (argc > 1) return qos_class_main();
    int q;
    if ((q = qos_class_main()) != QOS_CLASS_DEFAULT) return bad("no app type", q, QOS_CLASS_DEFAULT);
    if ((q = run("qos", "", PROC_TYPE_APP_DEFAULT, 0, ROLE_UI_FOCAL)) != QOS_CLASS_USER_INTERACTIVE) return bad("an app with a role", q, QOS_CLASS_USER_INTERACTIVE);
    if ((q = run("qos", "", PROC_TYPE_DAEMON_STANDARD, 0, 0)) != QOS_CLASS_DEFAULT) return bad("a standard daemon", q, QOS_CLASS_DEFAULT);
    if ((q = run("qos", "", PROC_TYPE_DAEMON_BACKGROUND, 0, 0)) != QOS_CLASS_BACKGROUND) return bad("a background daemon", q, QOS_CLASS_BACKGROUND);
    // A clamp alone, then passed to a child.
    if ((q = run("parent", "0x09", 0, CLAMP_BACKGROUND, 0)) != QOS_CLASS_BACKGROUND) return bad("a clamp alone, inherited", q, QOS_CLASS_BACKGROUND);
    // An app under a clamp, and its child with both.
    if ((q = run("parent", "0x11", PROC_TYPE_APP_DEFAULT, CLAMP_UTILITY, 0)) != QOS_CLASS_UTILITY) return bad("a clamped app, inherited", q, QOS_CLASS_UTILITY);
    printf("taskpolicy ok\n");
    return 0;
}
