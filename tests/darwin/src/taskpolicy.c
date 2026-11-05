// A spawn's task policy by task_policy.c: the main thread starts at the QoS
// task_compute_main_thread_qos gives its app type (an app user-interactive,
// a standard daemon at the legacy tier, a background daemon background;
// none, legacy as libpthread sets it), within the QoS clamp; the clamp and
// the app type pass to a child spawned without attributes
// (task_policy_create); and a role is taken. task_policy_get and
// task_policy_set by their flavors: the role (not settable on itself on
// embedded), the base QoS tiers (validated, kept), suppression (not on
// embedded), the policy state (root's only).

#include <limits.h>
#include <mach/mach.h>
#include <mach/task_policy.h>
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
    if (argc > 1) {
        // With a role to check, a mismatch is 99.
        if (argc > 2 && argv[2][0]) {
            task_category_policy_data_t c = {0};
            mach_msg_type_number_t cnt = TASK_CATEGORY_POLICY_COUNT;
            boolean_t def = FALSE;
            if (task_policy_get(mach_task_self(), TASK_CATEGORY_POLICY, (task_policy_t)&c, &cnt, &def) || (int)c.role != atoi(argv[2])) return 99;
        }
        return qos_class_main();
    }
    int q;
    if ((q = qos_class_main()) != QOS_CLASS_DEFAULT) return bad("no app type", q, QOS_CLASS_DEFAULT);
    task_t me = mach_task_self();
    kern_return_t kr;
    task_category_policy_data_t cat = {TASK_FOREGROUND_APPLICATION};
    mach_msg_type_number_t cnt = TASK_CATEGORY_POLICY_COUNT;
    boolean_t def = FALSE;
    if ((kr = task_policy_get(me, TASK_CATEGORY_POLICY, (task_policy_t)&cat, &cnt, &def)) || cat.role != TASK_UNSPECIFIED || cnt != 1) return bad("its own role", kr ? kr : cat.role, 0);
    if ((kr = task_policy_set(me, TASK_CATEGORY_POLICY, (task_policy_t)&cat, TASK_CATEGORY_POLICY_COUNT)) != KERN_INVALID_ARGUMENT) return bad("setting its own role", kr, KERN_INVALID_ARGUMENT);
    struct task_qos_policy qp = {LATENCY_QOS_TIER_2, THROUGHPUT_QOS_TIER_3};
    if ((kr = task_policy_set(me, TASK_BASE_QOS_POLICY, (task_policy_t)&qp, TASK_QOS_POLICY_COUNT))) return bad("setting the base QoS", kr, 0);
    struct task_qos_policy got = {0};
    cnt = TASK_QOS_POLICY_COUNT;
    if ((kr = task_policy_get(me, TASK_BASE_QOS_POLICY, (task_policy_t)&got, &cnt, &def)) || got.task_latency_qos_tier != LATENCY_QOS_TIER_2 || got.task_throughput_qos_tier != THROUGHPUT_QOS_TIER_3) return bad("the base QoS", got.task_latency_qos_tier, LATENCY_QOS_TIER_2);
    qp.task_latency_qos_tier = 0x1234;
    if ((kr = task_policy_set(me, TASK_BASE_QOS_POLICY, (task_policy_t)&qp, TASK_QOS_POLICY_COUNT)) != KERN_INVALID_ARGUMENT) return bad("an invalid tier", kr, KERN_INVALID_ARGUMENT);
    cnt = 1;
    if ((kr = task_policy_get(me, TASK_BASE_QOS_POLICY, (task_policy_t)&got, &cnt, &def)) != KERN_INVALID_ARGUMENT) return bad("too short a count", kr, KERN_INVALID_ARGUMENT);
    // TASK_SUPPRESSION_POLICY and TASK_POLICY_STATE (private): 16 words.
    integer_t words[16];
    memset(words, 0, sizeof words);
    if ((kr = task_policy_set(me, 3, words, 16)) != KERN_INVALID_ARGUMENT) return bad("suppression on embedded", kr, KERN_INVALID_ARGUMENT);
    memset(words, 0x55, sizeof words);
    cnt = 16;
    if ((kr = task_policy_get(me, 3, words, &cnt, &def)) || words[0] || words[2] || words[8]) return bad("the suppression policy", kr, 0);
    cnt = 16;
    def = TRUE;
    kr = task_policy_get(me, 4, words, &cnt, &def);
    if (getuid() != 0 ? kr != KERN_PROTECTION_FAILURE : (kr || words[0] || words[1])) return bad("the policy state", kr, getuid() ? KERN_PROTECTION_FAILURE : 0);
    if ((q = run("qos", "1", PROC_TYPE_APP_DEFAULT, 0, ROLE_UI_FOCAL)) != QOS_CLASS_USER_INTERACTIVE) return bad("an app with a role", q, QOS_CLASS_USER_INTERACTIVE);
    if ((q = run("qos", "", PROC_TYPE_DAEMON_STANDARD, 0, 0)) != QOS_CLASS_DEFAULT) return bad("a standard daemon", q, QOS_CLASS_DEFAULT);
    if ((q = run("qos", "", PROC_TYPE_DAEMON_BACKGROUND, 0, 0)) != QOS_CLASS_BACKGROUND) return bad("a background daemon", q, QOS_CLASS_BACKGROUND);
    // A clamp alone, then passed to a child.
    if ((q = run("parent", "0x09", 0, CLAMP_BACKGROUND, 0)) != QOS_CLASS_BACKGROUND) return bad("a clamp alone, inherited", q, QOS_CLASS_BACKGROUND);
    // An app under a clamp, and its child with both.
    if ((q = run("parent", "0x11", PROC_TYPE_APP_DEFAULT, CLAMP_UTILITY, 0)) != QOS_CLASS_UTILITY) return bad("a clamped app, inherited", q, QOS_CLASS_UTILITY);
    printf("taskpolicy ok\n");
    return 0;
}
