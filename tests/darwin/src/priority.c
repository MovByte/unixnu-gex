// getpriority and setpriority by kern_resource.c: a nice value set,
// clamped, raised by anyone but lowered only by root (EACCES), inherited by
// a child and found by group; ESRCH for no such process, EINVAL for an
// unknown which or too large a who; a thread's background, which strips its
// QoS policy; a process's background; GPU denial only
// for another process; a role only for an application (ENOTSUP otherwise),
// set on a spawned app by its parent and read back; game mode only with
// its entitlement.

#include <errno.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <pthread.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

extern int posix_spawnattr_setprocesstype_np(posix_spawnattr_t *, int);

// The private ones (bsd/sys/resource.h, resource_private.h).
#define PRIO_DARWIN_GPU 5
#define PRIO_DARWIN_ROLE 6
#define PRIO_DARWIN_GAME_MODE 7
#define PRIO_DARWIN_ROLE_DEFAULT 0x0
#define PRIO_DARWIN_ROLE_UI_FOCAL 0x1
#define PRIO_DARWIN_ROLE_UI 0x2
#define PRIO_DARWIN_ROLE_NON_UI 0x3

static char self[PATH_MAX];

static int bad(const char *what, long got, long want) {
    printf("priority: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

static pid_t run(const char *mode, int apptype, int *wr) {
    int p[2];
    pipe(p);
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, p[0], 0);
    posix_spawn_file_actions_addclose(&fa, p[1]);
    posix_spawnattr_t at;
    posix_spawnattr_init(&at);
    if (apptype) posix_spawnattr_setprocesstype_np(&at, apptype);
    char *args[] = {self, (char *)mode, NULL};
    char *env[] = {"MallocNanoZone=0", NULL};
    pid_t pid = -1;
    posix_spawn(&pid, self, &fa, &at, args, env);
    close(p[0]);
    *wr = p[1];
    return pid;
}

// A child: waits for its parent's word, then exits with its nice value, or
// as "app" with its role.
static int child(const char *mode) {
    char c;
    read(0, &c, 1);
    errno = 0;
    int v = getpriority(!strcmp(mode, "app") ? PRIO_DARWIN_ROLE : PRIO_PROCESS, 0);
    return errno ? 99 : v;
}

int main(int argc, char **argv) {
    if (argc > 1) return child(argv[1]);
    uint32_t n = sizeof self;
    _NSGetExecutablePath(self, &n);
    setpgid(0, 0);
    int r, wr, st;
    if ((r = getpriority(PRIO_PROCESS, 0)) != 0) return bad("the first nice value", r, 0);
    if (setpriority(PRIO_PROCESS, 0, 5)) return bad("a nice value", errno, 0);
    if ((r = getpriority(PRIO_PROCESS, getpid())) != 5) return bad("the nice value", r, 5);
    if (getuid() != 0 && (setpriority(PRIO_PROCESS, 0, 4) != -1 || errno != EACCES)) return bad("lowering it without root", errno, EACCES);
    if ((r = getpriority(PRIO_PGRP, 0)) != 5) return bad("the group's", r, 5);
    if ((r = getpriority(PRIO_USER, 0)) > 5) return bad("the user's", r, 5);
    // A child takes it.
    pid_t pid = run("nice", 0, &wr);
    write(wr, "g", 1);
    if (waitpid(pid, &st, 0) != pid || WEXITSTATUS(st) != 5) return bad("a child's", WEXITSTATUS(st), 5);
    close(wr);
    errno = 0;
    if (getpriority(PRIO_PROCESS, 999999) != -1 || errno != ESRCH) return bad("no such process", errno, ESRCH);
    if (getpriority(42, 0) != -1 || errno != EINVAL) return bad("an unknown which", errno, EINVAL);
    if (getpriority(PRIO_PROCESS, 0x80000000u) != -1 || errno != EINVAL) return bad("too large a who", errno, EINVAL);

    // The thread's background: its QoS policy goes (the kernel's -2, which
    // libsyscall's wrapper answers by clearing the thread's QoS), and it
    // reads back.
    pthread_set_qos_class_self_np(QOS_CLASS_UTILITY, 0);
    if ((r = setpriority(PRIO_DARWIN_THREAD, 0, PRIO_DARWIN_BG)) != 0 || qos_class_self() != QOS_CLASS_UNSPECIFIED) return bad("a QoS thread's background", r ? r : qos_class_self(), 0);
    if ((r = getpriority(PRIO_DARWIN_THREAD, 0)) != 1) return bad("the thread's background", r, 1);
    if ((r = setpriority(PRIO_DARWIN_THREAD, 0, 0)) != 0) return bad("the thread out of the background", r, 0);
    if (setpriority(PRIO_DARWIN_THREAD, 1, 0) != -1 || errno != EINVAL) return bad("another thread", errno, EINVAL);
    // The process's.
    if (setpriority(PRIO_DARWIN_PROCESS, 0, PRIO_DARWIN_BG)) return bad("the process's background", errno, 0);
    if ((r = getpriority(PRIO_DARWIN_PROCESS, 0)) != 1) return bad("the process's background, read", r, 1);
    setpriority(PRIO_DARWIN_PROCESS, 0, 0);
    // GPU denial: not the caller itself, nor pid 0.
    if (setpriority(PRIO_DARWIN_GPU, 0, 2) != -1 || errno != EINVAL) return bad("GPU denial of pid 0", errno, EINVAL);
    if (setpriority(PRIO_DARWIN_GPU, getpid(), 2) != -1 || errno != EPERM) return bad("GPU denial of itself", errno, EPERM);
    // A role: not for this process, which is no application.
    if (setpriority(PRIO_DARWIN_ROLE, 0, PRIO_DARWIN_ROLE_UI) != -1 || errno != ENOTSUP) return bad("a role for no app", errno, ENOTSUP);
    if ((r = getpriority(PRIO_DARWIN_ROLE, 0)) != PRIO_DARWIN_ROLE_DEFAULT) return bad("its role", r, 0);
    // An app's, set by its parent: it reads it back.
    pid = run("app", 0x100, &wr);
    if ((r = getpriority(PRIO_DARWIN_ROLE, pid)) != PRIO_DARWIN_ROLE_UI_FOCAL) return bad("a new app's role", r, PRIO_DARWIN_ROLE_UI_FOCAL);
    if (setpriority(PRIO_DARWIN_ROLE, pid, 42) != -1 || errno != EINVAL) return bad("no such role", errno, EINVAL);
    if (setpriority(PRIO_DARWIN_ROLE, pid, PRIO_DARWIN_ROLE_NON_UI)) return bad("an app's role", errno, 0);
    write(wr, "g", 1);
    if (waitpid(pid, &st, 0) != pid || WEXITSTATUS(st) != PRIO_DARWIN_ROLE_NON_UI) return bad("the role it read", WEXITSTATUS(st), PRIO_DARWIN_ROLE_NON_UI);
    close(wr);
    // Clamped to PRIO_MAX.
    if (setpriority(PRIO_PROCESS, 0, 50)) return bad("a nice value past PRIO_MAX", errno, 0);
    if ((r = getpriority(PRIO_PROCESS, 0)) != 20) return bad("PRIO_MAX", r, 20);
    // Game mode takes an entitlement.
    if (setpriority(PRIO_DARWIN_GAME_MODE, 0, 1) != -1 || errno != EPERM) return bad("game mode", errno, EPERM);
    printf("priority ok\n");
    return 0;
}
