// task_suspend, task_resume, task_suspend2 and task_resume2 by task.c: a
// task that suspends itself holds every thread (the caller once its call
// is answered, after the others stop) until something outside resumes it
// (SIGCONT here: task_resume_internal on the same user stop count); its
// call then answers KERN_SUCCESS; a resume with no hold is KERN_FAILURE;
// task_suspend2's token, given back once the task runs, has no hold left
// to release.

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern kern_return_t task_suspend2(task_t, task_suspension_token_t *);
extern kern_return_t task_resume2(task_suspension_token_t);

static int bad(const char *what, long got, long want) {
    printf("tasksuspend: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

static volatile int ticked;

static void *ticker(void *a) {
    (void)a;
    for (;;) {
        write(1, "t", 1);
        ticked = 1;
        usleep(20000);
    }
    return NULL;
}

// The child: ticks from a thread, then, once it has ticked (the parent
// waits for a tick), suspends its own task; once resumed, says how its
// call went.
static int child(const char *mode) {
    pthread_t t;
    pthread_create(&t, NULL, ticker, NULL);
    while (!ticked) usleep(10000);
    usleep(100000);
    char msg[32];
    if (!strcmp(mode, "legacy")) {
        kern_return_t kr = task_suspend(mach_task_self());
        snprintf(msg, sizeof msg, "R%d,%d", kr, task_resume(mach_task_self()));
    } else {
        task_suspension_token_t token;
        kern_return_t kr = task_suspend2(mach_task_self(), &token);
        snprintf(msg, sizeof msg, "R%d,%d", kr, task_resume2(token));
    }
    write(1, msg, strlen(msg));
    _exit(0);
}

static char self[PATH_MAX];

static int drain(int fd, int ms, char *buf, int max) {
    int n = 0;
    for (int w = 0; w < ms; w += 10) {
        ssize_t k;
        while (n < max && (k = read(fd, buf + n, max - n)) > 0) n += k;
        usleep(10000);
    }
    buf[n < max ? n : max - 1] = 0;
    return n;
}

static int run(const char *mode) {
    int p[2];
    pipe(p);
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, p[1], 1);
    posix_spawn_file_actions_addclose(&fa, p[0]);
    char *args[] = {self, (char *)mode, NULL};
    char *env[] = {"MallocNanoZone=0", NULL};
    pid_t pid;
    if (posix_spawn(&pid, self, &fa, NULL, args, env)) return bad("spawning", errno, 0);
    close(p[1]);
    // Its first tick, however long it takes to start.
    char c, buf[256];
    read(p[0], &c, 1);
    fcntl(p[0], F_SETFL, O_NONBLOCK);
    usleep(400000);
    drain(p[0], 50, buf, sizeof buf);
    if (drain(p[0], 300, buf, sizeof buf)) return bad("ticks from a suspended task", (long)strlen(buf), 0);
    kill(pid, SIGCONT);
    int n = 0;
    char all[512] = {0};
    for (int i = 0; i < 300 && !strchr(all, 'R'); i++) {
        n += drain(p[0], 10, all + n, (int)sizeof all - 1 - n);
    }
    char *r = strchr(all, 'R');
    // KERN_SUCCESS for the suspension; KERN_FAILURE (5) for the resume,
    // SIGCONT having taken the hold.
    if (!r || strncmp(r, "R0,5", 4)) {
        printf("tasksuspend: %s: %s\n", mode, r ? r : "no answer");
        return 1;
    }
    int st;
    waitpid(pid, &st, 0);
    close(p[0]);
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1) return child(argv[1]);
    uint32_t n = sizeof self;
    _NSGetExecutablePath(self, &n);
    kern_return_t kr;
    if ((kr = task_resume(mach_task_self())) != KERN_FAILURE) return bad("a resume with no hold", kr, KERN_FAILURE);
    if (run("legacy") || run("token")) return 1;
    printf("tasksuspend ok\n");
    return 0;
}
