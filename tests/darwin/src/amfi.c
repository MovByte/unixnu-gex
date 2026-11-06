// AMFI runs only trusted code: a program signed ad hoc whose cdhash is in
// no trust cache, and one in a trust cache that holds get-task-allow while
// Developer Mode is off, are refused at their load (EBADEXEC), by spawn
// and by exec alike.

#include <errno.h>
#include <spawn.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static int refused(const char *path) {
    pid_t pid;
    char *argv[] = {(char *)path, NULL};
    int e = posix_spawn(&pid, path, NULL, NULL, argv, environ);
    if (e != EBADEXEC) {
        printf("amfi: spawn of %s: %d, want EBADEXEC\n", path, e);
        return 0;
    }
    pid = fork();
    if (pid == 0) {
        execve(path, argv, environ);
        _exit(errno == EBADEXEC ? 0 : 1);
    }
    int st = 0;
    if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        printf("amfi: exec of %s: status %#x, want EBADEXEC\n", path, st);
        return 0;
    }
    return 1;
}

int main(void) {
    if (!refused("/var/tmp/gex-darwin-untrusted") || !refused("/var/tmp/gex-darwin-gta")) return 1;
    printf("amfi ok\n");
    return 0;
}
