// __PAGEZERO: every arm64 program has 4 GiB of it, below which the map has
// nothing (load_machfile refuses a program without it and raises the map's
// minimum past it), so an access there faults: a store through a null
// pointer and a read just under 4 GiB each end the process with SIGSEGV.

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

static int bad(const char *what, long got, long want) {
    printf("pagezero: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

static int ends(int which) {
    pid_t pid = fork();
    if (pid == 0) {
        if (which == 0) *(volatile int *)0 = 1;
        else (void)*(volatile uint64_t *)(uintptr_t)0xfffff000u;
        _exit(0);
    }
    int st;
    if (pid < 0 || waitpid(pid, &st, 0) != pid) return -1;
    return WIFSIGNALED(st) ? WTERMSIG(st) : 0x100 | WEXITSTATUS(st);
}

int main(void) {
    int s;
    if ((s = ends(0)) != SIGSEGV) return bad("a store through a null pointer", s, SIGSEGV);
    if ((s = ends(1)) != SIGSEGV) return bad("a read under 4 GiB", s, SIGSEGV);
    printf("pagezero ok\n");
    return 0;
}
