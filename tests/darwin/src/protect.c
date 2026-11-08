// Page protections hold the program's own accesses, as vm_fault answers
// them: a store to a page mapped read-only and a load from one mapped with
// no access are protection failures (SIGBUS); a load where nothing is
// mapped, a page unmapped, is an invalid address (SIGSEGV), and so is an
// access that runs from a readable page into an unmapped one. What a page
// allows is what its protection says now, after mprotect.

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

static int bad(const char *what, long got, long want) {
    printf("protect: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

// The signal a child ends by, doing `mode` to a fresh two-page mapping.
static int ends(int mode) {
    pid_t pid = fork();
    if (pid == 0) {
        size_t pg = (size_t)getpagesize();
        volatile char *a = mmap(0, 2 * pg, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
        a[0] = 1;
        switch (mode) {
        case 0: // a store to a read-only page
            mprotect((void *)a, pg, PROT_READ);
            a[8] = 2;
            break;
        case 1: // a load where nothing is mapped
            munmap((void *)a, 2 * pg);
            (void)a[8];
            break;
        case 2: // a load from a page with no access
            mprotect((void *)a, pg, PROT_NONE);
            (void)a[8];
            break;
        case 3: { // eight bytes from the last four of a page into an unmapped one
            munmap((void *)(a + pg), pg);
            uint64_t v;
            memcpy(&v, (const void *)(a + pg - 4), sizeof v);
            __asm__ volatile("" : : "r"(v));
            break;
        }
        case 4: // a store after the page is writable again
            mprotect((void *)a, pg, PROT_READ);
            mprotect((void *)a, pg, PROT_READ | PROT_WRITE);
            a[8] = 3;
            _exit(a[8] == 3 ? 0 : 7);
        }
        _exit(9);
    }
    int st;
    waitpid(pid, &st, 0);
    return WIFSIGNALED(st) ? WTERMSIG(st) : 0x100 | WEXITSTATUS(st);
}

int main(void) {
    int s;
    if ((s = ends(0)) != SIGBUS) return bad("a store to a read-only page", s, SIGBUS);
    if ((s = ends(1)) != SIGSEGV) return bad("a load where nothing is mapped", s, SIGSEGV);
    if ((s = ends(2)) != SIGBUS) return bad("a load from a page with no access", s, SIGBUS);
    if ((s = ends(3)) != SIGSEGV) return bad("an access into an unmapped page", s, SIGSEGV);
    if ((s = ends(4)) != 0x100) return bad("a store to a page writable again", s, 0x100);
    printf("protect ok\n");
    return 0;
}
