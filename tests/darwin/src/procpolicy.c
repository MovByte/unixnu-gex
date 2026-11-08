// process_policy (bsd/kern/process_policy.c): a scope but process or
// thread is EINVAL, a pid that is not there ESRCH; background and hardware
// access are not supported; a resource use but CPU's is not supported, an
// unknown one EINVAL; the app lifecycle's NONE does nothing and STATE is not
// supported; no-SMT and TECS apply to the caller or its own thread only;
// importance donation marks the caller, which no other process may ask of
// it, and a process that receives no importance holds no boost.

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

static long pp(long scope, long action, long policy, long subtype, void *attr, long pid, uint64_t tid) {
    register long x0 __asm__("x0") = scope;
    register long x1 __asm__("x1") = action;
    register long x2 __asm__("x2") = policy;
    register long x3 __asm__("x3") = subtype;
    register void *x4 __asm__("x4") = attr;
    register long x5 __asm__("x5") = pid;
    register uint64_t x6 __asm__("x6") = tid;
    register long x16 __asm__("x16") = 323;
    long carry;
    __asm__ volatile("svc #0x80\n\tcset %1, cs" : "+r"(x0), "=r"(carry) : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x6), "r"(x16) : "memory", "cc");
    if (carry) {
        errno = (int)x0;
        return -1;
    }
    return x0;
}

static int bad(const char *what, long got, long want) {
    printf("procpolicy: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

#define EXPECT(what, call, want_errno) \
    do { \
        errno = 0; \
        long r_ = (call); \
        long e_ = r_ == -1 ? errno : 0; \
        if (e_ != (want_errno)) return bad(what, e_, want_errno); \
    } while (0)

int main(void) {
    uint64_t me;
    pthread_threadid_np(NULL, &me);
    EXPECT("an unknown scope", pp(3, 1, 8, 0, NULL, 0, 0), EINVAL);
    EXPECT("a pid not there", pp(1, 1, 8, 0, NULL, 99999, 0), ESRCH);
    EXPECT("background", pp(1, 1, 1, 0, NULL, 0, 0), ENOTSUP);
    EXPECT("hardware access", pp(1, 1, 2, 0, NULL, 0, 0), ENOTSUP);
    EXPECT("wired memory use", pp(1, 1, 4, 1, NULL, 0, 0), ENOTSUP);
    EXPECT("an unknown resource", pp(1, 1, 4, 9, NULL, 0, 0), EINVAL);
    EXPECT("starvation, not restoring", pp(1, 1, 3, 0, NULL, 0, 0), EINVAL);
    EXPECT("starvation of an unknown resource", pp(1, 2, 3, 5, NULL, 0, 0), EINVAL);
    EXPECT("starvation restored", pp(1, 2, 3, 1, NULL, 0, 0), getuid() == 0 ? 0 : EPERM);
    EXPECT("the app lifecycle's NONE", pp(1, 1, 5, 0, NULL, 0, 0), 0);
    EXPECT("the app lifecycle's STATE", pp(1, 1, 5, 1, NULL, 0, 0), ENOTSUP);
    EXPECT("no SMT for this process", pp(1, 1, 8, 0, NULL, 0, 0), 0);
    EXPECT("no SMT, not applied", pp(1, 2, 8, 0, NULL, 0, 0), EINVAL);
    EXPECT("no SMT for this thread", pp(2, 1, 8, 0, NULL, 0, me), 0);
    EXPECT("no SMT for another thread", pp(2, 1, 8, 0, NULL, 0, me + 1), EINVAL);
    EXPECT("TECS for this thread", pp(2, 1, 9, 0, NULL, 0, me), 0);
    EXPECT("an unknown policy", pp(1, 1, 10, 0, NULL, 0, 0), EINVAL);

    // Importance: this process receives none, so it holds no boost; it may
    // mark itself a donor, by either call.
    EXPECT("a boost held without receiving", pp(1, 14, 7, 1, NULL, 0, 0), EINVAL);
    EXPECT("a boost for a thread", pp(2, 14, 7, 1, NULL, 0, 0), EINVAL);
    EXPECT("donating, not set", pp(1, 1, 7, 3, NULL, 0, 0), EINVAL);
    EXPECT("donating", pp(1, 10, 7, 3, NULL, 0, 0), 0);
    EXPECT("donating by the old call", pp(1, 5, 6, 6, NULL, 0, 0), 0);
    EXPECT("the old call, not enabled", pp(1, 1, 6, 6, NULL, 0, 0), EINVAL);
    EXPECT("the old call, unknown", pp(1, 5, 6, 1, NULL, 0, 0), EINVAL);

    // Another process's importance is not this one's to change.
    int p[2];
    pipe(p);
    pid_t pid = fork();
    if (pid == 0) {
        char c;
        read(p[0], &c, 1);
        _exit(0);
    }
    EXPECT("donating for another process", pp(1, 10, 7, 3, NULL, pid, 0), EINVAL);
    EXPECT("no SMT for another process", pp(1, 1, 8, 0, NULL, pid, 0), EINVAL);
    write(p[1], "x", 1);
    int st;
    waitpid(pid, &st, 0);
    printf("procpolicy ok\n");
    return 0;
}
