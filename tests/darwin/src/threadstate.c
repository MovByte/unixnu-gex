// thread_get_state and thread_set_state by thread_act.c and arm64's
// status.c: a suspended thread's registers (pc in its code, sp on its
// stack), a running thread's (held to stop, then let go), the caller's
// own; the flavor list; too short a count, or a 32-bit flavor, is
// KERN_INVALID_ARGUMENT; the NEON state read and written back; the debug
// state zeros, set with nothing enabled, refused with a context ID
// (KERN_PROTECTION_FAILURE); and a thread waiting in a call, its pc set,
// goes on there once its call is done.

#include <mach/mach.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static volatile unsigned long spins;
static volatile int stop, landed;
static int p[2];

static int bad(const char *what, long got, long want) {
    printf("threadstate: %s: %#lx, want %#lx\n", what, got, want);
    return 1;
}

static void *spin(void *a) {
    (void)a;
    while (!stop) spins++;
    return NULL;
}

static void *reader(void *a) {
    (void)a;
    char c;
    read(p[0], &c, 1);
    return NULL;
}

// Where the redirected reader goes on.
static void land(void) {
    landed = 1;
    pthread_exit(NULL);
}

int main(void) {
    kern_return_t kr;
    arm_thread_state64_t ts;
    mach_msg_type_number_t n;
    pthread_t t;
    pthread_create(&t, NULL, spin, NULL);
    while (spins < 1000) usleep(1000);
    thread_act_t th = pthread_mach_thread_np(t);
    uintptr_t lo = (uintptr_t)pthread_get_stackaddr_np(t) - pthread_get_stacksize_np(t), hi = (uintptr_t)pthread_get_stackaddr_np(t);

    // Running: held to stop, then let go.
    n = ARM_THREAD_STATE64_COUNT;
    if ((kr = thread_get_state(th, ARM_THREAD_STATE64, (thread_state_t)&ts, &n)) || n != ARM_THREAD_STATE64_COUNT) return bad("a running thread's state", kr, 0);
    unsigned long c1 = spins;
    usleep(50000);
    if (spins == c1) return bad("the thread let go", 0, 1);

    thread_suspend(th);
    n = ARM_THREAD_STATE64_COUNT;
    if ((kr = thread_get_state(th, ARM_THREAD_STATE64, (thread_state_t)&ts, &n))) return bad("a suspended thread's state", kr, 0);
    if (arm_thread_state64_get_sp(ts) < lo || arm_thread_state64_get_sp(ts) >= hi) return bad("its sp", (long)arm_thread_state64_get_sp(ts), (long)hi);
    if (!arm_thread_state64_get_pc(ts)) return bad("its pc", 0, 1);
    n = ARM_THREAD_STATE64_COUNT - 1;
    if ((kr = thread_get_state(th, ARM_THREAD_STATE64, (thread_state_t)&ts, &n)) != KERN_INVALID_ARGUMENT) return bad("too short a count", kr, KERN_INVALID_ARGUMENT);
    n = ARM_THREAD_STATE32_COUNT;
    if ((kr = thread_get_state(th, ARM_THREAD_STATE32, (thread_state_t)&ts, &n)) != KERN_INVALID_ARGUMENT) return bad("a 32-bit flavor", kr, KERN_INVALID_ARGUMENT);
    natural_t list[8];
    n = 8;
    if ((kr = thread_get_state(th, THREAD_STATE_FLAVOR_LIST, list, &n)) || n != 4 || list[0] != ARM_THREAD_STATE || list[3] != ARM_DEBUG_STATE) return bad("the flavor list", kr ? kr : n, 4);
    arm_neon_state64_t ns;
    n = ARM_NEON_STATE64_COUNT;
    if ((kr = thread_get_state(th, ARM_NEON_STATE64, (thread_state_t)&ns, &n)) || n != ARM_NEON_STATE64_COUNT) return bad("the NEON state", kr ? kr : n, ARM_NEON_STATE64_COUNT);
    if ((kr = thread_set_state(th, ARM_NEON_STATE64, (thread_state_t)&ns, ARM_NEON_STATE64_COUNT))) return bad("the NEON state written back", kr, 0);
    arm_debug_state64_t ds;
    memset(&ds, 0x55, sizeof ds);
    n = ARM_DEBUG_STATE64_COUNT;
    if ((kr = thread_get_state(th, ARM_DEBUG_STATE64, (thread_state_t)&ds, &n)) || ds.__bcr[0] || ds.__mdscr_el1) return bad("the debug state", kr, 0);
    if ((kr = thread_set_state(th, ARM_DEBUG_STATE64, (thread_state_t)&ds, ARM_DEBUG_STATE64_COUNT))) return bad("a debug state with nothing on", kr, 0);
    ds.__bcr[2] = 1u << 21;
    if ((kr = thread_set_state(th, ARM_DEBUG_STATE64, (thread_state_t)&ds, ARM_DEBUG_STATE64_COUNT)) != KERN_PROTECTION_FAILURE) return bad("a context ID", kr, KERN_PROTECTION_FAILURE);
    thread_resume(th);
    stop = 1;
    pthread_join(t, NULL);

    // Its own.
    n = ARM_THREAD_STATE64_COUNT;
    if ((kr = thread_get_state(mach_thread_self(), ARM_THREAD_STATE64, (thread_state_t)&ts, &n)) || !arm_thread_state64_get_sp(ts)) return bad("its own state", kr, 0);

    // A thread waiting in a call, sent on elsewhere.
    pipe(p);
    pthread_create(&t, NULL, reader, NULL);
    usleep(100000);
    th = pthread_mach_thread_np(t);
    thread_suspend(th);
    n = ARM_THREAD_STATE64_COUNT;
    thread_get_state(th, ARM_THREAD_STATE64, (thread_state_t)&ts, &n);
    arm_thread_state64_set_pc_fptr(ts, land);
    if ((kr = thread_set_state(th, ARM_THREAD_STATE64, (thread_state_t)&ts, ARM_THREAD_STATE64_COUNT))) return bad("setting a pc", kr, 0);
    thread_resume(th);
    write(p[1], "x", 1);
    pthread_join(t, NULL);
    if (!landed) return bad("the thread where it was sent", landed, 1);
    printf("threadstate ok\n");
    return 0;
}
