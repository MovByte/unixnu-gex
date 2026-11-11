// thread_policy_set and thread_policy_get by thread_policy.c on embedded:
// timesharing until set fixed (timeshare TRUE alone keeps it); the realtime time constraints validated
// (50 us to 50 ms of computation, no more than the constraint, raised to
// half of it), their defaults (a 10 ms quantum) reported with get_default
// set when the thread is not realtime, and a priority only
// BASEPRI_RTQUEUES; precedence; affinity refused (no affinity sets); the
// latency QoS tier validated and kept; the QoS policy not settable, and
// stripped when another policy is set; the policy state root's only; and a
// workqueue thread's parameters static (unchanged by a set).

#include <dispatch/dispatch.h>
#include <errno.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <mach/thread_policy.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

// The private flavors (thread_policy_private.h).
#define THREAD_POLICY_STATE 6
#define THREAD_QOS_POLICY 9
#define THREAD_TIME_CONSTRAINT_WITH_PRIORITY_POLICY 10

static int bad(const char *what, long got, long want) {
    printf("threadpolicy: %s: %#lx, want %#lx\n", what, got, want);
    return 1;
}

static uint32_t abs_us(uint64_t us) {
    mach_timebase_info_data_t tb;
    mach_timebase_info(&tb);
    return (uint32_t)(us * 1000 * tb.denom / tb.numer);
}

static thread_act_t wq_thread;

int main(void) {
    thread_act_t me = mach_thread_self();
    kern_return_t kr;
    integer_t w[16];
    mach_msg_type_number_t cnt;
    boolean_t def;

    cnt = 1; def = FALSE;
    if ((kr = thread_policy_get(me, THREAD_EXTENDED_POLICY, w, &cnt, &def)) || w[0] != 1 || def) return bad("timesharing", kr ? kr : w[0], 1);
    // The QoS policy: read, not settable, and gone once another policy is
    // set (and a thread with none may not take one again, EPERM).
    pthread_set_qos_class_self_np(QOS_CLASS_UTILITY, -3);
    cnt = 2; def = FALSE;
    if ((kr = thread_policy_get(me, THREAD_QOS_POLICY, w, &cnt, &def)) || w[0] != 3 || w[1] != -3) return bad("the QoS policy", kr ? kr : w[0], 3);
    w[0] = 4; w[1] = 0;
    if ((kr = thread_policy_set(me, THREAD_QOS_POLICY, w, 2)) != KERN_INVALID_ARGUMENT) return bad("setting the QoS policy", kr, KERN_INVALID_ARGUMENT);

    w[0] = 0;
    if ((kr = thread_policy_set(me, THREAD_EXTENDED_POLICY, w, 1))) return bad("fixed priority", kr, 0);
    cnt = 2; def = FALSE;
    if ((kr = thread_policy_get(me, THREAD_QOS_POLICY, w, &cnt, &def)) || w[0] != 0) return bad("the QoS policy after another", kr ? kr : w[0], 0);
    if (pthread_set_qos_class_self_np(QOS_CLASS_UTILITY, 0) != EPERM) return bad("a QoS once opted out", 0, EPERM);
    cnt = 1; def = FALSE;
    if ((kr = thread_policy_get(me, THREAD_EXTENDED_POLICY, w, &cnt, &def)) || w[0] != 0) return bad("fixed priority, read", kr ? kr : w[0], 0);
    // Timesharing is TRUE itself: any other true value asks for a fixed
    // priority.
    w[0] = 1;
    cnt = 1; def = FALSE;
    if ((kr = thread_policy_set(me, THREAD_EXTENDED_POLICY, w, 1)) || (kr = thread_policy_get(me, THREAD_EXTENDED_POLICY, w, &cnt, &def)) || w[0] != 1) return bad("timesharing again", kr ? kr : w[0], 1);
    w[0] = 2;
    cnt = 1; def = FALSE;
    if ((kr = thread_policy_set(me, THREAD_EXTENDED_POLICY, w, 1)) || (kr = thread_policy_get(me, THREAD_EXTENDED_POLICY, w, &cnt, &def)) || w[0] != 0) return bad("timeshare 2", kr ? kr : w[0], 0);

    cnt = 4; def = FALSE;
    if ((kr = thread_policy_get(me, THREAD_TIME_CONSTRAINT_POLICY, w, &cnt, &def)) || !def || w[0] != 0 || (uint32_t)w[1] != abs_us(5000) || (uint32_t)w[2] != abs_us(10000) || w[3] != 1) return bad("the realtime defaults", kr ? kr : w[1], abs_us(5000));
    thread_time_constraint_policy_data_t tc = {0, abs_us(20), abs_us(4000), 1};
    if ((kr = thread_policy_set(me, THREAD_TIME_CONSTRAINT_POLICY, (thread_policy_t)&tc, 4)) != KERN_INVALID_ARGUMENT) return bad("too little computation", kr, KERN_INVALID_ARGUMENT);
    tc.computation = abs_us(1000);
    if ((kr = thread_policy_set(me, THREAD_TIME_CONSTRAINT_POLICY, (thread_policy_t)&tc, 4))) return bad("realtime", kr, 0);
    cnt = 4; def = FALSE;
    if ((kr = thread_policy_get(me, THREAD_TIME_CONSTRAINT_POLICY, w, &cnt, &def)) || def || (uint32_t)w[1] != abs_us(2000) || (uint32_t)w[2] != abs_us(4000)) return bad("realtime, read (computation raised to half)", kr ? kr : w[1], abs_us(2000));
    cnt = 1; def = FALSE;
    if ((kr = thread_policy_get(me, THREAD_EXTENDED_POLICY, w, &cnt, &def)) || !def || w[0] != 1) return bad("timesharing while realtime", kr ? kr : def, 1);
    integer_t tcwp[5] = {0, (integer_t)abs_us(1000), (integer_t)abs_us(4000), 1, 98};
    if ((kr = thread_policy_set(me, THREAD_TIME_CONSTRAINT_WITH_PRIORITY_POLICY, tcwp, 5)) != KERN_INVALID_ARGUMENT) return bad("a realtime priority", kr, KERN_INVALID_ARGUMENT);

    w[0] = 5;
    if ((kr = thread_policy_set(me, THREAD_PRECEDENCE_POLICY, w, 1))) return bad("precedence", kr, 0);
    cnt = 1; def = FALSE;
    if ((kr = thread_policy_get(me, THREAD_PRECEDENCE_POLICY, w, &cnt, &def)) || w[0] != 5) return bad("precedence, read", kr ? kr : w[0], 5);

    if ((kr = thread_policy_set(me, THREAD_AFFINITY_POLICY, w, 1)) != KERN_INVALID_POLICY) return bad("setting affinity", kr, KERN_INVALID_POLICY);
    cnt = 1; def = FALSE;
    if ((kr = thread_policy_get(me, THREAD_AFFINITY_POLICY, w, &cnt, &def)) != KERN_NOT_SUPPORTED) return bad("affinity", kr, KERN_NOT_SUPPORTED);

    w[0] = LATENCY_QOS_TIER_2;
    if ((kr = thread_policy_set(me, THREAD_LATENCY_QOS_POLICY, w, 1))) return bad("a latency tier", kr, 0);
    cnt = 1; def = FALSE;
    if ((kr = thread_policy_get(me, THREAD_LATENCY_QOS_POLICY, w, &cnt, &def)) || w[0] != LATENCY_QOS_TIER_2) return bad("the latency tier", kr ? kr : w[0], LATENCY_QOS_TIER_2);
    w[0] = 0x1234;
    if ((kr = thread_policy_set(me, THREAD_LATENCY_QOS_POLICY, w, 1)) != KERN_INVALID_ARGUMENT) return bad("an invalid tier", kr, KERN_INVALID_ARGUMENT);

    cnt = 16; def = FALSE;
    kr = thread_policy_get(me, THREAD_POLICY_STATE, w, &cnt, &def);
    if (getuid() != 0 && kr != KERN_PROTECTION_FAILURE) return bad("the policy state", kr, KERN_PROTECTION_FAILURE);

    // A workqueue thread's.
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
        // KERN_POLICY_STATIC, which libsyscall's wrapper answers as
        // success without clearing the thread's QoS: nothing changes.
        wq_thread = mach_thread_self();
        integer_t v = 0, got = 0;
        mach_msg_type_number_t n = 1;
        boolean_t d = FALSE;
        if (thread_policy_set(wq_thread, THREAD_EXTENDED_POLICY, &v, 1) || thread_policy_get(wq_thread, THREAD_EXTENDED_POLICY, &got, &n, &d) || got != 1 || qos_class_self() == QOS_CLASS_UNSPECIFIED) wq_thread = 0;
        dispatch_semaphore_signal(done);
    });
    dispatch_semaphore_wait(done, DISPATCH_TIME_FOREVER);
    if (!wq_thread) return bad("a workqueue thread's", 0, KERN_POLICY_STATIC);
    printf("threadpolicy ok\n");
    return 0;
}
