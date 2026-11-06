// task_threads gives a task's threads in the order they were made, as
// ports of the flavor of the task port it was asked by (the task's own
// control port: the threads' self ports, its first mach_thread_self);
// thread_get_special_port gives a thread's inspect port, the same port
// task_threads gives by the inspect port, and refuses with
// KERN_INVALID_CAPABILITY what an inspect port may not ask for.

#include <mach/mach.h>
#include <pthread.h>
#include <stdio.h>

static int bad(const char *what, long got, long want) {
    printf("taskthreads: %s: %#lx, want %#lx\n", what, got, want);
    return 1;
}

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static int started, done;

static void *idle(void *arg) {
    (void)arg;
    pthread_mutex_lock(&lock);
    started++;
    pthread_cond_broadcast(&cond);
    while (!done) pthread_cond_wait(&cond, &lock);
    pthread_mutex_unlock(&lock);
    return NULL;
}

int main(void) {
    mach_port_t self = mach_task_self(), me = mach_thread_self(), insp = MACH_PORT_NULL, p = MACH_PORT_NULL;
    pthread_t t[2];
    for (int i = 0; i < 2; i++) pthread_create(&t[i], NULL, idle, NULL);
    pthread_mutex_lock(&lock);
    while (started < 2) pthread_cond_wait(&cond, &lock);
    pthread_mutex_unlock(&lock);

    thread_act_array_t a;
    mach_msg_type_number_t n;
    kern_return_t kr;
    if ((kr = task_threads(self, &a, &n)) || n != 3) return bad("task_threads", kr ? kr : (long)n, 3);
    if (a[0] != me) return bad("its first thread", a[0], me);
    for (unsigned i = 0; i < n; i++)
        for (unsigned j = i + 1; j < n; j++)
            if (!MACH_PORT_VALID(a[i]) || a[i] == a[j]) return bad("its threads' ports", a[i], a[j]);

    if ((kr = task_get_special_port(self, TASK_INSPECT_PORT, &insp))) return bad("the inspect port", kr, 0);
    thread_act_array_t ia;
    mach_msg_type_number_t in;
    if ((kr = task_threads(insp, &ia, &in)) || in != 3) return bad("task_threads by the inspect port", kr ? kr : (long)in, 3);
    for (unsigned i = 0; i < in; i++)
        if (!MACH_PORT_VALID(ia[i]) || ia[i] == a[i]) return bad("an inspect thread port", ia[i], a[i]);
    if ((kr = thread_get_special_port(me, THREAD_INSPECT_PORT, &p)) || p != ia[0]) return bad("the thread's inspect port", kr ? kr : (long)p, ia[0]);
    if ((kr = thread_get_special_port(ia[0], THREAD_INSPECT_PORT, &p)) || p != ia[0]) return bad("its own inspect port", kr ? kr : (long)p, ia[0]);
    if ((kr = thread_get_special_port(ia[1], THREAD_READ_PORT, &p)) != KERN_INVALID_CAPABILITY) return bad("a read port from it", kr, KERN_INVALID_CAPABILITY);
    if ((kr = thread_get_special_port(ia[1], 99, &p)) != KERN_INVALID_CAPABILITY) return bad("port 99 from it", kr, KERN_INVALID_CAPABILITY);
    if ((kr = thread_get_special_port(me, 99, &p)) != KERN_INVALID_ARGUMENT) return bad("port 99", kr, KERN_INVALID_ARGUMENT);

    pthread_mutex_lock(&lock);
    done = 1;
    pthread_cond_broadcast(&cond);
    pthread_mutex_unlock(&lock);
    for (int i = 0; i < 2; i++) pthread_join(t[i], NULL);
    printf("taskthreads ok\n");
    return 0;
}
