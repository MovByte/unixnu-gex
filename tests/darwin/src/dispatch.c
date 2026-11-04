// libdispatch: work on the global queues joined with a group, a serial
// queue drained with dispatch_sync, dispatch_apply, a semaphore signalled
// from another queue, and dispatch_after on the main queue.

#include <dispatch/dispatch.h>
#include <stdio.h>
#include <stdlib.h>

static int total;

int main(void) {
    dispatch_queue_t serial = dispatch_queue_create("gex.serial", NULL);
    dispatch_group_t g = dispatch_group_create();
    for (int i = 1; i <= 10; i++) {
        dispatch_group_async(g, dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
            dispatch_sync(serial, ^{
                total += i;
            });
        });
    }
    dispatch_group_wait(g, DISPATCH_TIME_FOREVER);
    __block int squares = 0;
    dispatch_apply(8, dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^(size_t i) {
        __atomic_fetch_add(&squares, (int)(i * i), __ATOMIC_RELAXED);
    });
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        dispatch_semaphore_signal(sem);
    });
    dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_MSEC), dispatch_get_main_queue(), ^{
        printf("dispatch %d %d\n", total, squares);
        exit(total == 55 && squares == 140 ? 0 : 1);
    });
    dispatch_main();
}
