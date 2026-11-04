// Threads, a mutex and a condition variable: four workers count to a
// total under the mutex, the last one signals the main thread.

#include <pthread.h>
#include <stdio.h>

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t done = PTHREAD_COND_INITIALIZER;
static int count, finished;

static void *work(void *arg) {
    for (int i = 0; i < 1000; i++) {
        pthread_mutex_lock(&lock);
        count++;
        pthread_mutex_unlock(&lock);
    }
    pthread_mutex_lock(&lock);
    if (++finished == 4) {
        pthread_cond_signal(&done);
    }
    pthread_mutex_unlock(&lock);
    return arg;
}

int main(void) {
    pthread_t t[4];
    for (long i = 0; i < 4; i++) {
        if (pthread_create(&t[i], NULL, work, (void *)i) != 0) {
            return 1;
        }
    }
    pthread_mutex_lock(&lock);
    while (finished < 4) {
        pthread_cond_wait(&done, &lock);
    }
    pthread_mutex_unlock(&lock);
    for (long i = 0; i < 4; i++) {
        void *r;
        pthread_join(t[i], &r);
        if ((long)r != i) {
            return 2;
        }
    }
    printf("pthread %d\n", count);
    return count == 4000 ? 0 : 3;
}
