// msync and its Mach routine: a shared file mapping's stores reach the file
// for another process to read, an invalidate brings the file back, a private
// mapping's stores stay its own, and what a bad request or a hole in the
// range gets. Also mach_vm_machine_attribute, which only MATTR_CACHE reaches
// on this architecture, and mach_vm_behavior_set of behaviors that act on
// the memory at once.

#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#define K ((size_t)0x4000)

// <mach/mach_vm.h> is refused on this platform; these are in libsystem.
extern kern_return_t mach_vm_msync(vm_map_t, mach_vm_address_t, mach_vm_size_t, vm_sync_t);
extern kern_return_t mach_vm_behavior_set(vm_map_t, mach_vm_address_t, mach_vm_size_t, vm_behavior_t);
extern kern_return_t mach_vm_machine_attribute(vm_map_t, mach_vm_address_t, mach_vm_size_t, vm_machine_attribute_t, vm_machine_attribute_val_t *);
extern char **environ;

static int bad(const char *what, long got, long want) {
    printf("msync: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

// In another process, which sees only what reached the file.
static int file_holds(const char *self, const char *path, const char *text) {
    char *argv[] = {(char *)self, (char *)path, (char *)text, NULL};
    pid_t pid;
    if (posix_spawn(&pid, self, NULL, NULL, argv, environ) != 0) return -1;
    int st = 0;
    if (waitpid(pid, &st, 0) != pid) return -1;
    return WIFEXITED(st) && WEXITSTATUS(st) == 0;
}

static int check_file(const char *path, const char *text) {
    int fd = open(path, O_RDONLY);
    char buf[32] = {0};
    return fd >= 0 && pread(fd, buf, strlen(text), 0) == (ssize_t)strlen(text) && memcmp(buf, text, strlen(text)) == 0 ? 0 : 1;
}

int main(int argc, char **argv) {
    if (argc == 3) return check_file(argv[1], argv[2]);

    char path[] = "/tmp/msync.XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0 || ftruncate(fd, 3 * K) != 0) return bad("the file", errno, 0);
    char *p = mmap(NULL, 3 * K, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) return bad("mmap", errno, 0);

    // A store reaches the file for a process with no mapping of it.
    memcpy(p, "first", 5);
    if (msync(p, K, MS_SYNC) != 0) return bad("MS_SYNC", errno, 0);
    if (file_holds(argv[0], path, "first") != 1) return bad("the file after MS_SYNC", 0, 1);
    memcpy(p, "again", 5);
    if (msync(p, K, MS_ASYNC) != 0) return bad("MS_ASYNC", errno, 0);
    if (file_holds(argv[0], path, "again") != 1) return bad("the file after MS_ASYNC", 0, 1);

    // What is wrong with the request.
    errno = 0;
    if (msync(p + 1, K, MS_SYNC) != -1 || errno != EINVAL) return bad("an unaligned address", errno, EINVAL);
    errno = 0;
    if (msync(p, 0, MS_SYNC) != -1 || errno != EINVAL) return bad("no length", errno, EINVAL);
    errno = 0;
    if (msync(p, K, MS_SYNC | MS_ASYNC) != -1 || errno != EINVAL) return bad("sync and async at once", errno, EINVAL);
    errno = 0;
    if (msync((void *)(uintptr_t)-K, 2 * K, MS_SYNC) != -1 || errno != EINVAL) return bad("a range past the top", errno, EINVAL);

    // A hole in the range: msync complains, and the Mach call only if asked.
    mach_vm_address_t a = (mach_vm_address_t)p;
    if (munmap(p + K, K) != 0) return bad("munmap", errno, 0);
    errno = 0;
    if (msync(p, 3 * K, MS_SYNC) != -1 || errno != ENOMEM) return bad("msync over a hole", errno, ENOMEM);
    kern_return_t kr = mach_vm_msync(mach_task_self(), a, 3 * K, VM_SYNC_SYNCHRONOUS);
    if (kr != KERN_SUCCESS) return bad("mach_vm_msync over a hole", kr, KERN_SUCCESS);
    kr = mach_vm_msync(mach_task_self(), a, 3 * K, VM_SYNC_SYNCHRONOUS | VM_SYNC_CONTIGUOUS);
    if (kr != KERN_INVALID_ADDRESS) return bad("mach_vm_msync contiguous over a hole", kr, KERN_INVALID_ADDRESS);
    kr = mach_vm_msync(mach_task_self(), a, K, VM_SYNC_SYNCHRONOUS | VM_SYNC_ASYNCHRONOUS);
    if (kr != KERN_INVALID_ARGUMENT) return bad("mach_vm_msync sync and async", kr, KERN_INVALID_ARGUMENT);
    if ((kr = mach_vm_msync(mach_task_self(), a, 0, VM_SYNC_SYNCHRONOUS)) != KERN_SUCCESS) return bad("mach_vm_msync of nothing", kr, KERN_SUCCESS);

    // The Mach call writes back, and only when asked to.
    memcpy(p, "third", 5);
    if ((kr = mach_vm_msync(mach_task_self(), a, K, VM_SYNC_SYNCHRONOUS)) != KERN_SUCCESS) return bad("mach_vm_msync", kr, KERN_SUCCESS);
    if (file_holds(argv[0], path, "third") != 1) return bad("the file after mach_vm_msync", 0, 1);

    // Invalidating with no write-back drops the stores: the file comes back.
    memcpy(p, "fourt", 5);
    if ((kr = mach_vm_msync(mach_task_self(), a, K, VM_SYNC_INVALIDATE)) != KERN_SUCCESS) return bad("VM_SYNC_INVALIDATE", kr, KERN_SUCCESS);
    if (memcmp(p, "third", 5) != 0) return bad("the mapping after an invalidate", p[0], 't');
    if (file_holds(argv[0], path, "third") != 1) return bad("the file after an invalidate", 0, 1);

    // With MS_INVALIDATE the stores go to the file first.
    memcpy(p, "fifth", 5);
    if (msync(p, K, MS_SYNC | MS_INVALIDATE) != 0) return bad("MS_SYNC | MS_INVALIDATE", errno, 0);
    if (memcmp(p, "fifth", 5) != 0) return bad("the mapping after MS_INVALIDATE", p[0], 'f');
    if (file_holds(argv[0], path, "fifth") != 1) return bad("the file after MS_INVALIDATE", 0, 1);

    // A private mapping's stores are never the file's.
    char *q = mmap(NULL, K, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (q == MAP_FAILED) return bad("a private mapping", errno, 0);
    memcpy(q, "mine!", 5);
    if (msync(q, K, MS_SYNC) != 0) return bad("MS_SYNC of a private mapping", errno, 0);
    if (memcmp(q, "mine!", 5) != 0) return bad("the private mapping's stores", q[0], 'm');
    if (file_holds(argv[0], path, "fifth") != 1) return bad("the file after a private msync", 0, 1);

    // Anonymous memory: nothing to write back; pages can be let go.
    char *r = mmap(NULL, 2 * K, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (r == MAP_FAILED) return bad("anonymous memory", errno, 0);
    memcpy(r, "data", 4);
    if (msync(r, 2 * K, MS_SYNC) != 0) return bad("MS_SYNC of anonymous memory", errno, 0);
    if (memcmp(r, "data", 4) != 0) return bad("anonymous memory after MS_SYNC", r[0], 'd');
    if (msync(r, 2 * K, MS_DEACTIVATE) != 0) return bad("MS_DEACTIVATE", errno, 0);
    if (memcmp(r, "data", 4) != 0) return bad("anonymous memory after MS_DEACTIVATE", r[0], 'd');
    if (msync(r, 2 * K, MS_KILLPAGES) != 0) return bad("MS_KILLPAGES", errno, 0);
    if (munmap(r + K, K) != 0) return bad("munmap", errno, 0);
    errno = 0;
    if (msync(r, 2 * K, MS_KILLPAGES) != -1 || errno != ENOMEM) return bad("MS_KILLPAGES over a hole", errno, ENOMEM);

    // The behaviors a message can ask for that act on the memory: what they
    // leave of it is the system's to say, except that these keep it.
    char *s = mmap(NULL, 2 * K, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (s == MAP_FAILED) return bad("anonymous memory", errno, 0);
    memset(s, 7, 2 * K);
    kr = mach_vm_behavior_set(mach_task_self(), (mach_vm_address_t)s, 2 * K, VM_BEHAVIOR_WILLNEED);
    if (kr != KERN_SUCCESS || s[0] != 7) return bad("VM_BEHAVIOR_WILLNEED", kr, KERN_SUCCESS);
    kr = mach_vm_behavior_set(mach_task_self(), (mach_vm_address_t)s, 2 * K, VM_BEHAVIOR_DONTNEED);
    if (kr != KERN_SUCCESS || s[K] != 7) return bad("VM_BEHAVIOR_DONTNEED", kr, KERN_SUCCESS);
    kr = mach_vm_behavior_set(mach_task_self(), (mach_vm_address_t)s, 2 * K, VM_BEHAVIOR_REUSABLE);
    if (kr != KERN_SUCCESS) return bad("VM_BEHAVIOR_REUSABLE", kr, KERN_SUCCESS);
    kr = mach_vm_behavior_set(mach_task_self(), (mach_vm_address_t)s, 2 * K, VM_BEHAVIOR_REUSE);
    if (kr != KERN_SUCCESS) return bad("VM_BEHAVIOR_REUSE", kr, KERN_SUCCESS);
    kr = mach_vm_behavior_set(mach_task_self(), (mach_vm_address_t)s, 2 * K, VM_BEHAVIOR_FREE);
    if (kr != KERN_SUCCESS) return bad("VM_BEHAVIOR_FREE", kr, KERN_SUCCESS);
    kr = mach_vm_behavior_set(mach_task_self(), (mach_vm_address_t)s, 2 * K, 999);
    if (kr != KERN_INVALID_ARGUMENT) return bad("a behavior that does not exist", kr, KERN_INVALID_ARGUMENT);

    // Only the cache attribute has an implementation here.
    vm_machine_attribute_val_t v = MATTR_VAL_CACHE_FLUSH;
    kr = mach_vm_machine_attribute(mach_task_self(), (mach_vm_address_t)s, K, MATTR_CACHE, &v);
    if (kr != KERN_SUCCESS || v != MATTR_VAL_CACHE_FLUSH) return bad("MATTR_CACHE", kr, KERN_SUCCESS);
    kr = mach_vm_machine_attribute(mach_task_self(), (mach_vm_address_t)s, K, MATTR_MIGRATE, &v);
    if (kr != KERN_INVALID_ADDRESS) return bad("MATTR_MIGRATE", kr, KERN_INVALID_ADDRESS);
    kr = mach_vm_machine_attribute(mach_task_self(), 0x1000, K, MATTR_CACHE, &v);
    if (kr != KERN_INVALID_ADDRESS) return bad("below the map's floor", kr, KERN_INVALID_ADDRESS);
    munmap(s + K, K);
    kr = mach_vm_machine_attribute(mach_task_self(), (mach_vm_address_t)s, 2 * K, MATTR_CACHE, &v);
    if (kr != KERN_FAILURE) return bad("MATTR_CACHE over a hole", kr, KERN_FAILURE);
    if ((kr = mach_vm_machine_attribute(mach_task_self(), (mach_vm_address_t)s, 0, MATTR_MIGRATE, &v)) != KERN_SUCCESS) return bad("no size", kr, KERN_SUCCESS);

    unlink(path);
    printf("msync ok\n");
    return 0;
}
