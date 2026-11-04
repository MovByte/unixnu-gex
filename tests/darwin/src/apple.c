// The apple[] strings by exec_add_apple_strings, in its order:
// executable_path, pfz, stack_guard, malloc_entropy, ptr_munge, main_stack,
// executable_file, dyld_file, executable_cdhash, executable_boothash and
// th_port. libSystem clears the secrets once it has read them (pfz,
// stack_guard and malloc_entropy whole; the values of ptr_munge, main_stack
// and th_port), so those are checked through what took them: the stack
// guard's embedded NUL, the main thread's stack, its port. The rest by the
// files' fsid and inode and the signature's CodeDirectory digest.

#include <CommonCrypto/CommonDigest.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach/mach.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/sysctl.h>

static int bad(const char *what, unsigned long long v) {
    printf("apple: %s (%llx)\n", what, v);
    return 1;
}

static const char *val(const char **apple, const char *key) {
    size_t n = strlen(key);
    for (int i = 0; apple[i]; i++)
        if (!strncmp(apple[i], key, n) && apple[i][n] == '=') return apple[i] + n + 1;
    return NULL;
}

static uint32_t be32(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

// The best CodeDirectory's SHA-256, as hex: this program's own signature,
// from its image in memory.
static int cdhash_hex(char out[41]) {
    const struct mach_header_64 *mh = (const void *)_dyld_get_image_header(0);
    const uint8_t *lc = (const uint8_t *)(mh + 1);
    const struct linkedit_data_command *sig = NULL;
    const struct segment_command_64 *linkedit = NULL, *text = NULL;
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *c = (const void *)lc;
        if (c->cmd == LC_CODE_SIGNATURE) sig = (const void *)c;
        if (c->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *s = (const void *)c;
            if (!strcmp(s->segname, "__LINKEDIT")) linkedit = s;
            if (!strcmp(s->segname, "__TEXT")) text = s;
        }
        lc += c->cmdsize;
    }
    if (!sig || !linkedit || !text) return -1;
    intptr_t slide = (intptr_t)mh - (intptr_t)text->vmaddr;
    const uint8_t *blob = (const uint8_t *)(linkedit->vmaddr + slide + sig->dataoff - linkedit->fileoff);
    uint32_t count = be32(blob + 8);
    for (uint32_t i = 0; i < count; i++) {
        if (be32(blob + 12 + 8 * i) != 0) continue;
        const uint8_t *cd = blob + be32(blob + 16 + 8 * i);
        if (cd[37] != 2) return -2;
        uint8_t d[CC_SHA256_DIGEST_LENGTH];
        CC_SHA256(cd, be32(cd + 4), d);
        for (int j = 0; j < 20; j++) sprintf(out + 2 * j, "%02x", d[j]);
        return 0;
    }
    return -3;
}

extern long __stack_chk_guard[8];

int main(int argc, const char **argv, const char **envp, const char **apple) {
    (void)argc;
    (void)envp;
    const char *v;
    // The shape: every entry where exec put it, the cleared ones empty.
    const char *want[] = {"executable_path=", "", "", "", "ptr_munge=", "main_stack=", "executable_file=", "dyld_file=", "executable_cdhash=", "executable_boothash=", "th_port="};
    for (int i = 0; i < 11; i++) {
        if (!apple[i]) return bad("apple[] ends early", i);
        size_t n = strlen(want[i]);
        if (n ? strncmp(apple[i], want[i], n) : apple[i][0] != 0) return bad(want[i][0] ? want[i] : "a cleared string", i);
    }
    if (strcmp(apple[4], "ptr_munge=") || strcmp(apple[5], "main_stack=") || strcmp(apple[10], "th_port=")) return bad("libSystem's clearing", 0);
    if (apple[11]) return bad("an apple[] string past th_port", 11);

    // stack_guard's first value keeps a NUL in its second byte.
    if (!__stack_chk_guard[0] || ((__stack_chk_guard[0] >> 8) & 0xff) != 0) return bad("stack_guard's embedded NUL", __stack_chk_guard[0]);

    // main_stack: libpthread's main thread starts at p->user_stack, within
    // the stack limit.
    unsigned long long top = 0;
    size_t tn = sizeof top;
    if (sysctlbyname("kern.usrstack64", &top, &tn, NULL, 0)) return bad("kern.usrstack64", 0);
    struct rlimit rl;
    getrlimit(RLIMIT_STACK, &rl);
    if ((unsigned long long)(uintptr_t)pthread_get_stackaddr_np(pthread_self()) != top) return bad("the main thread's stack address", (uintptr_t)pthread_get_stackaddr_np(pthread_self()));
    uintptr_t here = (uintptr_t)&v;
    if (here >= top || here < top - rl.rlim_cur) return bad("a local inside the stack", here);
    if ((uintptr_t)argv >= top || (uintptr_t)argv < top - rl.rlim_cur) return bad("argv on the stack", (uintptr_t)argv);

    // The files by fsid (the device, the filesystem type above it) and inode.
    struct stat st;
    unsigned long long fsid, ino;
    char path[1024];
    uint32_t n = sizeof path;
    if (_NSGetExecutablePath(path, &n) || stat(path, &st)) return bad("the program's own stat", 0);
    if (!(v = val(apple, "executable_file")) || sscanf(v, "%llx,%llx", &fsid, &ino) != 2 || (uint32_t)fsid != (uint32_t)st.st_dev || ino != st.st_ino || fsid >> 32 != 0x1a) return bad("executable_file", fsid);
    if (stat("/usr/lib/dyld", &st)) return bad("dyld's stat", 0);
    if (!(v = val(apple, "dyld_file")) || sscanf(v, "%llx,%llx", &fsid, &ino) != 2 || (uint32_t)fsid != (uint32_t)st.st_dev || ino != st.st_ino) return bad("dyld_file", ino);

    char cd[41];
    int r = cdhash_hex(cd);
    if (r) return bad("this program's CodeDirectory", r);
    if (!(v = val(apple, "executable_cdhash")) || strcmp(v, cd)) return bad("executable_cdhash", 0);
    if (!(v = val(apple, "executable_boothash")) || strlen(v) != 40) return bad("executable_boothash", 0);

    // th_port named the main thread: libpthread's port for it is the one
    // mach_thread_self names.
    mach_port_t self = mach_thread_self();
    if (pthread_mach_thread_np(pthread_self()) != self) return bad("libpthread's main thread port", pthread_mach_thread_np(pthread_self()));
    mach_port_deallocate(mach_task_self(), self);
    printf("apple ok\n");
    return 0;
}
