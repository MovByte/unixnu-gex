// shared_region_check_np and shared_region_map_and_slide_2_np as
// bsd/vm/vm_unix.c and osfmk/vm/vm_shared_region.c (xnu-10063.141.1) answer
// them for a task whose shared region launchd's dyld has mapped at boot:
//
// - check_np gives the region's first mapping, the cache's header;
// - map_and_slide_2_np with no files or no mappings does nothing; with more
//   files than _SR_FILE_MAPPINGS_MAX_FILES, or files that name more
//   mappings than it was given, it fails with the kern_return_t itself
//   (KERN_FAILURE, 5, read as EIO);
// - shared_region_map_and_slide_setup refuses a dyld-memory file (fd -1)
//   with more than one mapping or an unaligned one, a descriptor not open
//   (EBADF), one not readable (EPERM), what is not a regular file, and a
//   file root does not own (EPERM): one the caller made, run as another
//   user.

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int syscall(int, ...);

#define SYS_shared_region_check_np 294
#define SYS_shared_region_map_and_slide_2_np 536

struct shared_file_np {
    int sf_fd;
    uint32_t sf_mappings_count;
    uint32_t sf_slide;
};

struct shared_file_mapping_slide_np {
    uint64_t sms_address;
    uint64_t sms_size;
    uint64_t sms_file_offset;
    uint64_t sms_slide_size;
    uint64_t sms_slide_start;
    int32_t sms_max_prot;
    int32_t sms_init_prot;
};

static int bad(const char *what, long got, long want) {
    printf("shregion: %s: %ld, want %ld\n", what, got, want);
    return 1;
}

static long map2(uint32_t nf, struct shared_file_np *f, uint32_t nm, struct shared_file_mapping_slide_np *m) {
    return syscall(SYS_shared_region_map_and_slide_2_np, nf, f, nm, m);
}

static int expect(const char *what, long r, int want) {
    if (r != -1 || errno != want) return bad(what, r == -1 ? errno : r, want);
    return 0;
}

int main(void) {
    uint64_t start = 0;
    if (syscall(SYS_shared_region_check_np, &start) != 0) return bad("check_np", errno, 0);
    if (memcmp((const void *)start, "dyld_v1 ", 8) != 0) return bad("the cache's header at the first mapping", 0, 1);

    struct shared_file_np f[2];
    struct shared_file_mapping_slide_np m[2];
    memset(m, 0, sizeof m);
    int fail = 0;

    // Nothing to map.
    if (map2(0, NULL, 0, NULL) != 0) fail |= bad("no files", errno, 0);
    f[0] = (struct shared_file_np){-1, 1, 0};
    if (map2(1, f, 0, NULL) != 0) fail |= bad("no mappings", errno, 0);

    // The kern_return_t as the error.
    fail |= expect("too many files", map2(257, f, 1, m), 5);
    f[0] = (struct shared_file_np){-1, 2, 0};
    fail |= expect("a file naming more mappings than given", map2(1, f, 1, m), 5);
    fail |= expect("files out of reach", map2(1, (void *)8, 1, m), EFAULT);

    // Setup's refusals.
    m[0] = (struct shared_file_mapping_slide_np){0x200000000, 0x4000, 0, 0, 0, 1, 1};
    m[1] = m[0];
    fail |= expect("dyld's memory in two mappings", map2(1, f, 2, m), EINVAL);
    f[0] = (struct shared_file_np){-1, 1, 0};
    m[0].sms_address += 0x1000;
    fail |= expect("dyld's memory unaligned", map2(1, f, 1, m), EINVAL);
    m[0].sms_address -= 0x1000;
    f[0] = (struct shared_file_np){99, 1, 0};
    fail |= expect("a descriptor not open", map2(1, f, 1, m), EBADF);
    int dir = open("/System", O_RDONLY);
    f[0].sf_fd = dir;
    fail |= expect("a directory", map2(1, f, 1, m), EINVAL);
    close(dir);
    int wr = open("/private/var/tmp/gex-darwin-shregion-w", O_WRONLY | O_CREAT | O_TRUNC, 0600);
    f[0].sf_fd = wr;
    fail |= expect("a descriptor not open for reading", map2(1, f, 1, m), EPERM);
    close(wr);
    unlink("/private/var/tmp/gex-darwin-shregion-w");
    if (geteuid() != 0) {
        int own = open("/private/var/tmp/gex-darwin-shregion-own", O_RDWR | O_CREAT | O_TRUNC, 0644);
        if (own < 0 || ftruncate(own, 0x4000) != 0) return bad("a file of one's own", errno, 0);
        f[0].sf_fd = own;
        fail |= expect("a file not root's", map2(1, f, 1, m), EPERM);
        close(own);
        unlink("/private/var/tmp/gex-darwin-shregion-own");
    }

    // Still mapped where it was.
    uint64_t again = 0;
    if (syscall(SYS_shared_region_check_np, &again) != 0 || again != start) fail |= bad("check_np after", (long)again, (long)start);
    if (fail) return 1;
    printf("shregion ok\n");
    return 0;
}
