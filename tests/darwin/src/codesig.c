// fcntl's code signature calls on this program's own file: the end of the
// range its signature covers (the CodeDirectory's code limit, to the end
// of its last hashed page), the same answer when added again, library
// validation allowed, and a signature that is not one refused (EBADEXEC).

#include <errno.h>
#include <fcntl.h>
#include <libkern/OSByteOrder.h>
#include <mach-o/dyld.h>
#include <mach-o/getsect.h>
#include <mach-o/loader.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int bad(const char *what, long long v) {
    printf("codesig: %s (%lld)\n", what, v);
    return 1;
}

int main(void) {
    // The signature, as mapped with __LINKEDIT, put in a file at the
    // offset the program's own file has it (the program's file is the
    // host's, not one this system can open).
    const struct mach_header_64 *mh = (const struct mach_header_64 *)_dyld_get_image_header(0);
    intptr_t slide = _dyld_get_image_vmaddr_slide(0);
    const struct linkedit_data_command *sig = NULL;
    const struct segment_command_64 *le = NULL;
    const char *lc = (const char *)(mh + 1);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *c = (const struct load_command *)lc;
        if (c->cmd == LC_CODE_SIGNATURE) sig = (const struct linkedit_data_command *)c;
        if (c->cmd == LC_SEGMENT_64 && !strcmp(((const struct segment_command_64 *)c)->segname, "__LINKEDIT")) le = (const struct segment_command_64 *)c;
        lc += c->cmdsize;
    }
    if (!sig || !le) return bad("no LC_CODE_SIGNATURE", 0);
    const unsigned char *blob = (const unsigned char *)(slide + le->vmaddr + (sig->dataoff - le->fileoff));
    int fd = open("/tmp/gex-codesig", O_RDWR | O_CREAT | O_TRUNC, 0644);
    pwrite(fd, blob, sig->datasize, sig->dataoff);
    // The superblob's CodeDirectory (slot 0).
    uint32_t count = OSSwapBigToHostInt32(*(uint32_t *)(blob + 8)), cd_off = 0;
    for (uint32_t i = 0; i < count; i++) {
        if (OSSwapBigToHostInt32(*(uint32_t *)(blob + 12 + 8 * i)) == 0) cd_off = OSSwapBigToHostInt32(*(uint32_t *)(blob + 16 + 8 * i));
    }
    uint64_t limit = OSSwapBigToHostInt32(*(uint32_t *)(blob + cd_off + 32));
    uint64_t mask = (1ull << blob[cd_off + 39]) - 1;
    uint64_t want = (limit + mask) & ~mask;

    fsignatures_t fs = {.fs_file_start = 0, .fs_blob_start = (void *)(uintptr_t)sig->dataoff, .fs_blob_size = sig->datasize};
    if (fcntl(fd, F_ADDFILESIGS_RETURN, &fs)) return bad("F_ADDFILESIGS_RETURN", errno);
    if ((uint64_t)fs.fs_file_start != want) return bad("the signed range's end", fs.fs_file_start);
    fsignatures_t again = {.fs_file_start = 0, .fs_blob_start = (void *)(uintptr_t)sig->dataoff, .fs_blob_size = sig->datasize};
    if (fcntl(fd, F_ADDFILESIGS_RETURN, &again) || (uint64_t)again.fs_file_start != want) return bad("the signature added again", again.fs_file_start);
    fchecklv_t lv = {.lv_file_start = 0, .lv_error_message_size = 0, .lv_error_message = NULL};
    if (fcntl(fd, F_CHECK_LV, &lv)) return bad("F_CHECK_LV", errno);
    // Detached and corrupt: EBADEXEC.
    unsigned char junk[64] = {0xfa, 0xde, 0x0c, 0xc0, 0, 0, 0, 64, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 20};
    fsignatures_t det = {.fs_file_start = 4096 * 1024, .fs_blob_start = junk, .fs_blob_size = sizeof junk};
    if (fcntl(fd, F_ADDSIGS, &det) != -1 || errno != EBADEXEC) return bad("a corrupt signature", errno);
    close(fd);
    unlink("/tmp/gex-codesig");
    printf("codesig ok\n");
    return 0;
}
