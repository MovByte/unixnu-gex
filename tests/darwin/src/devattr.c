// getattrlist on devfs vnodes: devfs_getattr's attributes and the
// defaults the VFS gives what it lacks. Its ids are 32-bit, its tag
// VT_DEVFS, a device's I/O size MAXPHYSIO; it keeps no creation time,
// encoding, child count or extended security (no UUIDs), so asking for
// those is EINVAL unless the reply may say what it returns (then they are
// left out), but for the encoding: one that does not ask is given UTF-8's.
// The root is hidden, has one link as getattrlist counts a directory's,
// and has no parent to name.

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/attr.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

// sys/vnode.h, which the iOS SDK leaves out: enum vtype's VCHR and enum
// vtagtype's VT_DEVFS.
#define VCHR 4
#define VT_DEVFS 18

static int bad(const char *what, long got, long want) {
    printf("devattr: %s: %ld, want %ld\n", what, got, want);
    fflush(stdout);
    return 1;
}

struct reply {
    uint32_t len;
    attribute_set_t ret;
    attrreference_t name;
    dev_t devid;
    fsid_t fsid;
    fsobj_type_t type;
    fsobj_tag_t tag;
    fsobj_id_t objid;
    fsobj_id_t parobjid;
    struct timespec mod;
    uid_t uid;
    gid_t gid;
    uint32_t mode;
    uint32_t flags;
    uint32_t access;
    uint64_t fileid;
    uint64_t parentid;
    uint32_t links;
    off_t total;
    off_t alloc;
    uint32_t iosize;
    dev_t devtype;
} __attribute__((packed));

int main(void) {
    struct statfs fs;
    struct stat null_st, dev_st;
    if (statfs("/dev", &fs) || stat("/dev/null", &null_st) || stat("/dev", &dev_st)) return bad("stat", errno, 0);

    struct attrlist al = {ATTR_BIT_MAP_COUNT, 0};
    al.commonattr = ATTR_CMN_RETURNED_ATTRS | ATTR_CMN_NAME | ATTR_CMN_DEVID | ATTR_CMN_FSID | ATTR_CMN_OBJTYPE | ATTR_CMN_OBJTAG | ATTR_CMN_OBJID |
                    ATTR_CMN_PAROBJID | ATTR_CMN_MODTIME | ATTR_CMN_OWNERID | ATTR_CMN_GRPID | ATTR_CMN_ACCESSMASK | ATTR_CMN_FLAGS |
                    ATTR_CMN_USERACCESS | ATTR_CMN_FILEID | ATTR_CMN_PARENTID;
    al.fileattr = ATTR_FILE_LINKCOUNT | ATTR_FILE_TOTALSIZE | ATTR_FILE_ALLOCSIZE | ATTR_FILE_IOBLOCKSIZE | ATTR_FILE_DEVTYPE;
    char buf[512];
    if (getattrlist("/dev/null", &al, buf, sizeof buf, 0)) return bad("getattrlist /dev/null", errno, 0);
    struct reply *r = (struct reply *)buf;
    if (r->ret.commonattr != al.commonattr || r->ret.fileattr != al.fileattr) return bad("the returned set", r->ret.commonattr, al.commonattr);
    if (strcmp((char *)&r->name + r->name.attr_dataoffset, "null")) return bad("the name", 0, 1);
    if (r->devid != (dev_t)fs.f_fsid.val[0] || r->fsid.val[0] != fs.f_fsid.val[0] || r->fsid.val[1] != 19) return bad("the device", r->devid, fs.f_fsid.val[0]);
    if (r->type != VCHR || r->tag != VT_DEVFS) return bad("the tag", r->tag, VT_DEVFS);
    if (r->objid.fid_objno != (uint32_t)null_st.st_ino || r->objid.fid_generation) return bad("the object id", r->objid.fid_objno, (long)null_st.st_ino);
    if (r->parobjid.fid_objno != (uint32_t)dev_st.st_ino || r->parentid != dev_st.st_ino) return bad("the parent", (long)r->parentid, (long)dev_st.st_ino);
    if (r->fileid != null_st.st_ino) return bad("the file id", (long)r->fileid, (long)null_st.st_ino);
    if (r->uid || r->gid || r->mode != (S_IFCHR | 0666) || r->flags) return bad("the owner and mode", r->mode, S_IFCHR | 0666);
    if (r->access != (R_OK | W_OK)) return bad("the access", r->access, R_OK | W_OK);
    if (r->links != 1 || r->total || r->alloc || r->iosize != 64 * 1024) return bad("the sizes", r->iosize, 64 * 1024);
    if (r->devtype != null_st.st_rdev) return bad("the device type", r->devtype, null_st.st_rdev);

    // What devfs keeps none of.
    struct attrlist none = {ATTR_BIT_MAP_COUNT, 0};
    none.commonattr = ATTR_CMN_CRTIME;
    if (getattrlist("/dev/null", &none, buf, sizeof buf, 0) != -1 || errno != EINVAL) return bad("a creation time", errno, EINVAL);
    none.commonattr = ATTR_CMN_RETURNED_ATTRS | ATTR_CMN_CRTIME | ATTR_CMN_SCRIPT | ATTR_CMN_UUID | ATTR_CMN_ADDEDTIME;
    if (getattrlist("/dev/null", &none, buf, sizeof buf, 0)) return bad("asking what is returned", errno, 0);
    // (the length is the request's, all it asked for)
    if (r->ret.commonattr != ATTR_CMN_RETURNED_ATTRS || r->len != 4 + sizeof(attribute_set_t) + 16 + 4 + 16 + 16) return bad("what is returned", r->len, 76);
    none.commonattr = ATTR_CMN_SCRIPT;
    if (getattrlist("/dev/null", &none, buf, sizeof buf, 0) || *(uint32_t *)(buf + 4) != 0x7e) return bad("the encoding", *(uint32_t *)(buf + 4), 0x7e);
    // A mount with no extended security has no UUIDs.
    none.commonattr = ATTR_CMN_UUID;
    if (getattrlist("/dev/null", &none, buf, sizeof buf, 0) != -1 || errno != EINVAL) return bad("the UUID", errno, EINVAL);

    // The root.
    struct attrlist rl = {ATTR_BIT_MAP_COUNT, 0};
    rl.commonattr = ATTR_CMN_RETURNED_ATTRS | ATTR_CMN_FLAGS | ATTR_CMN_PARENTID;
    rl.dirattr = ATTR_DIR_LINKCOUNT | ATTR_DIR_ENTRYCOUNT | ATTR_DIR_MOUNTSTATUS | ATTR_DIR_IOBLOCKSIZE;
    if (getattrlist("/dev", &rl, buf, sizeof buf, 0)) return bad("getattrlist /dev", errno, 0);
    attribute_set_t *ret = (attribute_set_t *)(buf + 4);
    if (ret->commonattr != (ATTR_CMN_RETURNED_ATTRS | ATTR_CMN_FLAGS)) return bad("the root's common attributes", ret->commonattr, ATTR_CMN_RETURNED_ATTRS | ATTR_CMN_FLAGS);
    if (ret->dirattr != (ATTR_DIR_LINKCOUNT | ATTR_DIR_MOUNTSTATUS | ATTR_DIR_IOBLOCKSIZE)) return bad("the root's directory attributes", ret->dirattr, 0);
    uint32_t *w = (uint32_t *)(buf + 4 + sizeof(attribute_set_t));
    if (w[0] != UF_HIDDEN || w[1] != 1 || !(w[2] & DIR_MNTSTATUS_MNTPOINT) || w[3] != 512) return bad("the root's values", w[0], UF_HIDDEN);
    // The volume: devfs_vfs_getattr's counts, capabilities and attribute
    // masks; no times, file count, name or UUID; the root's owner, mode
    // with its type, and flags; no encoding where what is returned is said.
    struct attrlist vl = {ATTR_BIT_MAP_COUNT, 0};
    vl.commonattr = ATTR_CMN_RETURNED_ATTRS | ATTR_CMN_SCRIPT | ATTR_CMN_MODTIME | ATTR_CMN_OWNERID | ATTR_CMN_ACCESSMASK | ATTR_CMN_FLAGS;
    vl.volattr = ATTR_VOL_INFO | ATTR_VOL_FSTYPE | ATTR_VOL_SIGNATURE | ATTR_VOL_SIZE | ATTR_VOL_OBJCOUNT | ATTR_VOL_FILECOUNT | ATTR_VOL_MAXOBJCOUNT |
                 ATTR_VOL_NAME | ATTR_VOL_MOUNTFLAGS | ATTR_VOL_CAPABILITIES | ATTR_VOL_UUID | ATTR_VOL_ATTRIBUTES | ATTR_VOL_FSSUBTYPE | ATTR_VOL_SPACEUSED;
    uint32_t v[128] = {0};
    if (getattrlist("/dev", &vl, v, sizeof v, 0)) return bad("the volume", errno, 0);
    if (v[1] != (ATTR_CMN_RETURNED_ATTRS | ATTR_CMN_OWNERID | ATTR_CMN_ACCESSMASK | ATTR_CMN_FLAGS)) return bad("the volume's common attributes", v[1], 0);
    uint32_t want_vol = vl.volattr & ~(ATTR_VOL_INFO | ATTR_VOL_FILECOUNT | ATTR_VOL_NAME | ATTR_VOL_UUID);
    if (v[2] != want_vol) return bad("the volume's attributes", v[2], want_vol);
    struct statfs now;
    statfs("/dev", &now);
    uint32_t *p = v + 6;
    // owner, mode, flags; type, signature; size and used (8 bytes each)
    if (p[0] != 0 || p[1] != (S_IFDIR | 0555) || p[2] != UF_HIDDEN) return bad("the root's mode", p[1], S_IFDIR | 0555);
    if (p[3] != 19 || p[4] != 0x4244) return bad("the type", p[3], 19);
    uint64_t size = p[5] | (uint64_t)p[6] << 32, used = p[7] | (uint64_t)p[8] << 32;
    if (size != 512 * now.f_blocks || used != size) return bad("the size", (long)size, (long)(512 * now.f_blocks));
    if (p[9] != now.f_files || p[10] != now.f_files || p[11] != now.f_flags) return bad("the object counts", p[9], (long)now.f_files);
    uint32_t caps[8] = {0x2f26, 0x802, 0, 0, 0x60ffff, 0x7fff, 0, 0};
    if (memcmp(p + 12, caps, sizeof caps)) return bad("the capabilities", p[12], 0x2f26);
    // (XNU 10063's VFS_DFLT_ATTR_VOL; later kernels add ATTR_VOL_MOUNTEXTFLAGS,
    // 0x80000, to the valid volume attributes)
    uint32_t attrs[10] = {0xc63fddbf, 0x7013d9ff, 5, 0x362f, 0, 0x2279cbf, 0x4002d93d, 4, 0x22b, 0};
    for (int i = 0; i < 10; i++)
        if (p[20 + i] != attrs[i]) return bad("the attribute masks", p[20 + i], attrs[i]);
    if (p[30] != 0) return bad("the subtype", p[30], 0);
    printf("devattr ok\n");
    return 0;
}
