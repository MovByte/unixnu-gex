//! `/dev` as an iOS kernel makes it (`bsd/miscfs/devfs`): the nodes
//! `devfs_init` and the configured drivers make at boot, in the order
//! they make them, with their device numbers, owners and modes; the two
//! planes devfs keeps (the backing one the drivers add to, and the
//! mount's copy of it), which number the nodes and fill `devfs_stats`;
//! the devnodes' lazily kept times; and the attributes `devfs_getattr`
//! gives. The terminal nodes' drivers are [`super::ttydev`]'s.
//!
//! iOS's release kernel has no fdesc (no `fd`, `stdin`, `stdout`,
//! `stderr`), no audit pipes and no dtrace. Its monotonic driver takes a
//! major but makes no node: the A10X's only counter device, `core`, is
//! one whose `mtd_init` refuses (the kernelcache carries no `uncore`).
//!
//! A driver that takes its major from `cdevsw_add(-1)` (pf, fsevents,
//! random) gets the first free slot of the table when it runs, after the
//! slots the kexts that started before it took: that number is the
//! boot's, not the kernel source's, and it is reported where it is seen.
//! So are the nodes IOKit's drivers make (the disks, among them).

use crate::vfs::{FileType, Metadata, Times};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// What a devfs node opens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// `/dev/null` and `/dev/zero` (`mmread`, `mmwrite`).
    Null,
    Zero,
    /// `/dev/random` and `/dev/urandom`.
    Random,
    /// A terminal, whose node the terminal layer opens
    /// ([`super::ttydev`]).
    Terminal,
    /// A driver whose device is not modelled: its open is reported.
    Unmodelled(&'static str),
}

/// A devfs node: its name, device (major, if fixed, and minor), owner,
/// group, mode and kind.
#[derive(Clone, Copy, Debug)]
pub struct Node {
    pub name: &'static str,
    pub major: Option<u32>,
    pub minor: u32,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub kind: Kind,
}

const ROOT: u32 = 0;
const WHEEL: u32 = 0;
/// `UID_LOGD`, `GID_LOGD`.
const LOGD: u32 = 272;
/// bpf's `CDEV_MAJOR`.
const BPF_MAJOR: u32 = 23;

/// `MAXPHYSIO` on arm64: a character device's `va_iosize`.
pub const MAXPHYSIO: i32 = 64 * 1024;
/// `UF_HIDDEN`: what `devfs_getattr` gives the root's `va_flags`.
pub const UF_HIDDEN: u32 = 0x8000;

const fn node(name: &'static str, major: Option<u32>, minor: u32, uid: u32, gid: u32, mode: u32, kind: Kind) -> Node {
    Node { name, major, minor, uid, gid, mode, kind }
}

/// The boot's nodes before the ptys, in the order they are made:
/// `devfs_init`'s (in `vfsinit`; `tty`, the second, is the terminal
/// code's), then pf's (`pfinit`, in `dlil_init`).
const EARLY: &[Node] = &[
    node("console", Some(0), 0, ROOT, WHEEL, 0o622, Kind::Terminal),
    node("null", Some(3), 2, ROOT, WHEEL, 0o666, Kind::Null),
    node("zero", Some(3), 3, ROOT, WHEEL, 0o666, Kind::Zero),
    node("klog", Some(6), 0, ROOT, WHEEL, 0o600, Kind::Unmodelled("the kernel message log (klog, logopen)")),
    node("oslog", Some(7), 0, LOGD, LOGD, 0o600, Kind::Unmodelled("os_log's device (oslogopen)")),
    node("oslog_stream", Some(8), 0, ROOT, WHEEL, 0o600, Kind::Unmodelled("os_log's stream device (oslog_streamopen)")),
    node("pf", None, 0, ROOT, WHEEL, 0o600, Kind::Unmodelled("the packet filter (pfopen)")),
    node("pfm", None, 1, ROOT, WHEEL, 0o600, Kind::Unmodelled("the packet filter's manager (pfopen)")),
];

/// The pseudo-devices after ptmx, in `pseudo_inits` order: bpf's
/// NBPFILTER (4) nodes, fsevents, random.
const LATE: &[Node] = &[
    node("bpf0", Some(BPF_MAJOR), 0, ROOT, WHEEL, 0o600, Kind::Unmodelled("the Berkeley packet filter (bpfopen)")),
    node("bpf1", Some(BPF_MAJOR), 1, ROOT, WHEEL, 0o600, Kind::Unmodelled("the Berkeley packet filter (bpfopen)")),
    node("bpf2", Some(BPF_MAJOR), 2, ROOT, WHEEL, 0o600, Kind::Unmodelled("the Berkeley packet filter (bpfopen)")),
    node("bpf3", Some(BPF_MAJOR), 3, ROOT, WHEEL, 0o600, Kind::Unmodelled("the Berkeley packet filter (bpfopen)")),
    node("fsevents", None, 0, ROOT, WHEEL, 0o644, Kind::Unmodelled("the file system events device (fseventsopen)")),
    node("random", None, 0, ROOT, WHEEL, 0o666, Kind::Random),
    node("urandom", None, 1, ROOT, WHEEL, 0o666, Kind::Random),
];

/// A devfs node of this table by name.
pub fn lookup(name: &str) -> Option<&'static Node> {
    EARLY.iter().chain(LATE).find(|n| n.name == name)
}

/// The nodes the boot makes, in order (each goes at its directory's end),
/// all before `devfs_kernel_mount` copies the plane: `devfs_init`'s and
/// pf's, the BSD ptys' pairs, ptmx, then the late pseudo-devices.
fn boot_names() -> &'static [String] {
    static NAMES: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    NAMES.get_or_init(|| {
        let mut out: Vec<String> = EARLY.iter().map(|n| n.name.to_string()).collect();
        out.insert(1, "tty".into());
        for m in 0..super::ptmx::NPTY {
            let (c, x) = ((b'p' + (m / 16) as u8) as char, m % 16);
            out.push(format!("tty{c}{x:x}"));
            out.push(format!("pty{c}{x:x}"));
        }
        out.push("ptmx".into());
        out.extend(LATE.iter().map(|n| n.name.to_string()));
        out
    })
}

/// The devnodes of the backing plane when devfs is mounted: its root and
/// every boot node. `devfs_unique_fileno` numbered them 0 on; the mount's
/// copy (`dev_dup_plane`) numbers its own from here, in the same order.
fn backing() -> u64 {
    boot_names().len() as u64 + 1
}

/// The mount's root directory's inode number.
pub fn root_ino() -> u64 {
    backing()
}

/// A boot node's inode number in the mount's plane; none for a node made
/// later.
pub fn ino_of(name: &str) -> Option<u64> {
    boot_names().iter().position(|n| n == name).map(|i| backing() + 1 + i as u64)
}

/// The next `devfs_unique_fileno` (0: not yet begun).
static NEXT_INO: AtomicU64 = AtomicU64::new(0);

/// A node made after the mount (`devfs_make_node`): the backing plane's
/// devnode takes a number, then `devfs_propogate`'s copy in the mount's
/// plane the next, which is the one seen.
pub fn later_ino() -> u64 {
    let _ = NEXT_INO.compare_exchange(0, 2 * backing(), Ordering::AcqRel, Ordering::Acquire);
    NEXT_INO.fetch_add(2, Ordering::AcqRel) + 1
}

/// The listing of `/dev`: the boot's nodes, then the ptmx replicas in the
/// order their nodes were made.
pub fn list() -> Vec<String> {
    let mut out = boot_names().to_vec();
    let mut later: Vec<(String, u64)> = super::ttydev::list().into_iter().filter(|(n, _)| n.starts_with("ttys")).collect();
    later.sort_by_key(|&(_, ino)| ino);
    out.extend(later.into_iter().map(|(n, _)| n));
    out
}

/// `devfs_stats`: one mount; the devnodes and directory entries of both
/// planes (each a root and a node per name); no symlink names.
pub fn stats() -> (u64, u64) {
    let per_plane = list().len() as u64 + 1;
    (2 * per_plane, 2 * per_plane)
}

/// `devfs_statfs`'s `f_blocks`: the bookkeeping, in 512-byte blocks
/// (`sizeof(struct devfsmount)` 16, `devnode_t` 216 and `devdirent_t` 80
/// on arm64).
pub fn statfs_blocks() -> u64 {
    let (nodes, entries) = stats();
    (16 + nodes * 216 + entries * 80) / 512
}

/// `DEVFS_UPDATE_CHANGE`, `_MOD`, `_ACCESS`.
pub const UPDATE_CHANGE: u32 = 0x1;
pub const UPDATE_MOD: u32 = 0x2;
pub const UPDATE_ACCESS: u32 = 0x4;
/// `DEVFS_LAZY_UPDATE_SECONDS`.
const LAZY_UPDATE_SECONDS: i64 = 1;

/// `microtime`: seconds and microseconds.
fn microtime() -> (i64, u32) {
    let d = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    (d.as_secs() as i64, d.subsec_micros())
}

fn boot_sec() -> i64 {
    (super::mach::boottime_usec() / 1_000_000) as i64
}

/// A devnode's times and the marks of updates put off (`dn_atime`,
/// `dn_mtime`, `dn_ctime`, `dn_access`, `dn_update`, `dn_change`).
#[derive(Clone, Copy, Debug)]
pub struct DnTimes {
    atime: (i64, u32),
    mtime: (i64, u32),
    ctime: (i64, u32),
    access: bool,
    update: bool,
    change: bool,
}

impl DnTimes {
    /// `dev_add_node`'s: the second it was made.
    pub fn made_at(sec: i64) -> DnTimes {
        DnTimes { atime: (sec, 0), mtime: (sec, 0), ctime: (sec, 0), access: false, update: false, change: false }
    }

    /// A node made now.
    pub fn made_now() -> DnTimes {
        DnTimes::made_at(microtime().0)
    }

    /// A boot node.
    pub fn made_at_boot() -> DnTimes {
        DnTimes::made_at(boot_sec())
    }

    /// `dn_times_locked(dnp, now, now, now, flags)`: what `flags` names is
    /// now; a mark put off moves its time on, at most a lazy second past
    /// the old one.
    fn times_locked(&mut self, now: (i64, u32), flags: u32) {
        let ns = now.1 * 1000;
        let step = |t: &mut (i64, u32), mark: &mut bool, just: bool| {
            if just {
                *t = (now.0, ns);
                *mark = false;
            } else if *mark {
                *t = (now.0.min(t.0 + LAZY_UPDATE_SECONDS), ns);
                *mark = false;
            }
        };
        step(&mut self.atime, &mut self.access, flags & UPDATE_ACCESS != 0);
        step(&mut self.mtime, &mut self.update, flags & UPDATE_MOD != 0);
        step(&mut self.ctime, &mut self.change, flags & UPDATE_CHANGE != 0);
    }

    /// `devfs_consider_time_update`: an update a second or more after the
    /// time it would move is made now, with the ones put off; else it is
    /// marked for later.
    pub fn consider(&mut self, flags: u32) {
        let now = microtime();
        let needed = |last: i64| now.0 > last && now.0 - last >= LAZY_UPDATE_SECONDS;
        if (self.change || flags & UPDATE_CHANGE != 0) && needed(self.ctime.0)
            || (self.access || flags & UPDATE_ACCESS != 0) && needed(self.atime.0)
            || (self.update || flags & UPDATE_MOD != 0) && needed(self.mtime.0)
        {
            self.times_locked(now, flags);
            return;
        }
        // dn_mark_for_delayed_times_update.
        self.change |= flags & UPDATE_CHANGE != 0;
        self.access |= flags & UPDATE_ACCESS != 0;
        self.update |= flags & UPDATE_MOD != 0;
    }

    /// `devfs_getattr`'s times: what is put off made now, and a time never
    /// set the boot's. The modification time's seconds, and all three.
    pub fn getattr(&mut self) -> (i64, Times) {
        self.times_locked(microtime(), 0);
        if self.ctime.0 == 0 {
            self.ctime = (boot_sec(), 0);
        }
        if self.mtime.0 == 0 {
            self.mtime = self.ctime;
        }
        if self.atime.0 == 0 {
            self.atime = self.ctime;
        }
        (self.mtime.0, Times { mtime_ns: self.mtime.1, atime: self.atime.0, atime_ns: self.atime.1, ctime: self.ctime.0, ctime_ns: self.ctime.1 })
    }
}

/// The times of this table's nodes and of the root, by name ("" the root).
static TIMES: Mutex<Option<HashMap<&'static str, DnTimes>>> = Mutex::new(None);

fn with_times<R>(name: &'static str, f: impl FnOnce(&mut DnTimes) -> R) -> R {
    let mut g = TIMES.lock().unwrap_or_else(|e| e.into_inner());
    f(g.get_or_insert_with(HashMap::new).entry(name).or_insert_with(DnTimes::made_at_boot))
}

/// `devfsspec_read` and `devfsspec_write`'s marks on a node of this table.
pub fn touch(n: &Node, flags: u32) {
    with_times(n.name, |t| t.consider(flags));
}

/// `devfs_readdir`'s access of the root.
pub fn touch_root() {
    with_times("", |t| t.consider(UPDATE_ACCESS));
}

/// A node's attributes (`devfs_getattr`): its device as the boot numbered
/// it (major 0 when that is the boot's own choice, which a stat reports).
pub fn metadata(n: &'static Node) -> Metadata {
    let dev = (n.major.unwrap_or(0) << 24) | n.minor;
    let (mtime, times) = with_times(n.name, |t| t.getattr());
    Metadata {
        file_type: FileType::CharDevice,
        size: 0,
        mode: n.mode,
        ino: ino_of(n.name).unwrap_or(0),
        mtime,
        nlink: 1,
        rdev: super::ttydev::linux_rdev(dev),
        times,
    }
}

/// The root directory's attributes: mode 0555; its links "." and its own
/// name and its ".." (itself); its size `dn_len`, 8 and the name's length
/// for each entry.
pub fn root_metadata() -> Metadata {
    let (mtime, times) = with_times("", |t| t.getattr());
    Metadata {
        file_type: FileType::Directory,
        size: list().iter().map(|n| n.len() as u64 + 8).sum(),
        mode: 0o555,
        ino: root_ino(),
        mtime,
        nlink: 3,
        rdev: 0,
        times,
    }
}

/// The boot node a stat's attributes are of (by its inode number and
/// device), if they are one of this table's.
pub fn node_of(md: &Metadata) -> Option<&'static Node> {
    if md.file_type != FileType::CharDevice {
        return None;
    }
    EARLY.iter().chain(LATE).find(|n| ino_of(n.name) == Some(md.ino) && super::ttydev::linux_rdev((n.major.unwrap_or(0) << 24) | n.minor) == md.rdev)
}

/// What `vn_stat` makes of a devfs vnode's attributes beyond the node's:
/// `st_blksize` its `va_iosize` (`MAXPHYSIO` for a character device, the
/// mount's `f_iosize` else), `st_blocks` the size rounded to the mount's
/// 512-byte blocks, no birth time (devfs has no `va_create_time`), and the
/// root owned by root, hidden.
pub fn stat_fixup(st: &mut crate::fs::Stat, md: &Metadata, path: &str) {
    st.blksize = if md.file_type == FileType::CharDevice { MAXPHYSIO } else { 512 };
    st.blocks = (md.size as i64 + 511) / 512;
    st.birth = Some((0, 0));
    if path == "/dev" {
        st.uid = ROOT;
        st.gid = WHEEL;
        st.flags = UF_HIDDEN;
    }
}
