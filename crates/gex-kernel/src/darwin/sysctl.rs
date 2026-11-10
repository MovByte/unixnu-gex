//! Darwin's `sysctl` tree (`bsd/kern/kern_newsysctl.c`): the kernel's own
//! nodes ([`super::sysctl_nodes`], read from its kernelcache), found by
//! number or by name, and the values this kernel has for them. A node the
//! device has and this kernel has no value for is reported, not taken for a
//! name that does not exist. The values describe the iPad7,1 the UniXNU
//! iPadOS 17.7 profile runs.

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::errno::Errno;

/// What a node holds, in the representation `sysctl` copies out.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Str(&'static str),
    /// Bytes as they are, with no terminator added.
    Data(&'static [u8]),
    I32(i32),
    I64(i64),
    /// `struct timeval`: seconds, microseconds.
    Timeval(i64, i32),
    /// `kern.boottime`: the calendar time at boot, as a `struct timeval`.
    BootTime,
    /// The asking process's `user_stack`, as an `int` (`kern.usrstack`)
    /// or whole (`kern.usrstack64`).
    UserStack32,
    UserStack64,
}

impl Value {
    /// The node's value for the process whose main stack's top is
    /// `user_stack`.
    pub fn bytes(&self, user_stack: u64) -> Vec<u8> {
        match self {
            Value::UserStack32 => (user_stack as i32).to_le_bytes().to_vec(),
            Value::UserStack64 => user_stack.to_le_bytes().to_vec(),
            Value::Str(s) => {
                let mut b = s.as_bytes().to_vec();
                b.push(0);
                b
            }
            Value::Data(d) => d.to_vec(),
            Value::I32(v) => v.to_le_bytes().to_vec(),
            Value::I64(v) => v.to_le_bytes().to_vec(),
            Value::Timeval(s, us) => {
                let mut b = s.to_le_bytes().to_vec();
                b.extend_from_slice(&us.to_le_bytes());
                b.extend_from_slice(&[0; 4]);
                b
            }
            Value::BootTime => {
                let us = super::mach::boottime_usec();
                Value::Timeval((us / 1_000_000) as i64, (us % 1_000_000) as i32).bytes(user_stack)
            }
        }
    }
}

/// The top-level node numbers.
pub const CTL_KERN: i32 = 1;
pub const CTL_VM: i32 = 2;
pub const CTL_HW: i32 = 6;
/// Where nodes without a standard number go.
pub const PRIVATE: i32 = 0x7f00;

/// `bootsessionuuid_string`.
/// `kern.bootsessionuuid`: this boot's, a version 4 UUID in capitals as
/// the real system's is. What sets it is outside the kernel; here it comes
/// from the one thing unique to the boot, the time it began.
pub fn bootsessionuuid() -> &'static str {
    use sha2::Digest;
    static UUID: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    UUID.get_or_init(|| {
        let d = sha2::Sha256::digest(super::mach::boottime_usec().to_le_bytes());
        let mut b = [0u8; 16];
        b.copy_from_slice(&d[..16]);
        b[6] = (b[6] & 0x0f) | 0x40;
        b[8] = (b[8] & 0x3f) | 0x80;
        let hex = |r: std::ops::Range<usize>| r.map(|i| format!("{:02X}", b[i])).collect::<String>();
        format!("{}-{}-{}-{}-{}", hex(0..4), hex(4..6), hex(6..8), hex(8..10), hex(10..16))
    })
}

/// `(name, oid, value)`.
/// The values this kernel has, by node.
pub fn value(path: &str) -> Option<Value> {
    use super::mig::machine::NCPUS;
    use Value::*;
    Some(match path {
        "kern.ostype" => Str("Darwin"),
        "kern.osrelease" => Str("23.6.0"),
        "kern.osrevision" => I32(199_506),
        "kern.version" => Str(VERSION),
        "kern.maxproc" => I32(super::rlimit::MAXPROC as i32),
        "kern.maxfiles" => I32(super::rlimit::MAXFILES as i32),
        "kern.argmax" => I32(super::rlimit::ARG_MAX as i32),
        "kern.securelevel" => I32(0),
        "kern.hostid" => I32(0),
        "kern.posix1version" => I32(200_112),
        "kern.ngroups" => I32(16),
        "kern.boottime" => BootTime,
        "kern.maxfilesperproc" => I32(super::rlimit::MAXFILESPERPROC as i32),
        "kern.maxprocperuid" => I32(super::rlimit::MAXPROCPERUID as i32),
        "kern.usrstack" => UserStack32,
        "kern.usrstack64" => UserStack64,
        "kern.osversion" => Str("21H461"),
        "kern.bootargs" => Str(""),
        "kern.osproductversion" => Str("17.7.11"),
        "kern.osvariant_status" => I64(0),
        "kern.secure_kernel" => I32(0),
        "kern.hv_vmm_present" => I32(0),
        "kern.bootsessionuuid" => Str(bootsessionuuid()),
        "kern.uuid" => Str("D6F6E0D2-FE60-38A0-9214-556B7FAF8951"),
        "kern.osbuildconfig" => Str("release"),
        "kern.willshutdown" => I32(0),
        // The `-minimalboot` boot argument, and a dark boot's: neither given.
        "kern.minimalboot" => I32(0),
        "kern.darkboot" => I32(0),
        "kern.memorystatus_level" => I32(100),
        "hw.machine" => Str("iPad7,1"),
        "hw.model" => Str("J120AP"),
        "hw.ncpu" | "hw.activecpu" | "hw.physicalcpu" | "hw.physicalcpu_max" | "hw.logicalcpu" | "hw.logicalcpu_max" => I32(NCPUS as i32),
        "hw.byteorder" => I32(1234),
        "hw.pagesize" | "hw.pagesize_compat" | "hw.pagesize32" => I32(16384),
        "hw.memsize" => I64(4 << 30),
        "hw.cputype" => I32(0x0100_000c),
        "hw.cpusubtype" => I32(super::mig::machine::CPU_SUBTYPE as i32),
        "hw.cpufamily" => I32(0x67ce_ee93u32 as i32),
        "hw.cachelinesize" | "hw.cachelinesize_compat" => I32(64),
        "hw.l1icachesize" | "hw.l1icachesize_compat" => I32(65_536),
        "hw.l1dcachesize" | "hw.l1dcachesize_compat" => I32(65_536),
        "hw.l2cachesize" | "hw.l2cachesize_compat" => I32(8 << 20),
        "hw.tbfrequency" => I64(24_000_000),
        "hw.cpu64bit_capable" => I32(1),
        "hw.optional.neon" | "hw.optional.AdvSIMD" | "hw.optional.neon_hpfp" | "hw.optional.AdvSIMD_HPFPCvt" | "hw.optional.floatingpoint" | "hw.optional.armv8_crc32" | "hw.optional.arm64" | "hw.optional.arm.FEAT_AES" | "hw.optional.arm.FEAT_PMULL" | "hw.optional.arm.FEAT_SHA1" | "hw.optional.arm.FEAT_SHA256" => I32(1),
        // ARMv8.1 and later features an A10X does not have.
        "hw.optional.armv8_1_atomics" | "hw.optional.neon_fp16" | "hw.optional.armv8_2_fhm" | "hw.optional.armv8_2_sha3" | "hw.optional.armv8_2_sha512" | "hw.optional.armv8_3_compnum" | "hw.optional.arm.FEAT_LSE" | "hw.optional.arm.FEAT_LSE2" | "hw.optional.arm.FEAT_RDM" | "hw.optional.arm.FEAT_FP16" | "hw.optional.arm.FEAT_FHM" | "hw.optional.arm.FEAT_DotProd" | "hw.optional.arm.FEAT_FCMA" | "hw.optional.arm.FEAT_JSCVT" | "hw.optional.arm.FEAT_LRCPC" | "hw.optional.arm.FEAT_LRCPC2" | "hw.optional.arm.FEAT_FRINTTS" | "hw.optional.arm.FEAT_FlagM" | "hw.optional.arm.FEAT_FlagM2" | "hw.optional.arm.FEAT_I8MM" | "hw.optional.arm.FEAT_BF16" | "hw.optional.arm.FEAT_SHA3" | "hw.optional.arm.FEAT_SHA512" | "hw.optional.arm.FEAT_PAuth" | "hw.optional.arm.FEAT_PAuth2" | "hw.optional.arm.FEAT_FPAC" | "hw.optional.arm.FEAT_BTI" | "hw.optional.arm.FEAT_DPB" | "hw.optional.arm.FEAT_DPB2" | "hw.optional.arm.FEAT_SB" | "hw.optional.arm.FEAT_SPECRES" | "hw.optional.arm.FEAT_RPRES" | "hw.optional.arm.FEAT_SME" | "hw.optional.arm.FEAT_SME2" => I32(0),
        "hw.targettype" => Str("J120"),
        // The platform expert's names (`PEGetTargetName`,
        // `PEGetProductName`): the board and the product.
        "hw.target" => Str("J120AP"),
        "hw.product" => Str("iPad7,1"),
        // /chosen/osenvironment: 32 bytes the boot loader leaves zero on
        // a normal boot.
        "hw.osenvironment" => Data(&[0; 32]),
        // /chosen/ephemeral-storage.
        "hw.ephemeral_storage" => I32(0),
        "security.mac.amfi.developer_mode_status" => I32(1),
        _ => return None,
    })
}

/// `version`: the running kernel's own string.
const VERSION: &str = "Darwin Kernel Version 23.6.0: Fri Jul 11 17:39:39 PDT 2025; root:xnu-10063.142.1.703.8~1/RELEASE_ARM64_T8010";

/// A number's bytes at the width its node is declared to have: `hw.pagesize`
/// is a 64-bit node and `hw.pagesize_compat` the `int` of the same value.
/// A node served by `sysctl_io_number` gives an `int` to a caller whose
/// buffer holds exactly one (`old`, `oldlen`), if the value fits.
pub fn sized(path: &str, kind: u32, mut b: Vec<u8>, old: u64, oldlen: u64) -> Result<Vec<u8>, Errno> {
    match (kind & ctl::TYPE, b.len()) {
        (ctl::TYPE_QUAD, 4) => {
            let v = i32::from_le_bytes([b[0], b[1], b[2], b[3]]);
            b = i64::from(v).to_le_bytes().to_vec();
        }
        (ctl::TYPE_INT, 8) => b.truncate(4),
        _ => {}
    }
    let io_number = matches!(path, "hw.pagesize" | "hw.pagesize32" | "hw.tbfrequency" | "kern.usrstack64");
    if io_number && b.len() == 8 && old != 0 && oldlen == 4 {
        let v = i64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
        let small = v as i32;
        if i64::from(small) != v {
            return Err(Errno::ERANGE);
        }
        b.truncate(4);
    }
    Ok(b)
}

/// `CTL_MAXNAME`: the most components a name can have.
pub const CTL_MAXNAME: usize = 12;

/// `oid_kind`'s type field and flags.
pub mod ctl {
    pub const TYPE: u32 = 0xf;
    pub const TYPE_NODE: u32 = 1;
    pub const TYPE_INT: u32 = 2;
    pub const TYPE_QUAD: u32 = 4;
    pub const RD: u32 = 0x8000_0000;
    pub const WR: u32 = 0x4000_0000;
    pub const ANYBODY: u32 = 0x1000_0000;
    pub const SECURE: u32 = 0x0800_0000;
    pub const EXPERIMENT: u32 = 0x0010_0000;
}

/// One node of the tree.
#[derive(Clone, Copy, Debug)]
pub struct Node {
    /// Its name from the root, `kern.ostype`.
    pub path: &'static str,
    pub number: i32,
    /// `oid_kind`.
    pub kind: u32,
    pub fmt: &'static str,
    /// Whether a node has its own handler (and takes numbers past its
    /// name), or is only a directory.
    pub handler: bool,
}

/// What a kext registers, not in the kernel's own list.
static KEXT_NODES: &[Node] = &[
    Node { path: "security.mac.amfi", number: 100, kind: ctl::RD | ctl::WR | 0x00e0_0000 | ctl::TYPE_NODE, fmt: "N", handler: false },
    Node { path: "security.mac.amfi.developer_mode_status", number: 100, kind: ctl::RD | 0x00e0_0000 | 2, fmt: "I", handler: true },
];

struct Tree {
    /// Every node with its numbers from the root, in their order.
    nodes: Vec<(Vec<i32>, Node)>,
    by_oid: HashMap<Vec<i32>, usize>,
    by_path: HashMap<&'static str, usize>,
}

fn tree() -> &'static Tree {
    static TREE: OnceLock<Tree> = OnceLock::new();
    TREE.get_or_init(|| {
        let mut all: Vec<Node> = super::sysctl_nodes::NODES.iter().chain(KEXT_NODES).copied().collect();
        all.sort_by_key(|n| n.path.split('.').count());
        let mut oids: HashMap<&'static str, Vec<i32>> = HashMap::new();
        let mut nodes = Vec::with_capacity(all.len());
        for n in all {
            let mut oid = match n.path.rsplit_once('.') {
                Some((parent, _)) => oids.get(parent).cloned().unwrap_or_default(),
                None => Vec::new(),
            };
            oid.push(n.number);
            oids.insert(n.path, oid.clone());
            nodes.push((oid, n));
        }
        nodes.sort_by(|a, b| a.0.cmp(&b.0));
        let by_oid = nodes.iter().enumerate().map(|(i, (o, _))| (o.clone(), i)).collect();
        let by_path = nodes.iter().enumerate().map(|(i, (_, n))| (n.path, i)).collect();
        Tree { nodes, by_oid, by_path }
    })
}

/// Whether a node has no handler of its own: only children.
fn is_dir(n: &Node) -> bool {
    n.kind & ctl::TYPE == ctl::TYPE_NODE && !n.handler
}

/// `sysctl_root`'s walk: the node `oid` names, and the numbers past it for
/// a node that takes them.
pub fn find(oid: &[i32]) -> Result<(&'static Node, &[i32]), Errno> {
    let t = tree();
    for i in 1..=oid.len().min(CTL_MAXNAME) {
        let Some(&at) = t.by_oid.get(&oid[..i]) else { return Err(Errno::ENOENT) };
        let n = &t.nodes[at].1;
        if n.kind & ctl::TYPE == ctl::TYPE_NODE {
            if n.handler {
                return Ok((n, &oid[i..]));
            }
            if i == oid.len() {
                return Err(Errno::ENOENT);
            }
        } else {
            if i != oid.len() {
                return Err(Errno::EISDIR);
            }
            return Ok((n, &[]));
        }
    }
    Err(Errno::ENOENT)
}

/// `name2oid`: a name's numbers. A trailing dot is ignored, and a walk
/// stops being able to go on at a node with a handler or a leaf.
pub fn name2oid(name: &str) -> Result<Vec<i32>, Errno> {
    let t = tree();
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() {
        return Err(Errno::ENOENT);
    }
    let &at = t.by_path.get(name).ok_or(Errno::ENOENT)?;
    let oid = &t.nodes[at].0;
    if oid.len() > CTL_MAXNAME {
        return Err(Errno::ENOENT);
    }
    // Every node on the way is a directory, as the walk needs.
    for i in 1..oid.len() {
        if !is_dir(&t.nodes[t.by_oid[&oid[..i]]].1) {
            return Err(Errno::ENOENT);
        }
    }
    Ok(oid.clone())
}

/// `sysctl_sysctl_name`: the dotted name of `oid`, numbers past the tree as
/// numbers. An empty name is the root's, as a walk that finds nothing leaves.
pub fn name_of(oid: &[i32]) -> String {
    let t = tree();
    let mut out = String::new();
    let mut walking = true;
    for (i, n) in oid.iter().enumerate() {
        let node = walking.then(|| t.by_oid.get(&oid[..=i]).map(|&at| &t.nodes[at].1)).flatten();
        if !out.is_empty() {
            out.push('.');
        }
        match node {
            Some(nd) => {
                out.push_str(nd.path.rsplit('.').next().unwrap_or(nd.path));
                walking = is_dir(nd);
            }
            None => {
                walking = false;
                out.push_str(&n.to_string());
            }
        }
    }
    out
}

/// `sysctl_sysctl_next`: the first leaf after `oid`, in number order.
pub fn next(oid: &[i32]) -> Option<Vec<i32>> {
    tree().nodes.iter().find(|(o, n)| !is_dir(n) && o.as_slice() > oid).map(|(o, _)| o.clone())
}

/// `sysctl_sysctl_oidfmt`: the kind and format of what `oid` names.
pub fn oid_fmt(oid: &[i32]) -> Result<(u32, &'static str), Errno> {
    let t = tree();
    for i in 1..=oid.len().min(CTL_MAXNAME) {
        let Some(&at) = t.by_oid.get(&oid[..i]) else { return Err(Errno::ENOENT) };
        let n = &t.nodes[at].1;
        if n.kind & ctl::TYPE == ctl::TYPE_NODE {
            if n.handler || i == oid.len() {
                return Ok((n.kind, n.fmt));
            }
        } else {
            if i != oid.len() {
                return Err(Errno::EISDIR);
            }
            return Ok((n.kind, n.fmt));
        }
    }
    Err(Errno::ENOENT)
}

/// `kern.osreleasetype`: launchd sets it once, from SystemVersion.plist's
/// ReleaseType; empty before.
static OSRELEASETYPE: std::sync::Mutex<Vec<u8>> = std::sync::Mutex::new(Vec::new());

/// `kern.osreleasetype`'s value.
pub fn os_release_type() -> Vec<u8> {
    OSRELEASETYPE.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Set it, from launchd's one write.
pub fn set_os_release_type(v: Vec<u8>) {
    *OSRELEASETYPE.lock().unwrap_or_else(|e| e.into_inner()) = v;
}

/// `kern.hostname`, `MAXHOSTNAMELEN` bytes at most, the system's.
static HOSTNAME: std::sync::Mutex<Option<Vec<u8>>> = std::sync::Mutex::new(None);
pub const MAXHOSTNAMELEN: usize = 256;

/// The hostname.
pub fn hostname() -> Vec<u8> {
    HOSTNAME.lock().unwrap_or_else(|e| e.into_inner()).clone().unwrap_or_else(|| b"iPad".to_vec())
}

/// Set the hostname.
pub fn set_hostname(v: Vec<u8>) {
    *HOSTNAME.lock().unwrap_or_else(|e| e.into_inner()) = Some(v);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_numbers_resolve() {
        assert_eq!(name2oid("kern.osrelease"), Ok(vec![1, 2]));
        assert_eq!(name2oid("hw.machine"), Ok(vec![6, 1]));
        assert_eq!(name2oid("no.such.node"), Err(Errno::ENOENT));
        let (n, tail) = find(&[1, 2]).unwrap();
        assert_eq!(n.path, "kern.osrelease");
        assert!(tail.is_empty());
        assert_eq!(find(&[1]).err(), Some(Errno::ENOENT), "a directory is not a node to read");
        assert_eq!(find(&[1, 2, 3]).err(), Some(Errno::EISDIR));
        let (n, tail) = find(&[1, 14, 1, 7]).unwrap();
        assert_eq!(n.path, "kern.proc.pid");
        assert_eq!(tail, &[7]);
        assert_eq!(name_of(&[1, 14, 1, 7]), "kern.proc.pid.7");
        assert_eq!(oid_fmt(&[1, 2]).unwrap().1, "A");
        let after = next(&[1, 2]).unwrap();
        assert!(after.as_slice() > &[1i32, 2][..]);
    }

    #[test]
    fn the_paths_are_unique_and_the_values_are_of_nodes() {
        let t = tree();
        assert_eq!(t.by_path.len(), t.nodes.len());
        for (_, n) in &t.nodes {
            if value(n.path).is_some() {
                assert_ne!(n.kind & ctl::TYPE, ctl::TYPE_NODE, "{} is a directory", n.path);
            }
        }
    }
}
