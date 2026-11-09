//! Sandbox's compiled profiles and their evaluation, as the iOS 17
//! Sandbox.kext reads them (`profile.c`'s loader and the evaluator its
//! MAC hooks share).
//!
//! A profile blob starts with a 14-byte header: its flags (a collection's
//! has bit 15 set), its node count, the operation count (191 here), the
//! sizes of four tables of 16-bit entries that follow it, and the number of
//! profiles in a collection. A single profile's operation table follows
//! those tables; a collection's profiles do, each a name, its flags and an
//! operation table. Each operation's entry names the node its evaluation
//! starts at: the nodes, 8 bytes each from the next 8-byte boundary, are
//! filters (a type, an argument, and the node to go on to when it matches
//! and when it does not) or terminals (the decision). A node only leads to
//! nodes after it.
//!
//! Every malformed profile is refused at evaluation (EPERM), as the kernel
//! refuses it.

/// The operations a profile has (the `0xbf` the loader checks).
pub const OPERATIONS: usize = 191;
/// A collection profile's entry: a name, flags, and its operation table.
const ENTRY: usize = 4 + 2 * OPERATIONS;
const NODE: usize = 8;

/// A pattern variable a literal pattern names (the header's second
/// table), by its name's kind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Var {
    AnyUuid,
    AnyPathComponent,
    AnyUserHome,
    Digits,
    Home,
    FrontUserHome,
    ProcessTempDir,
    Entitlement(Vec<u8>),
    /// A name the kernel does not know: it never matches.
    Unsupported,
}

/// One profile: offsets into its blob, and its blob's regexes and pattern
/// variables.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    /// The profile's name (a string table index) and flags, for a
    /// collection's.
    pub name: u16,
    pub flags: u16,
    ops: usize,
    nodes: usize,
    nodes_end: usize,
    pub regexes: Vec<super::applematch::Program>,
    pub vars: Vec<Var>,
}

/// Why a blob is refused (the loader's messages).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoadError {
    Truncated,
    WrongFlags,
    OperationCount(u8),
    /// A regex or pattern variable that does not load: EINVAL.
    Invalid,
}

fn u16_at(b: &[u8], o: usize) -> Option<u16> {
    b.get(o..o + 2).map(|s| u16::from_le_bytes([s[0], s[1]]))
}

/// The header's fields and where its tables end.
struct Header {
    flags: u16,
    nodes: usize,
    profiles: usize,
    /// The regex and pattern-variable tables' entries.
    regexes: (usize, usize),
    vars: (usize, usize),
    tables_end: usize,
}

fn header(b: &[u8]) -> Result<Header, LoadError> {
    if b.len() < 0xe {
        return Err(LoadError::Truncated);
    }
    if b[4] as usize != OPERATIONS {
        return Err(LoadError::OperationCount(b[4]));
    }
    let (c, d) = (usize::from(b[5]), usize::from(b[6]));
    let (e, f) = (usize::from(u16_at(b, 0xa).unwrap()), usize::from(u16_at(b, 0xc).unwrap()));
    Ok(Header {
        flags: u16_at(b, 0).unwrap(),
        nodes: usize::from(u16_at(b, 2).unwrap()),
        profiles: usize::from(u16_at(b, 8).unwrap()),
        regexes: (0xe, e),
        vars: (0xe + 2 * e, c),
        tables_end: 0xe + 2 * (e + c + d + f),
    })
}

fn nodes_after(end: usize, count: usize, len: usize) -> Result<(usize, usize), LoadError> {
    let base = (end + NODE - 1) & !(NODE - 1);
    let nodes_end = base + count * NODE;
    if nodes_end > len {
        return Err(LoadError::Truncated);
    }
    Ok((base, nodes_end))
}

/// The blob's regexes (`0x...909c`): each an object past the nodes, a
/// size and an AppleMatch program, loaded.
fn regexes(b: &[u8], h: &Header, nodes_end: usize) -> Result<Vec<super::applematch::Program>, LoadError> {
    (0..h.regexes.1)
        .map(|i| {
            let at = nodes_end + usize::from(u16_at(b, h.regexes.0 + 2 * i).ok_or(LoadError::Truncated)?) * NODE;
            let n = usize::from(u16_at(b, at).ok_or(LoadError::Invalid)?);
            let blob = b.get(at + 2..at + 2 + n).ok_or(LoadError::Invalid)?;
            super::applematch::load(blob).map_err(|_| LoadError::Invalid)
        })
        .collect()
}

/// The blob's pattern variables (`0x...8dc0`), named by strings past the
/// nodes; the kind by the name, its case ignored.
fn vars(b: &[u8], h: &Header, nodes_end: usize) -> Result<Vec<Var>, LoadError> {
    (0..h.vars.1)
        .map(|i| {
            let at = nodes_end + usize::from(u16_at(b, h.vars.0 + 2 * i).ok_or(LoadError::Truncated)?) * NODE;
            let n = usize::from(u16_at(b, at).ok_or(LoadError::Invalid)?);
            let name = b.get(at + 2..at + 2 + n).ok_or(LoadError::Invalid)?;
            if n == 0 || name[n - 1] != 0 {
                return Err(LoadError::Invalid);
            }
            let name = &name[..n - 1];
            let is = |w: &str| name.eq_ignore_ascii_case(w.as_bytes());
            const ENT: &[u8] = b"ENTITLEMENT:";
            Ok(if is("ANY_UUID") {
                Var::AnyUuid
            } else if is("ANY_PATH_COMPONENT") {
                Var::AnyPathComponent
            } else if is("ANY_USER_HOME") {
                Var::AnyUserHome
            } else if is("DIGITS") {
                Var::Digits
            } else if is("HOME") {
                Var::Home
            } else if is("FRONT_USER_HOME") {
                Var::FrontUserHome
            } else if is("PROCESS_TEMP_DIR") {
                Var::ProcessTempDir
            } else if name.len() >= ENT.len() && name[..ENT.len()].eq_ignore_ascii_case(ENT) {
                Var::Entitlement(name[ENT.len()..].to_vec())
            } else {
                Var::Unsupported
            })
        })
        .collect()
}

/// A single profile blob (the platform profile's form: no profiles
/// counted, its operation table after the header's tables).
pub fn single(b: &[u8]) -> Result<Profile, LoadError> {
    let h = header(b)?;
    let ops = h.tables_end;
    let (nodes, nodes_end) = nodes_after(ops + 2 * OPERATIONS, h.nodes, b.len())?;
    Ok(Profile { name: 0, flags: h.flags, ops, nodes, nodes_end, regexes: regexes(b, &h, nodes_end)?, vars: vars(b, &h, nodes_end)? })
}

/// A collection blob's profiles.
pub fn collection(b: &[u8]) -> Result<Vec<Profile>, LoadError> {
    let h = header(b)?;
    if h.flags & 0x8000 == 0 {
        return Err(LoadError::WrongFlags);
    }
    let first = h.tables_end;
    let (nodes, nodes_end) = nodes_after(first + h.profiles * ENTRY, h.nodes, b.len())?;
    let (regexes, vars) = (regexes(b, &h, nodes_end)?, vars(b, &h, nodes_end)?);
    (0..h.profiles)
        .map(|i| {
            let at = first + i * ENTRY;
            Ok(Profile { name: u16_at(b, at).ok_or(LoadError::Truncated)?, flags: u16_at(b, at + 2).ok_or(LoadError::Truncated)?, ops: at + 4, nodes, nodes_end, regexes: regexes.clone(), vars: vars.clone() })
        })
        .collect()
}

/// A decision: the action (1, EPERM, denies) and the terminal's flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decision {
    pub errno: u32,
    pub flags: u32,
}

impl Decision {
    /// The evaluator's packed result.
    pub fn packed(self) -> u64 {
        u64::from(self.flags) << 32 | u64::from(self.errno)
    }
}

/// A malformed profile's result: EPERM, flags 5.
const REFUSED: Decision = Decision { errno: 1, flags: 5 };

/// Why a filter gave no answer: the evaluation is refused with this
/// decision (a malformed operand, or a helper's error: `0x5_0000_0000`
/// with its errno), or the filter needs what this port cannot say yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stop {
    Refuse(Decision),
    Unported(String),
}

/// A helper's error as the interpreter refuses with it (`0x...4250`).
fn helper_error(errno: u32) -> Stop {
    Stop::Refuse(Decision { errno, flags: 5 })
}

/// `ESRCH`, the helpers' error when there is no process to ask about.
pub const ESRCH: u32 = 3;

/// What an entitlement's value is, for `%entitlement-load` and the filters
/// that read the value it loaded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Bool(bool),
    String(Vec<u8>),
    Array(Vec<Value>),
    Other,
}

/// The operation's kinds (the argument block's first word) the filters
/// test for.
pub mod kind {
    pub const VNODE: u32 = 1;
    pub const SOCKET: u32 = 2;
    pub const PROCESS: u32 = 4;
    pub const FSCTL: u32 = 5;
    pub const SYSCTL: u32 = 0xf;
    pub const POSIX_IPC: u32 = 6;
    pub const HOST_SPECIAL_PORT: u32 = 7;
    pub const SYSCALL_UNIX: u32 = 0x14;
    pub const MAC_SYSCALL: u32 = 0x19;
}

/// What evaluation asks of the system: the operation's subject (the
/// process and credential), its objects, and the system's state. Each
/// answer is the kernel's; what the system cannot answer yet is
/// [`Stop::Unported`], what the kernel's helper fails at is its error.
pub trait Facts {
    /// The operation's kind ([`kind`]).
    fn kind(&self) -> u32;
    /// `0x...3774`: the subject process, `ESRCH` when the hook named none
    /// and allows no default to the current one.
    fn ensure_proc(&mut self) -> Result<(), Stop>;
    /// `0x...37cc`: the subject's credential (its process's, when the hook
    /// gave none).
    fn ensure_cred(&mut self) -> Result<(), Stop> {
        self.ensure_proc()
    }
    /// `cs_entitlement_flags`, `cs_restricted`, `proc_isinitproc`,
    /// `csproc_get_platform_binary`, `proc_platform`, `proc_is_translated`
    /// and `proc_is_rsr` of the subject process.
    fn cs_entitlement_flags(&mut self) -> Result<u32, Stop>;
    fn cs_restricted(&mut self) -> Result<bool, Stop>;
    fn initproc(&mut self) -> Result<bool, Stop>;
    fn platform_binary(&mut self) -> Result<bool, Stop>;
    fn proc_platform(&mut self) -> Result<u32, Stop>;
    fn translated(&mut self) -> Result<bool, Stop>;
    fn rsr(&mut self) -> Result<bool, Stop>;
    /// Whether the subject has a sandbox, whether its profile is the
    /// protobox collection's, and the byte its sandbox keeps at `+0x3b`
    /// of its shared state.
    fn sandboxed(&self) -> bool;
    fn protoboxed(&self) -> Result<bool, Stop>;
    fn sandbox_flag_3b(&self) -> Result<bool, Stop>;
    /// AMFI's entitlement queries on the subject's credential: the key is
    /// the boolean true, the key is present; `None` when the credential has
    /// no entitlements (`kIOReturnNotFound`).
    fn entitlement_bool(&mut self, key: &[u8]) -> Result<Option<bool>, Stop>;
    fn entitlement_present(&mut self, key: &[u8]) -> Result<Option<bool>, Stop>;
    /// The entitlement's value (`0x...a135ec`), none when it is absent.
    fn entitlement_value(&mut self, key: &[u8]) -> Result<Option<Value>, Stop>;
    /// Whether the subject process, or an ancestor of it whose parent's
    /// pid is at least 2, has the key as the boolean true
    /// (`0x...69f529c` with AMFI's process query).
    fn ancestor_entitled(&mut self, key: &[u8]) -> Result<bool, Stop>;
    /// `0x...3820`: the target process of a process operation, `ESRCH`
    /// when it is gone; and AMFI's boolean query on it.
    fn ensure_target(&mut self) -> Result<(), Stop>;
    fn target_entitlement_bool(&mut self, key: &[u8]) -> Result<Option<bool>, Stop>;
    /// The current thread's persona's uid and type (`current_persona_get`),
    /// none without one.
    fn persona(&mut self) -> Result<Option<(i32, u32)>, Stop>;
    /// The home directory of the user record of the subject's uid, of the
    /// front user's, and the subject's user's temporary directory (pattern
    /// variables HOME, FRONT_USER_HOME, PROCESS_TEMP_DIR): what Sandbox
    /// was told of them, none when it has no record.
    fn home(&mut self) -> Result<Option<Vec<u8>>, Stop>;
    fn front_user_home(&mut self) -> Result<Option<Vec<u8>>, Stop>;
    fn temp_dir(&mut self) -> Result<Option<Vec<u8>>, Stop>;
    /// `kern.osreleasetype`, as launchd set it (empty before).
    fn os_release_type(&self) -> Vec<u8>;
    fn developer_mode(&self) -> bool;
    /// The operation's numbers: the host special port (kind 7), the reboot
    /// flags, the Unix syscall number (kind 0x14), the MAC syscall's call
    /// number (kind 0x19).
    fn host_special_port(&self) -> u16;
    fn reboot_flags(&self) -> u16;
    fn syscall_number(&self) -> u32;
    fn mac_call(&self) -> u32;
    /// The operation's strings: the MAC syscall's policy name (kind 0x19),
    /// a POSIX IPC name (kind 6).
    fn mac_policy(&self) -> Option<Vec<u8>>;
    fn posix_ipc_name(&self) -> Option<Vec<u8>>;
    /// A vnode operation's vnode type (`enum vtype`) and whether it is a
    /// terminal, none when the operation has no vnode or names a path whose
    /// type is not known yet (a lookup's preflight).
    fn vnode_type(&mut self) -> Result<Option<(u32, bool)>, Stop>;
    /// A vnode operation's path (`0x...3874`: the vnode's path, or the
    /// path the hook gave, made canonical) and its mount point's length in
    /// it (`args[0x160]`: -1 when the path is the mount point); none
    /// without a vnode. An error refuses.
    fn path(&mut self) -> Result<Option<(Vec<u8>, i64)>, Stop> {
        Err(Stop::Unported("sandbox: a vnode operation's path".into()))
    }
    /// A vnode operation's mode bits (`va_mode & 0xfff`), none when the
    /// operation names a path under a directory instead.
    fn vnode_mode(&mut self) -> Result<Option<u16>, Stop> {
        Err(Stop::Unported("sandbox: a vnode's mode".into()))
    }
    /// A vnode operation's extended attribute name (`args[0xe8]`).
    fn xattr_name(&mut self) -> Option<Vec<u8>> {
        None
    }
    /// The operation's object named by a string (`args[0xd8]`) for a kind
    /// that names one (preference domain, kext bundle, notification,
    /// sysctl, MAC policy, POSIX IPC, ...), with its length when the hook
    /// gave one.
    fn object_string(&mut self) -> Option<Vec<u8>> {
        None
    }
    /// A Mach service name operation (kind 7): the name, whether it is a
    /// global name (`args[0xe0]`), and whether an XPC service's
    /// (`args[0xe1]`).
    fn mach_name(&mut self) -> Option<(Vec<u8>, bool, bool)> {
        None
    }
    /// The operation's number for a kind that has one: an fsctl command
    /// (5), an ioctl command (1, 2), a privilege (16).
    fn object_number(&mut self) -> Result<Option<u32>, Stop> {
        Err(Stop::Unported("sandbox: the operation's number".into()))
    }
    /// The subject's executable's path (`proc_getexecutablevnode`); none for
    /// the kernel's process.
    fn process_path(&mut self) -> Result<Option<Vec<u8>>, Stop> {
        Err(Stop::Unported("sandbox: the process's executable path".into()))
    }
    /// The subject's credential's uid.
    fn uid(&mut self) -> Result<u32, Stop> {
        Err(Stop::Unported("sandbox: the credential's uid".into()))
    }
    /// The code signing identifier of the subject (AMFI's, from its
    /// credential), of each process from the subject up while the parent's
    /// pid is at least 2, and of the operation's target process.
    fn signing_identifier(&mut self) -> Result<Option<Vec<u8>>, Stop> {
        Err(Stop::Unported("sandbox: the signing identifier".into()))
    }
    fn ancestor_signing_identifiers(&mut self) -> Result<Vec<Vec<u8>>, Stop> {
        Err(Stop::Unported("sandbox: the ancestors' signing identifiers".into()))
    }
    fn target_signing_identifier(&mut self) -> Result<Option<Vec<u8>>, Stop> {
        Err(Stop::Unported("sandbox: the target's signing identifier".into()))
    }
    /// A vnode operation's file system type name (`vfs_name`), or a mount
    /// operation's (kind 28).
    fn filesystem_name(&mut self) -> Result<Option<Vec<u8>>, Stop> {
        Err(Stop::Unported("sandbox: the file system's name".into()))
    }
    /// The extension class an operation names (`args[0x58]`).
    fn extension_class(&mut self) -> Option<Vec<u8>> {
        None
    }
    /// A filter of a kind this port does not decide yet.
    fn unported(&mut self, what: String) -> Stop {
        Stop::Unported(what)
    }
}

/// The interpreter's state across one evaluation's profiles (the argument
/// block's caches): the entitlement `%entitlement-load` loaded, by the
/// address of the key it was asked for.
#[derive(Default)]
pub struct Scratch {
    loaded: Option<((usize, usize), Option<Value>)>,
}

/// What a terminal's modifiers left for the operation's caller to act on
/// (`0xfffffff006a072f8`'s records): message strings, kept the first time
/// each is set, and a storage class to name for a vnode operation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Effects {
    pub message: Option<Vec<u8>>,
    pub message2: Option<Vec<u8>>,
    pub message3: Option<Vec<u8>>,
    pub storage_class: Option<Vec<u8>>,
}

/// What evaluation came to.
pub enum Outcome {
    Decided(Decision, Effects),
    /// A node of a kind not ported yet: what it is.
    Unported(String),
}

/// A string a profile names: at or past the nodes' end, a length (its NUL
/// counted) and the bytes, the last of them NUL.
fn string_at(b: &[u8], p: &Profile, at: usize) -> Option<Vec<u8>> {
    if at < p.nodes_end {
        return None;
    }
    let n = usize::from(u16_at(b, at)?);
    let s = b.get(at + 2..at + 2 + n)?;
    (n != 0 && s[n - 1] == 0).then(|| s[..n - 1].to_vec())
}

/// Apply one 4-byte modifier record at `at`; false refuses the decision.
fn modify(b: &[u8], p: &Profile, at: usize, d: &mut Decision, fx: &mut Effects, unported: &mut Option<String>) -> bool {
    let Some(r) = b.get(at..at + 4) else { return false };
    let arg = u16::from_le_bytes([r[2], r[3]]);
    let string = || string_at(b, p, p.nodes_end + usize::from(arg) * NODE);
    match r[0] {
        // The decision's errno, for a denial.
        2 => {
            if d.flags & 1 != 0 {
                d.errno = if arg == 0 { 1 } else { u32::from(arg) };
            }
            true
        }
        3..=8 | 13..=16 | 18 => true,
        9 if d.flags & 1 != 0 => {
            fx.message = None;
            true
        }
        9 | 10 | 11 => {
            let Some(s) = string() else { return false };
            let slot = match r[0] {
                9 => &mut fx.message,
                10 => &mut fx.message2,
                _ => &mut fx.message3,
            };
            if slot.is_none() {
                *slot = Some(s);
            }
            true
        }
        // Its class is a vnode operation's, under the platform profile only
        // (the caller's to apply); a bad string refuses wherever it is.
        12 => match string() {
            Some(s) => {
                fx.storage_class = Some(s);
                true
            }
            None => false,
        },
        1 | 17 | 19 => {
            *unported = Some(format!("sandbox modifier {} ({arg})", r[0]));
            true
        }
        // Any other kind is nothing: only a record cut short refuses.
        _ => true,
    }
}

/// A filter's integer compare (`0x...53d4`): the value against the
/// argument, or, with the flag, against the bitmap the argument names (an
/// integer object: kind 1, its size in bytes, its bits). A value past 16
/// bits never matches.
fn int_match(b: &[u8], p: &Profile, flag: bool, arg: u16, value: u64) -> Result<bool, Stop> {
    if value >> 16 != 0 {
        return Ok(false);
    }
    int_match_any(b, p, flag, arg, value)
}

/// The compare's tail (`0x...53e8`), with no 16-bit check.
fn int_match_any(b: &[u8], p: &Profile, flag: bool, arg: u16, value: u64) -> Result<bool, Stop> {
    if !flag {
        return Ok(value == u64::from(arg));
    }
    let r = p.nodes_end + usize::from(arg) * NODE;
    let refused = Stop::Refuse(REFUSED);
    let Some(&object) = b.get(r) else { return Err(refused) };
    if object != 1 {
        return Ok(false);
    }
    let size = usize::from(u16_at(b, r + 2).ok_or(refused.clone())?);
    if r + 4 + size > b.len() {
        return Err(refused);
    }
    let byte = (value / 8) as usize;
    Ok(byte < size && b[r + 4 + byte] >> (value % 8) & 1 != 0)
}

/// libkern's `isspace`.
fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// libkern's `sscanf(s, "%2hhx%2hhx%2hhx%2hhx-%2hhx%2hhx-%2hhx%2hhx-%2hhx%2hhx-
/// %2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%n")` (`vsscanf`'s integer conversion,
/// `libkern/stdio/scanf.c`): the characters it read when every
/// conversion succeeded and it reached the `%n`.
fn scan_uuid(s: &[u8]) -> Option<usize> {
    const SIGNOK: u32 = 0x40;
    const NDIGITS: u32 = 0x80;
    const PFXOK: u32 = 0x100;
    const NZDIGITS: u32 = 0x200;
    let s = &s[..s.iter().position(|&c| c == 0).unwrap_or(s.len())];
    let (mut i, mut inr, mut nread) = (0usize, s.len() as isize, 0usize);
    let at = |i: usize| s.get(i).copied().unwrap_or(0);
    for field in 0..16 {
        if matches!(field, 4 | 6 | 8 | 10) {
            if inr <= 0 || at(i) != b'-' {
                return None;
            }
            inr -= 1;
            i += 1;
            nread += 1;
        }
        if inr <= 0 {
            return None;
        }
        while is_space(at(i)) {
            nread += 1;
            inr -= 1;
            if inr > 0 {
                i += 1;
            } else {
                return None;
            }
        }
        let mut flags = PFXOK | SIGNOK | NDIGITS | NZDIGITS;
        let mut p: Vec<u8> = Vec::new();
        let mut width = 2;
        while width > 0 {
            let c = at(i);
            let ok = match c {
                b'0' => {
                    flags &= if flags & NZDIGITS != 0 { !(SIGNOK | NZDIGITS | NDIGITS) } else { !(SIGNOK | PFXOK | NDIGITS) };
                    true
                }
                b'1'..=b'9' | b'a'..=b'f' | b'A'..=b'F' => {
                    flags &= !(SIGNOK | PFXOK | NDIGITS);
                    true
                }
                b'+' | b'-' if flags & SIGNOK != 0 => {
                    flags &= !SIGNOK;
                    true
                }
                b'x' | b'X' if flags & PFXOK != 0 && p.len() == 1 => {
                    flags &= !PFXOK;
                    true
                }
                _ => false,
            };
            if !ok {
                break;
            }
            p.push(c);
            inr -= 1;
            if inr > 0 {
                i += 1;
            } else {
                break;
            }
            width -= 1;
        }
        if flags & NDIGITS != 0 {
            return None;
        }
        if matches!(p.last(), Some(b'x' | b'X')) {
            p.pop();
            i -= 1;
            inr += 1;
        }
        nread += p.len();
    }
    Some(nread)
}

/// A pattern variable's length at the start of `s` (`0x...81b8`): zero
/// when it does not match there.
fn var_len(v: &Var, s: &[u8], facts: &mut dyn Facts) -> Result<usize, Stop> {
    let prefix = |h: Option<Vec<u8>>| h.filter(|h| s.starts_with(h)).map_or(0, |h| h.len());
    Ok(match v {
        Var::AnyUuid => uuid_len(s),
        Var::AnyPathComponent => s.iter().position(|&c| c == b'/').unwrap_or(s.len()),
        Var::Digits => s.iter().take_while(|c| c.is_ascii_digit()).count(),
        Var::AnyUserHome => {
            let Some(r) = s.strip_prefix(b"/private/var/") else { return Ok(0) };
            if r.starts_with(b"mobile") {
                19
            } else if let Some(u) = r.strip_prefix(b"Users/").map(|u| u.iter().take_while(|&&c| c != b'/').count()).filter(|&k| k > 0) {
                19 + u
            } else if uuid_len(r) == 36 {
                49
            } else if let Some(k) = r.strip_prefix(b"euser").map(|e| e.iter().take_while(|c| c.is_ascii_digit()).count()).filter(|&k| k > 0) {
                18 + k
            } else {
                0
            }
        }
        Var::Home => prefix(facts.home()?),
        Var::FrontUserHome => prefix(facts.front_user_home()?),
        Var::ProcessTempDir => prefix(Some(facts.temp_dir()?.unwrap_or_else(|| b"/private/var/tmp".to_vec()))),
        Var::Entitlement(key) => {
            if key.is_empty() || facts.ensure_cred().is_err() {
                return Ok(0);
            }
            // A user client class must be the whole rest.
            let whole = key == b"com.apple.security.exception.iokit-user-client-class" || key == b"com.apple.security.iokit-user-client-class";
            let fits = |v: &[u8]| s.starts_with(v) && (!whole || v.len() == s.len());
            match facts.entitlement_value(key)? {
                Some(Value::String(v)) if fits(&v) => v.len(),
                Some(Value::Array(a)) => a.iter().find_map(|e| match e {
                    Value::String(v) if fits(v) => Some(v.len()),
                    _ => None,
                }).unwrap_or(0),
                _ => 0,
            }
        }
        Var::Unsupported => 0,
    })
}

/// ANY_UUID: 36 when the scan reads exactly 36 characters.
fn uuid_len(s: &[u8]) -> usize {
    if s.len() >= 36 && scan_uuid(s) == Some(36) { 36 } else { 0 }
}

/// A literal pattern (`0x...6720`): a program of literal runs, pattern
/// variables, scans, byte ranges, conditional skips and one choice point
/// with a stack of positions, run over `s`; it matches when it reaches an
/// accept. Anything out of order ends it without a match.
fn literal(b: &[u8], p: &Profile, at: usize, s: &[u8], facts: &mut dyn Facts) -> Result<bool, Stop> {
    let n = usize::from(u16_at(b, at).ok_or(Stop::Refuse(REFUSED))?);
    let prog = b.get(at + 2..at + 2 + n).ok_or(Stop::Refuse(REFUSED))?;
    if s.len() > 0xffff || n == 0 {
        return Ok(false);
    }
    let slen = s.len();
    let (mut pc, mut pos, mut cond) = (0usize, 0usize, false);
    let mut stack: Vec<usize> = Vec::new();
    let mut choice: Option<(usize, usize)> = None;
    let byte = |i: usize| prog.get(i).copied();
    loop {
        let Some(op) = byte(pc) else { return Ok(false) };
        let step = if op & 0x80 != 0 {
            if cond { 1 } else { usize::from(op & 0x7f) + 2 }
        } else if op & 0x40 != 0 {
            let k = usize::from(op & 0x3f) + 1;
            let Some(lit) = prog.get(pc + 1..pc + 1 + k) else { return Ok(false) };
            cond = s[pos..].starts_with(lit);
            if cond {
                pos += k;
            }
            k + 1
        } else if op & 0x10 != 0 {
            let r = match p.vars.get(usize::from(op & 0xf)) {
                Some(v) => var_len(v, &s[pos..], facts)?,
                None => 0,
            };
            cond = r != 0;
            pos += r;
            1
        } else if op & 0x20 != 0 {
            return Ok(false);
        } else {
            match op {
                0 => {
                    cond = pos == slen;
                    1
                }
                1 => {
                    let (Some(lo), Some(hi)) = (byte(pc + 1), byte(pc + 2)) else { return Ok(false) };
                    let r = match p.vars.get(usize::from(lo) | usize::from(hi) << 8) {
                        Some(v) => var_len(v, &s[pos..], facts)?,
                        None => 0,
                    };
                    cond = r != 0;
                    pos += r;
                    3
                }
                2 | 3 => {
                    let Some(c) = byte(pc + 1) else { return Ok(false) };
                    match s[pos..].iter().position(|&x| x == c) {
                        Some(i) => {
                            pos += i + 1;
                            cond = true;
                            if op == 3 {
                                if choice.is_some() || stack.len() > 31 {
                                    return Ok(false);
                                }
                                stack.push(pos);
                                choice = Some((pc, stack.len()));
                            }
                        }
                        None => cond = false,
                    }
                    2
                }
                4 => {
                    let Some(k) = byte(pc + 1).map(|k| usize::from(k) + 0x41) else { return Ok(false) };
                    let Some(lit) = prog.get(pc + 2..pc + 2 + k) else { return Ok(false) };
                    cond = s[pos..].starts_with(lit);
                    if cond {
                        pos += k;
                    }
                    k + 2
                }
                5 => {
                    let Some(&top) = stack.last() else { return Ok(false) };
                    pos = top;
                    1
                }
                6 => {
                    if stack.len() > 31 {
                        return Ok(false);
                    }
                    stack.push(pos);
                    1
                }
                7 => {
                    if stack.pop().is_none() {
                        return Ok(false);
                    }
                    1
                }
                8 => {
                    let (Some(lo), Some(hi)) = (byte(pc + 1), byte(pc + 2)) else { return Ok(false) };
                    if cond { 3 } else { (usize::from(lo) | usize::from(hi) << 8) + 0x84 }
                }
                10 => return Ok(true),
                11 => {
                    let Some(b2) = byte(pc + 1) else { return Ok(false) };
                    let k = usize::from(b2 & 0x7f) + 1;
                    let Some(ranges) = prog.get(pc + 2..pc + 2 + 2 * k) else { return Ok(false) };
                    loop {
                        cond = pos < slen && ranges.chunks(2).any(|r| r[0] <= s[pos] && s[pos] <= r[1]);
                        if cond {
                            pos += 1;
                        }
                        if !cond || b2 & 0x80 == 0 {
                            break;
                        }
                    }
                    2 * k + 2
                }
                15 => {
                    if cond {
                        1
                    } else {
                        // Back to the choice point, from the position it
                        // kept, to scan on.
                        let Some((cpc, depth)) = choice.take() else { return Ok(false) };
                        if depth > stack.len() || depth == 0 {
                            return Ok(false);
                        }
                        pos = stack[depth - 1];
                        stack.truncate(depth - 1);
                        pc = cpc;
                        continue;
                    }
                }
                _ => return Ok(false),
            }
        };
        let next = pc + step;
        if next <= pc || next >= n {
            return Ok(false);
        }
        pc = next;
    }
}

/// A filter's string compare (`0x...56bc`): the literal pattern the
/// argument names, or with the flag the regex of that index
/// (`0x...6680`).
fn str_match(b: &[u8], p: &Profile, flag: bool, arg: u16, s: &[u8], facts: &mut dyn Facts) -> Result<bool, Stop> {
    if flag {
        let re = p.regexes.get(usize::from(arg)).ok_or(Stop::Refuse(REFUSED))?;
        return match re.matches(s, 0) {
            Ok(f) => Ok(f.id != 0),
            Err(_) => Err(helper_error(1)),
        };
    }
    literal(b, p, p.nodes_end + usize::from(arg) * NODE, s, facts)
}

/// The string a filter names by its argument (`0x...65b4`).
fn operand(b: &[u8], p: &Profile, arg: u16) -> Result<(usize, Vec<u8>), Stop> {
    let at = p.nodes_end + usize::from(arg) * NODE;
    string_at(b, p, at).map(|s| (at, s)).ok_or(Stop::Refuse(REFUSED))
}

/// `kAMFI` entitlement key that keeps a platform binary from counting as
/// Apple-signed.
const CAN_EXECUTE_CDHASH: &[u8] = b"com.apple.private.amfi.can-execute-cdhash";

/// One filter node: whether it matches.
fn filter(b: &[u8], p: &Profile, ty: u8, flag: bool, arg: u16, facts: &mut dyn Facts, scratch: &mut Scratch) -> Result<bool, Stop> {
    let k = facts.kind();
    Ok(match ty {
        // process-attribute.
        43 => {
            facts.ensure_proc()?;
            match arg {
                0 => facts.sandbox_flag_3b()?,
                1 => facts.cs_entitlement_flags()? & 0x8 != 0,
                2 => facts.cs_restricted()?,
                3 => facts.initproc()?,
                4 => facts.platform_binary()?,
                5 => facts.sandboxed(),
                6 => facts.cs_entitlement_flags()? & 0x8000 != 0,
                8 => facts.cs_entitlement_flags()? & 0x8000_0000 != 0,
                // Apple-signed: a platform binary not allowed to run any
                // cdhash.
                9 => facts.entitlement_bool(CAN_EXECUTE_CDHASH)? != Some(true) && facts.platform_binary()?,
                10 => facts.proc_platform()? == 6,
                11 => facts.translated()?,
                12 => facts.protoboxed()?,
                13 => facts.rsr()?,
                14 => facts.persona()?.map_or(true, |(uid, _)| uid == -1),
                _ => false,
            }
        }
        // %entitlement-is-bool-true (86 its other form), %entitlement-is-present.
        86 | 87 | 88 => {
            let (_, key) = operand(b, p, arg)?;
            facts.ensure_cred()?;
            let v = if ty == 88 { facts.entitlement_present(&key)? } else { facts.entitlement_bool(&key)? };
            v == Some(true)
        }
        // require-ancestor-with-entitlement.
        63 => {
            let (_, key) = operand(b, p, arg)?;
            facts.ensure_proc()?;
            facts.ancestor_entitled(&key)?
        }
        // The target process's entitlement.
        66 => {
            if k != kind::PROCESS {
                return Ok(false);
            }
            facts.ensure_target()?;
            let (_, key) = operand(b, p, arg)?;
            facts.target_entitlement_bool(&key)? == Some(true)
        }
        // %entitlement-load: the value, kept for the filters after it.
        30 => {
            let (at, key) = operand(b, p, arg)?;
            let id = (b.as_ptr() as usize, at);
            if scratch.loaded.as_ref().map(|(i, _)| *i) != Some(id) {
                scratch.loaded = None;
                facts.ensure_cred()?;
                scratch.loaded = Some((id, facts.entitlement_value(&key)?));
            }
            matches!(scratch.loaded, Some((_, Some(_))))
        }
        // %entitlement-boolean, %entitlement-string: the loaded value's.
        31 => match scratch.loaded {
            Some((_, Some(Value::Bool(v)))) => int_match_any(b, p, flag, arg, u64::from(v))?,
            _ => false,
        },
        32 => match scratch.loaded.clone() {
            Some((_, Some(Value::String(s)))) => str_match(b, p, flag, arg, &s, facts)?,
            _ => false,
        },
        // system-attribute.
        26 => {
            let has = |w: &[u8]| facts.os_release_type().split(|&c| c == b' ').any(|x| x == w);
            match arg {
                3 => has(b"Internal"),
                4 => has(b"Carrier"),
                6 => has(b"Recovery"),
                7 => facts.developer_mode(),
                9 => has(b"Restore"),
                10 => has(b"Darwin"),
                // 8 is a byte the kext's constant data holds as zero.
                _ => false,
            }
        }
        // persona-type.
        64 => match facts.persona()? {
            Some((_, t)) => int_match(b, p, flag, arg, u64::from(t))?,
            None => false,
        },
        // vnode-type (0xffff: a terminal).
        29 => match facts.vnode_type()? {
            Some((_, true)) if arg == 0xffff => true,
            Some((t, _)) => t == u32::from(arg),
            None => false,
        },
        // host-special-port, syscall-number, mac-syscall-number.
        47 => k == kind::HOST_SPECIAL_PORT && int_match(b, p, flag, arg, u64::from(facts.host_special_port()))?,
        65 => k == kind::SYSCALL_UNIX && int_match(b, p, flag, arg, u64::from(facts.syscall_number()))?,
        82 => k == kind::MAC_SYSCALL && int_match(b, p, flag, arg, u64::from(facts.mac_call()))?,
        // reboot-flags: every flag the argument names.
        54 => arg & !facts.reboot_flags() == 0,
        // mac-policy-name, ipc-posix-name.
        81 | 5 => {
            let (want, s) = if ty == 81 { (kind::MAC_SYSCALL, facts.mac_policy()) } else { (kind::POSIX_IPC, facts.posix_ipc_name()) };
            match s {
                Some(s) if k == want => str_match(b, p, flag, arg, &s, facts)?,
                _ => false,
            }
        }
        // path, mount-relative-path, and the mount point's path.
        1 | 2 | 91 => {
            if k != kind::VNODE {
                return Ok(false);
            }
            let Some((path, mnt)) = facts.path()? else { return Ok(false) };
            let subject: &[u8] = match (ty, mnt) {
                (1, _) | (2, 1) | (91, -1) => &path,
                (2, -1) | (91, 0) => b"/",
                (2, off) => path.get(off as usize..).unwrap_or(&[]),
                (_, off) => path.get(..off as usize).unwrap_or(&path),
            };
            str_match(b, p, flag, arg, subject, facts)?
        }
        // xattr.
        3 => match facts.xattr_name() {
            Some(n) if k == kind::VNODE => str_match(b, p, flag, arg, &n, facts)?,
            _ => false,
        },
        // The vnode's mode: every bit the argument names.
        4 => k == kind::VNODE && facts.vnode_mode()?.is_some_and(|m| arg & !m == 0),
        // global-name, local-name, xpc-service-name.
        6 | 7 | 50 => match facts.mach_name() {
            Some((n, global, xpc)) if k == kind::HOST_SPECIAL_PORT => {
                let wanted = match ty {
                    6 => global,
                    7 => !global,
                    _ => global && xpc,
                };
                wanted && str_match(b, p, flag, arg, &n, facts)?
            }
            _ => false,
        },
        // The operation's object by name, for its kind: 25 (9), 27 (10),
        // preference-domain (11), kext-bundle-id (12), info-type (13),
        // notification-name (14), sysctl-name (15), 49 (18).
        25 | 27 | 28 | 33 | 34 | 35 | 38 | 49 => {
            let want = match ty {
                25 => 9,
                27 => 10,
                28 => 11,
                33 => 12,
                34 => 13,
                35 => 14,
                38 => 15,
                _ => 18,
            };
            match facts.object_string() {
                Some(n) if k == want => str_match(b, p, flag, arg, &n, facts)?,
                _ => false,
            }
        }
        // fsctl-command, privilege-id.
        15 | 42 => {
            let want = if ty == 15 { 5 } else { 16 };
            match facts.object_number()? {
                Some(v) if k == want => int_match(b, p, flag, arg, u64::from(v))?,
                _ => false,
            }
        }
        // extension, storage-class-extension, and the extension ancestry
        // filter: a process without a sandbox has no extensions.
        23 | 56 | 59 if !facts.sandboxed() => false,
        // extension-class.
        24 => match facts.extension_class() {
            Some(c) => str_match(b, p, flag, arg, &c, facts)?,
            None => false,
        },
        // process-path.
        39 => match facts.process_path()? {
            Some(path) => str_match(b, p, flag, arg, &path, facts)?,
            None => false,
        },
        // The credential's uid.
        44 => {
            facts.ensure_cred()?;
            int_match(b, p, flag, arg, u64::from(facts.uid()?))?
        }
        // filesystem-name.
        48 => match facts.filesystem_name()? {
            Some(n) if k == kind::VNODE || k == 28 => str_match(b, p, flag, arg, &n, facts)?,
            _ => false,
        },
        // signing-identifier.
        51 => {
            facts.ensure_cred()?;
            match facts.signing_identifier()? {
                Some(id) => str_match(b, p, flag, arg, &id, facts)?,
                None => false,
            }
        }
        // The target process's signing identifier.
        53 => {
            if k != kind::PROCESS {
                return Ok(false);
            }
            facts.ensure_target()?;
            match facts.target_signing_identifier()? {
                Some(id) => str_match(b, p, flag, arg, &id, facts)?,
                None => false,
            }
        }
        // ancestor-signing-identifier: the subject, then its ancestors.
        62 => {
            facts.ensure_proc()?;
            let mut hit = false;
            for id in facts.ancestor_signing_identifiers()? {
                if str_match(b, p, flag, arg, &id, facts)? {
                    hit = true;
                    break;
                }
            }
            hit
        }
        40 | 46 | 67 => false,
        _ => return Err(facts.unported(format!("sandbox filter type {ty} ({arg})"))),
    })
}

/// Evaluate operation `op` of profile `p` in blob `b`, asking `facts`
/// what each filter node needs.
pub fn evaluate(b: &[u8], p: &Profile, op: usize, facts: &mut dyn Facts, scratch: &mut Scratch) -> Outcome {
    let refused = Outcome::Decided(REFUSED, Effects::default());
    let Some(idx) = (op < OPERATIONS).then(|| u16_at(b, p.ops + 2 * op)).flatten() else { return refused };
    let mut at = p.nodes + usize::from(idx) * NODE;
    loop {
        if at < p.nodes || at >= p.nodes_end || at + NODE > b.len() {
            return refused;
        }
        let n = &b[at..at + NODE];
        match n[0] {
            0 => {
                let ty = n[1] & 0x7f;
                if !(1..=0x5d).contains(&ty) {
                    return refused;
                }
                let arg = u16::from_le_bytes([n[2], n[3]]);
                let matched = match filter(b, p, ty, n[1] & 0x80 != 0, arg, facts, scratch) {
                    Ok(m) => m,
                    Err(Stop::Refuse(d)) => return Outcome::Decided(d, Effects::default()),
                    Err(Stop::Unported(what)) => return Outcome::Unported(what),
                };
                let next = if matched { u16::from_le_bytes([n[4], n[5]]) } else { u16::from_le_bytes([n[6], n[7]]) };
                let to = p.nodes + usize::from(next) * NODE;
                // Only forward.
                if to <= at {
                    return refused;
                }
                at = to;
            }
            1 => {
                let word = u32::from(n[1]) | u32::from(n[2]) << 8 | u32::from(n[3]) << 16;
                let mut fx = Effects::default();
                let mut unported = None;
                // The extended form: its one modifier inline; else as many
                // as byte 4 says, past the nodes.
                let (mut d, records): (Decision, Vec<usize>) = if word & 0x80_0000 != 0 {
                    (Decision { errno: word & 1, flags: word & 0x7f_ffff }, vec![at + 4])
                } else {
                    let d = Decision { errno: word & 1, flags: word & 0xff_ffff };
                    if n[4] == 0 {
                        (d, Vec::new())
                    } else {
                        let first = p.nodes_end + usize::from(u16::from_le_bytes([n[6], n[7]])) * NODE;
                        (d, (0..usize::from(n[4])).map(|k| first + 4 * k).collect())
                    }
                };
                for r in records {
                    if !modify(b, p, r, &mut d, &mut fx, &mut unported) {
                        return refused;
                    }
                }
                if let Some(what) = unported {
                    return Outcome::Unported(what);
                }
                return Outcome::Decided(d, fx);
            }
            _ => return refused,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A single profile blob with no tables and `nodes`, every operation
    /// starting at node `start`.
    fn blob(start: u16, nodes: &[[u8; 8]]) -> Vec<u8> {
        let mut b = vec![0u8; 0xe];
        b[2..4].copy_from_slice(&(nodes.len() as u16).to_le_bytes());
        b[4] = OPERATIONS as u8;
        for _ in 0..OPERATIONS {
            b.extend_from_slice(&start.to_le_bytes());
        }
        b.resize((b.len() + 7) & !7, 0);
        for n in nodes {
            b.extend_from_slice(n);
        }
        b
    }

    /// A subject that answers only the reboot flags (filter type 54).
    pub(super) struct Flags(pub(super) u16);

    impl Facts for Flags {
        fn kind(&self) -> u32 {
            0
        }
        fn ensure_proc(&mut self) -> Result<(), Stop> {
            Ok(())
        }
        fn cs_entitlement_flags(&mut self) -> Result<u32, Stop> {
            Err(Stop::Unported("cs".into()))
        }
        fn cs_restricted(&mut self) -> Result<bool, Stop> {
            Err(Stop::Unported("cs".into()))
        }
        fn initproc(&mut self) -> Result<bool, Stop> {
            Err(Stop::Unported("initproc".into()))
        }
        fn platform_binary(&mut self) -> Result<bool, Stop> {
            Err(Stop::Unported("platform".into()))
        }
        fn proc_platform(&mut self) -> Result<u32, Stop> {
            Err(Stop::Unported("platform".into()))
        }
        fn translated(&mut self) -> Result<bool, Stop> {
            Ok(false)
        }
        fn rsr(&mut self) -> Result<bool, Stop> {
            Ok(false)
        }
        fn sandboxed(&self) -> bool {
            false
        }
        fn protoboxed(&self) -> Result<bool, Stop> {
            Ok(false)
        }
        fn sandbox_flag_3b(&self) -> Result<bool, Stop> {
            Ok(false)
        }
        fn entitlement_bool(&mut self, _: &[u8]) -> Result<Option<bool>, Stop> {
            Ok(None)
        }
        fn entitlement_present(&mut self, _: &[u8]) -> Result<Option<bool>, Stop> {
            Ok(None)
        }
        fn entitlement_value(&mut self, _: &[u8]) -> Result<Option<Value>, Stop> {
            Ok(None)
        }
        fn ancestor_entitled(&mut self, _: &[u8]) -> Result<bool, Stop> {
            Ok(false)
        }
        fn ensure_target(&mut self) -> Result<(), Stop> {
            Err(helper_error(ESRCH))
        }
        fn target_entitlement_bool(&mut self, _: &[u8]) -> Result<Option<bool>, Stop> {
            Ok(None)
        }
        fn persona(&mut self) -> Result<Option<(i32, u32)>, Stop> {
            Ok(None)
        }
        fn home(&mut self) -> Result<Option<Vec<u8>>, Stop> {
            Ok(None)
        }
        fn front_user_home(&mut self) -> Result<Option<Vec<u8>>, Stop> {
            Ok(None)
        }
        fn temp_dir(&mut self) -> Result<Option<Vec<u8>>, Stop> {
            Ok(None)
        }
        fn os_release_type(&self) -> Vec<u8> {
            Vec::new()
        }
        fn developer_mode(&self) -> bool {
            false
        }
        fn host_special_port(&self) -> u16 {
            0
        }
        fn reboot_flags(&self) -> u16 {
            self.0
        }
        fn syscall_number(&self) -> u32 {
            0
        }
        fn mac_call(&self) -> u32 {
            0
        }
        fn mac_policy(&self) -> Option<Vec<u8>> {
            None
        }
        fn posix_ipc_name(&self) -> Option<Vec<u8>> {
            None
        }
        fn vnode_type(&mut self) -> Result<Option<(u32, bool)>, Stop> {
            Ok(None)
        }
    }

    fn eval(b: &[u8], p: &Profile, op: usize, facts: &mut dyn Facts) -> Outcome {
        evaluate(b, p, op, facts, &mut Scratch::default())
    }

    fn deny() -> [u8; 8] {
        [1, 1, 0, 0, 0, 0, 0, 0]
    }

    fn allow() -> [u8; 8] {
        [1, 0, 0, 0, 0, 0, 0, 0]
    }

    #[test]
    fn a_filter_chooses_between_its_two_next_nodes() {
        // Node 0: reboot-flags 7: match -> node 1 (allow), else 2.
        let b = blob(0, &[[0, 54, 7, 0, 1, 0, 2, 0], allow(), deny()]);
        let p = single(&b).unwrap();
        for (flags, errno) in [(0xf, 0), (0x3, 1)] {
            let Outcome::Decided(d, _) = eval(&b, &p, 5, &mut Flags(flags)) else { panic!() };
            assert_eq!(d.errno, errno);
        }
    }

    #[test]
    fn libkerns_scan_reads_a_uuid() {
        assert_eq!(scan_uuid(b"01234567-89ab-cdef-0123-456789ABCDEF/x"), Some(36));
        // One-digit fields and signs read short.
        assert_eq!(scan_uuid(b"1234567-89ab-cdef-0123-456789abcdef0"), Some(35));
        assert_eq!(scan_uuid(b"0x234567-89ab-cdef-0123-456789abcdef"), None);
        assert_eq!(uuid_len(b"01234567-89ab-cdef-0123-456789abcdeg"), 0);
    }

    #[test]
    fn a_subpath_pattern() {
        // subpath "/Applications", as the compiler writes it.
        let prog = b"L/Applications\x0f@/\x80\n\x00\x0f\n";
        let mut b = vec![0u8; 8];
        b.extend_from_slice(&(prog.len() as u16).to_le_bytes());
        b.extend_from_slice(prog);
        let p = Profile { name: 0, flags: 0, ops: 0, nodes: 0, nodes_end: 0, regexes: Vec::new(), vars: Vec::new() };
        let b = &b[..];
        for (s, want) in [(&b"/Applications"[..], true), (b"/Applications/X.app", true), (b"/ApplicationsX", false), (b"/Appl", false)] {
            assert_eq!(literal(&b, &p, 8, s, &mut Flags(0)), Ok(want), "{}", String::from_utf8_lossy(s));
        }
    }

    #[test]
    fn malformed_profiles_are_refused() {
        // A node that leads back to itself.
        let b = blob(0, &[[0, 54, 0, 0, 0, 0, 0, 0]]);
        let p = single(&b).unwrap();
        assert!(matches!(eval(&b, &p, 0, &mut Flags(0)), Outcome::Decided(d, _) if d == REFUSED));
        // A bad opcode, an operation past the table.
        let b = blob(0, &[[7, 0, 0, 0, 0, 0, 0, 0]]);
        let p = single(&b).unwrap();
        assert!(matches!(eval(&b, &p, 0, &mut Flags(0)), Outcome::Decided(d, _) if d == REFUSED));
        assert!(matches!(eval(&b, &p, OPERATIONS, &mut Flags(0)), Outcome::Decided(d, _) if d == REFUSED));
        let mut b = blob(0, &[allow()]);
        b[4] = 0xbe;
        assert_eq!(single(&b), Err(LoadError::OperationCount(0xbe)));
        assert_eq!(collection(&blob(0, &[allow()])), Err(LoadError::WrongFlags));
    }

    #[test]
    fn a_collections_profiles_have_their_own_operation_tables() {
        let mut b = vec![0u8; 0xe];
        b[0..2].copy_from_slice(&0x8000u16.to_le_bytes());
        b[2..4].copy_from_slice(&2u16.to_le_bytes());
        b[4] = OPERATIONS as u8;
        b[8..10].copy_from_slice(&2u16.to_le_bytes());
        for (name, start) in [(9u16, 0u16), (10, 1)] {
            b.extend_from_slice(&name.to_le_bytes());
            b.extend_from_slice(&0u16.to_le_bytes());
            for _ in 0..OPERATIONS {
                b.extend_from_slice(&start.to_le_bytes());
            }
        }
        b.resize((b.len() + 7) & !7, 0);
        b.extend_from_slice(&deny());
        b.extend_from_slice(&allow());
        let ps = collection(&b).unwrap();
        assert_eq!(ps.iter().map(|p| p.name).collect::<Vec<_>>(), vec![9, 10]);
        let errnos: Vec<u32> = ps.iter().map(|p| match eval(&b, p, 0, &mut Flags(0)) {
            Outcome::Decided(d, _) => d.errno,
            Outcome::Unported(_) => 99,
        }).collect();
        assert_eq!(errnos, vec![1, 0]);
    }
}

#[cfg(test)]
mod platform {
    use super::*;

    /// Every operation of a real platform profile (`GEX_SANDBOX_PLATFORM`,
    /// the kernelcache's blob), for a subject that answers little: what
    /// decides and which filters stop it. Not run without it.
    #[test]
    fn a_platform_profiles_operations_evaluate() {
        let Some(path) = std::env::var_os("GEX_SANDBOX_PLATFORM") else { return };
        let b = std::fs::read(path).unwrap();
        let p = single(&b).unwrap();
        // Its eight regexes loaded.
        assert_eq!(p.regexes.len(), 8);
        let (mut decided, mut unported) = (0, std::collections::BTreeMap::new());
        for op in 0..OPERATIONS {
            match evaluate(&b, &p, op, &mut super::tests::Flags(0), &mut Scratch::default()) {
                Outcome::Decided(..) => decided += 1,
                Outcome::Unported(w) => *unported.entry(w).or_insert(0) += 1,
            }
        }
        eprintln!("decided {decided}, unported {unported:?}");
    }
}
