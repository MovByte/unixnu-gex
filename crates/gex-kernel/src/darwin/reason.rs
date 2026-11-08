//! Exit reasons (`bsd/kern/sys_reason.c`): why a process ended, as a
//! namespace and a code, flags, and a kcdata buffer (`kern_cdata.c`) of
//! what was said of it: who sent the signal, a description and payload
//! from userspace. A signal carries one to the thread it is given to; the
//! thread's becomes the process's when the signal ends it.

use crate::GuestMem;
use std::sync::Arc;

/// `OS_REASON_*` namespaces.
pub mod ns {
    pub const JETSAM: u32 = 1;
    pub const SIGNAL: u32 = 2;
}

/// `OS_REASON_FLAG_*`.
pub mod flag {
    pub const NO_CRASH_REPORT: u64 = 0x1;
    pub const GENERATE_CRASH_REPORT: u64 = 0x2;
    pub const FROM_USERSPACE: u64 = 0x4;
    pub const FAILED_DATA_COPYIN: u64 = 0x8;
    pub const PAYLOAD_TRUNCATED: u64 = 0x10;
    pub const BAD_PARAMS: u64 = 0x20;
    pub const CONSISTENT_FAILURE: u64 = 0x40;
    pub const ONE_TIME_FAILURE: u64 = 0x80;
    pub const NO_CRASHED_TID: u64 = 0x100;
    pub const ABORT: u64 = 0x200;
    pub const CAPTURE_LOGS: u64 = 0x800;
    pub const SECURITY_SENSITIVE: u64 = 0x1000;
    /// `OS_REASON_FLAG_MASK_ALLOWED_FROM_USER`.
    pub const ALLOWED_FROM_USER: u64 = CONSISTENT_FAILURE | ONE_TIME_FAILURE | NO_CRASH_REPORT | ABORT | CAPTURE_LOGS | SECURITY_SENSITIVE;
}

/// `JETSAM_REASON_MEMORY_PERPROCESSLIMIT`.
pub const JETSAM_REASON_MEMORY_PERPROCESSLIMIT: u64 = 7;

/// `OS_REASON_BUFFER_MAX_SIZE`.
const BUFFER_MAX_SIZE: u32 = 5120;
/// `KCDATA_BUFFER_BEGIN_OS_REASON`, `KCDATA_TYPE_BUFFER_END`.
const BUFFER_BEGIN_OS_REASON: u32 = 0x53A2_0900;
const TYPE_BUFFER_END: u32 = 0xF191_58ED;
/// `KCDATA_TYPE_PID`, `KCDATA_TYPE_PROCNAME`, `EXIT_REASON_USER_DESC`,
/// `EXIT_REASON_USER_PAYLOAD`.
const TYPE_PID: u32 = 0x36;
const TYPE_PROCNAME: u32 = 0x37;
const USER_DESC: u32 = 0x1002;
const USER_PAYLOAD: u32 = 0x1003;
/// `EXIT_REASON_USER_DESC_MAX_LEN`, `EXIT_REASON_PAYLOAD_MAX_LEN`.
const USER_DESC_MAX_LEN: usize = 1024;
const PAYLOAD_MAX_LEN: u32 = 2048;
/// `sizeof(struct kcdata_item)`, `KCDATA_ALIGNMENT_SIZE`,
/// `KCDATA_FLAGS_STRUCT_HAS_PADDING`.
const ITEM: u32 = 16;
const ALIGNMENT: u32 = 16;
const HAS_PADDING: u64 = 0x80;

/// `sizeof(p_name)`: `2 * MAXCOMLEN + 1`.
pub const P_NAME_LEN: usize = 33;

/// A process's `p_name` as the kernel keeps it: zeroed when the process is
/// made, copied whole at fork, and at each exec the image's name and a NUL
/// written over its start (what was past them stays).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PName(pub [u8; P_NAME_LEN]);

impl Default for PName {
    fn default() -> Self {
        PName([0; P_NAME_LEN])
    }
}

impl PName {
    /// `set_proc_name`: the name, cut to `sizeof(p_name) - 1`, and a NUL.
    pub fn set(&mut self, name: &[u8]) {
        let n = name.len().min(P_NAME_LEN - 1);
        self.0[..n].copy_from_slice(&name[..n]);
        self.0[n] = 0;
    }
}

/// A kcdata buffer filled with `memcpy` (`KCFLAG_USE_MEMCOPY`), its end
/// marker kept after the last item.
#[derive(Clone, Debug)]
struct Kcdata {
    buf: Vec<u8>,
    /// `kcd_addr_end - kcd_addr_begin`.
    end: usize,
}

/// `kcdata_calc_padding`.
fn padding(size: u32) -> u32 {
    size.wrapping_neg() & 0xf
}

/// `kcdata_estimate_required_buffer_size`.
fn estimate(items: u32, payload: u32) -> u32 {
    items * (ALIGNMENT - 1) + items * ITEM + 2 * ITEM + payload
}

impl Kcdata {
    /// `kcdata_memory_static_init`: the BEGIN item; none when `size`
    /// cannot hold it and its end marker.
    fn new(begin: u32, size: u32) -> Option<Kcdata> {
        let mut k = Kcdata { buf: vec![0; size as usize], end: 0 };
        k.item(begin, 0)?;
        Some(k)
    }

    /// `kcdata_get_memory_addr`: an item of `size` bytes, padded to 16, and
    /// the end marker after it; its data's offset, or none when it does
    /// not fit (KERN_INSUFFICIENT_BUFFER_SIZE).
    fn item(&mut self, ty: u32, size: u32) -> Option<usize> {
        let pad = padding(size);
        let flags = u64::from(pad & 0xf) | HAS_PADDING;
        let padded = size + pad;
        let total = padded + ITEM;
        let length = self.buf.len() as u64;
        if u64::from(total) + u64::from(ITEM) > length || length - u64::from(total + ITEM) < self.end as u64 {
            return None;
        }
        let at = self.end;
        self.buf[at..at + 4].copy_from_slice(&ty.to_le_bytes());
        self.buf[at + 4..at + 8].copy_from_slice(&padded.to_le_bytes());
        self.buf[at + 8..at + 16].copy_from_slice(&flags.to_le_bytes());
        self.end += ITEM as usize;
        let data = self.end;
        self.buf[data + size as usize..data + padded as usize].fill(0);
        self.end += padded as usize;
        // kcdata_write_buffer_end.
        let e = self.end;
        self.buf[e..e + 16].fill(0);
        self.buf[e..e + 4].copy_from_slice(&TYPE_BUFFER_END.to_le_bytes());
        Some(data)
    }

    /// `kcdata_memory_get_used_bytes`: the items and the end marker.
    fn used(&self) -> usize {
        self.end + ITEM as usize
    }
}

/// An `os_reason`.
#[derive(Clone, Debug)]
pub struct OsReason {
    pub namespace: u32,
    pub code: u64,
    pub flags: u64,
    kcd: Option<Kcdata>,
}

impl OsReason {
    /// `os_reason_create`: no flags, no buffer.
    pub fn new(namespace: u32, code: u64) -> OsReason {
        OsReason { namespace, code, flags: 0, kcd: None }
    }

    /// `os_reason_alloc_buffer`: a fresh buffer of `size` bytes (none for
    /// zero; EINVAL past the maximum, EIO when it cannot hold its BEGIN
    /// item).
    fn alloc_buffer(&mut self, size: u32) -> Result<(), ()> {
        self.kcd = None;
        if size > BUFFER_MAX_SIZE {
            return Err(());
        }
        if size == 0 {
            return Ok(());
        }
        self.kcd = Some(Kcdata::new(BUFFER_BEGIN_OS_REASON, size).ok_or(())?);
        Ok(())
    }

    /// The buffer's used bytes, as `proc_pidexitreasoninfo` copies them out.
    pub fn data(&self) -> &[u8] {
        self.kcd.as_ref().map_or(&[], |k| &k.buf[..k.used()])
    }

    /// `build_signal_reason(signum, procname)`, sent by process `pid` whose
    /// `p_name` is `name`: OS_REASON_SIGNAL, the signal, the sender's pid
    /// and name (`procname` instead when given; "unknown" for a sender with
    /// no name).
    pub fn signal(signum: u32, pid: i32, name: &[u8; P_NAME_LEN], procname: Option<&[u8]>) -> OsReason {
        let mut r = OsReason::new(ns::SIGNAL, u64::from(signum));
        if r.alloc_buffer(estimate(2, P_NAME_LEN as u32 + 4)).is_err() {
            return r;
        }
        let k = r.kcd.as_mut().expect("a signal reason's buffer");
        if let Some(at) = k.item(TYPE_PID, 4) {
            k.buf[at..at + 4].copy_from_slice(&pid.to_le_bytes());
        }
        if let Some(at) = k.item(TYPE_PROCNAME, P_NAME_LEN as u32) {
            if let Some(p) = procname {
                // strncpy into a buffer of the name's size, its last byte
                // NUL, then that string's length copied.
                let mut t = [0u8; P_NAME_LEN];
                let n = p.iter().position(|&c| c == 0).unwrap_or(p.len()).min(P_NAME_LEN);
                t[..n].copy_from_slice(&p[..n]);
                t[P_NAME_LEN - 1] = 0;
                let len = t.iter().position(|&c| c == 0).unwrap_or(P_NAME_LEN);
                k.buf[at..at + len].copy_from_slice(&t[..len]);
            } else if name[0] != 0 {
                k.buf[at..at + P_NAME_LEN].copy_from_slice(name);
            } else {
                // The kernel copies the bytes of its pointer to "unknown"
                // here (`&default_sender_procname`), not the string: a
                // kernel address no process here has.
                return r;
            }
        }
        r
    }

    /// `build_userspace_exit_reason(namespace, code, payload, payload_size,
    /// reason_string, reason_flags)`: from userspace (only the flags it may
    /// give, and a crash report unless it said none), with the description
    /// and the payload (up to its maximum) read from its memory.
    pub fn userspace(m: &GuestMem<'_>, namespace: u32, code: u64, payload: u64, payload_size: u32, reason_string: u64, reason_flags: u64) -> OsReason {
        let mut r = OsReason::new(namespace, code);
        r.flags |= flag::FROM_USERSPACE;
        r.flags |= reason_flags & flag::ALLOWED_FROM_USER;
        if r.flags & flag::NO_CRASH_REPORT == 0 {
            r.flags |= flag::GENERATE_CRASH_REPORT;
        }
        let (mut items, mut data) = (0u32, 0u32);
        let (mut payload, mut payload_size) = (payload, payload_size);
        if payload != 0 {
            if payload_size == 0 {
                r.flags |= flag::BAD_PARAMS;
                payload = 0;
            } else {
                items += 1;
                if payload_size > PAYLOAD_MAX_LEN {
                    r.flags |= flag::PAYLOAD_TRUNCATED;
                    payload_size = PAYLOAD_MAX_LEN;
                }
                data += payload_size;
            }
        }
        // copyinstr: the string and its NUL; cut to the maximum (its last
        // byte NUL) when it has none in that much.
        let mut desc: Option<Vec<u8>> = None;
        if reason_string != 0 {
            match super::exec::copyinstr(m, reason_string, USER_DESC_MAX_LEN) {
                Ok(mut s) => {
                    s.push(0);
                    items += 1;
                    data += s.len() as u32;
                    desc = Some(s);
                }
                Err(crate::Errno::ENAMETOOLONG) => {
                    let mut s = m.read(reason_string, USER_DESC_MAX_LEN).map(<[u8]>::to_vec).unwrap_or_default();
                    s[USER_DESC_MAX_LEN - 1] = 0;
                    items += 1;
                    data += s.len() as u32;
                    desc = Some(s);
                }
                Err(_) => r.flags |= flag::FAILED_DATA_COPYIN,
            }
        }
        if items != 0 {
            let failed = |r: &mut OsReason| {
                r.flags |= flag::FAILED_DATA_COPYIN;
                let _ = r.alloc_buffer(0);
            };
            if r.alloc_buffer(estimate(items, data)).is_err() {
                failed(&mut r);
                return r;
            }
            let k = r.kcd.as_mut().expect("a userspace reason's buffer");
            if let Some(s) = desc.as_ref().filter(|s| !s.is_empty()) {
                match k.item(USER_DESC, s.len() as u32) {
                    Some(at) => k.buf[at..at + s.len()].copy_from_slice(s),
                    None => {
                        failed(&mut r);
                        return r;
                    }
                }
            }
            if payload != 0 {
                let k = r.kcd.as_mut().expect("a userspace reason's buffer");
                let Some(at) = k.item(USER_PAYLOAD, payload_size) else {
                    failed(&mut r);
                    return r;
                };
                match m.read(payload, payload_size as usize) {
                    Ok(b) => k.buf[at..at + payload_size as usize].copy_from_slice(b),
                    Err(_) => {
                        failed(&mut r);
                        return r;
                    }
                }
            }
        }
        r
    }

    /// A jetsam kill's: OS_REASON_JETSAM and the cause, no buffer.
    pub fn jetsam(code: u64, flags: u64) -> OsReason {
        OsReason { namespace: ns::JETSAM, code, flags, kcd: None }
    }

    /// `struct proc_exitreasonbasicinfo` (packed, 24 bytes).
    pub fn basic_info(&self) -> [u8; 24] {
        let mut b = [0u8; 24];
        b[0..4].copy_from_slice(&self.namespace.to_le_bytes());
        b[4..12].copy_from_slice(&self.code.to_le_bytes());
        b[12..20].copy_from_slice(&self.flags.to_le_bytes());
        b[20..24].copy_from_slice(&(self.data().len() as u32).to_le_bytes());
        b
    }
}

/// A reason as a signal carries it through the generic layers.
pub use crate::signal::Note;

/// The reason a note carries.
pub fn of(note: &Note) -> Option<Arc<OsReason>> {
    Arc::clone(note).downcast::<OsReason>().ok()
}

/// `kernproc`'s pid and `p_name` ("kernel_task", `process_name`'s strlcpy).
pub fn kernproc() -> (i32, [u8; P_NAME_LEN]) {
    let mut n = [0u8; P_NAME_LEN];
    n[..11].copy_from_slice(b"kernel_task");
    (0, n)
}

/// `build_signal_reason(signum, NULL)` with process `pid` the sender, by its
/// published record; none for a process with no Darwin record.
pub fn signal_from_record(procs: &crate::proc::ProcTable, pid: i32, signum: u32) -> Option<Note> {
    let (r, _) = procs.darwin(pid)?;
    let p = r.downcast::<super::procinfo::Public>().ok()?;
    Some(Arc::new(OsReason::signal(signum, pid, &p.p_name.0, None)))
}

/// `OS_REASON_TOTAL_USER_FAULTS_PER_PROC`.
const USER_FAULTS_PER_PROC: u32 = 5;

impl crate::syscalls::Kernel {
    /// `abort_with_payload_internal(namespace, code, payload, payload_size,
    /// reason_string, reason_flags)`: the reason built (an abort's), then
    /// SIGABRT to this thread if it takes it, else to whichever thread
    /// does, carrying it (`psignal_try_thread_with_reason`). For
    /// `os_fault_with_payload` (`user_fault`), a simulated EXC_GUARD instead,
    /// at most five a process (EQFULL after).
    pub(crate) fn darwin_abort_with_payload(&mut self, m: &GuestMem<'_>, a: &[u64; 6], user_fault: bool) -> Result<u64, crate::Errno> {
        use super::signal::dsig;
        const EQFULL: i32 = 106;
        if user_fault {
            if self.dtask.user_faults >= USER_FAULTS_PER_PROC {
                return Err(super::errno::errno_of(EQFULL));
            }
            self.dtask.user_faults += 1;
        }
        let r = OsReason::userspace(m, a[0] as u32, a[1], a[2], a[3] as u32, a[4], a[5] | flag::ABORT);
        if user_fault {
            self.darwin_unimplemented(format!("os_fault_with_payload's simulated EXC_GUARD (task_violated_guard, a corpse) for namespace {} code {:#x}", r.namespace, r.code));
            return Err(super::errno::errno_of(16));
        }
        self.darwin_psignal_try_thread(dsig::SIGABRT, Some(Arc::new(r)));
        Ok(0)
    }

    /// `psignal_try_thread_with_reason(p, current_thread(), d, reason)`:
    /// Darwin signal `d` to this thread if it takes it (it may be masked,
    /// and it has not, or it waits for it), else to whichever thread does;
    /// with no reason given, one naming this process
    /// (`build_signal_reason(d, NULL)`) for a signal that kills.
    pub(crate) fn darwin_psignal_try_thread(&mut self, d: u32, note: Option<Note>) {
        let note = note.unwrap_or_else(|| self.darwin_signal_reason(d));
        let l = super::kern::signal_to_linux(d);
        let bit = 1u64 << (l - 1);
        let me = self.tid;
        let (no_sigmask, waited) = self.dtask.threads.map.get(&me).map_or((false, false), |t| (t.cancel.no_sigmask, t.sigwait & super::signal::sigmask(d) != 0));
        let ts = self.thread_signals.get(me);
        let takes = !no_sigmask && ts.as_ref().is_some_and(|t| t.blocked() & bit == 0 || waited);
        match ts.filter(|_| takes) {
            Some(ts) => {
                // To this thread: told to the knotes as any post is, the
                // reason given it if the signal would kill it.
                self.signals.process().record_post(l);
                if self.darwin_signal_kills(me, &ts, d, false) {
                    ts.set_exit_reason_if_none(|| note);
                }
                let src = crate::signal::Source { code: 0, pid: self.pid, uid: self.creds.uid() };
                self.darwin_note_sender(l, Some(src));
                ts.raise_from(l, src);
                self.darwin_psignal(me, l, false);
            }
            None => self.signals.process().raise_noted(l, None, Some(note)),
        }
    }

    /// `terminate_with_payload_internal(pid, namespace, code, payload,
    /// payload_size, reason_string, reason_flags)`: SIGKILL, carrying the
    /// reason built, to a live process the caller may SIGKILL (an abort's
    /// flag kept only for itself); to itself, on this thread.
    pub(crate) fn darwin_terminate_with_payload(&mut self, m: &GuestMem<'_>, a: &[u64; 6], reason_flags: u64) -> Result<u64, crate::Errno> {
        use super::signal::dsig;
        use crate::Errno;
        let pid = a[0] as i32;
        if pid <= 0 {
            return Err(Errno::EINVAL);
        }
        if self.darwin_public(pid).is_none_or(|(_, zombie)| zombie) {
            return Err(Errno::ESRCH);
        }
        if !self.darwin_cansignal(pid, dsig::SIGKILL, true) {
            return Err(Errno::EPERM);
        }
        let mut reason_flags = reason_flags;
        if pid != self.pid {
            reason_flags &= !flag::ABORT;
        }
        let r = OsReason::userspace(m, a[1] as u32, a[2], a[3], a[4] as u32, a[5], reason_flags | flag::NO_CRASHED_TID);
        let note: Note = Arc::new(r);
        let l = super::kern::signal_to_linux(dsig::SIGKILL);
        if pid == self.pid {
            // psignal_thread_with_reason on this thread.
            if let Some(ts) = self.thread_signals.get(self.tid) {
                ts.set_exit_reason_if_none(|| note);
                ts.raise(l, None);
            }
            return Ok(0);
        }
        let _ = self.procs.kill_noted(self.pid, pid, l, Some(note));
        Ok(0)
    }

    /// `proc_pidexitreasoninfo` for process `pid`: its parent's to ask
    /// (EACCES; no process is traced here), ENOENT for none; the basic
    /// record, or the full one with the kcdata buffer copied to where the
    /// caller's record says (ENOMEM unless it fits).
    pub(crate) fn darwin_pidexitreasoninfo(&mut self, m: &mut GuestMem<'_>, pid: i32, buf: u64, basic: bool) -> Result<u64, i32> {
        if self.procs.ppid(pid) != self.pid {
            return Err(13);
        }
        let Some(r) = self.procs.exit_reason(pid).and_then(|n| of(&n)) else { return Err(2) };
        let data = r.data();
        if basic {
            m.write(buf, &r.basic_info()).map_err(|_| 14)?;
            return Ok(24);
        }
        let eri = m.read(buf, 32).map_err(|_| 14)?.to_vec();
        let size = u32::from_le_bytes(eri[20..24].try_into().unwrap());
        let kcd = u64::from_le_bytes(eri[24..32].try_into().unwrap());
        let mut out = eri.clone();
        out[0..4].copy_from_slice(&r.namespace.to_le_bytes());
        out[4..12].copy_from_slice(&r.code.to_le_bytes());
        out[12..20].copy_from_slice(&r.flags.to_le_bytes());
        if kcd == 0 || (size as usize) < data.len() {
            return Err(12);
        }
        out[20..24].copy_from_slice(&(data.len() as u32).to_le_bytes());
        if !data.is_empty() {
            m.write(kcd, data).map_err(|_| 14)?;
        }
        m.write(buf, &out).map_err(|_| 14)?;
        Ok(32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_signal_reason_is_laid_out_as_kcdata() {
        let mut name = [0u8; P_NAME_LEN];
        name[..4].copy_from_slice(b"kill");
        let r = OsReason::signal(9, 42, &name, None);
        assert_eq!((r.namespace, r.code, r.flags), (ns::SIGNAL, 9, 0));
        let d = r.data();
        // BEGIN (no data), PID (4 bytes padded to 16), PROCNAME (33 padded
        // to 48), and the end marker.
        assert_eq!(d.len(), 16 + 32 + 64 + 16);
        assert_eq!(&d[0..16], &[0x00, 0x09, 0xa2, 0x53, 0, 0, 0, 0, 0x80, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&d[16..24], &[0x36, 0, 0, 0, 16, 0, 0, 0]);
        assert_eq!(u64::from_le_bytes(d[24..32].try_into().unwrap()), 0x80 | 12);
        assert_eq!(&d[32..36], &42i32.to_le_bytes());
        assert_eq!(u32::from_le_bytes(d[48..52].try_into().unwrap()), 0x37);
        assert_eq!(u32::from_le_bytes(d[52..56].try_into().unwrap()), 48);
        assert_eq!(u64::from_le_bytes(d[56..64].try_into().unwrap()), 0x80 | 15);
        assert_eq!(&d[64..68], b"kill");
        assert_eq!(u32::from_le_bytes(d[112..116].try_into().unwrap()), TYPE_BUFFER_END);
    }

    #[test]
    fn a_buffer_too_small_for_its_begin_item_is_none() {
        assert!(Kcdata::new(BUFFER_BEGIN_OS_REASON, 31).is_none());
        assert!(Kcdata::new(BUFFER_BEGIN_OS_REASON, 32).is_some());
    }
}
