//! A Darwin process's unix stream sockets' sends and receives: `sendit`
//! and `recvit` (`bsd/kern/uipc_syscalls.c`) and the calls that lead to
//! them, `sosend` and `soreceive` (`uipc_socket.c`) over the socket's
//! buffers as `uipc_send` and `uipc_rcvd` keep them ([`crate::unix`]),
//! `unp_internalize` and `unp_externalize` for the descriptors a message
//! carries, and `copyout_control` for the control a receive hands back.
//!
//! A send that must wait before its first byte, and a receive with nothing
//! to read, wait for their socket and are then made again
//! (`Kernel::darwin_retry`): the descriptors they carry come from, or go
//! to, the process's table, which only the kernel has. The rest of a send
//! that stopped part way waits as a pipe write's does
//! ([`BlockOp::WriteStream`]), each round of it `sosend`'s.

use super::sysno as sys;
use crate::errno::{Errno, SysResult};
use crate::file::{InFlight, OpenFile};
use crate::fs::oflags;
use crate::syscalls::{BlockOp, Kernel, SyscallOutcome};
use crate::unix::UnixSocket;
use crate::GuestMem;
use std::sync::Arc;

const UIO_MAXIOV: u64 = 1024;
const INT_MAX: u64 = i32::MAX as u64;
const SOL_SOCKET: u32 = 0xffff;
const SCM_RIGHTS: u32 = 1;
/// `sizeof(struct cmsghdr)`.
const CMSGHDR: usize = 12;
/// `MCLBYTES`: the most control `sockargs` takes, its descriptors widened
/// to pointers.
const MCLBYTES: usize = 2048;
/// A 64-bit process's `struct msghdr`.
const MSGHDR: usize = 48;

/// `MSG_*` (`bsd/sys/socket.h`).
mod msg {
    pub const OOB: u64 = 0x1;
    pub const PEEK: u64 = 0x2;
    pub const EOR: u64 = 0x8;
    pub const CTRUNC: u64 = 0x20;
    pub const WAITALL: u64 = 0x40;
    pub const DONTWAIT: u64 = 0x80;
    pub const WAITSTREAM: u64 = 0x200;
    pub const NBIO: u64 = 0x2_0000;
    pub const SKIPCFIL: u64 = 0x4_0000;
    pub const NOSIGNAL: u64 = 0x8_0000;
}

/// How a socket call ends: with its result, or waiting.
pub(crate) enum Step {
    Done(u64),
    Wait(BlockOp),
}

fn is_send(raw: u64) -> bool {
    matches!(raw, sys::WRITE | sys::WRITE_NOCANCEL | sys::WRITEV | sys::WRITEV_NOCANCEL | sys::SENDTO | sys::SENDTO_NOCANCEL | sys::SENDMSG | sys::SENDMSG_NOCANCEL)
}

/// How much of `[addr, addr + len)` a copy in (`write` false) or out can
/// reach before it faults.
fn reach(m: &mut GuestMem<'_>, addr: u64, len: u64, write: bool) -> u64 {
    const STEP: u64 = 4096;
    let mut at = 0;
    while at < len {
        let n = (STEP - (addr + at) % STEP).min(len - at);
        let ok = if write { m.read_mut(addr + at, n as usize).is_ok() } else { m.read(addr + at, n as usize).is_ok() };
        if !ok {
            break;
        }
        at += n;
    }
    at
}

/// A send gathered as `sendit` has it.
struct Send {
    /// The bytes, of each vector in turn.
    vecs: Vec<(u64, u64)>,
    resid: u64,
    flags: u64,
    /// The control `sockargs` copied in.
    control: Option<Vec<u8>>,
    /// A `write` or `writev` (`soo_write`), whose SIGPIPE only the
    /// socket's `SOF_NOSIGPIPE` forbids; a `sendto` or `sendmsg` (`sendit`)
    /// heeds `MSG_NOSIGNAL` too.
    write: bool,
}

/// A receive gathered as `recvit` has it.
struct Recv {
    vecs: Vec<(u64, u64)>,
    resid: u64,
    flags: u64,
    /// A `recvmsg`'s header, and its `msg_name`, `msg_control` and
    /// `msg_controllen`.
    hdr: Option<(u64, u64, u64, u32)>,
    /// A `recvfrom`'s `from` and `fromlenaddr`.
    from: Option<(u64, u64)>,
}

impl Kernel {
    /// The Darwin unix stream socket behind `fd`, whose buffers are kept
    /// as XNU keeps them.
    pub(crate) fn darwin_xnu_stream(&self, fd: u64) -> Option<(Arc<OpenFile>, Arc<UnixSocket>)> {
        let file = self.fds.get(fd as i32).ok()?;
        let sock = Arc::clone(&file.handle).as_unix_socket()?;
        (sock.stream && sock.is_xnu()).then_some((file, sock))
    }

    /// `write`, `writev`, `sendto` or `sendmsg` (`raw`) on a Darwin unix
    /// stream socket.
    pub(crate) fn darwin_unix_send(&mut self, m: &mut GuestMem<'_>, raw: u64, a: &[u64; 6]) -> SyscallOutcome {
        let r = self.darwin_unix_send_step(m, raw, a);
        self.darwin_socket_end(m, r)
    }

    /// `read`, `readv`, `recvfrom` or `recvmsg` (`raw`) on a Darwin unix
    /// stream socket.
    pub(crate) fn darwin_unix_recv(&mut self, m: &mut GuestMem<'_>, raw: u64, a: &[u64; 6]) -> SyscallOutcome {
        let r = self.darwin_unix_recv_step(m, raw, a);
        self.darwin_socket_end(m, r)
    }

    fn darwin_socket_end(&mut self, m: &mut GuestMem<'_>, r: Result<Step, Errno>) -> SyscallOutcome {
        match r {
            Ok(Step::Wait(op)) => SyscallOutcome::Blocking(op),
            Ok(Step::Done(n)) => {
                let _ = super::set_result(m, self.ctx_addr, n);
                SyscallOutcome::Continue
            }
            Err(e) => {
                let _ = super::set_result(m, self.ctx_addr, e.as_return());
                SyscallOutcome::Continue
            }
        }
    }

    /// A socket call whose wait is over, made again: its result, or the
    /// wait it is in again.
    pub(crate) fn darwin_socket_again(&mut self, m: &mut GuestMem<'_>, raw: u64, a: [u64; 6]) -> Result<SysResult, BlockOp> {
        let r = if is_send(raw) { self.darwin_unix_send_step(m, raw, &a) } else { self.darwin_unix_recv_step(m, raw, &a) };
        match r {
            Ok(Step::Done(n)) => Ok(Ok(n)),
            Ok(Step::Wait(op)) => Err(op),
            Err(e) => Ok(Err(e)),
        }
    }

    /// A send's arguments, checked in the order its call checks them.
    fn darwin_send_args(&mut self, m: &mut GuestMem<'_>, raw: u64, a: &[u64; 6], file: &OpenFile) -> Result<Send, Errno> {
        match raw {
            // dofilewrite: the descriptor's FWRITE, then the length.
            sys::WRITE | sys::WRITE_NOCANCEL => {
                if !file.writable {
                    return Err(Errno::EBADF);
                }
                if a[2] > INT_MAX {
                    return Err(Errno::EINVAL);
                }
                Ok(Send { vecs: vec![(a[1], a[2])], resid: a[2], flags: 0, control: None, write: true })
            }
            sys::WRITEV | sys::WRITEV_NOCANCEL => {
                self.darwin_uio_check(m, true, a)?;
                let vecs = self.darwin_uio_copyin(m, a[1], a[2] as i32)?;
                let resid = vecs.iter().map(|v| v.1).sum();
                Ok(Send { vecs, resid, flags: 0, control: None, write: true })
            }
            // sendto_nocancel, then sendit's address.
            sys::SENDTO | sys::SENDTO_NOCANCEL => {
                if a[4] != 0 {
                    super::sockaddr::get(m, a[4], a[5] as u32 as u64, true)?;
                }
                Ok(Send { vecs: vec![(a[1], a[2])], resid: a[2], flags: a[3] as u32 as u64, control: None, write: false })
            }
            // sendmsg_nocancel: MSG_SKIPCFIL, the header, its vector's
            // count and lengths; then sendit's address and control.
            _ => {
                let flags = a[2] as u32 as u64;
                if flags & msg::SKIPCFIL != 0 {
                    return Err(Errno::EPERM);
                }
                let h = m.read(a[1], MSGHDR)?.to_vec();
                let u64_at = |o: usize| u64::from_le_bytes(h[o..o + 8].try_into().unwrap());
                let u32_at = |o: usize| u32::from_le_bytes(h[o..o + 4].try_into().unwrap());
                let (name, namelen, iov, iovlen, control, controllen) = (u64_at(0), u32_at(8), u64_at(16), u32_at(24) as i32, u64_at(32), u32_at(40));
                if iovlen <= 0 || iovlen as u64 > UIO_MAXIOV {
                    return Err(Errno::EMSGSIZE);
                }
                let vecs = self.darwin_uio_copyin(m, iov, iovlen)?;
                let mut resid = 0u64;
                for &(_, len) in &vecs {
                    if len > i64::MAX as u64 {
                        return Err(Errno::EINVAL);
                    }
                    resid += len;
                    if resid > i64::MAX as u64 {
                        return Err(Errno::EINVAL);
                    }
                }
                if name != 0 {
                    super::sockaddr::get(m, name, u64::from(namelen), true)?;
                }
                let control = if control != 0 {
                    let len = controllen as usize;
                    if len < CMSGHDR {
                        return Err(Errno::EINVAL);
                    }
                    // sockargs: room for the descriptors as pointers.
                    if len > i32::MAX as usize / 2 || (len - CMSGHDR) * 2 + CMSGHDR > MCLBYTES {
                        return Err(Errno::EINVAL);
                    }
                    Some(m.read(control, len)?.to_vec())
                } else {
                    None
                };
                Ok(Send { vecs, resid, flags, control, write: false })
            }
        }
    }

    fn darwin_unix_send_step(&mut self, m: &mut GuestMem<'_>, raw: u64, a: &[u64; 6]) -> Result<Step, Errno> {
        let (file, sock) = self.darwin_xnu_stream(a[0]).ok_or(Errno::EBADF)?;
        let send = self.darwin_send_args(m, raw, a, &file)?;
        let st = file.handle.so_state().ok_or(Errno::ENOTSOCK)?;
        let nosigpipe = Self::darwin_sockopts(&file, &st).nosigpipe || (!send.write && send.flags & msg::NOSIGNAL != 0);
        let r = self.darwin_sosend(m, raw, a, &file, &sock, send);
        match &r {
            // sendit's (or soo_write's) psignal.
            Err(Errno::EPIPE) if !nosigpipe => self.darwin_send_sigpipe(),
            // The rest waits: an EPIPE when it comes back is the same.
            Ok(Step::Wait(BlockOp::WriteStream { .. })) => self.darwin_pipe_sigpipe = Some(!nosigpipe),
            _ => {}
        }
        r
    }

    /// `sosend` of a stream: `sosendcheck`, waiting while there is no room
    /// (but on a non-blocking socket: `SS_NBIO`, or `MSG_NBIO`), then
    /// rounds of passes until all is sent.
    fn darwin_sosend(&mut self, m: &mut GuestMem<'_>, raw: u64, a: &[u64; 6], file: &Arc<OpenFile>, sock: &Arc<UnixSocket>, send: Send) -> Result<Step, Errno> {
        let Send { vecs, resid, flags, control, .. } = send;
        if resid > INT_MAX || flags & msg::EOR != 0 {
            return Err(Errno::EINVAL);
        }
        let nbio = file.flags() & oflags::O_NONBLOCK != 0 || flags & msg::NBIO != 0;
        let resid = resid as usize;
        let clen = control.as_ref().map_or(0, Vec::len);
        if !sock.xnu_sendcheck(resid, clen)? {
            return self.darwin_send_wait(raw, a, file, resid, clen, nbio);
        }
        // The bytes, copied in a pass at a time (uiomove): none readable,
        // and the first pass fails with nothing sent; part way, the passes
        // before the fault would go.
        let mut readable = 0u64;
        for &(base, len) in &vecs {
            let r = reach(m, base, len, false);
            readable += r;
            if r < len {
                if readable > 0 {
                    self.darwin_unimplemented("a send from memory that cannot be read part way (sosend's copy, a pass at a time)".into());
                }
                return Err(Errno::EFAULT);
            }
        }
        let mut data = Vec::with_capacity(resid);
        for &(base, len) in &vecs {
            data.extend_from_slice(m.read(base, len as usize)?);
        }
        // uipc_send: no urgent data (EOPNOTSUPP, not ENOTSUP); the
        // control's descriptors.
        if flags & msg::OOB != 0 {
            return Err(super::errno::EOPNOTSUPP);
        }
        let control = match control {
            Some(c) => Some((c.len(), self.darwin_unp_internalize(&c)?)),
            None => None,
        };
        let mut sent = match sock.xnu_send(&data, control) {
            Ok(n) => n,
            // Another sender took the room since: the wait after all, the
            // descriptors' holds let go with the control.
            Err(Errno::EAGAIN) => return self.darwin_send_wait(raw, a, file, resid, clen, nbio),
            Err(e) => return Err(e),
        };
        // More rounds while there is room.
        while sent < resid {
            match sock.xnu_send(&data[sent..], None) {
                Ok(n) => sent += n,
                Err(Errno::EAGAIN) => break,
                Err(e) => return Err(e),
            }
        }
        if sent == resid {
            return Ok(Step::Done(sent as u64));
        }
        // sendit: EWOULDBLOCK only when no byte went (a first round of
        // control alone counts none).
        if nbio {
            return if sent == 0 { Err(Errno::EAGAIN) } else { Ok(Step::Done(sent as u64)) };
        }
        // The rest waits for room, a round of sosend each time there is.
        Ok(Step::Wait(BlockOp::WriteStream {
            handle: Arc::clone(&file.handle),
            buf: 0,
            len: resid - sent,
            gathered: Some(data[sent..].into()),
            xnu: Some((resid, sent as u64)),
        }))
    }

    /// No room before a send's first byte: EWOULDBLOCK on a non-blocking
    /// socket, else the wait, the call made again after it.
    fn darwin_send_wait(&mut self, raw: u64, a: &[u64; 6], file: &Arc<OpenFile>, resid: usize, clen: usize, nbio: bool) -> Result<Step, Errno> {
        if nbio {
            return Err(Errno::EAGAIN);
        }
        self.darwin_retry = Some((raw, *a));
        Ok(Step::Wait(BlockOp::WriteWait { handle: Arc::clone(&file.handle), resid, clen }))
    }

    /// `unp_internalize`: one `SCM_RIGHTS` message, its length the
    /// control's; each descriptor open (EBADF), of a kind a message carries
    /// (`fg_sendable`: EINVAL), and not guarded against it (its guard's
    /// exception); each then held in flight.
    fn darwin_unp_internalize(&mut self, c: &[u8]) -> Result<Vec<InFlight>, Errno> {
        let word = |o: usize| u32::from_le_bytes(c[o..o + 4].try_into().unwrap());
        if word(8) != SCM_RIGHTS || word(4) != SOL_SOCKET || word(0) as usize != c.len() {
            return Err(Errno::EINVAL);
        }
        let n = (c.len() - CMSGHDR) / 4;
        let fds: Vec<i32> = (0..n).map(|i| word(CMSGHDR + 4 * i) as i32).collect();
        for &fd in &fds {
            let f = self.fds.get(fd).map_err(|_| Errno::EBADF)?;
            if !super::procinfo::fg_sendable(&f) {
                return Err(Errno::EINVAL);
            }
            if let Some(g) = self.fds.guard(fd).filter(|g| g.has(super::guarded::attr::SOCKET_IPC)) {
                return Err(self.darwin_fp_guard_exception(fd, g, super::guarded::flavor::SOCKET_IPC));
            }
        }
        fds.iter().map(|&fd| self.fds.get_held(fd)).collect()
    }

    /// A receive's arguments, checked in the order its call checks them.
    fn darwin_recv_args(&mut self, m: &mut GuestMem<'_>, raw: u64, a: &[u64; 6], file: &OpenFile) -> Result<Recv, Errno> {
        match raw {
            sys::READ | sys::READ_NOCANCEL => {
                if !file.readable {
                    return Err(Errno::EBADF);
                }
                if a[2] > INT_MAX {
                    return Err(Errno::EINVAL);
                }
                Ok(Recv { vecs: vec![(a[1], a[2])], resid: a[2], flags: 0, hdr: None, from: None })
            }
            sys::READV | sys::READV_NOCANCEL => {
                self.darwin_uio_check(m, false, a)?;
                let vecs = self.darwin_uio_copyin(m, a[1], a[2] as i32)?;
                let resid = vecs.iter().map(|v| v.1).sum();
                Ok(Recv { vecs, resid, flags: 0, hdr: None, from: None })
            }
            // recvfrom_nocancel: its address's length in, then recvit's
            // limit.
            sys::RECVFROM | sys::RECVFROM_NOCANCEL => {
                if a[5] != 0 {
                    m.read_u32(a[5])?;
                }
                if a[2] > INT_MAX {
                    return Err(Errno::EINVAL);
                }
                Ok(Recv { vecs: vec![(a[1], a[2])], resid: a[2], flags: a[3] as u32 as u64, hdr: None, from: Some((a[4], a[5])) })
            }
            // recvmsg_nocancel: the header, its vector's count and
            // lengths; then recvit's limit.
            _ => {
                let h = m.read(a[1], MSGHDR)?.to_vec();
                let u64_at = |o: usize| u64::from_le_bytes(h[o..o + 8].try_into().unwrap());
                let u32_at = |o: usize| u32::from_le_bytes(h[o..o + 4].try_into().unwrap());
                let (name, iov, iovlen, control, controllen) = (u64_at(0), u64_at(16), u32_at(24) as i32, u64_at(32), u32_at(40));
                if iovlen <= 0 || iovlen as u64 > UIO_MAXIOV {
                    return Err(Errno::EMSGSIZE);
                }
                let vecs = self.darwin_uio_copyin(m, iov, iovlen)?;
                let mut resid = 0u64;
                for &(_, len) in &vecs {
                    if len > i64::MAX as u64 {
                        return Err(Errno::EINVAL);
                    }
                    resid += len;
                    if resid > i64::MAX as u64 {
                        return Err(Errno::EINVAL);
                    }
                }
                if resid > INT_MAX {
                    return Err(Errno::EINVAL);
                }
                Ok(Recv { vecs, resid, flags: a[2] as u32 as u64, hdr: Some((a[1], name, control, controllen)), from: None })
            }
        }
    }

    fn darwin_unix_recv_step(&mut self, m: &mut GuestMem<'_>, raw: u64, a: &[u64; 6]) -> Result<Step, Errno> {
        let (file, sock) = self.darwin_xnu_stream(a[0]).ok_or(Errno::EBADF)?;
        let Recv { vecs, resid, flags, hdr, from } = self.darwin_recv_args(m, raw, a, &file)?;
        // soreceive: urgent data is not a unix socket's (pru_rcvoob's
        // EOPNOTSUPP).
        if flags & msg::OOB != 0 {
            return Err(super::errno::EOPNOTSUPP);
        }
        let peek = flags & msg::PEEK != 0;
        let nbio = file.flags() & oflags::O_NONBLOCK != 0 || flags & (msg::DONTWAIT | msg::NBIO) != 0;
        // MSG_WAITALL and MSG_WAITSTREAM wait on for more than one record
        // holds.
        if flags & (msg::WAITALL | msg::WAITSTREAM) != 0 && sock.xnu_would_wait_all(resid as usize) {
            self.darwin_unimplemented("MSG_WAITALL or MSG_WAITSTREAM on a unix stream waiting for more than it holds".into());
            return Err(Errno::EOPNOTSUPP);
        }
        // The copy out (uiomove) of what is taken.
        for &(base, len) in &vecs {
            if reach(m, base, len, true) < len {
                self.darwin_unimplemented("a receive into memory that cannot be written (soreceive's copy, an mbuf at a time)".into());
                return Err(Errno::EFAULT);
            }
        }
        // unp_externalize: every descriptor into the table, or none
        // (EMSGSIZE, the descriptors let go).
        let mut installed: Vec<i32> = Vec::new();
        let fds = &self.fds;
        let mut externalize = |files: Vec<InFlight>| -> Result<(), Errno> {
            let opened: Vec<Arc<OpenFile>> = files.iter().map(|f| Arc::clone(f.file())).collect();
            installed = fds.insert_all(opened).map_err(|_| Errno::EMSGSIZE)?;
            Ok(())
        };
        let out = match sock.xnu_recv(resid as usize, peek, &mut externalize) {
            Ok(out) => out,
            Err(Errno::EAGAIN) => {
                // Nothing to read: nothing asked for is done at once, a
                // non-blocking socket says so, else the wait, the call
                // made again after it.
                if resid == 0 {
                    return Ok(Step::Done(0));
                }
                if nbio {
                    return Err(Errno::EAGAIN);
                }
                self.darwin_retry = Some((raw, *a));
                return Ok(Step::Wait(BlockOp::AcceptWait { socket: Arc::clone(&file.handle) }));
            }
            Err(e) => return Err(e),
        };
        let n = out.data.len();
        let mut at = 0usize;
        for &(base, len) in &vecs {
            if at == n {
                break;
            }
            let take = (len as usize).min(n - at);
            m.write(base, &out.data[at..at + take])?;
            at += take;
        }
        // recvit: no address for a stream's sender (copyout_sa of none).
        if let Some((from, lenp)) = from {
            if from != 0 && lenp != 0 {
                m.write_u32(lenp, 0)?;
            }
        }
        if let Some((msghdr, name, control, controllen)) = hdr {
            let mut flags_out = flags;
            if name != 0 {
                m.write_u32(msghdr + 8, 0)?;
            }
            if control != 0 {
                let copied = match out.control {
                    Some(len) => {
                        // The message as externalized (its descriptors) or,
                        // peeked, as sopeek_scm_rights leaves it (none).
                        let mut cm = Vec::with_capacity(len);
                        cm.extend_from_slice(&(len as u32).to_le_bytes());
                        cm.extend_from_slice(&SOL_SOCKET.to_le_bytes());
                        cm.extend_from_slice(&SCM_RIGHTS.to_le_bytes());
                        for fd in &installed {
                            cm.extend_from_slice(&fd.to_le_bytes());
                        }
                        cm.resize(len, 0);
                        // copyout_control: what fits of CMSG_ALIGN(cmsg_len).
                        let size = (len + 3) & !3;
                        if size > len {
                            self.darwin_unimplemented("a received control message whose length is not 4-byte aligned".into());
                            return Err(Errno::EINVAL);
                        }
                        let tocopy = (controllen as usize).min(size);
                        if tocopy < size {
                            flags_out |= msg::CTRUNC;
                        }
                        m.write(control, &cm[..tocopy])?;
                        tocopy as u32
                    }
                    None => 0,
                };
                m.write_u32(msghdr + 40, copied)?;
            }
            m.write_u32(msghdr + 44, flags_out as u32)?;
        }
        Ok(Step::Done(n as u64))
    }
}
