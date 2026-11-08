//! Pipes as XNU makes them (`bsd/kern/sys_pipe.c`): `pipe()`, a write
//! with `pipe_write`'s rules and `fp_writev`'s answer, and `pipe_stat`.
//! The buffer itself is [`crate::pipe::Pipe`] with XNU's rules
//! ([`crate::pipe::Pipe::new_xnu`]).

use super::sysno as sys;
use crate::errno::Errno;
use crate::file::{OpenFile, PipeEnd};
use crate::fs::oflags;
use crate::pipe::{xnu, Pipe};
use crate::syscalls::{BlockOp, Kernel, SyscallOutcome};
use crate::GuestMem;
use gex_abi::ctx;
use std::sync::atomic::Ordering;
use std::sync::Arc;

/// `FG_NOSIGPIPE`.
pub const FG_NOSIGPIPE: u32 = 0x40;

thread_local! {
    /// The process whose call is running on this thread: what a pipe's
    /// SIGIO is sent from (`pipeselwakeup` in the caller's context).
    static CALLER: std::cell::Cell<i32> = const { std::cell::Cell::new(0) };
}

/// Note the process whose call runs on this thread.
pub fn set_caller(pid: i32) {
    CALLER.with(|c| c.set(pid));
}

/// The process whose call runs on this thread.
pub fn caller() -> i32 {
    CALLER.with(|c| c.get())
}

/// `UIO_MAXIOV`.
const UIO_MAXIOV: u64 = 1024;

impl Kernel {
    /// `pipe()`: the read end in x0, the write end in x1.
    pub(crate) fn darwin_pipe(&mut self, m: &mut GuestMem<'_>) -> Result<u64, Errno> {
        let p = Arc::new(Pipe::new_xnu());
        let r = OpenFile::new(Arc::new(PipeEnd { pipe: Arc::clone(&p), write: false }), "pipe:[0]".into(), oflags::O_RDONLY, true, false);
        let w = OpenFile::new(Arc::new(PipeEnd { pipe: p, write: true }), "pipe:[0]".into(), oflags::O_WRONLY, false, true);
        let rfd = self.fds.insert(r, false)?;
        let wfd = match self.fds.insert(w, false) {
            Ok(fd) => fd,
            Err(e) => {
                let _ = self.fds.close(rfd as i32);
                return Err(e);
            }
        };
        m.write_u64(self.ctx_addr + ctx::x(1) as u64, wfd)?;
        Ok(rfd)
    }

    /// The Darwin pipe descriptor `fd` is on, if it is one.
    pub(crate) fn darwin_pipe_of(&self, fd: u64) -> Option<(Arc<OpenFile>, Arc<Pipe>, bool)> {
        let file = self.fds.get(fd as i32).ok()?;
        let (pipe, write) = file.handle.pipe_end()?;
        pipe.is_xnu().then_some((file, pipe, write))
    }

    /// `write` or `writev` (`raw`) to a Darwin pipe.
    pub(crate) fn darwin_pipe_write(&mut self, m: &mut GuestMem<'_>, raw: u64, a: &[u64; 6]) -> SyscallOutcome {
        match self.darwin_pipe_write_inner(m, raw, a) {
            Ok(out) => out,
            Err(e) => {
                let _ = super::set_result(m, self.ctx_addr, e.as_return());
                SyscallOutcome::Continue
            }
        }
    }

    fn darwin_pipe_write_inner(&mut self, m: &mut GuestMem<'_>, raw: u64, a: &[u64; 6]) -> Result<SyscallOutcome, Errno> {
        let (file, pipe, _) = self.darwin_pipe_of(a[0]).ok_or(Errno::EBADF)?;
        if !file.writable {
            return Err(Errno::EBADF);
        }
        // The bytes, a uio of one vector or of writev's.
        let data = if raw == sys::WRITE || raw == sys::WRITE_NOCANCEL {
            if a[2] > i32::MAX as u64 {
                return Err(Errno::EINVAL);
            }
            m.read(a[1], a[2] as usize)?.to_vec()
        } else {
            let (iov, cnt) = (a[1], a[2] as u32 as u64);
            if cnt == 0 || cnt > UIO_MAXIOV {
                return Err(Errno::EINVAL);
            }
            let mut total = 0u64;
            let mut v = Vec::new();
            for i in 0..cnt {
                let (base, len) = (m.read_u64(iov + 16 * i)?, m.read_u64(iov + 16 * i + 8)?);
                total += len;
                if len > i64::MAX as u64 || total > i32::MAX as u64 {
                    return Err(Errno::EINVAL);
                }
                v.extend_from_slice(m.read(base, len as usize)?);
            }
            v
        };
        let orig = data.len();
        let nosigpipe = file.darwin_lflags.load(Ordering::Acquire) & FG_NOSIGPIPE != 0;
        if let Err(e) = pipe.xnu_begin_write(orig) {
            return Err(self.darwin_write_error(e, nosigpipe));
        }
        let mut done = 0usize;
        // One pass: what fits (pipe_write sleeps when that is not all).
        if orig > 0 {
            match pipe.xnu_write_with(orig, orig, |dst, from| dst.copy_from_slice(&data[from..from + dst.len()])) {
                Ok(n) => done = n as usize,
                Err(Errno::EAGAIN) => {}
                Err(e) => return Err(self.darwin_write_error(e, nosigpipe)),
            }
        }
        if done == orig {
            super::set_result(m, self.ctx_addr, done as u64)?;
            return Ok(SyscallOutcome::Continue);
        }
        // pipe_write's EAGAIN on a non-blocking descriptor, the bytes it put
        // in counted (fp_writev).
        if file.flags() & oflags::O_NONBLOCK != 0 {
            if done == 0 {
                return Err(Errno::EAGAIN);
            }
            super::set_result(m, self.ctx_addr, done as u64)?;
            return Ok(SyscallOutcome::Continue);
        }
        // It sleeps for room and goes on, until all of it is in.
        self.darwin_pipe_sigpipe = Some(!nosigpipe);
        Ok(SyscallOutcome::Blocking(BlockOp::WriteStream {
            handle: Arc::clone(&file.handle),
            buf: 0,
            len: orig - done,
            gathered: Some(data[done..].into()),
            xnu: Some((orig, done as u64)),
        }))
    }

    /// fp_writev's EPIPE: the process takes SIGPIPE unless the descriptor
    /// asked not to.
    fn darwin_write_error(&mut self, e: Errno, nosigpipe: bool) -> Errno {
        if e == Errno::EPIPE && !nosigpipe {
            self.darwin_send_sigpipe();
        }
        e
    }

    /// `psignal(p, SIGPIPE)`.
    pub(crate) fn darwin_send_sigpipe(&mut self) {
        let source = crate::signal::Source { code: crate::signal::SI_USER, pid: self.pid, uid: self.creds.uid() };
        let note = self.darwin_signal_reason(super::signal::dsig::SIGPIPE);
        self.signals.process().raise_noted(crate::signal::sig::SIGPIPE, Some(source), Some(note));
    }

    /// `pipe_stat` for a Darwin pipe descriptor: a FIFO whose size is what
    /// is buffered and whose block size is `MAX_PIPESIZE`.
    pub(crate) fn darwin_pipe_stat(&mut self, m: &mut GuestMem<'_>, fd: u64, buf: u64) -> Result<u64, Errno> {
        let (_, pipe, write) = self.darwin_pipe_of(fd).ok_or(Errno::EBADF)?;
        let (readers, _) = pipe.ends();
        let (size, max, cnt) = pipe.xnu_sizes().expect("a Darwin pipe");
        // The write end has no buffer: its peer's, while there is one.
        let _ = size;
        let (pipe_size, pipe_count) = if !write || readers > 0 { (max, cnt) } else { (0, 0) };
        let pipe_size = if pipe_size == 0 { xnu::PIPE_SIZE.max(xnu::BLOCKS[0]) } else { pipe_size };
        let st = crate::fs::Stat {
            ino: crate::vfs::anon_ino((Arc::as_ptr(&pipe) as usize + usize::from(write)) as *const u8),
            mode: 0o010000 | 0o660,
            uid: self.creds.uid(),
            gid: self.creds.gid(),
            size: pipe_count as i64,
            blksize: pipe_size as i32,
            blocks: ((pipe_count + pipe_size - 1) / pipe_size) as i64,
            ..Default::default()
        };
        m.write(buf, &st.encode_darwin())?;
        Ok(0)
    }
}
