//! Linux error numbers, and the negative-return convention.
//!
//! The aarch64 syscall ABI reports failure by returning `-errno` in `x0`, so
//! errors are values here rather than a separate channel.

/// A Linux errno value.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Errno(pub i32);

impl Errno {
    pub const EPERM: Errno = Errno(1);
    pub const ENOENT: Errno = Errno(2);
    pub const ESRCH: Errno = Errno(3);
    pub const EINTR: Errno = Errno(4);
    pub const EDOM: Errno = Errno(33);
    pub const EALREADY: Errno = Errno(114);
    pub const EOWNERDEAD: Errno = Errno(130);
    pub const EIO: Errno = Errno(5);
    pub const ENXIO: Errno = Errno(6);
    pub const E2BIG: Errno = Errno(7);
    pub const EBADF: Errno = Errno(9);
    pub const ECHILD: Errno = Errno(10);
    pub const EAGAIN: Errno = Errno(11);
    pub const ENOEXEC: Errno = Errno(8);
    pub const ENOMEM: Errno = Errno(12);
    pub const EACCES: Errno = Errno(13);
    pub const EFAULT: Errno = Errno(14);
    pub const EBUSY: Errno = Errno(16);
    pub const EEXIST: Errno = Errno(17);
    pub const EXDEV: Errno = Errno(18);
    pub const ENODEV: Errno = Errno(19);
    pub const ENOTDIR: Errno = Errno(20);
    pub const EISDIR: Errno = Errno(21);
    pub const EINVAL: Errno = Errno(22);
    pub const ENFILE: Errno = Errno(23);
    pub const EMFILE: Errno = Errno(24);
    pub const ENOTTY: Errno = Errno(25);
    pub const EFBIG: Errno = Errno(27);
    pub const ENOSPC: Errno = Errno(28);
    pub const ESPIPE: Errno = Errno(29);
    pub const EROFS: Errno = Errno(30);
    pub const EPIPE: Errno = Errno(32);
    pub const ERANGE: Errno = Errno(34);
    pub const EDEADLK: Errno = Errno(35);
    pub const EOVERFLOW: Errno = Errno(75);
    pub const ENAMETOOLONG: Errno = Errno(36);
    pub const ENOSYS: Errno = Errno(38);
    pub const ENOTEMPTY: Errno = Errno(39);
    pub const ELOOP: Errno = Errno(40);
    /// Also `ENOATTR`: no such extended attribute.
    pub const ENODATA: Errno = Errno(61);
    pub const ETIMEDOUT: Errno = Errno(110);
    pub const EOPNOTSUPP: Errno = Errno(95);
    pub const EBADMSG: Errno = Errno(74);
    pub const EAFNOSUPPORT: Errno = Errno(97);
    pub const ECONNREFUSED: Errno = Errno(111);
    pub const EADDRINUSE: Errno = Errno(98);
    /// The same number as EAGAIN on Linux, and the name `flock` uses.
    pub const EWOULDBLOCK: Errno = Errno(11);
    pub const ENOTCONN: Errno = Errno(107);
    pub const EINPROGRESS: Errno = Errno(115);
    pub const EPROTONOSUPPORT: Errno = Errno(93);
    pub const ENETUNREACH: Errno = Errno(101);
    pub const ENOTSOCK: Errno = Errno(88);
    pub const EDESTADDRREQ: Errno = Errno(89);
    pub const EMSGSIZE: Errno = Errno(90);
    pub const EPROTOTYPE: Errno = Errno(91);
    pub const ENOPROTOOPT: Errno = Errno(92);
    pub const ECONNRESET: Errno = Errno(104);
    pub const ENOBUFS: Errno = Errno(105);
    pub const EISCONN: Errno = Errno(106);
    /// Only between a process and the global kernel, never a guest's: a
    /// moved socket another holder connected out (`net::op::WENT_OUT`).
    pub const EREMCHG: Errno = Errno(78);

    /// The value the guest sees in `x0`.
    pub fn as_return(self) -> u64 {
        (-(self.0 as i64)) as u64
    }

    /// A host errno in the numbering guests are answered in, Linux's. The
    /// two systems share only part of theirs.
    pub fn from_host(code: i32) -> Errno {
        if cfg!(target_os = "macos") {
            crate::darwin::errno::errno_of(code)
        } else {
            Errno(code)
        }
    }

    /// Map a host I/O error onto the guest errno. The host's own number
    /// comes first: `ErrorKind` folds `EPERM` into `EACCES`.
    pub fn from_io(e: &std::io::Error) -> Errno {
        use std::io::ErrorKind::*;
        if let Some(code) = e.raw_os_error().filter(|&c| c > 0) {
            return Errno::from_host(code);
        }
        match e.kind() {
            NotFound => Errno::ENOENT,
            PermissionDenied => Errno::EACCES,
            AlreadyExists => Errno::EEXIST,
            InvalidInput => Errno::EINVAL,
            BrokenPipe => Errno::EPIPE,
            WouldBlock => Errno::EAGAIN,
            Interrupted => Errno::EINTR,
            _ => Errno::EIO,
        }
    }
}

/// The result of a syscall that produces a value.
pub type SysResult = Result<u64, Errno>;

/// Convert a syscall result to the `x0` the guest expects.
pub fn encode(r: SysResult) -> u64 {
    match r {
        Ok(v) => v,
        Err(e) => e.as_return(),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_host_error_keeps_its_own_meaning() {
        use super::Errno;
        use std::io::Error;
        assert_eq!(Errno::from_io(&Error::from_raw_os_error(1)), Errno::EPERM);
        assert_eq!(Errno::from_io(&Error::from_raw_os_error(13)), Errno::EACCES);
        let not_empty = if cfg!(target_os = "macos") { 66 } else { 39 };
        assert_eq!(Errno::from_io(&Error::from_raw_os_error(not_empty)), Errno(39));
        let again = if cfg!(target_os = "macos") { 35 } else { 11 };
        assert_eq!(Errno::from_io(&Error::from_raw_os_error(again)), Errno::EAGAIN);
    }

    use super::*;

    #[test]
    fn errors_encode_as_negative() {
        assert_eq!(encode(Err(Errno::ENOENT)) as i64, -2);
        assert_eq!(encode(Err(Errno::ENOSYS)) as i64, -38);
        assert_eq!(encode(Ok(17)), 17);
        // A large successful return must not look like an error.
        assert_eq!(encode(Ok(0x7fff_ffff_ffff_ffff)), 0x7fff_ffff_ffff_ffff);
    }
}
