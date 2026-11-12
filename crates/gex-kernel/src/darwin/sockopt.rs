//! A socket's socket-level options as XNU keeps them (`sosetoptlock`,
//! `sogetoptlock` in `bsd/kern/uipc_socket.c`; `setsockopt` and `getsockopt`
//! in `bsd/kern/uipc_syscalls.c`): the `so_options` bits, `so_linger`, and
//! the buffers' high- and low-water marks, which the kqueue socket filters
//! (and so `select` and `poll`) read. An option whose effect the transports
//! here do not carry is reported where it would take effect.

use crate::errno::Errno;
use crate::syscalls::Kernel;
use crate::vfs::SoState;
use crate::GuestMem;

/// `SOL_SOCKET`.
pub const SOL_SOCKET: u64 = 0xffff;
/// `IPPROTO_TCP`, and its `TCP_NODELAY`.
const IPPROTO_TCP: u64 = 6;
const TCP_NODELAY: u32 = 1;
/// `TF_NODELAY`, the `t_flags` bit TCP_NODELAY reads back as.
const TF_NODELAY: u32 = 0x4;

/// The socket-level option names.
pub mod so {
    pub const DEBUG: u32 = 0x0001;
    pub const ACCEPTCONN: u32 = 0x0002;
    pub const REUSEADDR: u32 = 0x0004;
    pub const KEEPALIVE: u32 = 0x0008;
    pub const DONTROUTE: u32 = 0x0010;
    pub const BROADCAST: u32 = 0x0020;
    pub const USELOOPBACK: u32 = 0x0040;
    pub const LINGER: u32 = 0x0080;
    pub const OOBINLINE: u32 = 0x0100;
    pub const REUSEPORT: u32 = 0x0200;
    pub const SNDBUF: u32 = 0x1001;
    pub const RCVBUF: u32 = 0x1002;
    pub const SNDLOWAT: u32 = 0x1003;
    pub const RCVLOWAT: u32 = 0x1004;
    pub const NOSIGPIPE: u32 = 0x1022;
    pub const LINGER_SEC: u32 = 0x1080;
}

/// `SB_MAX` (`kern.ipc.maxsockbuf`'s default): no buffer is reserved past it.
const SB_MAX: u32 = 8192 * 1024;
/// `MCLBYTES`.
const MCLBYTES: u32 = 2048;
/// `hz`: SO_LINGER_SEC's seconds are kept in ticks.
const HZ: i64 = 100;
/// Marks an IPPROTO_TCP option's name apart from the socket-level ones.
const TCP_LEVEL: u32 = 0x8000_0000;
/// `ENOBUFS`, in the canonical numbering the errors here are carried in.
const ENOBUFS: Errno = Errno(105);

/// The options of one socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SockOpts {
    /// `so_options`, of the bits these options set.
    pub options: u32,
    /// `so_linger`, in ticks.
    pub linger: i16,
    /// The receive and send buffers' `sb_hiwat` and `sb_lowat`.
    pub rcv_hiwat: u32,
    pub snd_hiwat: u32,
    pub rcv_lowat: u32,
    pub snd_lowat: u32,
    /// A TCP socket's `TF_NODELAY`.
    pub tcp_nodelay: bool,
    /// `so_flags`' `SOF_NOSIGPIPE`: a send's EPIPE raises no SIGPIPE.
    pub nosigpipe: bool,
}

impl SockOpts {
    /// A socket as its protocol attached it (`soreserve`): its buffers'
    /// sizes, a receive low-water mark of 1, a send one of MCLBYTES (1 for
    /// a unix datagram socket) no higher than the send buffer.
    pub fn attached(st: &SoState) -> SockOpts {
        let snd_hiwat = st.hiwat.1.min(u64::from(SB_MAX)) as u32;
        SockOpts {
            options: 0,
            linger: 0,
            rcv_hiwat: st.hiwat.0.min(u64::from(SB_MAX)) as u32,
            snd_hiwat,
            rcv_lowat: 1,
            snd_lowat: (st.snd_lowat as u32).min(snd_hiwat),
            tcp_nodelay: false,
            nosigpipe: false,
        }
    }
}

/// `sbreserve`: a buffer's high-water mark set to `cc` (no more than
/// `sb_max`; refused when it already is that), its low-water mark kept
/// below it.
fn sbreserve(hiwat: &mut u32, lowat: &mut u32, cc: u32) -> bool {
    let mut cc = cc;
    if cc > SB_MAX {
        if *hiwat == SB_MAX {
            return false;
        }
        cc = SB_MAX;
    }
    *hiwat = cc;
    if *lowat > *hiwat {
        *lowat = *hiwat;
    }
    true
}

impl Kernel {
    /// The socket behind `fd` and its options (`file_socket`): EBADF for
    /// no descriptor, ENOTSOCK for one that is not a socket.
    fn darwin_socket_opts(&self, fd: i32) -> Result<(std::sync::Arc<crate::file::OpenFile>, SoState), Errno> {
        let file = self.fds.get(fd)?;
        let st = file.handle.so_state().ok_or(Errno::ENOTSOCK)?;
        Ok((file, st))
    }

    /// The options of a socket's open file, as they are now.
    pub(crate) fn darwin_sockopts(file: &crate::file::OpenFile, st: &SoState) -> SockOpts {
        let g = file.darwin_sockopt.lock().unwrap_or_else(|e| e.into_inner());
        g.unwrap_or_else(|| SockOpts::attached(st))
    }

    /// `setsockopt(s, level, name, val, valsize)` for the socket-level
    /// options kept here; `None` for any other.
    pub(crate) fn darwin_setsockopt(&mut self, m: &GuestMem<'_>, a: &[u64; 6]) -> Option<Result<u64, Errno>> {
        let (fd, level, name, val, valsize) = (a[0] as i32, a[1] & 0xffff_ffff, a[2] as u32, a[3], a[4] as u32 as u64);
        if level == IPPROTO_TCP {
            return self.darwin_tcp_option(fd, name).map(|r| r.and_then(|()| self.darwin_setsockopt_in(m, fd, name | TCP_LEVEL, val, valsize)));
        }
        if level != SOL_SOCKET || !handled(name) {
            return None;
        }
        Some(self.darwin_setsockopt_in(m, fd, name, val, valsize))
    }

    fn darwin_setsockopt_in(&mut self, m: &GuestMem<'_>, fd: i32, name: u32, val: u64, valsize: u64) -> Result<u64, Errno> {
        if val == 0 && valsize != 0 {
            return Err(Errno::EFAULT);
        }
        let (file, st) = self.darwin_socket_opts(fd)?;
        // A socket shut down both ways takes no more options.
        if st.cantrcv && st.cantsend {
            return Err(Errno::EINVAL);
        }
        // sooptcopyin: at least `min` bytes, no more than `len` read.
        let copyin = |len: u64| -> Result<Vec<u8>, Errno> {
            if valsize < len {
                return Err(Errno::EINVAL);
            }
            Ok(m.read(val, len as usize)?.to_vec())
        };
        let mut o = Self::darwin_sockopts(&file, &st);
        match name {
            so::LINGER | so::LINGER_SEC => {
                let b = copyin(8)?;
                let (onoff, secs) = (i32::from_le_bytes(b[0..4].try_into().unwrap()), i32::from_le_bytes(b[4..8].try_into().unwrap()));
                if onoff != 0 {
                    self.darwin_unimplemented("SO_LINGER turned on (an abortive or lingering close)".into());
                    return Err(Errno::ENOPROTOOPT);
                }
                o.linger = if name == so::LINGER { secs as i16 } else { (i64::from(secs) * HZ) as i16 };
                o.options &= !so::LINGER;
            }
            so::DEBUG | so::KEEPALIVE | so::DONTROUTE | so::USELOOPBACK | so::BROADCAST | so::REUSEADDR | so::REUSEPORT | so::OOBINLINE => {
                let on = i32::from_le_bytes(copyin(4)?[..4].try_into().unwrap()) != 0;
                if on && matches!(name, so::DONTROUTE | so::OOBINLINE) {
                    let what = if name == so::DONTROUTE { "SO_DONTROUTE turned on (routing around the tables)" } else { "SO_OOBINLINE turned on (urgent data in line)" };
                    self.darwin_unimplemented(what.into());
                    return Err(Errno::ENOPROTOOPT);
                }
                if on {
                    o.options |= name;
                } else {
                    o.options &= !name;
                }
            }
            so::SNDBUF | so::RCVBUF | so::SNDLOWAT | so::RCVLOWAT => {
                let v = i32::from_le_bytes(copyin(4)?[..4].try_into().unwrap());
                if v < 1 {
                    return Err(Errno::EINVAL);
                }
                let v = v as u32;
                match name {
                    so::SNDBUF => {
                        if !sbreserve(&mut o.snd_hiwat, &mut o.snd_lowat, v) {
                            return Err(ENOBUFS);
                        }
                    }
                    so::RCVBUF => {
                        if !sbreserve(&mut o.rcv_hiwat, &mut o.rcv_lowat, v) {
                            return Err(ENOBUFS);
                        }
                    }
                    so::SNDLOWAT => {
                        // A unix stream's send space is its peer's receive
                        // buffer, counted with what waits there.
                        let hiwat = if st.unix_stream { o.snd_hiwat.saturating_add(st.snd_used as u32) } else { o.snd_hiwat };
                        o.snd_lowat = v.min(hiwat);
                    }
                    _ => {
                        let lowat = v.min(o.rcv_hiwat);
                        // soreceive waits for this much before a blocking
                        // read returns, which the reads here do not.
                        if lowat > 1 {
                            self.darwin_unimplemented(format!("SO_RCVLOWAT {lowat} (a blocking receive waiting for it)"));
                            return Err(Errno::ENOPROTOOPT);
                        }
                        o.rcv_lowat = lowat;
                    }
                }
            }
            n if n == TCP_NODELAY | TCP_LEVEL => o.tcp_nodelay = i32::from_le_bytes(copyin(4)?[..4].try_into().unwrap()) != 0,
            so::NOSIGPIPE => o.nosigpipe = i32::from_le_bytes(copyin(4)?[..4].try_into().unwrap()) != 0,
            _ => unreachable!("an option kept here"),
        }
        *file.darwin_sockopt.lock().unwrap_or_else(|e| e.into_inner()) = Some(o);
        Ok(0)
    }

    /// `getsockopt(s, level, name, val, avalsize)` for the socket-level
    /// options kept here (and SO_ACCEPTCONN, which XNU's has no case for);
    /// `None` for any other.
    pub(crate) fn darwin_getsockopt(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Option<Result<u64, Errno>> {
        let (fd, level, name, val, avalsize) = (a[0] as i32, a[1] & 0xffff_ffff, a[2] as u32, a[3], a[4]);
        if level == IPPROTO_TCP {
            return self.darwin_tcp_option(fd, name).map(|r| r.and_then(|()| self.darwin_getsockopt_in(m, fd, name | TCP_LEVEL, val, avalsize)));
        }
        if level != SOL_SOCKET || !(handled(name) || name == so::ACCEPTCONN) {
            return None;
        }
        Some(self.darwin_getsockopt_in(m, fd, name, val, avalsize))
    }

    fn darwin_getsockopt_in(&mut self, m: &mut GuestMem<'_>, fd: i32, name: u32, val: u64, avalsize: u64) -> Result<u64, Errno> {
        let (file, st) = self.darwin_socket_opts(fd)?;
        let valsize = if val != 0 { u64::from(m.read_u32(avalsize)?) } else { 0 };
        let o = Self::darwin_sockopts(&file, &st);
        let bytes: Vec<u8> = match name {
            so::LINGER | so::LINGER_SEC => {
                let onoff = i32::from(o.options & so::LINGER != 0);
                let l = if name == so::LINGER { i32::from(o.linger) } else { (i64::from(o.linger) / HZ) as i32 };
                [onoff.to_le_bytes(), l.to_le_bytes()].concat()
            }
            // The option's own bit, not 1.
            so::DEBUG | so::KEEPALIVE | so::DONTROUTE | so::USELOOPBACK | so::BROADCAST | so::REUSEADDR | so::REUSEPORT | so::OOBINLINE => (o.options & name).to_le_bytes().to_vec(),
            so::SNDBUF => {
                let hiwat = if st.unix_stream { o.snd_hiwat.saturating_add(st.snd_used as u32) } else { o.snd_hiwat };
                hiwat.to_le_bytes().to_vec()
            }
            so::RCVBUF => o.rcv_hiwat.to_le_bytes().to_vec(),
            so::SNDLOWAT => o.snd_lowat.to_le_bytes().to_vec(),
            so::RCVLOWAT => o.rcv_lowat.to_le_bytes().to_vec(),
            n if n == TCP_NODELAY | TCP_LEVEL => (if o.tcp_nodelay { TF_NODELAY } else { 0 }).to_le_bytes().to_vec(),
            // so_flags & SOF_NOSIGPIPE, which is 1.
            so::NOSIGPIPE => i32::from(o.nosigpipe).to_le_bytes().to_vec(),
            _ => return Err(Errno::ENOPROTOOPT),
        };
        // sooptcopyout: as much as there is room for, and that much said.
        let n = (bytes.len() as u64).min(valsize);
        if val != 0 {
            m.write(val, &bytes[..n as usize])?;
        }
        m.write_u32(avalsize, n as u32)?;
        Ok(0)
    }

    /// `sock_setsockopt(so, SOL_SOCKET, SO_NOSIGPIPE, &on)` from the kernel
    /// (`F_SETNOSIGPIPE` on a socket): sosetoptlock's check of a socket
    /// shut down both ways, then the flag.
    pub(crate) fn darwin_so_set_nosigpipe(&mut self, fd: i32, on: bool) -> Result<(), Errno> {
        let (file, st) = self.darwin_socket_opts(fd)?;
        if st.cantrcv && st.cantsend {
            return Err(Errno::EINVAL);
        }
        let mut o = Self::darwin_sockopts(&file, &st);
        o.nosigpipe = on;
        *file.darwin_sockopt.lock().unwrap_or_else(|e| e.into_inner()) = Some(o);
        Ok(())
    }

    /// Whether `fd` is a socket with `SOF_NOSIGPIPE`.
    pub(crate) fn darwin_so_nosigpipe(&self, fd: i32) -> bool {
        self.darwin_socket_opts(fd).is_ok_and(|(file, st)| Self::darwin_sockopts(&file, &st).nosigpipe)
    }

    /// Whether a connect of `fd` to the address at `addr` would carry
    /// SO_KEEPALIVE onto a connection the host makes: a TCP socket asking
    /// for it, to an AF_INET address off the loopback network.
    pub(crate) fn darwin_keepalive_off_host(&mut self, m: &GuestMem<'_>, fd: i32, addr: u64, len: u64) -> bool {
        const AF_INET: u8 = 2;
        let Ok((file, st)) = self.darwin_socket_opts(fd) else { return false };
        if st.unix_stream || Self::darwin_sockopts(&file, &st).options & so::KEEPALIVE == 0 || len < 8 {
            return false;
        }
        match m.read(addr, 8) {
            Ok(b) => b[1] == AF_INET && b[4] != 127,
            Err(_) => false,
        }
    }

    /// An IPPROTO_TCP option: TCP_NODELAY on a TCP socket is kept here
    /// (`Some(Ok)`); another of TCP's goes on to the translation (`None`);
    /// on a socket of another protocol, whose `pr_ctloutput` reads the
    /// level its own way, it is reported.
    fn darwin_tcp_option(&mut self, fd: i32, name: u32) -> Option<Result<(), Errno>> {
        use super::sockerr::Proto;
        match self.darwin_sock_proto(fd) {
            Some(Proto::Tcp) if name == TCP_NODELAY => Some(Ok(())),
            Some(Proto::Tcp) | None => None,
            Some(_) => {
                self.darwin_unimplemented(format!("IPPROTO_TCP option {name:#x} on a socket that is not TCP"));
                Some(Err(Errno::ENOPROTOOPT))
            }
        }
    }

    /// A refused bind of a socket that asked to share its address or port,
    /// which XNU's protocols might have allowed: their sharing rules are not
    /// the bind tables' here.
    pub(crate) fn darwin_bind_refused(&mut self, fd: i32) {
        let Ok((file, st)) = self.darwin_socket_opts(fd) else { return };
        let o = Self::darwin_sockopts(&file, &st);
        if o.options & (so::REUSEADDR | so::REUSEPORT) != 0 {
            self.darwin_unimplemented("a bind refused (EADDRINUSE) to a socket with SO_REUSEADDR or SO_REUSEPORT (address sharing)".into());
        }
    }
}

/// Whether `addr` (of `len` bytes) is an AF_INET address of the limited
/// broadcast address, 255.255.255.255.
pub(crate) fn is_broadcast(m: &GuestMem<'_>, addr: u64, len: u64) -> bool {
    const AF_INET: u8 = 2;
    if addr == 0 || len < 8 {
        return false;
    }
    match m.read(addr, 8) {
        Ok(b) => b[1] == AF_INET && b[4..8] == [255; 4],
        Err(_) => false,
    }
}

/// The socket-level options kept here.
fn handled(name: u32) -> bool {
    matches!(
        name,
        so::DEBUG | so::KEEPALIVE | so::DONTROUTE | so::USELOOPBACK | so::BROADCAST | so::REUSEADDR | so::REUSEPORT | so::OOBINLINE | so::LINGER | so::LINGER_SEC | so::SNDBUF | so::RCVBUF | so::SNDLOWAT | so::RCVLOWAT | so::NOSIGPIPE
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_buffer_past_the_limit_is_cut_to_it_once() {
        let (mut hi, mut lo) = (131072, 2048);
        assert!(sbreserve(&mut hi, &mut lo, 1 << 30));
        assert_eq!(hi, SB_MAX);
        assert!(!sbreserve(&mut hi, &mut lo, 1 << 30));
        assert!(sbreserve(&mut hi, &mut lo, 1024));
        assert_eq!((hi, lo), (1024, 1024));
    }
}
