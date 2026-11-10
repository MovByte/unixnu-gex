//! What the socket layer refuses before a protocol is asked: `solisten`,
//! `accept_nocancel`, `soconnectlock`, `sosend`, `soreceive` and
//! `soconnect2`, in the error each gives.

use super::bsd::sys;
use super::errno::EOPNOTSUPP;
use crate::errno::Errno;
use crate::net;
use crate::syscalls::Kernel;

const MSG_OOB: u64 = 1;
const AF_INET: u64 = 2;
const SOCK_STREAM: u64 = 1;
const SOCK_DGRAM: u64 = 2;
const IPPROTO_TCP: u64 = 6;
const IPPROTO_UDP: u64 = 17;

/// A socket's protocol, as far as these checks need it.
#[derive(Clone, Copy, PartialEq)]
enum Proto {
    UnixStream,
    Tcp,
    /// No connections (`PR_CONNREQUIRED` clear), and no out-of-band data.
    Datagram,
}

impl Kernel {
    fn darwin_sock_proto(&self, fd: i32) -> Option<Proto> {
        let io = self.fd_io();
        if io.dgram_of(fd).is_ok() {
            return Some(Proto::Datagram);
        }
        if io.unix_of(fd).is_ok() || io.remote_unix_of(fd).is_ok() {
            return Some(Proto::UnixStream);
        }
        let s = io.socket_of(fd).ok()?;
        Some(if s.kind == net::Kind::Udp { Proto::Datagram } else { Proto::Tcp })
    }

    /// The error, if this socket call is one that is refused here.
    pub(crate) fn darwin_sock_refused(&mut self, raw: u64, a: &[u64; 6]) -> Option<Errno> {
        // pru_connect2_notsupp, once the two sockets exist.
        if raw == sys::SOCKETPAIR {
            let made = matches!((a[1] as u32 as u64, a[2] as u32 as u64), (SOCK_STREAM, 0 | IPPROTO_TCP) | (SOCK_DGRAM, 0 | IPPROTO_UDP));
            return (a[0] as u32 as u64 == AF_INET && made).then_some(EOPNOTSUPP);
        }
        let (send, flags) = match raw {
            sys::SENDTO | sys::SENDTO_NOCANCEL => (true, a[3]),
            sys::SENDMSG | sys::SENDMSG_NOCANCEL => (true, a[2]),
            sys::RECVFROM | sys::RECVFROM_NOCANCEL => (false, a[3]),
            sys::RECVMSG | sys::RECVMSG_NOCANCEL => (false, a[2]),
            sys::LISTEN | sys::ACCEPT | sys::ACCEPT_NOCANCEL | sys::CONNECT | sys::CONNECT_NOCANCEL => (false, 0),
            _ => return None,
        };
        let fd = a[0] as i32;
        let proto = self.darwin_sock_proto(fd)?;
        let state = self.fds.get(fd).ok()?.handle.so_state()?;
        let listening = state.qlen.is_some();
        match raw {
            sys::LISTEN => (proto == Proto::Datagram).then_some(EOPNOTSUPP),
            sys::ACCEPT | sys::ACCEPT_NOCANCEL => match (proto, listening) {
                (Proto::Datagram, _) => Some(EOPNOTSUPP),
                (_, false) => Some(Errno::EINVAL),
                _ => None,
            },
            sys::CONNECT | sys::CONNECT_NOCANCEL => listening.then_some(EOPNOTSUPP),
            _ if flags & MSG_OOB == 0 => None,
            _ => match (proto, send) {
                // sosend, before it looks at the socket's state.
                (Proto::Datagram, true) => Some(EOPNOTSUPP),
                // uipc_send, for what sosendcheck lets through.
                (Proto::UnixStream, true) => (!state.cantsend && state.can_write).then_some(EOPNOTSUPP),
                // pru_rcvoob_notsupp.
                (Proto::Datagram | Proto::UnixStream, false) => Some(EOPNOTSUPP),
                (Proto::Tcp, _) => {
                    self.darwin_unimplemented("MSG_OOB on a TCP socket (the host's connection carries no urgent data here)".into());
                    Some(Errno::EINVAL)
                }
            },
        }
    }
}
