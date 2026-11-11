//! What differs for a Darwin process's sockets: the address structures
//! (a length byte and an 8-bit family where Linux has a 16-bit family), the
//! numbers of address families, message flags and socket options, and how a
//! socket's address is copied out (`bsd/kern/uipc_syscalls.c`,
//! `bsd/kern/uipc_usrreq.c` and `bsd/sys/socket.h`, xnu-10063.141.1).

use crate::errno::Errno;
use crate::GuestMem;

/// `SOCK_MAXADDRLEN`: the longest address a call takes.
pub const SOCK_MAXADDRLEN: usize = 255;

/// `AF_*` of the families a Darwin process can ask for and this kernel
/// has: `AF_UNIX`, `AF_INET`, `AF_INET6`.
pub mod af {
    pub const UNSPEC: u8 = 0;
    pub const UNIX: u8 = 1;
    pub const INET: u8 = 2;
    pub const INET6: u8 = 30;
}

/// The Linux `AF_*` of a Darwin family, where there is one.
pub fn family_to_linux(d: u64) -> Option<u64> {
    match u8::try_from(d).ok()? {
        af::UNSPEC => Some(0),
        af::UNIX => Some(1),
        af::INET => Some(2),
        af::INET6 => Some(10),
        _ => None,
    }
}

/// Whether a number is one of Darwin's families (`AF_MAX` is 41): a
/// family this kernel does not carry is refused with `EAFNOSUPPORT`, and
/// said when it is one Darwin has.
pub fn family_exists(d: u64) -> bool {
    (3..=40).contains(&d)
}

/// A Darwin `MSG_*` flag word as Linux's. `MSG_NOSIGNAL` is 0x80000 there.
pub fn msg_flags_to_linux(f: u64) -> u64 {
    // (Darwin, Linux): OOB, PEEK, DONTROUTE, EOR, TRUNC, CTRUNC, WAITALL,
    // DONTWAIT, NOSIGNAL.
    const MAP: [(u64, u64); 9] = [
        (0x1, 0x1),
        (0x2, 0x2),
        (0x4, 0x4),
        (0x8, 0x80),
        (0x10, 0x20),
        (0x20, 0x8),
        (0x40, 0x100),
        (0x80, 0x40),
        (0x80000, 0x4000),
    ];
    let mut l = 0;
    for (d, x) in MAP {
        if f & d != 0 {
            l |= x;
        }
    }
    l
}

/// A Linux `msg_flags` as Darwin's (the flags a receive reports).
pub fn msg_flags_from_linux(f: u32) -> u32 {
    const MAP: [(u32, u32); 7] = [(0x1, 0x1), (0x2, 0x2), (0x4, 0x4), (0x80, 0x8), (0x20, 0x10), (0x8, 0x20), (0x100, 0x40)];
    let mut d = 0;
    for (l, x) in MAP {
        if f & l != 0 {
            d |= x;
        }
    }
    d
}

/// `SOL_SOCKET` in Darwin's numbering.
pub const SOL_SOCKET: u64 = 0xffff;
/// Linux's.
pub const LINUX_SOL_SOCKET: u64 = 1;

/// Darwin `SO_*` options (at `SOL_SOCKET`) that have a Linux one, and what
/// that is. Every other option Darwin defines has none here: it is refused
/// as unimplemented (`so_name`).
pub fn so_to_linux(opt: u64) -> Option<u64> {
    Some(match opt {
        0x0001 => 1,  // SO_DEBUG
        0x0002 => 30, // SO_ACCEPTCONN
        0x0004 => 2,  // SO_REUSEADDR
        0x0008 => 9,  // SO_KEEPALIVE
        0x0010 => 5,  // SO_DONTROUTE
        0x0020 => 6,  // SO_BROADCAST
        0x1080 => 13, // SO_LINGER (seconds)
        0x0100 => 10, // SO_OOBINLINE
        0x0200 => 15, // SO_REUSEPORT
        0x1001 => 7,  // SO_SNDBUF
        0x1002 => 8,  // SO_RCVBUF
        0x1003 => 19, // SO_SNDLOWAT
        0x1004 => 18, // SO_RCVLOWAT
        0x1007 => 4,  // SO_ERROR
        0x1008 => 3,  // SO_TYPE
        _ => return None,
    })
}

/// The name of every `SO_*` option bsd/sys/socket.h defines at this tag
/// that has no Linux counterpart here, for the message that says it is
/// refused.
pub fn so_name(opt: u64) -> String {
    let n = match opt {
        0x0040 => "SO_USELOOPBACK",
        0x0080 => "SO_LINGER (in ticks)",
        0x0400 => "SO_TIMESTAMP",
        0x0800 => "SO_TIMESTAMP_MONOTONIC",
        0x1000 => "SO_ACCEPTFILTER",
        0x2000 => "SO_DONTTRUNC",
        0x4000 => "SO_WANTMORE",
        0x8000 => "SO_WANTOOBFLAG",
        0x1_0000 => "SO_NOWAKEFROMSLEEP",
        0x2_0000 => "SO_NOAPNFALLBK",
        0x4_0000 => "SO_TIMESTAMP_CONTINUOUS",
        0x1005 => "SO_SNDTIMEO",
        0x1006 => "SO_RCVTIMEO",
        0x1010 => "SO_LABEL",
        0x1011 => "SO_PEERLABEL",
        0x1020 => "SO_NREAD",
        0x1021 => "SO_NKE",
        0x1022 => "SO_NOSIGPIPE",
        0x1023 => "SO_NOADDRERR",
        0x1024 => "SO_NWRITE",
        0x1025 => "SO_REUSESHAREUID",
        0x1026 => "SO_NOTIFYCONFLICT",
        0x1027 => "SO_UPCALLCLOSEWAIT",
        0x1081 => "SO_RESTRICTIONS",
        0x1082 => "SO_RANDOMPORT",
        0x1083 => "SO_NP_EXTENSIONS",
        0x1085 => "SO_EXECPATH",
        0x1086 => "SO_TRAFFIC_CLASS",
        0x1087 => "SO_RECV_TRAFFIC_CLASS",
        0x1088 => "SO_TRAFFIC_CLASS_DBG",
        0x1090 => "SO_PRIVILEGED_TRAFFIC_CLASS",
        0x1091 => "SO_DEFUNCTIT",
        0x1100 => "SO_DEFUNCTOK",
        0x1101 => "SO_ISDEFUNCT",
        0x1102 => "SO_OPPORTUNISTIC",
        0x1103 => "SO_FLUSH",
        0x1104 => "SO_RECV_ANYIF",
        0x1105 => "SO_TRAFFIC_MGT_BACKGROUND",
        0x1106 => "SO_FLOW_DIVERT_TOKEN",
        0x1107 => "SO_DELEGATED",
        0x1108 => "SO_DELEGATED_UUID",
        0x1109 => "SO_NECP_ATTRIBUTES",
        0x1110 => "SO_CFIL_SOCK_ID",
        0x1111 => "SO_NECP_CLIENTUUID",
        0x1112 => "SO_NUMRCVPKT",
        0x1113 => "SO_AWDL_UNRESTRICTED",
        0x1114 => "SO_EXTENDED_BK_IDLE",
        0x1115 => "SO_MARK_CELLFALLBACK",
        0x1116 => "SO_NET_SERVICE_TYPE",
        0x1117 => "SO_QOSMARKING_POLICY_OVERRIDE",
        0x1118 => "SO_INTCOPROC_ALLOW",
        0x1119 => "SO_NETSVC_MARKING_LEVEL",
        0x1120 => "SO_NECP_LISTENUUID",
        0x1122 => "SO_MPKL_SEND_INFO",
        0x1123 => "SO_STATISTICS_EVENT",
        0x1124 => "SO_WANT_KEV_SOCKET_CLOSED",
        0x1125 => "SO_MARK_KNOWN_TRACKER",
        0x1126 => "SO_MARK_KNOWN_TRACKER_NON_APP_INITIATED",
        0x1127 => "SO_MARK_WAKE_PKT",
        0x1128 => "SO_RECV_WAKE_PKT",
        0x1129 => "SO_MARK_APPROVED_APP_DOMAIN",
        0x1130 => "SO_FALLBACK_MODE",
        0x1131 => "SO_RESOLVER_SIGNATURE",
        0x1132 => "SO_MARK_CELLFALLBACK_UUID",
        0x1133 => "SO_APPLICATION_ID",
        0x1135 => "SO_MARK_DOMAIN_INFO_SILENT",
        _ => return format!("SOL_SOCKET option {opt:#x}"),
    };
    n.to_string()
}

/// A socket option's level and number in Linux's terms: `Ok` for one that
/// has a counterpart, else what to say about it. `IPPROTO_TCP`'s
/// `TCP_NODELAY` is the same on both sides; the rest of the protocol
/// levels' options are numbered differently and are not carried over.
pub fn sockopt_to_linux(level: u64, opt: u64) -> Result<(u64, u64), String> {
    const IPPROTO_TCP: u64 = 6;
    const TCP_NODELAY: u64 = 1;
    match level & 0xffff_ffff {
        SOL_SOCKET => so_to_linux(opt).map(|o| (LINUX_SOL_SOCKET, o)).ok_or_else(|| so_name(opt)),
        IPPROTO_TCP if opt == TCP_NODELAY => Ok((IPPROTO_TCP, TCP_NODELAY)),
        l => Err(format!("level {l} option {opt:#x}")),
    }
}

/// `getsockaddr`/`getsockaddr_s`: a caller's address as the kernel holds
/// it, its length byte set to the length given. `translate_unspec` is the
/// `AF_UNSPEC`-as-`AF_INET` rule for a full-sized `sockaddr_in`.
pub fn get(m: &GuestMem<'_>, addr: u64, len: u64, translate_unspec: bool) -> Result<Vec<u8>, Errno> {
    if len as usize > SOCK_MAXADDRLEN {
        return Err(Errno::ENAMETOOLONG);
    }
    if len < 2 {
        return Err(Errno::EINVAL);
    }
    if addr == 0 {
        return Err(Errno::EINVAL);
    }
    let mut sa = m.read(addr, len as usize)?.to_vec();
    if translate_unspec && sa[1] == af::UNSPEC && len == 16 {
        sa[1] = af::INET;
    }
    sa[0] = len as u8;
    Ok(sa)
}

/// The path of a `sockaddr_un` as `unp_bind` and `unp_connect` take it:
/// the bytes after the family up to the length given, read as a C string.
/// A family other than `AF_UNSPEC` and `AF_UNIX` is `EAFNOSUPPORT`; no path
/// bytes, or `SOCK_MAXADDRLEN` of them, `EINVAL`; and an empty string is
/// a path that names nothing (`ENOENT`).
pub fn unix_path(sa: &[u8]) -> Result<String, Errno> {
    if sa[1] != af::UNSPEC && sa[1] != af::UNIX {
        return Err(Errno::EAFNOSUPPORT);
    }
    let n = sa[0] as isize - 2;
    if n <= 0 || n as usize >= SOCK_MAXADDRLEN {
        return Err(Errno::EINVAL);
    }
    let path = &sa[2..(2 + n as usize).min(sa.len())];
    let end = path.iter().position(|&c| c == 0).unwrap_or(path.len());
    if end == 0 {
        return Err(Errno::ENOENT);
    }
    Ok(path[..end].iter().map(|&b| char::from(b)).collect())
}

/// The address of a `sockaddr_in` as `in_pcbbind` and `in_pcbconnect` take
/// it: a full-size structure of the right family.
pub fn inet(sa: &[u8]) -> Result<(u32, u16), Errno> {
    if sa[0] != 16 {
        return Err(Errno::EINVAL);
    }
    if sa[1] != af::INET {
        return Err(Errno::EAFNOSUPPORT);
    }
    Ok((u32::from_be_bytes([sa[4], sa[5], sa[6], sa[7]]), u16::from_be_bytes([sa[2], sa[3]])))
}

/// A `sockaddr_in`, as the kernel makes one: 16 bytes.
pub fn out_inet(ip: u32, port: u16) -> Vec<u8> {
    let mut b = vec![0u8; 16];
    b[0] = 16;
    b[1] = af::INET;
    b[2..4].copy_from_slice(&port.to_be_bytes());
    b[4..8].copy_from_slice(&ip.to_be_bytes());
    b
}

/// A bound `sockaddr_un`: the length byte, the family and the path with
/// its NUL.
pub fn out_unix(path: &str) -> Vec<u8> {
    let mut b = vec![0u8; 2];
    b.extend(path.chars().map(|c| c as u32 as u8));
    b.push(0);
    b[0] = b.len().min(255) as u8;
    b[1] = af::UNIX;
    b
}

/// `sun_noname`: what an unbound unix socket is, a bare `struct sockaddr`.
pub fn out_unnamed() -> Vec<u8> {
    let mut b = vec![0u8; 16];
    b[0] = 16;
    b[1] = af::UNIX;
    b
}

/// How an address is copied out and its length reported.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Rule {
    /// `accept`: with an address asked for, at most the caller's length
    /// (which must be readable), and the whole length is what is reported.
    Name,
    /// `getsockname`, `getpeername`: as `accept`, but the length is read
    /// first whether or not an address is asked for, and the address is
    /// written wherever it points.
    Sock,
    /// `recvfrom`, `recvmsg` (`copyout_sa`): a caller who gave no room is
    /// told there is none (length 0), not how much there would be.
    Recv,
}

/// What `*lenp` is set to and how many bytes of `sa` are written, for a
/// caller who offered `room`.
pub fn out_lengths(rule: Rule, room: u32, sa: &[u8]) -> (u32, usize) {
    let whole = sa.len() as u32;
    match rule {
        Rule::Name | Rule::Sock => (whole, (room.min(whole)) as usize),
        Rule::Recv if room == 0 => (0, 0),
        Rule::Recv => (whole, room.min(whole) as usize),
    }
}

/// Copy `sa` out to `addr`, with the length at `lenp` read first and set
/// after. `accept` with no `addr` copies nothing; `recvfrom` with no `lenp`
/// has no room (`msg_namelen` 0); `getsockname` and `getpeername` copy the
/// length in unconditionally, so none is EFAULT.
pub fn put(m: &mut GuestMem<'_>, addr: u64, lenp: u64, sa: &[u8], rule: Rule) -> Result<(), Errno> {
    let room = match rule {
        Rule::Sock => m.read_u32(lenp)?,
        _ if addr == 0 => return Ok(()),
        Rule::Name => m.read_u32(lenp)?,
        Rule::Recv if lenp == 0 => 0,
        Rule::Recv => m.read_u32(lenp)?,
    };
    let (report, n) = out_lengths(rule, room, sa);
    if n > 0 {
        m.write(addr, &sa[..n])?;
    }
    if lenp != 0 {
        m.write_u32(lenp, report)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn families_and_flags_translate() {
        assert_eq!(family_to_linux(30), Some(10));
        assert_eq!(family_to_linux(1), Some(1));
        assert_eq!(family_to_linux(17), None);
        assert!(family_exists(17) && family_exists(32) && !family_exists(0) && !family_exists(200));
        // MSG_DONTWAIT and MSG_WAITALL swap places with Linux's
        assert_eq!(msg_flags_to_linux(0x80), 0x40);
        assert_eq!(msg_flags_to_linux(0x40 | 0x2), 0x100 | 0x2);
        assert_eq!(msg_flags_to_linux(0x80000), 0x4000);
        assert_eq!(msg_flags_from_linux(0x20 | 0x8), 0x10 | 0x20);
    }

    #[test]
    fn options_have_a_counterpart_or_are_named() {
        assert_eq!(sockopt_to_linux(0xffff, 0x4), Ok((1, 2)));
        assert_eq!(sockopt_to_linux(0xffff, 0x1007), Ok((1, 4)));
        assert_eq!(sockopt_to_linux(0xffff, 0x1022), Err("SO_NOSIGPIPE".into()));
        assert_eq!(sockopt_to_linux(6, 1), Ok((6, 1)));
        assert!(sockopt_to_linux(6, 0x10).is_err());
        assert!(sockopt_to_linux(0, 4).is_err());
    }

    #[test]
    fn a_unix_path_is_what_the_length_gives_up_to_a_nul() {
        let mut sa = vec![0u8; 106];
        sa[1] = 1;
        sa[2..2 + 15].copy_from_slice(b"/var/run/syslog");
        sa[0] = 106;
        assert_eq!(unix_path(&sa).unwrap(), "/var/run/syslog");
        // cut by the length rather than a NUL
        sa[0] = 2 + 8;
        assert_eq!(unix_path(&sa).unwrap(), "/var/run");
        // nothing after the family
        sa[0] = 2;
        assert_eq!(unix_path(&sa), Err(Errno::EINVAL));
        // an empty string is a name for nothing
        sa[0] = 106;
        sa[2] = 0;
        assert_eq!(unix_path(&sa), Err(Errno::ENOENT));
        sa[1] = 2;
        assert_eq!(unix_path(&sa), Err(Errno::EAFNOSUPPORT));
    }

    #[test]
    fn an_inet_address_is_full_size_and_the_right_family() {
        let sa = out_inet(0x7f00_0001, 8080);
        assert_eq!(inet(&sa), Ok((0x7f00_0001, 8080)));
        assert_eq!(&sa[..2], &[16, 2]);
        let mut short = sa.clone();
        short[0] = 8;
        assert_eq!(inet(&short), Err(Errno::EINVAL));
        let mut other = sa;
        other[1] = 30;
        assert_eq!(inet(&other), Err(Errno::EAFNOSUPPORT));
    }

    #[test]
    fn addresses_are_made_as_xnu_makes_them() {
        assert_eq!(out_unnamed(), [16, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let u = out_unix("/tmp/s");
        assert_eq!((u[0], u[1]), (9, 1));
        assert_eq!(&u[2..], b"/tmp/s\0");
    }

    #[test]
    fn copy_out_reports_as_each_call_does() {
        let sa = out_inet(1, 2);
        assert_eq!(out_lengths(Rule::Name, 4, &sa), (16, 4));
        assert_eq!(out_lengths(Rule::Name, 0, &sa), (16, 0));
        assert_eq!(out_lengths(Rule::Recv, 0, &sa), (0, 0));
        assert_eq!(out_lengths(Rule::Recv, 4, &sa), (16, 4));
        assert_eq!(out_lengths(Rule::Recv, 32, &sa), (16, 16));
    }

    #[test]
    fn put_writes_what_fits() {
        let mut b = vec![0xaau8; 64];
        let mut m = GuestMem::new(&mut b);
        m.write_u32(32, 6).unwrap();
        put(&mut m, 8, 32, &out_inet(0x0102_0304, 0x0506), Rule::Name).unwrap();
        assert_eq!(m.read_u32(32).unwrap(), 16);
        assert_eq!(m.read(8, 7).unwrap(), &[16, 2, 5, 6, 1, 2, 0xaa]);
    }

    #[test]
    fn get_sets_the_length_and_checks_it() {
        let mut b = vec![0u8; 300];
        b[0] = 99;
        b[1] = 0;
        let m = GuestMem::new(&mut b);
        assert_eq!(get(&m, 0, 16, false), Err(Errno::EINVAL));
        assert_eq!(get(&m, 4, 1, false), Err(Errno::EINVAL));
        assert_eq!(get(&m, 4, 256, false), Err(Errno::ENAMETOOLONG));
        let sa = get(&m, 0x20, 16, true).unwrap();
        assert_eq!((sa[0], sa[1]), (16, 2), "AF_UNSPEC at the size of a sockaddr_in is AF_INET");
        let sa = get(&m, 0x20, 15, true).unwrap();
        assert_eq!((sa[0], sa[1]), (15, 0));
    }
}
