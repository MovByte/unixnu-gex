//! Linux errno values in Darwin's numbering.
//!
//! The two agree from EPERM (1) to ERANGE (34) except at 11, which is
//! EAGAIN on Linux and EDEADLK on Darwin; above 34 they diverge.

/// The Linux errno whose Darwin number is `darwin` (EINVAL for one with
/// none).
pub fn from_darwin(darwin: i32) -> i32 {
    (1..=133).find(|&l| to_darwin(l) == darwin && (l == 22 || darwin != 22)).unwrap_or(22)
}

/// Where a Darwin errno with no Linux number is carried: this plus the
/// Darwin number, inside the range a call's return reads as an error.
pub const NATIVE: i32 = 3000;

/// A Darwin errno with no Linux number (EBADEXEC, EBADARCH, EAUTH...).
pub const fn native(darwin: i32) -> crate::errno::Errno {
    crate::errno::Errno(NATIVE + darwin)
}

/// A Darwin errno as gex carries it: its Linux number, or past
/// [`NATIVE`] when Linux has none.
pub fn errno_of(darwin: i32) -> crate::errno::Errno {
    match (1..=133).find(|&l| to_darwin(l) == darwin) {
        Some(l) => crate::errno::Errno(l),
        None => native(darwin),
    }
}

/// `EOPNOTSUPP`, which Linux has as one number with `ENOTSUP`, carried on
/// that number for Darwin's `ENOTSUP`.
pub const EOPNOTSUPP: crate::errno::Errno = native(102);

/// `EBADEXEC`.
pub const EBADEXEC: crate::errno::Errno = native(85);

/// `EBADMACHO`.
pub const EBADMACHO: crate::errno::Errno = native(88);

/// Darwin's number for a Linux errno.
pub fn to_darwin(linux: i32) -> i32 {
    match linux {
        l if (NATIVE + 1..NATIVE + 1000).contains(&l) => l - NATIVE,
        11 => 35,  // EAGAIN
        35 => 11,  // EDEADLK
        1..=34 => linux,
        36 => 63,  // ENAMETOOLONG
        37 => 77,  // ENOLCK
        38 => 78,  // ENOSYS
        39 => 66,  // ENOTEMPTY
        40 => 62,  // ELOOP
        42 => 91,  // ENOMSG
        43 => 90,  // EIDRM
        61 => 96,  // ENODATA
        62 => 101, // ETIME
        71 => 100, // EPROTO
        74 => 94,  // EBADMSG
        75 => 84,  // EOVERFLOW
        84 => 92,  // EILSEQ
        88 => 38,  // ENOTSOCK
        89 => 39,  // EDESTADDRREQ
        90 => 40,  // EMSGSIZE
        91 => 41,  // EPROTOTYPE
        92 => 42,  // ENOPROTOOPT
        93 => 43,  // EPROTONOSUPPORT
        94 => 44,  // ESOCKTNOSUPPORT
        95 => 45,  // EOPNOTSUPP, Darwin's ENOTSUP
        96 => 46,  // EPFNOSUPPORT
        97 => 47,  // EAFNOSUPPORT
        98 => 48,  // EADDRINUSE
        99 => 49,  // EADDRNOTAVAIL
        100 => 50, // ENETDOWN
        101 => 51, // ENETUNREACH
        102 => 52, // ENETRESET
        103 => 53, // ECONNABORTED
        104 => 54, // ECONNRESET
        105 => 55, // ENOBUFS
        106 => 56, // EISCONN
        107 => 57, // ENOTCONN
        108 => 58, // ESHUTDOWN
        109 => 59, // ETOOMANYREFS
        110 => 60, // ETIMEDOUT
        111 => 61, // ECONNREFUSED
        112 => 64, // EHOSTDOWN
        113 => 65, // EHOSTUNREACH
        114 => 37, // EALREADY
        115 => 36, // EINPROGRESS
        116 => 70, // ESTALE
        122 => 69, // EDQUOT
        125 => 89, // ECANCELED
        130 => 105, // EOWNERDEAD
        131 => 104, // ENOTRECOVERABLE
        // Nothing closer on Darwin.
        _ => 22, // EINVAL
    }
}

#[cfg(test)]
mod tests {
    use super::to_darwin;

    #[test]
    fn the_shared_range_is_unchanged_but_eagain() {
        for e in (1..=34).filter(|&e| e != 11) {
            assert_eq!(to_darwin(e), e);
        }
        assert_eq!(to_darwin(11), 35);
        assert_eq!(to_darwin(38), 78);
        assert_eq!(to_darwin(2), 2);
    }
}
