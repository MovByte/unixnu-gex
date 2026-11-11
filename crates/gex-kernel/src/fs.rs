//! Open-file constants and the `struct stat` layout.
//!
//! The descriptor table lives in [`crate::file`] and the backends in
//! [`crate::vfs`]; what stays here is the ABI vocabulary they share with the
//! guest.

/// Open-file flags, in the kernel's own spelling: x86's, which i386 and
/// wasm32 programs use on every build. The four bits Linux spells
/// differently per architecture (`O_DIRECTORY`, `O_NOFOLLOW`, `O_DIRECT`,
/// `O_LARGEFILE`) arrive from an AArch64 program in the asm-generic spelling
/// and are turned into this one at the guest's door ([`from_guest`]).
pub mod oflags {
    pub const O_RDONLY: u64 = 0o0;
    pub const O_WRONLY: u64 = 0o1;
    pub const O_RDWR: u64 = 0o2;
    pub const O_CREAT: u64 = 0o100;
    pub const O_EXCL: u64 = 0o200;
    pub const O_TRUNC: u64 = 0o1000;
    pub const O_APPEND: u64 = 0o2000;
    pub const O_NONBLOCK: u64 = 0o4000;
    /// Opening a terminal does *not* make it this session's controlling one.
    /// Without this flag a session leader's open claims it -- see `open_pty`.
    pub const O_NOCTTY: u64 = 0o400;
    pub const O_DIRECTORY: u64 = 0o200000;
    pub const O_CLOEXEC: u64 = 0o2000000;
    /// An unnamed file created inside the named *directory*. The bit overlaps
    /// `O_DIRECTORY`, which is why it is always tested together with it.
    pub const O_TMPFILE: u64 = 0o20000000;
    /// A handle to a name rather than to its contents. Legal on a dangling
    /// symlink, and usable only for the `*at` calls and `fstat`.
    pub const O_PATH: u64 = 0o10000000;
    pub const O_NOFOLLOW: u64 = 0o400000;
    pub const O_DIRECT: u64 = 0o40000;
    /// i386's; x86-64 has none of its own (Linux forces it on there).
    pub const O_LARGEFILE: u64 = 0o100000;
    pub const ACCMODE: u64 = 0o3;

    /// The asm-generic spelling (AArch64's).
    pub mod generic {
        pub const O_DIRECTORY: u64 = 0o40000;
        pub const O_NOFOLLOW: u64 = 0o100000;
        pub const O_DIRECT: u64 = 0o200000;
        pub const O_LARGEFILE: u64 = 0o400000;
    }

    /// Each pair (generic, kernel) of the bits that differ.
    const DIFFER: [(u64, u64); 4] = [
        (generic::O_DIRECTORY, O_DIRECTORY),
        (generic::O_NOFOLLOW, O_NOFOLLOW),
        (generic::O_DIRECT, O_DIRECT),
        (generic::O_LARGEFILE, O_LARGEFILE),
    ];

    /// Generic spelling to the kernel's.
    pub fn from_generic(f: u64) -> u64 {
        DIFFER.iter().fold(f & !DIFFER.iter().fold(0, |m, d| m | d.0), |out, &(g, k)| {
            if f & g != 0 { out | k } else { out }
        })
    }

    /// The kernel's spelling to generic (`fcntl(F_GETFL)`).
    pub fn to_generic(f: u64) -> u64 {
        DIFFER.iter().fold(f & !DIFFER.iter().fold(0, |m, d| m | d.1), |out, &(g, k)| {
            if f & k != 0 { out | g } else { out }
        })
    }

    /// Whether this process spells its open flags the generic way: an
    /// AArch64 program. Not an i386 or wasm32 one (`compat`, which use x86's
    /// on every build).
    pub fn generic_guest(compat: bool) -> bool {
        !gex_abi::X86 && !compat
    }

    /// Flags as this process passed them, in the kernel's spelling.
    pub fn from_guest(f: u64, compat: bool) -> u64 {
        if generic_guest(compat) { from_generic(f) } else { f }
    }

    /// Flags in the kernel's spelling, as this process reads them.
    pub fn to_guest(f: u64, compat: bool) -> u64 {
        if generic_guest(compat) { to_generic(f) } else { f }
    }
}

/// `st_mode` type bits.
pub mod mode {
    pub const S_IFMT: u32 = 0o170000;
    pub const S_IFIFO: u32 = 0o010000;
    pub const S_IFCHR: u32 = 0o020000;
    pub const S_IFDIR: u32 = 0o040000;
    pub const S_IFREG: u32 = 0o100000;
}

/// Metadata in the shape `fstat` reports.
#[derive(Clone, Copy, Debug, Default)]
pub struct Stat {
    pub dev: u64,
    pub ino: u64,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u64,
    pub size: i64,
    pub blksize: i32,
    pub blocks: i64,
    pub mtime: i64,
    pub mtime_ns: u32,
    pub atime: i64,
    pub atime_ns: u32,
    pub ctime: i64,
    pub ctime_ns: u32,
    /// Darwin's `st_flags`.
    pub flags: u32,
    /// Darwin's `st_birthtimespec`, where the filesystem has one of its
    /// own; else the modification time stands for it.
    pub birth: Option<(i64, u32)>,
}

/// A guest `struct stat` as bytes, on the stack: every flavour fits in 144,
/// and `stat`/`fstat` then write it without an allocation (each one took
/// the process allocator's lock, which a threaded `stat` loop queues on).
pub struct StatBytes {
    b: [u8; 144],
    n: usize,
}

impl StatBytes {
    fn zeroed(n: usize) -> StatBytes {
        StatBytes { b: [0; 144], n }
    }
}

impl std::ops::Deref for StatBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.b[..self.n]
    }
}

impl std::ops::DerefMut for StatBytes {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.b[..self.n]
    }
}

impl Stat {
    /// (seconds, nanoseconds) of atime, mtime, ctime, in `struct stat`'s
    /// order.
    pub fn times(&self) -> [(i64, u32); 3] {
        [(self.atime, self.atime_ns), (self.mtime, self.mtime_ns), (self.ctime, self.ctime_ns)]
    }

    /// Serialise into the guest kernel's `struct stat`: 128 bytes on aarch64,
    /// 144 on x86-64, where `st_nlink` widens to 64 bits and precedes
    /// `st_mode` and `st_blksize` is 64 bits.
    pub fn encode(&self) -> Vec<u8> {
        self.encode_for(false).to_vec()
    }

    /// Darwin's `struct stat` (the 64-bit-inode one, 144 bytes): a 32-bit
    /// device, 16-bit mode and link count, then a birth time after the
    /// three Linux has (the filesystem's, or the modification time), the
    /// size, blocks, a 32-bit block size, the flags and a zero generation.
    pub fn encode_darwin(&self) -> StatBytes {
        let mut b = StatBytes::zeroed(144);
        b[0..4].copy_from_slice(&(self.dev as u32).to_le_bytes());
        b[4..6].copy_from_slice(&(self.mode as u16).to_le_bytes());
        b[6..8].copy_from_slice(&(self.nlink.min(u16::MAX as u32) as u16).to_le_bytes());
        b[8..16].copy_from_slice(&self.ino.to_le_bytes());
        b[16..20].copy_from_slice(&self.uid.to_le_bytes());
        b[20..24].copy_from_slice(&self.gid.to_le_bytes());
        // st_rdev as Darwin's dev_t (major << 24 | minor).
        b[24..28].copy_from_slice(&crate::darwin::attrcall::darwin_dev(self.rdev).to_le_bytes());
        let [at, mt, ct] = self.times();
        let bt = self.birth.unwrap_or(mt);
        for (off, (t, ns)) in [32usize, 48, 64, 80].into_iter().zip([at, mt, ct, bt]) {
            b[off..off + 8].copy_from_slice(&t.to_le_bytes());
            b[off + 8..off + 16].copy_from_slice(&(ns as i64).to_le_bytes());
        }
        b[96..104].copy_from_slice(&self.size.to_le_bytes());
        b[104..112].copy_from_slice(&self.blocks.to_le_bytes());
        b[112..116].copy_from_slice(&self.blksize.to_le_bytes());
        b[116..120].copy_from_slice(&self.flags.to_le_bytes());
        b
    }

    /// Darwin's `struct stat` with a 32-bit inode number (`user64_stat`,
    /// 120 bytes), what `stat`, `lstat`, `fstat` and `fstatat` write
    /// (`vn_stat` with `isstat64` 0, then `munge_user64_stat`): the inode
    /// number truncated, no birth time, and the spare fields zero.
    pub fn encode_darwin_ino32(&self) -> StatBytes {
        let mut b = StatBytes::zeroed(120);
        b[0..4].copy_from_slice(&(self.dev as u32).to_le_bytes());
        b[4..8].copy_from_slice(&(self.ino as u32).to_le_bytes());
        b[8..10].copy_from_slice(&(self.mode as u16).to_le_bytes());
        b[10..12].copy_from_slice(&(self.nlink.min(u16::MAX as u32) as u16).to_le_bytes());
        b[12..16].copy_from_slice(&self.uid.to_le_bytes());
        b[16..20].copy_from_slice(&self.gid.to_le_bytes());
        b[20..24].copy_from_slice(&crate::darwin::attrcall::darwin_dev(self.rdev).to_le_bytes());
        for (off, (t, ns)) in [24usize, 40, 56].into_iter().zip(self.times()) {
            b[off..off + 8].copy_from_slice(&t.to_le_bytes());
            b[off + 8..off + 16].copy_from_slice(&(ns as i64).to_le_bytes());
        }
        b[72..80].copy_from_slice(&self.size.to_le_bytes());
        b[80..88].copy_from_slice(&self.blocks.to_le_bytes());
        b[88..92].copy_from_slice(&self.blksize.to_le_bytes());
        b[92..96].copy_from_slice(&self.flags.to_le_bytes());
        b
    }

    /// As [`Stat::encode`], or the i386 `struct stat64` (96 bytes, packed to
    /// 4-byte alignment) for a 32-bit process.
    pub fn encode_for(&self, compat: bool) -> StatBytes {
        if compat {
            let mut b = StatBytes::zeroed(96);
            b[0..8].copy_from_slice(&self.dev.to_le_bytes());
            b[12..16].copy_from_slice(&(self.ino as u32).to_le_bytes());
            b[16..20].copy_from_slice(&self.mode.to_le_bytes());
            b[20..24].copy_from_slice(&self.nlink.to_le_bytes());
            b[24..28].copy_from_slice(&self.uid.to_le_bytes());
            b[28..32].copy_from_slice(&self.gid.to_le_bytes());
            b[32..40].copy_from_slice(&self.rdev.to_le_bytes());
            b[44..52].copy_from_slice(&self.size.to_le_bytes());
            b[52..56].copy_from_slice(&(self.blksize as u32).to_le_bytes());
            b[56..64].copy_from_slice(&(self.blocks as u64).to_le_bytes());
            for (off, (t, ns)) in [64usize, 72, 80].into_iter().zip(self.times()) {
                b[off..off + 4].copy_from_slice(&(t as u32).to_le_bytes());
                b[off + 4..off + 8].copy_from_slice(&ns.to_le_bytes());
            }
            b[88..96].copy_from_slice(&self.ino.to_le_bytes());
            return b;
        }
        if gex_abi::X86 {
            let mut b = StatBytes::zeroed(144);
            b[0..8].copy_from_slice(&self.dev.to_le_bytes());
            b[8..16].copy_from_slice(&self.ino.to_le_bytes());
            b[16..24].copy_from_slice(&(self.nlink as u64).to_le_bytes());
            b[24..28].copy_from_slice(&self.mode.to_le_bytes());
            b[28..32].copy_from_slice(&self.uid.to_le_bytes());
            b[32..36].copy_from_slice(&self.gid.to_le_bytes());
            b[40..48].copy_from_slice(&self.rdev.to_le_bytes());
            b[48..56].copy_from_slice(&self.size.to_le_bytes());
            b[56..64].copy_from_slice(&(self.blksize as i64).to_le_bytes());
            b[64..72].copy_from_slice(&self.blocks.to_le_bytes());
            for (off, (t, ns)) in [72usize, 88, 104].into_iter().zip(self.times()) {
                b[off..off + 8].copy_from_slice(&t.to_le_bytes());
                b[off + 8..off + 16].copy_from_slice(&(ns as u64).to_le_bytes());
            }
            return b;
        }
        let mut b = StatBytes::zeroed(128);
        b[0..8].copy_from_slice(&self.dev.to_le_bytes());
        b[8..16].copy_from_slice(&self.ino.to_le_bytes());
        b[16..20].copy_from_slice(&self.mode.to_le_bytes());
        b[20..24].copy_from_slice(&self.nlink.to_le_bytes());
        b[24..28].copy_from_slice(&self.uid.to_le_bytes());
        b[28..32].copy_from_slice(&self.gid.to_le_bytes());
        b[32..40].copy_from_slice(&self.rdev.to_le_bytes());
        b[48..56].copy_from_slice(&self.size.to_le_bytes());
        b[56..60].copy_from_slice(&self.blksize.to_le_bytes());
        b[64..72].copy_from_slice(&self.blocks.to_le_bytes());
        for (off, (t, ns)) in [72usize, 88, 104].into_iter().zip(self.times()) {
            b[off..off + 8].copy_from_slice(&t.to_le_bytes());
            b[off + 8..off + 16].copy_from_slice(&(ns as u64).to_le_bytes());
        }
        b
    }
}

#[cfg(test)]
mod oflag_tests {
    use super::oflags::*;

    #[test]
    fn generic_spelling_round_trips() {
        let all = O_RDWR | O_CREAT | O_CLOEXEC | O_NONBLOCK;
        for (g, k) in [
            (generic::O_DIRECTORY, O_DIRECTORY),
            (generic::O_NOFOLLOW, O_NOFOLLOW),
            (generic::O_DIRECT, O_DIRECT),
            (generic::O_LARGEFILE, O_LARGEFILE),
        ] {
            assert_eq!(from_generic(g | all), k | all, "{g:#o}");
            assert_eq!(to_generic(k | all), g | all, "{k:#o}");
        }
        let every = generic::O_DIRECTORY | generic::O_NOFOLLOW | generic::O_DIRECT | generic::O_LARGEFILE;
        assert_eq!(to_generic(from_generic(every | all)), every | all);
        // An i386 or wasm32 program spells them x86's way on every build.
        assert_eq!(from_guest(O_NOFOLLOW, true), O_NOFOLLOW);
    }
}

#[cfg(test)]
mod stat_tests {
    use super::Stat;

    /// `user64_stat` against `user64_stat64`: the same fields at their own
    /// offsets, the inode number truncated and no birth time.
    #[test]
    fn the_32_bit_inode_struct_is_the_64_bit_one_munged() {
        let st = Stat {
            dev: 0x0100_0002,
            ino: 0x1_2345_6789,
            mode: 0o100640,
            nlink: 3,
            uid: 501,
            gid: 20,
            rdev: 7,
            size: 5,
            blksize: 4096,
            blocks: 8,
            atime: 11,
            atime_ns: 12,
            mtime: 13,
            mtime_ns: 14,
            ctime: 15,
            ctime_ns: 16,
            flags: 0x8000,
            birth: None,
        };
        let (w, n) = (st.encode_darwin(), st.encode_darwin_ino32());
        assert_eq!(n.len(), 120);
        let i32_at = |b: &[u8], o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        let i16_at = |b: &[u8], o: usize| u16::from_le_bytes(b[o..o + 2].try_into().unwrap());
        assert_eq!(i32_at(&n, 0), i32_at(&w, 0));
        assert_eq!(i32_at(&n, 4), 0x2345_6789);
        assert_eq!(i16_at(&n, 8), i16_at(&w, 4));
        assert_eq!(i16_at(&n, 10), i16_at(&w, 6));
        assert_eq!(n[12..24], w[16..28]);
        assert_eq!(n[24..72], w[32..80]);
        assert_eq!(n[72..96], w[96..120]);
        assert_eq!(i32_at(&n, 92), 0x8000);
        assert!(n[96..120].iter().all(|&b| b == 0));
    }
}
