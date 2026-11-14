//! The owners, modes and file flags of the files of the device's sealed
//! volumes, as their images have them: the system volume, and the SystemOS
//! cryptex the shared cache is in. A host's extraction of the root keeps
//! its files' contents but not these: they come from the boot payload's
//! `SystemVolume.attrs` and `SystemOS.attrs`, which
//! `tools/darwin-volume-attrs.py` writes from the IPSW's root filesystem
//! image and its SystemOS cryptex image (mtree(5)-style specifications;
//! their `flags` are `st_flags` in hexadecimal).
//!
//! [`lookup`] answers for a path of a volume as the guest names it below
//! the volume's root, its components taken as they are (no link
//! followed): the stat of a file of the root, and the overlay's files
//! presented as the volume's own.

use std::sync::{Mutex, OnceLock};

/// An entry's type (`type=`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Dir,
    File,
    Link,
    Char,
    Block,
    Fifo,
    Socket,
}

impl Kind {
    fn parse(v: &str) -> Option<Kind> {
        Some(match v {
            "dir" => Kind::Dir,
            "file" => Kind::File,
            "link" => Kind::Link,
            "char" => Kind::Char,
            "block" => Kind::Block,
            "fifo" => Kind::Fifo,
            "socket" => Kind::Socket,
            _ => return None,
        })
    }
}

/// A file's attributes on the volume: its type, owner, group, permission
/// bits (with the set-id and sticky bits) and `st_flags`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attrs {
    pub kind: Kind,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub flags: u32,
}

/// A directory's entries, sorted by name: each one's attributes, and for a
/// directory its own index.
type Entries = Vec<(Box<[u8]>, Attrs, Option<u32>)>;

/// A volume's attributes: its root's, and its directories' entries (the
/// root's first).
pub struct Volume {
    root: Attrs,
    dirs: Vec<Entries>,
}

/// The defaults `/set` gives, keyword by keyword.
#[derive(Clone, Copy, Default)]
struct Defaults {
    kind: Option<Kind>,
    uid: Option<u32>,
    gid: Option<u32>,
    mode: Option<u32>,
    flags: Option<u32>,
}

impl Defaults {
    /// `k=v` words over these.
    fn apply<'a>(&mut self, words: impl Iterator<Item = &'a str>, line: usize) -> Result<(), String> {
        for w in words {
            let (k, v) = w.split_once('=').ok_or_else(|| format!("line {line}: a keyword without a value: {w}"))?;
            let bad = || format!("line {line}: {k}={v}");
            match k {
                "type" => self.kind = Some(Kind::parse(v).ok_or_else(bad)?),
                "uid" => self.uid = Some(v.parse().map_err(|_| bad())?),
                "gid" => self.gid = Some(v.parse().map_err(|_| bad())?),
                "mode" => self.mode = Some(u32::from_str_radix(v, 8).ok().filter(|m| *m <= 0o7777).ok_or_else(bad)?),
                "flags" => self.flags = Some(u32::from_str_radix(v, 16).map_err(|_| bad())?),
                _ => return Err(format!("line {line}: the keyword {k}, which this specification does not have")),
            }
        }
        Ok(())
    }

    fn unset<'a>(&mut self, words: impl Iterator<Item = &'a str>, line: usize) -> Result<(), String> {
        for w in words {
            match w {
                "type" => self.kind = None,
                "uid" => self.uid = None,
                "gid" => self.gid = None,
                "mode" => self.mode = None,
                "flags" => self.flags = None,
                "all" => *self = Defaults::default(),
                _ => return Err(format!("line {line}: /unset {w}")),
            }
        }
        Ok(())
    }

    fn attrs(&self, line: usize) -> Result<Attrs, String> {
        let missing = |k: &str| format!("line {line}: an entry without {k}");
        Ok(Attrs {
            kind: self.kind.ok_or_else(|| missing("type"))?,
            uid: self.uid.ok_or_else(|| missing("uid"))?,
            gid: self.gid.ok_or_else(|| missing("gid"))?,
            mode: self.mode.ok_or_else(|| missing("mode"))?,
            flags: self.flags.ok_or_else(|| missing("flags"))?,
        })
    }
}

/// vis(3)'s octal escapes undone: `\ooo` is the byte.
fn unvis(s: &str, line: usize) -> Result<Box<[u8]>, String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' {
            let oct = b.get(i + 1..i + 4).filter(|o| o.iter().all(|c| (b'0'..=b'7').contains(c))).ok_or_else(|| format!("line {line}: the escape in {s}"))?;
            let v = oct.iter().fold(0u32, |a, c| a * 8 + u32::from(c - b'0'));
            out.push(u8::try_from(v).map_err(|_| format!("line {line}: the escape in {s}"))?);
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    Ok(out.into_boxed_slice())
}

/// A specification read: `/set` and `/unset` lines, `..` leaving the
/// directory an entry of type `dir` entered, `.` the root.
pub fn parse(spec: &[u8]) -> Result<Volume, String> {
    let text = std::str::from_utf8(spec).map_err(|e| format!("not text: {e}"))?;
    let mut defaults = Defaults::default();
    let mut dirs: Vec<Entries> = Vec::new();
    let mut root = None;
    // The directories entered, innermost last.
    let mut stack: Vec<u32> = Vec::new();
    let mut ended = false;
    for (n, l) in text.lines().enumerate() {
        let line = n + 1;
        let l = l.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        if ended {
            return Err(format!("line {line}: past the root's end"));
        }
        let mut words = l.split_ascii_whitespace();
        let first = words.next().unwrap_or("");
        match first {
            "/set" => defaults.apply(words, line)?,
            "/unset" => defaults.unset(words, line)?,
            ".." => {
                let d = stack.pop().ok_or_else(|| format!("line {line}: .. outside every directory"))?;
                dirs[d as usize].sort_by(|a, b| a.0.cmp(&b.0));
                ended = stack.is_empty();
            }
            _ => {
                let mut e = defaults;
                e.apply(words, line)?;
                let attrs = e.attrs(line)?;
                let name = unvis(first, line)?;
                let child = (attrs.kind == Kind::Dir).then(|| {
                    dirs.push(Vec::new());
                    (dirs.len() - 1) as u32
                });
                match stack.last() {
                    None if &*name == b"." && attrs.kind == Kind::Dir => root = Some(attrs),
                    None => return Err(format!("line {line}: an entry before the root's")),
                    Some(&d) => {
                        if name.is_empty() || name.contains(&b'/') || &*name == b"." || &*name == b".." {
                            return Err(format!("line {line}: the name {first}"));
                        }
                        dirs[d as usize].push((name, attrs, child));
                    }
                }
                if let Some(c) = child {
                    stack.push(c);
                }
            }
        }
    }
    if !stack.is_empty() {
        return Err("a directory left open at the end".into());
    }
    let root = root.ok_or("no root entry")?;
    for d in &dirs {
        if d.windows(2).any(|w| w[0].0 == w[1].0) {
            return Err("a name twice in one directory".into());
        }
    }
    Ok(Volume { root, dirs })
}

impl Volume {
    /// The attributes of `path` (below the volume's root), its components
    /// as they are.
    pub fn lookup(&self, path: &str) -> Option<Attrs> {
        let mut attrs = self.root;
        let mut dir = Some(0u32);
        for c in path.split('/').filter(|c| !c.is_empty()) {
            let entries = &self.dirs[dir? as usize];
            let i = entries.binary_search_by(|e| (*e.0).cmp(c.as_bytes())).ok()?;
            attrs = entries[i].1;
            dir = entries[i].2;
        }
        Some(attrs)
    }
}

/// A volume whose attributes the boot payload carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Vol {
    /// The system volume, `/`.
    System,
    /// The SystemOS cryptex (`os.dmg`), which the device grafts at
    /// `/private/preboot/Cryptexes/OS` and this root has at
    /// `/System/Cryptexes/OS`.
    OsCryptex,
}

impl Vol {
    /// The payload's file of its specification.
    pub fn file(self) -> &'static str {
        match self {
            Vol::System => "SystemVolume.attrs",
            Vol::OsCryptex => "SystemOS.attrs",
        }
    }

    fn name(self) -> &'static str {
        match self {
            Vol::System => "the device's system volume",
            Vol::OsCryptex => "the device's SystemOS cryptex",
        }
    }

    fn slot(self) -> &'static Slot {
        static SYSTEM: Slot = Slot { spec: Mutex::new(None), read: OnceLock::new() };
        static OS_CRYPTEX: Slot = Slot { spec: Mutex::new(None), read: OnceLock::new() };
        match self {
            Vol::System => &SYSTEM,
            Vol::OsCryptex => &OS_CRYPTEX,
        }
    }
}

/// A volume's specification until it is read, and what it read as.
struct Slot {
    spec: Mutex<Option<Vec<u8>>>,
    read: OnceLock<Result<Volume, String>>,
}

/// The boot payload's specification of `vol`, read when first looked in.
pub fn set(vol: Vol, spec: Vec<u8>) -> Result<(), String> {
    let slot = vol.slot();
    let mut g = slot.spec.lock().unwrap_or_else(|e| e.into_inner());
    if g.is_some() || slot.read.get().is_some() {
        return Err(format!("the attributes of {} are set already", vol.name()));
    }
    *g = Some(spec);
    Ok(())
}

/// The attributes of file `path` of `vol` (its path below the volume's
/// root, as the guest names it, no link followed). `Err` says why there are
/// none: no specification was booted with, it does not read, or the volume
/// has no such file.
pub fn lookup(vol: Vol, path: &str) -> Result<Attrs, String> {
    let slot = vol.slot();
    let v = slot.read.get_or_init(|| {
        let spec = slot.spec.lock().unwrap_or_else(|e| e.into_inner()).take();
        match spec {
            Some(s) => parse(&s).map_err(|e| format!("the boot payload's {}: {e}", vol.file())),
            None => Err(format!("the owners, modes and flags of {} (the boot payload's {})", vol.name(), vol.file())),
        }
    });
    let v = v.as_ref().map_err(Clone::clone)?;
    v.lookup(path).ok_or_else(|| format!("{path}, which {} does not have", vol.name()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC: &[u8] = b"# test
. type=dir uid=0 gid=0 mode=0755 flags=0
/set flags=20 gid=0 mode=0644 type=file uid=0
a
b\\040c uid=501 mode=4755
etc type=link flags=0 mode=0755
sub type=dir mode=0700 flags=0
/set flags=0 gid=80 mode=0444 type=file uid=0
x
..
..
";

    #[test]
    fn looks_entries_up_by_path() {
        let v = parse(SPEC).unwrap();
        let a = |kind, uid, gid, mode, flags| Some(Attrs { kind, uid, gid, mode, flags });
        assert_eq!(v.lookup("/"), a(Kind::Dir, 0, 0, 0o755, 0));
        assert_eq!(v.lookup("/a"), a(Kind::File, 0, 0, 0o644, 0x20));
        assert_eq!(v.lookup("/b c"), a(Kind::File, 501, 0, 0o4755, 0x20));
        assert_eq!(v.lookup("/etc"), a(Kind::Link, 0, 0, 0o755, 0));
        // A directory's line is read with the defaults before its own /set.
        assert_eq!(v.lookup("/sub"), a(Kind::Dir, 0, 0, 0o700, 0));
        assert_eq!(v.lookup("/sub/x"), a(Kind::File, 0, 80, 0o444, 0));
        assert_eq!(v.lookup("/sub/y"), None);
        assert_eq!(v.lookup("/a/x"), None);
        assert_eq!(v.lookup("/etc/x"), None);
    }

    /// The device's own, from the boot payload GEX_DARWIN_BOOT names.
    #[test]
    #[ignore = "needs the boot payload's SystemVolume.attrs"]
    fn reads_the_device_system_volume() {
        let dir = std::env::var("GEX_DARWIN_BOOT").expect("GEX_DARWIN_BOOT");
        let v = parse(&std::fs::read(format!("{dir}/SystemVolume.attrs")).unwrap()).unwrap();
        let a = |kind, uid, gid, mode, flags| Some(Attrs { kind, uid, gid, mode, flags });
        assert_eq!(v.lookup("/sbin/launchd"), a(Kind::File, 0, 0, 0o755, 0x20));
        assert_eq!(v.lookup("/private/var/mobile"), a(Kind::Dir, 501, 501, 0o711, 0));
        assert_eq!(v.lookup("/etc"), a(Kind::Link, 0, 0, 0o755, 0));
        assert_eq!(v.lookup("/bin/ps"), a(Kind::File, 0, 0, 0o4755, 0x20));
        assert_eq!(v.lookup("/var"), a(Kind::Link, 0, 80, 0o755, 0));
        assert_eq!(v.lookup("/System/Cryptexes/OS/System"), None);
    }

    /// The SystemOS cryptex's, from the same payload: the shared cache is
    /// root's, group admin.
    #[test]
    #[ignore = "needs the boot payload's SystemOS.attrs"]
    fn reads_the_device_os_cryptex() {
        let dir = std::env::var("GEX_DARWIN_BOOT").expect("GEX_DARWIN_BOOT");
        let v = parse(&std::fs::read(format!("{dir}/SystemOS.attrs")).unwrap()).unwrap();
        let a = |kind, uid, gid, mode, flags| Some(Attrs { kind, uid, gid, mode, flags });
        assert_eq!(v.lookup("/"), a(Kind::Dir, 0, 0, 0o755, 0));
        assert_eq!(v.lookup("/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64"), a(Kind::File, 0, 80, 0o755, 0));
        assert_eq!(v.lookup("/sbin/launchd"), None);
    }

    #[test]
    fn refuses_what_it_cannot_read() {
        assert!(parse(b". type=dir uid=0 gid=0 mode=0755 flags=0\nx\n..\n").is_err());
        assert!(parse(b". type=dir uid=0 gid=0 mode=0755 flags=0\nx type=file size=3\n..\n").is_err());
        assert!(parse(b". type=dir uid=0 gid=0 mode=0755 flags=0\n").is_err());
    }
}
