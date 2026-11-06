//! Trust caches: the cdhashes of the code the system trusts as platform
//! code (`bsd/kern/kern_trustcache.c`, and libTrustCache as AMFI links it).
//!
//! The boot loader hands the kernel a bundle at `/chosen/memory-map/
//! TrustCache`: a count, each module's offset from the bundle's start, and
//! the modules. Module 0 is the static trust cache; on a release kernel
//! the others are engineering modules, skipped. A module is a version, a
//! UUID, a count and its entries: a cdhash (v0), with its hash type and
//! flags (v1), and a launch-constraint category (v2), sorted by cdhash.

use std::sync::OnceLock;

/// A trust cache entry as a query finds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub hash_type: u8,
    pub flags: u8,
    /// The launch-constraint category (v2 modules), none in an older one.
    pub category: Option<u8>,
}

/// One loaded module.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Module {
    pub version: u32,
    pub uuid: [u8; 16],
    entries: Vec<u8>,
}

/// Why a module or a bundle does not load (libTrustCache's errors, and
/// the kernel's panics for the bundle).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// Shorter than the header, or than its entries.
    Truncated,
    /// A version other than 0, 1 and 2.
    Version(u32),
    /// The bundle's offsets or count are out of its length.
    Bundle(String),
}

const HEADER: usize = 0x18;

fn entry_size(version: u32) -> Option<usize> {
    match version {
        0 => Some(20),
        1 => Some(22),
        2 => Some(24),
        _ => None,
    }
}

impl Module {
    /// libTrustCache's module check (`0x...bb8f8`): a known version and
    /// room for its entries (bytes past them are allowed; order, duplicates
    /// and the entries' fields are not checked).
    pub fn load(b: &[u8]) -> Result<Module, Error> {
        if b.len() < HEADER {
            return Err(Error::Truncated);
        }
        let version = u32::from_le_bytes(b[0..4].try_into().unwrap());
        let size = entry_size(version).ok_or(Error::Version(version))?;
        let count = u32::from_le_bytes(b[0x14..0x18].try_into().unwrap()) as usize;
        let end = count.checked_mul(size).and_then(|n| n.checked_add(HEADER)).ok_or(Error::Truncated)?;
        if end > b.len() {
            return Err(Error::Truncated);
        }
        Ok(Module { version, uuid: b[4..20].try_into().unwrap(), entries: b[HEADER..end].to_vec() })
    }

    fn entry(&self, i: usize) -> &[u8] {
        let size = entry_size(self.version).unwrap();
        &self.entries[i * size..(i + 1) * size]
    }

    fn count(&self) -> usize {
        self.entries.len() / entry_size(self.version).unwrap()
    }

    /// The entry for `cdhash`: a scan of a v0 module, a binary search of a
    /// later one, on the 20 bytes of the cdhash only.
    pub fn lookup(&self, cdhash: &[u8; 20]) -> Option<Entry> {
        let at = if self.version == 0 {
            (0..self.count()).find(|&i| &self.entry(i)[..20] == cdhash)?
        } else {
            let (mut lo, mut hi) = (0usize, self.count());
            loop {
                if lo >= hi {
                    return None;
                }
                let mid = lo + (hi - lo) / 2;
                match self.entry(mid)[..20].cmp(cdhash) {
                    std::cmp::Ordering::Equal => break mid,
                    std::cmp::Ordering::Less => lo = mid + 1,
                    std::cmp::Ordering::Greater => hi = mid,
                }
            }
        };
        let e = self.entry(at);
        Some(match self.version {
            0 => Entry { hash_type: 0, flags: 0, category: None },
            1 => Entry { hash_type: e[20], flags: e[21], category: None },
            _ => Entry { hash_type: e[20], flags: e[21], category: Some(e[22]) },
        })
    }
}

/// `load_static_trust_cache`: the bundle's module 0 as the static trust
/// cache (its failure is the kernel's panic); the other modules are
/// engineering modules, which a release kernel skips.
pub fn load_bundle(b: &[u8]) -> Result<Module, Error> {
    let bad = |what: &str| Error::Bundle(what.into());
    let num = b.get(0..4).map(|s| u32::from_le_bytes(s.try_into().unwrap())).ok_or(bad("no module count"))? as usize;
    if num == 0 {
        return Err(bad("trust cache segment isn't zero but no trust caches available"));
    }
    if b.len() < 4 + 4 * num {
        return Err(bad("trust cache segment length smaller than required"));
    }
    let off = u32::from_le_bytes(b[4..8].try_into().unwrap()) as usize;
    if off >= b.len() {
        return Err(bad("trust cache module begins after segment ends"));
    }
    Module::load(&b[off..])
}

/// The static trust cache the system booted with; none when the boot gave
/// no bundle ("no external trust caches found").
static STATIC: OnceLock<Option<Module>> = OnceLock::new();

/// Set the boot's static trust cache, once.
pub fn set_static(m: Option<Module>) {
    let _ = STATIC.set(m);
}

/// AMFI's platform test (`0x...ab3e10`): a query of the static trust cache,
/// then of the loaded ones (none are loaded here: loading one is AMFI's
/// user client's, after the cryptexes' manifests are checked).
pub fn platform(cdhash: &[u8; 20]) -> Option<Entry> {
    STATIC.get().and_then(Option::as_ref).and_then(|m| m.lookup(cdhash))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module(version: u32, hashes: &[[u8; 20]]) -> Vec<u8> {
        let mut b = version.to_le_bytes().to_vec();
        b.extend_from_slice(&[7u8; 16]);
        b.extend_from_slice(&(hashes.len() as u32).to_le_bytes());
        for (i, h) in hashes.iter().enumerate() {
            b.extend_from_slice(h);
            if version > 0 {
                b.extend_from_slice(&[2, i as u8]);
            }
            if version > 1 {
                b.extend_from_slice(&[9, 0]);
            }
        }
        b
    }

    #[test]
    fn a_module_finds_its_cdhashes() {
        let hs: Vec<[u8; 20]> = (1..=9u8).map(|i| [i * 10; 20]).collect();
        for v in 0..=2 {
            let m = Module::load(&module(v, &hs)).unwrap();
            for (i, h) in hs.iter().enumerate() {
                let e = m.lookup(h).unwrap();
                assert_eq!(e.flags, if v > 0 { i as u8 } else { 0 });
                assert_eq!(e.category, (v == 2).then_some(9));
            }
            assert_eq!(m.lookup(&[15; 20]), None);
        }
        assert_eq!(Module::load(&module(3, &hs)), Err(Error::Version(3)));
        let b = module(2, &hs);
        assert_eq!(Module::load(&b[..b.len() - 1]), Err(Error::Truncated));
    }

    #[test]
    fn a_bundles_first_module_is_the_static_cache() {
        let m = module(2, &[[1; 20]]);
        let mut b = 2u32.to_le_bytes().to_vec();
        b.extend_from_slice(&12u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&m);
        assert!(load_bundle(&b).unwrap().lookup(&[1; 20]).is_some());
        assert!(load_bundle(&0u32.to_le_bytes()).is_err());
    }
}
