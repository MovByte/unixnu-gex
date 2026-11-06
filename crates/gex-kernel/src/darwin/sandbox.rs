//! Sandbox's compiled profiles and their evaluation, as the iOS 17
//! Sandbox.kext reads them (`profile.c`'s loader and the evaluator its
//! MAC hooks share).
//!
//! A profile blob starts with a 14-byte header: its flags (a collection's
//! has bit 15 set), its node count, the operation count (191 here), the
//! sizes of four tables of 16-bit entries that follow it, and the number of
//! profiles in a collection. A single profile's operation table follows
//! those tables; a collection's profiles do, each a name, its flags and an
//! operation table. Each operation's entry names the node its evaluation
//! starts at: the nodes, 8 bytes each from the next 8-byte boundary, are
//! filters (a type, an argument, and the node to go on to when it matches
//! and when it does not) or terminals (the decision). A node only leads to
//! nodes after it.
//!
//! Every malformed profile is refused at evaluation (EPERM), as the kernel
//! refuses it.

/// The operations a profile has (the `0xbf` the loader checks).
pub const OPERATIONS: usize = 191;
/// A collection profile's entry: a name, flags, and its operation table.
const ENTRY: usize = 4 + 2 * OPERATIONS;
const NODE: usize = 8;

/// One profile: offsets into its blob.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    /// The profile's name (a string table index) and flags, for a
    /// collection's.
    pub name: u16,
    pub flags: u16,
    ops: usize,
    nodes: usize,
    nodes_end: usize,
}

/// Why a blob is refused (the loader's messages).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoadError {
    Truncated,
    WrongFlags,
    OperationCount(u8),
}

fn u16_at(b: &[u8], o: usize) -> Option<u16> {
    b.get(o..o + 2).map(|s| u16::from_le_bytes([s[0], s[1]]))
}

/// The header's fields and where its tables end.
struct Header {
    flags: u16,
    nodes: usize,
    profiles: usize,
    tables_end: usize,
}

fn header(b: &[u8]) -> Result<Header, LoadError> {
    if b.len() < 0xe {
        return Err(LoadError::Truncated);
    }
    if b[4] as usize != OPERATIONS {
        return Err(LoadError::OperationCount(b[4]));
    }
    let (c, d) = (usize::from(b[5]), usize::from(b[6]));
    let (e, f) = (usize::from(u16_at(b, 0xa).unwrap()), usize::from(u16_at(b, 0xc).unwrap()));
    Ok(Header {
        flags: u16_at(b, 0).unwrap(),
        nodes: usize::from(u16_at(b, 2).unwrap()),
        profiles: usize::from(u16_at(b, 8).unwrap()),
        tables_end: 0xe + 2 * (e + c + d + f),
    })
}

fn nodes_after(end: usize, count: usize, len: usize) -> Result<(usize, usize), LoadError> {
    let base = (end + NODE - 1) & !(NODE - 1);
    let nodes_end = base + count * NODE;
    if nodes_end > len {
        return Err(LoadError::Truncated);
    }
    Ok((base, nodes_end))
}

/// A single profile blob (the platform profile's form: no profiles
/// counted, its operation table after the header's tables).
pub fn single(b: &[u8]) -> Result<Profile, LoadError> {
    let h = header(b)?;
    let ops = h.tables_end;
    let (nodes, nodes_end) = nodes_after(ops + 2 * OPERATIONS, h.nodes, b.len())?;
    Ok(Profile { name: 0, flags: h.flags, ops, nodes, nodes_end })
}

/// A collection blob's profiles.
pub fn collection(b: &[u8]) -> Result<Vec<Profile>, LoadError> {
    let h = header(b)?;
    if h.flags & 0x8000 == 0 {
        return Err(LoadError::WrongFlags);
    }
    let first = h.tables_end;
    let (nodes, nodes_end) = nodes_after(first + h.profiles * ENTRY, h.nodes, b.len())?;
    (0..h.profiles)
        .map(|i| {
            let at = first + i * ENTRY;
            Ok(Profile { name: u16_at(b, at).ok_or(LoadError::Truncated)?, flags: u16_at(b, at + 2).ok_or(LoadError::Truncated)?, ops: at + 4, nodes, nodes_end })
        })
        .collect()
}

/// A decision: the action (1, EPERM, denies) and the terminal's flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decision {
    pub errno: u32,
    pub flags: u32,
}

impl Decision {
    /// The evaluator's packed result.
    pub fn packed(self) -> u64 {
        u64::from(self.flags) << 32 | u64::from(self.errno)
    }
}

/// A malformed profile's result: EPERM, flags 5.
const REFUSED: Decision = Decision { errno: 1, flags: 5 };

/// What a filter said, or that this port cannot say yet.
pub enum Filtered {
    Matched(bool),
    Unported(String),
}

/// What a terminal's modifiers left for the operation's caller to act on
/// (`0xfffffff006a072f8`'s records): message strings, kept the first time
/// each is set, and a storage class to name for a vnode operation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Effects {
    pub message: Option<Vec<u8>>,
    pub message2: Option<Vec<u8>>,
    pub message3: Option<Vec<u8>>,
    pub storage_class: Option<Vec<u8>>,
}

/// What evaluation came to.
pub enum Outcome {
    Decided(Decision, Effects),
    /// A node of a kind not ported yet: what it is.
    Unported(String),
}

/// A string a profile names: at or past the nodes' end, a length (its NUL
/// counted) and the bytes, the last of them NUL.
fn string_at(b: &[u8], p: &Profile, at: usize) -> Option<Vec<u8>> {
    if at < p.nodes_end {
        return None;
    }
    let n = usize::from(u16_at(b, at)?);
    let s = b.get(at + 2..at + 2 + n)?;
    (n != 0 && s[n - 1] == 0).then(|| s[..n - 1].to_vec())
}

/// Apply one 4-byte modifier record at `at`; false refuses the decision.
fn modify(b: &[u8], p: &Profile, at: usize, d: &mut Decision, fx: &mut Effects, unported: &mut Option<String>) -> bool {
    let Some(r) = b.get(at..at + 4) else { return false };
    let arg = u16::from_le_bytes([r[2], r[3]]);
    let string = || string_at(b, p, p.nodes_end + usize::from(arg) * NODE);
    match r[0] {
        // The decision's errno, for a denial.
        2 => {
            if d.flags & 1 != 0 {
                d.errno = if arg == 0 { 1 } else { u32::from(arg) };
            }
            true
        }
        3..=8 | 13..=16 | 18 => true,
        9 if d.flags & 1 != 0 => {
            fx.message = None;
            true
        }
        9 | 10 | 11 => {
            let Some(s) = string() else { return false };
            let slot = match r[0] {
                9 => &mut fx.message,
                10 => &mut fx.message2,
                _ => &mut fx.message3,
            };
            if slot.is_none() {
                *slot = Some(s);
            }
            true
        }
        // Its class is a vnode operation's, under the platform profile only
        // (the caller's to apply); a bad string refuses wherever it is.
        12 => match string() {
            Some(s) => {
                fx.storage_class = Some(s);
                true
            }
            None => false,
        },
        1 | 17 | 19 => {
            *unported = Some(format!("sandbox modifier {} ({arg})", r[0]));
            true
        }
        // Any other kind is nothing: only a record cut short refuses.
        _ => true,
    }
}

/// Evaluate operation `op` of profile `p` in blob `b`, asking `filter`
/// about each filter node (its type, flag bit and argument).
pub fn evaluate(b: &[u8], p: &Profile, op: usize, filter: &mut dyn FnMut(u8, bool, u16) -> Filtered) -> Outcome {
    let refused = Outcome::Decided(REFUSED, Effects::default());
    let Some(idx) = (op < OPERATIONS).then(|| u16_at(b, p.ops + 2 * op)).flatten() else { return refused };
    let mut at = p.nodes + usize::from(idx) * NODE;
    loop {
        if at < p.nodes || at >= p.nodes_end || at + NODE > b.len() {
            return refused;
        }
        let n = &b[at..at + NODE];
        match n[0] {
            0 => {
                let ty = n[1] & 0x7f;
                if !(1..=0x5d).contains(&ty) {
                    return refused;
                }
                let arg = u16::from_le_bytes([n[2], n[3]]);
                let matched = match filter(ty, n[1] & 0x80 != 0, arg) {
                    Filtered::Matched(m) => m,
                    Filtered::Unported(what) => return Outcome::Unported(what),
                };
                let next = if matched { u16::from_le_bytes([n[4], n[5]]) } else { u16::from_le_bytes([n[6], n[7]]) };
                let to = p.nodes + usize::from(next) * NODE;
                // Only forward.
                if to <= at {
                    return refused;
                }
                at = to;
            }
            1 => {
                let word = u32::from(n[1]) | u32::from(n[2]) << 8 | u32::from(n[3]) << 16;
                let mut fx = Effects::default();
                let mut unported = None;
                // The extended form: its one modifier inline; else as many
                // as byte 4 says, past the nodes.
                let (mut d, records): (Decision, Vec<usize>) = if word & 0x80_0000 != 0 {
                    (Decision { errno: word & 1, flags: word & 0x7f_ffff }, vec![at + 4])
                } else {
                    let d = Decision { errno: word & 1, flags: word & 0xff_ffff };
                    if n[4] == 0 {
                        (d, Vec::new())
                    } else {
                        let first = p.nodes_end + usize::from(u16::from_le_bytes([n[6], n[7]])) * NODE;
                        (d, (0..usize::from(n[4])).map(|k| first + 4 * k).collect())
                    }
                };
                for r in records {
                    if !modify(b, p, r, &mut d, &mut fx, &mut unported) {
                        return refused;
                    }
                }
                if let Some(what) = unported {
                    return Outcome::Unported(what);
                }
                return Outcome::Decided(d, fx);
            }
            _ => return refused,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A single profile blob with no tables and `nodes`, every operation
    /// starting at node `start`.
    fn blob(start: u16, nodes: &[[u8; 8]]) -> Vec<u8> {
        let mut b = vec![0u8; 0xe];
        b[2..4].copy_from_slice(&(nodes.len() as u16).to_le_bytes());
        b[4] = OPERATIONS as u8;
        for _ in 0..OPERATIONS {
            b.extend_from_slice(&start.to_le_bytes());
        }
        b.resize((b.len() + 7) & !7, 0);
        for n in nodes {
            b.extend_from_slice(n);
        }
        b
    }

    fn deny() -> [u8; 8] {
        [1, 1, 0, 0, 0, 0, 0, 0]
    }

    fn allow() -> [u8; 8] {
        [1, 0, 0, 0, 0, 0, 0, 0]
    }

    #[test]
    fn a_filter_chooses_between_its_two_next_nodes() {
        // Node 0: filter type 3 (arg 7): match -> node 1 (allow), else 2.
        let b = blob(0, &[[0, 3, 7, 0, 1, 0, 2, 0], allow(), deny()]);
        let p = single(&b).unwrap();
        let mut seen = Vec::new();
        for want in [true, false] {
            let out = evaluate(&b, &p, 5, &mut |t, _, a| {
                seen.push((t, a));
                Filtered::Matched(want)
            });
            let Outcome::Decided(d, _) = out else { panic!() };
            assert_eq!(d.errno, if want { 0 } else { 1 });
        }
        assert_eq!(seen, vec![(3, 7), (3, 7)]);
    }

    #[test]
    fn malformed_profiles_are_refused() {
        // A node that leads back to itself.
        let b = blob(0, &[[0, 3, 0, 0, 0, 0, 0, 0]]);
        let p = single(&b).unwrap();
        assert!(matches!(evaluate(&b, &p, 0, &mut |_, _, _| Filtered::Matched(true)), Outcome::Decided(d, _) if d == REFUSED));
        // A bad opcode, an operation past the table.
        let b = blob(0, &[[7, 0, 0, 0, 0, 0, 0, 0]]);
        let p = single(&b).unwrap();
        assert!(matches!(evaluate(&b, &p, 0, &mut |_, _, _| Filtered::Matched(true)), Outcome::Decided(d, _) if d == REFUSED));
        assert!(matches!(evaluate(&b, &p, OPERATIONS, &mut |_, _, _| Filtered::Matched(true)), Outcome::Decided(d, _) if d == REFUSED));
        let mut b = blob(0, &[allow()]);
        b[4] = 0xbe;
        assert_eq!(single(&b), Err(LoadError::OperationCount(0xbe)));
        assert_eq!(collection(&blob(0, &[allow()])), Err(LoadError::WrongFlags));
    }

    #[test]
    fn a_collections_profiles_have_their_own_operation_tables() {
        let mut b = vec![0u8; 0xe];
        b[0..2].copy_from_slice(&0x8000u16.to_le_bytes());
        b[2..4].copy_from_slice(&2u16.to_le_bytes());
        b[4] = OPERATIONS as u8;
        b[8..10].copy_from_slice(&2u16.to_le_bytes());
        for (name, start) in [(9u16, 0u16), (10, 1)] {
            b.extend_from_slice(&name.to_le_bytes());
            b.extend_from_slice(&0u16.to_le_bytes());
            for _ in 0..OPERATIONS {
                b.extend_from_slice(&start.to_le_bytes());
            }
        }
        b.resize((b.len() + 7) & !7, 0);
        b.extend_from_slice(&deny());
        b.extend_from_slice(&allow());
        let ps = collection(&b).unwrap();
        assert_eq!(ps.iter().map(|p| p.name).collect::<Vec<_>>(), vec![9, 10]);
        let errnos: Vec<u32> = ps.iter().map(|p| match evaluate(&b, p, 0, &mut |_, _, _| Filtered::Matched(true)) {
            Outcome::Decided(d, _) => d.errno,
            Outcome::Unported(_) => 99,
        }).collect();
        assert_eq!(errnos, vec![1, 0]);
    }
}

#[cfg(test)]
mod platform {
    use super::*;

    /// Every operation of a real platform profile (`GEX_SANDBOX_PLATFORM`,
    /// the kernelcache's blob) walks to a decision or to a filter, both
    /// ways at each filter. Not run without it.
    #[test]
    fn a_platform_profiles_terminals_all_read() {
        let Some(path) = std::env::var_os("GEX_SANDBOX_PLATFORM") else { return };
        let b = std::fs::read(path).unwrap();
        let p = single(&b).unwrap();
        let (mut decided, mut unported) = (0, std::collections::BTreeSet::new());
        for op in 0..OPERATIONS {
            for pick in [true, false] {
                match evaluate(&b, &p, op, &mut |_, _, _| Filtered::Matched(pick)) {
                    // (A profile's own denial can be the refusal's value,
                    // EPERM with flags 5.)
                    Outcome::Decided(..) => decided += 1,
                    Outcome::Unported(w) => {
                        unported.insert(w);
                    }
                }
            }
        }
        eprintln!("decided {decided}, unported {unported:?}");
    }
}
