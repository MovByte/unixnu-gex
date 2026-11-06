//! AppleMatch (`com.apple.kext.AppleMatch`), the regular expression engine
//! Sandbox's profiles compile their regexes for: a packed program, its
//! validation when loaded, and its matcher.
//!
//! A program is `00 00 00 03`, the code's length, the code, then a pool of
//! literal strings. Each instruction's kind is its first byte's low
//! nibble: a string from the pool, a byte, a switch on the byte, accept
//! (with a 12-bit id), group start and end, the single-byte operations
//! (any byte, start, end, search, fail), a jump, a class of byte ranges, a
//! possessive star over a class, and a split. The matcher runs one thread
//! until the first split, then every thread in step (a Pike machine): the
//! first accept reached, in the threads' order, is the match.

/// `load`'s and `match`'s errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// -1: the program is not valid.
    Invalid,
    /// -3: a slot count out of range.
    BadArgument,
}

/// A loaded program.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Program {
    code: Vec<u8>,
    extra: Vec<u8>,
}

fn u16_at(b: &[u8], o: usize) -> usize {
    usize::from(b[o]) | usize::from(b[o + 1]) << 8
}

/// An instruction's length by its first byte; none for the kinds that do
/// not exist. (A split with no targets, `0x0f`, has length -1: the
/// kernel's validator steps back over it, and can do so forever; it is
/// refused here as not valid.)
fn oplen(op: u8) -> Option<isize> {
    Some(match op & 0xf {
        0 | 4 | 8 | 10 | 12 => 3,
        2 | 5 | 6 | 7 => 2,
        9 => 1,
        3 => 3 * isize::from(op >> 4) + 1,
        11 | 13 => isize::from((op >> 3) | 1),
        15 => isize::from((op >> 3) & 0x1e) - 1,
        _ => return None,
    })
}

/// `load` (`0x...b504`): validate a program. Each instruction must start
/// where the last ended and the code must end on one; operands must name
/// the pool within it, and jump, switch and split targets instruction
/// starts; no instruction that goes on to the next may be the last.
pub fn load(blob: &[u8]) -> Result<Program, Error> {
    if blob.len() < 6 || blob[..4] != [0, 0, 0, 3] {
        return Err(Error::Invalid);
    }
    let n = u16_at(blob, 4);
    if n == 0 || blob.len() < n + 6 {
        return Err(Error::Invalid);
    }
    let (code, extra) = (&blob[6..6 + n], &blob[6 + n..]);
    let mut start = vec![false; n];
    let mut pc = 0usize;
    loop {
        start[pc] = true;
        let len = oplen(code[pc]).ok_or(Error::Invalid)?;
        if len < 1 {
            return Err(Error::Invalid);
        }
        pc += len as usize;
        if pc >= n {
            break;
        }
    }
    if pc != n {
        return Err(Error::Invalid);
    }
    let target = |t: usize| t < n && start[t];
    let mut pc = 0usize;
    while pc < n {
        let op = code[pc];
        let len = oplen(op).ok_or(Error::Invalid)? as usize;
        if len > n - pc {
            return Err(Error::Invalid);
        }
        let falls = match op & 0xf {
            0 | 4 | 8 | 12 => {
                if u16_at(code, pc + 1) + usize::from(op >> 2) > extra.len() {
                    return Err(Error::Invalid);
                }
                true
            }
            2 | 6 | 7 => true,
            3 => {
                if op < 0x20 || !(0..usize::from(op >> 4)).all(|i| target(u16_at(code, pc + 1 + 3 * i))) {
                    return Err(Error::Invalid);
                }
                false
            }
            5 => false,
            9 => match (op >> 4) & 7 {
                0..=3 => true,
                4 => false,
                _ => return Err(Error::Invalid),
            },
            10 => {
                if !target(u16_at(code, pc + 1)) {
                    return Err(Error::Invalid);
                }
                false
            }
            11 | 13 => {
                if op < 0x10 {
                    return Err(Error::Invalid);
                }
                true
            }
            15 => {
                if op >= 0x20 && !(0..usize::from(op >> 4) - 1).all(|i| target(u16_at(code, pc + 1 + 2 * i))) {
                    return Err(Error::Invalid);
                }
                true
            }
            _ => return Err(Error::Invalid),
        };
        if falls && pc + len == n {
            return Err(Error::Invalid);
        }
        pc += len;
    }
    Ok(Program { code: code.to_vec(), extra: extra.to_vec() })
}

/// Whether byte `c` is in one of `count` ranges at `at` (lo, hi; a range
/// with lo past hi wraps around).
fn in_ranges(code: &[u8], at: usize, count: usize, c: u8) -> bool {
    (0..count).any(|i| {
        let (lo, hi) = (code[at + 2 * i], code[at + 2 * i + 1]);
        c.wrapping_sub(lo) <= hi.wrapping_sub(lo)
    })
}

const UNSET: u64 = u64::MAX;

#[derive(Clone)]
struct Thread {
    pc: usize,
    lit: usize,
    hw: usize,
    slots: Vec<[u64; 2]>,
}

impl Thread {
    fn child(&self, pc: usize, lit: usize) -> Thread {
        Thread { pc, lit, hw: self.hw, slots: self.slots.clone() }
    }
}

/// `0x...b40c`: a thread joins a list unless one at the same place is
/// there.
fn add(list: &mut Vec<Thread>, from: &Thread, pc: usize, lit: usize) {
    if !list.iter().any(|t| t.pc == pc && t.lit == lit) {
        list.push(from.child(pc, lit));
    }
}

/// A match: the accept's id (zero for none) and the groups' slots, start
/// and end offsets (none for a group not reached).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Found {
    pub id: u16,
    pub slots: Vec<Option<(u64, u64)>>,
}

impl Program {
    /// `match` (`0x...a24c`) over all of `s`, keeping `nslots` group slots
    /// (none, as Sandbox asks; else 1 to 255, slot 0 the whole subject).
    pub fn matches(&self, s: &[u8], nslots: usize) -> Result<Found, Error> {
        if nslots > 255 {
            return Err(Error::BadArgument);
        }
        let mut slots = vec![[UNSET; 2]; nslots];
        if nslots != 0 {
            slots[0] = [0, s.len() as u64];
        }
        let t = Thread { pc: 0, lit: 0, hw: 0, slots };
        Ok(self.phase1(s, t).map(|t| self.found(&t)).unwrap_or_default())
    }

    fn found(&self, t: &Thread) -> Found {
        let slots = t.slots[..t.hw.max(usize::from(!t.slots.is_empty()))].iter().map(|&[a, b]| (a != UNSET && b != UNSET).then_some((a, b))).collect();
        Found { id: (u16_at(&self.code, t.pc) >> 4) as u16, slots }
    }

    fn group(&self, t: &mut Thread, pos: usize, start: bool) {
        let idx = u16_at(&self.code, t.pc) >> 4;
        if idx < t.slots.len() {
            if start {
                t.slots[idx][0] = pos as u64;
                t.hw = t.hw.max(idx + 1);
            } else {
                t.slots[idx][1] = pos as u64;
            }
        }
    }

    /// The search's scan (`0x...a8cc`): from `from`, the first position the
    /// instruction at `spc` can match there, and the instruction after it.
    /// Only a string, byte, switch or class can follow a search.
    fn scan(&self, s: &[u8], spc: usize, from: usize) -> Option<(usize, usize)> {
        let (code, end) = (&self.code, s.len());
        let op = code[spc];
        match op & 0xf {
            0 | 4 | 8 | 12 => {
                let l = usize::from(op >> 2);
                let lit = &self.extra[u16_at(code, spc + 1)..];
                let lim = end.checked_sub(l)?;
                (from..=lim).find(|&p| s[p] == lit[0] && (op < 8 || (1..l).all(|i| s[p + i] == lit[i]))).and_then(|p| (spc + 3 < 0x10000).then_some((spc + 3, p)))
            }
            2 => (from..end).find(|&p| s[p] == code[spc + 1]).and_then(|p| (spc <= 0xfffd).then_some((spc + 2, p))),
            3 => {
                // Duplicate bytes: the last entry wins here.
                let mut table = [0usize; 256];
                for i in 0..usize::from(op >> 4) {
                    table[usize::from(code[spc + 3 + 3 * i])] = i;
                }
                (from..end).find_map(|p| {
                    let e = spc + 1 + 3 * table[usize::from(s[p])];
                    (code[e + 2] == s[p]).then(|| (u16_at(code, e), p))
                })
            }
            11 => {
                let count = usize::from(op >> 4);
                let lo = code[spc + 1];
                let hull = code[spc + 2 * count].wrapping_sub(lo);
                (from..end).find(|&p| s[p].wrapping_sub(lo) <= hull && op >= 0x10 && in_ranges(code, spc + 1, count, s[p])).and_then(|p| {
                    let npc = spc + ((2 * count) | 1);
                    (npc < 0x10000).then_some((npc, p))
                })
            }
            _ => None,
        }
    }

    /// One thread until a split hands over to [`Self::phase2`]: an accept
    /// ends it, a failure ends it unless a search can restart one byte on.
    fn phase1(&self, s: &[u8], mut t: Thread) -> Option<Thread> {
        let (code, end) = (&self.code, s.len());
        let mut pos = 0usize;
        let mut restart: Option<(usize, usize)> = None;
        loop {
            let pc = t.pc;
            let op = code[pc];
            let mut failed = false;
            match op & 0xf {
                6 | 7 => {
                    self.group(&mut t, pos, op & 0xf == 7);
                    t.pc += 2;
                }
                0 | 4 | 8 | 12 => {
                    let l = usize::from(op >> 2);
                    let off = u16_at(code, pc + 1);
                    t.pc += 3;
                    if t.pc > 0xffff || end - pos < l || self.extra[off..off + l] != s[pos..pos + l] {
                        failed = true;
                    } else {
                        pos += l;
                    }
                }
                2 => {
                    if pos == end || code[pc + 1] != s[pos] {
                        failed = true;
                    } else {
                        t.pc += 2;
                        pos += 1;
                    }
                }
                3 => match (0..usize::from(op >> 4)).find(|&i| pos != end && code[pc + 3 + 3 * i] == s[pos]) {
                    Some(i) => {
                        t.pc = u16_at(code, pc + 1 + 3 * i);
                        pos += 1;
                    }
                    None => failed = true,
                },
                5 => return Some(t),
                9 => match (op >> 4) & 7 {
                    0 => {
                        if pos == end {
                            failed = true;
                        } else {
                            t.pc += 1;
                            pos += 1;
                        }
                    }
                    1 => {
                        failed = pos != 0;
                        t.pc += 1;
                    }
                    2 => {
                        failed = pos != end;
                        t.pc += 1;
                    }
                    3 => {
                        if pc + 1 > 0xffff {
                            failed = true;
                        } else {
                            let (npc, hit) = self.scan(s, pc + 1, pos)?;
                            restart = Some((pc + 1, pos));
                            t.pc = npc;
                            pos = hit + 1;
                        }
                    }
                    _ => failed = true,
                },
                10 => t.pc = u16_at(code, pc + 1),
                11 => {
                    if pos == end || op < 0x10 || !in_ranges(code, pc + 1, usize::from(op >> 4), s[pos]) {
                        failed = true;
                    } else {
                        t.pc += usize::from((op >> 3) | 1);
                        pos += 1;
                    }
                }
                13 => {
                    if pos == end || op < 0x10 || !in_ranges(code, pc + 1, usize::from(op >> 4), s[pos]) {
                        t.pc += usize::from((op >> 3) | 1);
                    } else {
                        pos += 1;
                    }
                }
                15 => {
                    let npc = pc + oplen(op)? as usize;
                    if npc > 0xffff {
                        failed = true;
                    } else {
                        let mut cur = Vec::new();
                        add(&mut cur, &t, npc, 0);
                        if op >= 0x20 {
                            for i in 0..usize::from(op >> 4) - 1 {
                                add(&mut cur, &t, u16_at(code, pc + 1 + 2 * i), 0);
                            }
                        }
                        return self.phase2(s, cur, pos);
                    }
                }
                // Kinds 1 and 14 do not load.
                _ => unreachable!("an AppleMatch program that loaded has no kind {}", op & 0xf),
            }
            if failed {
                let (spc, spos) = restart?;
                let (npc, hit) = self.scan(s, spc, spos + 1)?;
                restart = Some((spc, spos + 1));
                t.pc = npc;
                pos = hit + 1;
            }
        }
    }

    /// Every thread in step, a byte at a time; the first accept reached in
    /// the threads' order wins.
    fn phase2(&self, s: &[u8], mut cur: Vec<Thread>, mut pos: usize) -> Option<Thread> {
        let (code, end) = (&self.code, s.len());
        while pos <= end {
            if cur.is_empty() {
                return None;
            }
            let mut next: Vec<Thread> = Vec::new();
            let mut i = 0;
            while i < cur.len() {
                let mut t = cur[i].clone();
                i += 1;
                loop {
                    let pc = t.pc;
                    let op = code[pc];
                    match op & 0xf {
                        6 | 7 => {
                            self.group(&mut t, pos, op & 0xf == 7);
                            t.pc += 2;
                            continue;
                        }
                        0 | 4 | 8 | 12 => {
                            let l = usize::from(op >> 2);
                            if pc + 3 > 0xffff || pos == end || self.extra[u16_at(code, pc + 1) + t.lit] != s[pos] {
                                break;
                            }
                            if t.lit + 1 != l {
                                add(&mut next, &t, pc, t.lit + 1);
                            } else {
                                add(&mut next, &t, pc + 3, 0);
                            }
                        }
                        2 => {
                            if pos != end && code[pc + 1] == s[pos] {
                                add(&mut next, &t, pc + 2, 0);
                            }
                        }
                        3 => {
                            if let Some(j) = (0..usize::from(op >> 4)).find(|&j| pos != end && code[pc + 3 + 3 * j] == s[pos]) {
                                add(&mut next, &t, u16_at(code, pc + 1 + 3 * j), 0);
                            }
                        }
                        5 => return Some(t),
                        9 => match (op >> 4) & 7 {
                            0 => {
                                if pos != end {
                                    add(&mut next, &t, pc + 1, 0);
                                }
                            }
                            1 if pos == 0 => {
                                t.pc += 1;
                                continue;
                            }
                            2 if pos == end => {
                                t.pc += 1;
                                continue;
                            }
                            3 => {
                                if pc != 0xffff {
                                    add(&mut next, &t, pc, 0);
                                    add(&mut cur, &t, pc + 1, 0);
                                }
                            }
                            _ => {}
                        },
                        10 => {
                            t.pc = u16_at(code, pc + 1);
                            continue;
                        }
                        11 => {
                            if pos != end && op >= 0x10 && in_ranges(code, pc + 1, usize::from(op >> 4), s[pos]) {
                                add(&mut next, &t, pc + usize::from((op >> 3) | 1), 0);
                            }
                        }
                        13 => {
                            if pos == end || op < 0x10 || !in_ranges(code, pc + 1, usize::from(op >> 4), s[pos]) {
                                t.pc += usize::from((op >> 3) | 1);
                                continue;
                            }
                            add(&mut next, &t, pc, t.lit);
                        }
                        15 => {
                            let npc = pc + oplen(op)? as usize;
                            if npc <= 0xffff {
                                add(&mut cur, &t, npc, 0);
                                if op >= 0x20 {
                                    for j in 0..usize::from(op >> 4) - 1 {
                                        add(&mut cur, &t, u16_at(code, pc + 1 + 2 * j), 0);
                                    }
                                }
                            }
                        }
                        _ => unreachable!("an AppleMatch program that loaded has no kind {}", op & 0xf),
                    }
                    break;
                }
            }
            pos += 1;
            cur = next;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prog(code: &[u8]) -> Vec<u8> {
        let mut b = vec![0, 0, 0, 3];
        b.extend_from_slice(&(code.len() as u16).to_le_bytes());
        b.extend_from_slice(code);
        b
    }

    #[test]
    fn an_anchored_class_plus() {
        // ^/a[^/]+$ : bol, '/', 'a', class [^/], split(exit) -> jmp class, eol, accept 1.
        let code = [0x19, 0x02, b'/', 0x02, b'a', 0x1b, 0x30, 0x2e, 0x2f, 0x0e, 0x00, 0x0a, 0x05, 0x00, 0x29, 0x15, 0x00];
        let p = load(&prog(&code)).unwrap();
        assert_eq!(p.matches(b"/abc", 0).unwrap().id, 1);
        assert_eq!(p.matches(b"/a", 0).unwrap().id, 0);
        assert_eq!(p.matches(b"/ab/c", 0).unwrap().id, 0);
        assert_eq!(p.matches(b"x/abc", 0).unwrap().id, 0);
    }

    #[test]
    fn invalid_programs_are_refused() {
        assert_eq!(load(&prog(&[0x01])).unwrap_err(), Error::Invalid);
        // A byte as the last instruction.
        assert_eq!(load(&prog(&[0x02, b'a'])).unwrap_err(), Error::Invalid);
        // A jump into the middle of an instruction.
        assert_eq!(load(&prog(&[0x02, b'a', 0x0a, 0x01, 0x00, 0x15, 0x00])).unwrap_err(), Error::Invalid);
        assert_eq!(load(&prog(&[0x0f, 0x15, 0x00])).unwrap_err(), Error::Invalid);
    }
}

#[cfg(test)]
mod blobs {
    /// Vectors (`GEX_APPLEMATCH_VECTORS`: lines of a program, a subject,
    /// both hex, and the accept id) taken from the kernel's matcher's
    /// behavior over real profiles' regexes. Not run without them.
    #[test]
    fn the_matcher_agrees_with_its_vectors() {
        let Some(path) = std::env::var_os("GEX_APPLEMATCH_VECTORS") else { return };
        let hex = |h: &str| if h == "-" { Vec::new() } else { (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect::<Vec<u8>>() };
        let text = std::fs::read_to_string(path).unwrap();
        let (mut n, mut bad) = (0, 0);
        let mut last: Option<(String, super::Program)> = None;
        for line in text.lines() {
            let f: Vec<&str> = line.split(' ').collect();
            if last.as_ref().map(|(k, _)| k.as_str()) != Some(f[0]) {
                last = Some((f[0].to_string(), super::load(&hex(f[0])).unwrap()));
            }
            let p = &last.as_ref().unwrap().1;
            let id = p.matches(&hex(f[1]), 0).unwrap().id;
            n += 1;
            if u32::from(id) != f[2].parse::<u32>().unwrap() {
                bad += 1;
            }
        }
        assert_eq!(bad, 0, "{bad} of {n} differ");
    }
}
