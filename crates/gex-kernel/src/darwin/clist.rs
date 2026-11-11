//! Character lists (`bsd/kern/tty_subr.c`): the ring buffers a terminal's
//! raw, canonical and output queues are, each byte with a quote bit beside
//! it when the list keeps them (`QBITS`). The ring's positions are kept as
//! XNU keeps them, since `ndqb` answers by them.

/// `TTY_CHARMASK`.
pub const TTY_CHARMASK: i32 = 0x0000_00ff;
/// `TTY_QUOTE`: the character was quoted (`VLNEXT`, or `\\` before an erase).
pub const TTY_QUOTE: i32 = 0x0000_0100;
/// `TTYCLSIZE`: each of a terminal's lists holds this many characters.
pub const TTYCLSIZE: usize = 1024;

/// `struct clist`: `c_cs` is the buffer (its length `c_cn`), `c_cf` and
/// `c_cl` the first and one past the last character as indices into it
/// (`None` while the list is empty, as XNU's null pointers), `c_cc` the
/// count, and `c_cq` the quote bits, one per position.
#[derive(Clone, Debug, Default)]
pub struct Clist {
    cs: Vec<u8>,
    cq: Option<Vec<u8>>,
    cf: Option<usize>,
    cl: Option<usize>,
    cc: usize,
}

/// `isset`, `setbit`, `clrbit` over a bitmap of bytes.
fn isset(map: &[u8], i: usize) -> bool {
    map[i / 8] & (1 << (i % 8)) != 0
}
fn setbit(map: &mut [u8], i: usize) {
    map[i / 8] |= 1 << (i % 8);
}
fn clrbit(map: &mut [u8], i: usize) {
    map[i / 8] &= !(1 << (i % 8));
}

/// `clrbits`: bits `off` to `off + len` of `cp` cleared.
fn clrbits(cp: &mut [u8], off: usize, len: usize) {
    if len == 1 {
        clrbit(cp, off);
        return;
    }
    let (mut sby, sbi) = (off / 8, off % 8);
    let (eby, ebi) = ((off + len) / 8, (off + len) % 8);
    if sby == eby {
        let mask = ((((1u32 << (ebi - sbi)) - 1) << sbi) & 0xff) as u8;
        cp[sby] &= !mask;
    } else {
        let mask = ((1u32 << sbi) - 1) as u8;
        cp[sby] &= mask;
        sby += 1;
        let mask = ((1u32 << ebi) - 1) as u8;
        // The remainder's bits, for a non-0 `ebi`.
        if mask != 0 {
            cp[eby] &= !mask;
        }
        for b in &mut cp[sby..eby] {
            *b = 0;
        }
    }
}

impl Clist {
    /// `clalloc(clp, size, quot)`: room for `size` characters, with quote
    /// bits when `quot`.
    pub fn alloc(size: usize, quot: bool) -> Clist {
        Clist { cs: vec![0; size], cq: quot.then(|| vec![0; (size - 1) / 8 + 1]), cf: None, cl: None, cc: 0 }
    }

    /// `c_cc`.
    pub fn len(&self) -> usize {
        self.cc
    }

    pub fn is_empty(&self) -> bool {
        self.cc == 0
    }

    /// `c_cn`.
    pub fn capacity(&self) -> usize {
        self.cs.len()
    }

    /// The list's allocation for a `putc` or `b_to_q` that finds it has
    /// none (`clalloc(clp, 1024, 1)`).
    fn ensure(&mut self) {
        if self.cs.is_empty() {
            *self = Clist::alloc(1024, true);
        }
    }

    fn quoted(&self, i: usize) -> bool {
        self.cq.as_ref().is_some_and(|q| isset(q, i))
    }

    /// `getc`: the first character, with TTY_QUOTE if it was quoted; -1 for
    /// none.
    pub fn getc(&mut self) -> i32 {
        if self.cc == 0 {
            return -1;
        }
        let cf = self.cf.expect("a list with characters has a first");
        let mut c = i32::from(self.cs[cf]);
        if self.quoted(cf) {
            c |= TTY_QUOTE;
        }
        let mut next = cf + 1;
        if next == self.cs.len() {
            next = 0;
        }
        self.cf = Some(next);
        self.cc -= 1;
        if self.cc == 0 {
            self.cf = None;
            self.cl = None;
        }
        c
    }

    /// `q_to_b`: up to `buf.len()` characters, their quote bits dropped;
    /// how many.
    pub fn q_to_b(&mut self, buf: &mut [u8]) -> usize {
        let mut count = buf.len();
        let mut p = 0;
        while count > 0 && self.cc > 0 {
            let (cf, cl) = (self.cf.unwrap(), self.cl.unwrap());
            let mut cc = if cf >= cl { self.cs.len() - cf } else { cl - cf };
            if cc > count {
                cc = count;
            }
            buf[p..p + cc].copy_from_slice(&self.cs[cf..cf + cc]);
            count -= cc;
            p += cc;
            self.cc -= cc;
            let mut next = cf + cc;
            if next == self.cs.len() {
                next = 0;
            }
            self.cf = Some(next);
        }
        if self.cc == 0 {
            self.cf = None;
            self.cl = None;
        }
        p
    }

    /// `ndqb(clp, flag)`: with `flag` 0 the characters that follow in one
    /// piece of the buffer; else how many come before the first with a bit
    /// of `flag` (or, with TTY_QUOTE in it, the first quoted).
    pub fn ndqb(&self, flag: i32) -> usize {
        let cc = self.cc;
        if cc == 0 {
            return 0;
        }
        let (cf, cl) = (self.cf.unwrap(), self.cl.unwrap());
        if flag == 0 {
            // `c_cl - c_cf`, unsigned: no more than zero when the
            // characters wrap.
            return if cl > cf { cl - cf } else { self.cs.len() - cf };
        }
        let mut count = 0;
        let mut i = cf;
        let mut left = cc;
        if flag & TTY_QUOTE != 0 {
            let bits = flag & !TTY_QUOTE;
            // XNU tests the quote bit of the position after the character
            // (`i` is advanced first): kept.
            while left > 0 {
                left -= 1;
                let ch = i32::from(self.cs[i]);
                i += 1;
                if ch & bits != 0 || self.cq.as_ref().is_some_and(|q| i < q.len() * 8 && isset(q, i)) {
                    break;
                }
                count += 1;
                if i == self.cs.len() {
                    break;
                }
            }
        } else {
            while left > 0 {
                left -= 1;
                let ch = i32::from(self.cs[i]);
                i += 1;
                if ch & flag != 0 {
                    break;
                }
                count += 1;
                if i == self.cs.len() {
                    break;
                }
            }
        }
        count
    }

    /// `ndflush`: the first `count` characters dropped.
    pub fn ndflush(&mut self, count: usize) {
        if count == self.cc {
            self.cc = 0;
            self.cf = None;
            self.cl = None;
            return;
        }
        let mut count = count;
        while count > 0 && self.cc > 0 {
            let (cf, cl) = (self.cf.unwrap(), self.cl.unwrap());
            let mut cc = if cf >= cl { self.cs.len() - cf } else { cl - cf };
            if cc > count {
                cc = count;
            }
            count -= cc;
            self.cc -= cc;
            let mut next = cf + cc;
            if next == self.cs.len() {
                next = 0;
            }
            self.cf = Some(next);
        }
        if self.cc == 0 {
            self.cf = None;
            self.cl = None;
        }
    }

    /// `putc`: `c` (and its TTY_QUOTE) at the end; false when the list is
    /// full.
    pub fn putc(&mut self, c: i32) -> bool {
        if self.cc == 0 {
            self.ensure();
            self.cf = Some(0);
            self.cl = Some(0);
        }
        if self.cc == self.cs.len() {
            return false;
        }
        let i = self.cl.unwrap();
        self.cs[i] = (c & 0xff) as u8;
        if let Some(q) = self.cq.as_mut() {
            if c & TTY_QUOTE != 0 {
                setbit(q, i);
            } else {
                clrbit(q, i);
            }
        }
        self.cc += 1;
        let mut next = i + 1;
        if next == self.cs.len() {
            next = 0;
        }
        self.cl = Some(next);
        true
    }

    /// `b_to_q`: `buf` at the end, unquoted; how many did not fit.
    pub fn b_to_q(&mut self, buf: &[u8]) -> usize {
        let mut count = buf.len();
        if count == 0 {
            return 0;
        }
        if self.cc == 0 {
            self.ensure();
            self.cf = Some(0);
            self.cl = Some(0);
        }
        if self.cc == self.cs.len() {
            return count;
        }
        let mut p = 0;
        while count > 0 && self.cc < self.cs.len() {
            let (cf, cl) = (self.cf.unwrap(), self.cl.unwrap());
            let mut cc = if cf > cl { cf - cl } else { self.cs.len() - cl };
            if cc > count {
                cc = count;
            }
            self.cs[cl..cl + cc].copy_from_slice(&buf[p..p + cc]);
            if let Some(q) = self.cq.as_mut() {
                clrbits(q, cl, cc);
            }
            p += cc;
            count -= cc;
            self.cc += cc;
            let mut next = cl + cc;
            if next == self.cs.len() {
                next = 0;
            }
            self.cl = Some(next);
        }
        count
    }

    /// `firstc` and `nextc` as one walk: each character from the first,
    /// with its TTY_QUOTE.
    pub fn iter(&self) -> impl Iterator<Item = i32> + '_ {
        let n = self.cs.len();
        let start = self.cf.unwrap_or(0);
        (0..self.cc).map(move |k| {
            let i = (start + k) % n;
            let mut c = i32::from(self.cs[i]);
            if self.quoted(i) {
                c |= TTY_QUOTE;
            }
            c
        })
    }

    /// `unputc`: the last character taken back, with its TTY_QUOTE; -1 for
    /// none.
    pub fn unputc(&mut self) -> i32 {
        if self.cc == 0 {
            return -1;
        }
        let cl = self.cl.unwrap();
        let i = if cl == 0 { self.cs.len() - 1 } else { cl - 1 };
        self.cl = Some(i);
        self.cc -= 1;
        let mut c = i32::from(self.cs[i]);
        if self.quoted(i) {
            c |= TTY_QUOTE;
        }
        if self.cc == 0 {
            self.cf = None;
            self.cl = None;
        }
        c
    }

    /// `tq = *clp; clp->c_cc = 0; clp->c_cf = clp->c_cl = NULL`: the list
    /// emptied with its buffer kept, and a copy of the old list that reads
    /// that same buffer ([`Self::getc_detached`]), as `ttypend`'s does
    /// while new input goes into it.
    pub fn detach(&mut self) -> Detached {
        let d = Detached { cf: self.cf, cc: self.cc };
        self.cc = 0;
        self.cf = None;
        self.cl = None;
        d
    }

    /// `getc(&tq)` of a [`Self::detach`]ed copy: from the list's buffer as
    /// it is now.
    pub fn getc_detached(&self, d: &mut Detached) -> i32 {
        if d.cc == 0 {
            return -1;
        }
        let cf = d.cf.expect("a list with characters has a first");
        let mut c = i32::from(self.cs[cf]);
        if self.quoted(cf) {
            c |= TTY_QUOTE;
        }
        let mut next = cf + 1;
        if next == self.cs.len() {
            next = 0;
        }
        d.cf = Some(next);
        d.cc -= 1;
        if d.cc == 0 {
            d.cf = None;
        }
        c
    }

    /// `catq(from, to)`: every character of `from` moved onto `self`.
    pub fn catq(&mut self, from: &mut Clist) {
        loop {
            let c = from.getc();
            if c == -1 {
                break;
            }
            self.putc(c);
        }
    }
}

/// A list's old head and count, reading its buffer after [`Clist::detach`].
#[derive(Clone, Copy, Debug)]
pub struct Detached {
    cf: Option<usize>,
    cc: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn characters_keep_their_quotes_and_order_round_the_ring() {
        let mut q = Clist::alloc(8, true);
        assert_eq!(q.b_to_q(b"abcdef"), 0);
        assert_eq!(q.getc(), i32::from(b'a'));
        assert_eq!(q.getc(), i32::from(b'b'));
        assert!(q.putc(i32::from(b'g') | TTY_QUOTE));
        assert!(q.putc(i32::from(b'h')));
        assert!(q.putc(i32::from(b'i')));
        assert!(q.putc(i32::from(b'j')));
        assert!(!q.putc(i32::from(b'k')));
        assert_eq!(q.len(), 8);
        // The ring wrapped: the first piece is up to the buffer's end.
        assert_eq!(q.ndqb(0), 6);
        let all: Vec<i32> = q.iter().collect();
        assert_eq!(all[4], i32::from(b'g') | TTY_QUOTE);
        assert_eq!(q.unputc(), i32::from(b'j'));
        let mut buf = [0u8; 16];
        assert_eq!(q.q_to_b(&mut buf), 7);
        assert_eq!(&buf[..7], b"cdefghi");
        assert!(q.is_empty());
        assert_eq!(q.getc(), -1);
    }

    #[test]
    fn a_full_list_takes_no_more() {
        let mut q = Clist::alloc(4, false);
        assert_eq!(q.b_to_q(b"abcdef"), 2);
        q.ndflush(3);
        assert_eq!(q.len(), 1);
        assert_eq!(q.getc(), i32::from(b'd'));
        assert_eq!(q.ndqb(0), 0);
    }

    #[test]
    fn ndqb_stops_at_a_flagged_character() {
        let mut q = Clist::alloc(16, true);
        q.b_to_q(b"ab\x81cd");
        assert_eq!(q.ndqb(0x80), 2);
    }
}
