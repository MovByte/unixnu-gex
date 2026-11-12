//! XNU's socket buffer accounting (`uipc_socket2.c`), for the unix sockets
//! a Darwin process uses: the mbufs `sosend` copies a send into, what
//! `sballoc` charges a buffer for each (its length to `sb_cc`, its storage
//! to `sb_mbcnt`), `sbcompress`'s folding of a small mbuf into the one
//! before it, and `sbspace`.
//!
//! The kernel's mbufs are 512 bytes (`_MSIZE` without
//! `CONFIG_MBUF_MCACHE`), with 288 of them for data (`MLEN` and `MHLEN`);
//! clusters are 2 KB, or 4 KB for a pass of more than 2 KB (the 16 KB
//! jumbo clusters are a `SOF_MULTIPAGES` socket's, which a unix one is not).

use std::collections::VecDeque;

/// `_MSIZE`.
pub const MSIZE: usize = 512;
/// `MLEN` and `MHLEN`, the same here.
pub const MLEN: usize = 288;
/// `MINCLSIZE` (`MLEN + MHLEN`).
pub const MINCLSIZE: usize = 576;
pub const MCLBYTES: usize = 2048;
pub const MBIGCLBYTES: usize = 4096;
/// `sb_efficiency`: `sbreserve`'s mbuf storage allowance per byte.
pub const SB_EFFICIENCY: usize = 8;

/// One mbuf in a buffer: the room for data it has (its cluster's, or its
/// own), the cluster's size (0 for none), where its data starts in that
/// room, how much there is, and whether it is control (an ancillary
/// message) or address rather than data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mbuf {
    pub room: usize,
    pub ext: usize,
    pub off: usize,
    pub len: usize,
    pub kind: Kind,
}

/// `m_type`, as far as the buffer tells them apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Data,
    Control,
    Name,
}

impl Mbuf {
    /// An mbuf of its own, `len` bytes in it.
    pub fn small(len: usize, kind: Kind) -> Mbuf {
        Mbuf { room: MLEN, ext: 0, off: 0, len, kind }
    }

    /// The control mbuf `sockargs` copies `msg_controllen` bytes into: a
    /// cluster when its descriptors' expansion to pointers (twice the
    /// payload, on LP64) passes `MLEN`.
    pub fn control(len: usize) -> Mbuf {
        const CMSGHDR: usize = 12;
        let alloc = (len.saturating_sub(CMSGHDR)) * 2 + CMSGHDR;
        if alloc > MLEN {
            Mbuf { room: MCLBYTES, ext: MCLBYTES, off: 0, len, kind: Kind::Control }
        } else {
            Mbuf::small(len, Kind::Control)
        }
    }

    /// What `sballoc` charges to `sb_mbcnt` for it.
    pub fn storage(&self) -> usize {
        MSIZE + self.ext
    }

    /// `M_TRAILINGSPACE`.
    pub fn trailing(&self) -> usize {
        self.room - self.off - self.len
    }
}

/// The clusters (or the one mbuf) `sosend` takes from `m_getpackets_internal`
/// for a pass of `alloc` bytes: 4 KB clusters past 2 KB (one more for a
/// remainder of at least `MINCLSIZE`), 2 KB ones past `MLEN`
/// (`soreserveheadroom`), else one mbuf.
fn packets(alloc: usize) -> (usize, usize) {
    if alloc > MCLBYTES {
        let n = alloc / MBIGCLBYTES + usize::from(alloc % MBIGCLBYTES >= MINCLSIZE);
        (n, MBIGCLBYTES)
    } else if alloc > MLEN {
        (alloc.div_ceil(MCLBYTES), MCLBYTES)
    } else {
        (1, 0)
    }
}

/// `sosendmaxchain`: a pass of a stream's send ends once its chain holds
/// this much and `MINCLSIZE` or more is left.
const SOSENDMAXCHAIN: usize = 65536;

/// One `sosend` call's mbufs in hand (`freelist`): what an allocation gave
/// that a pass has not filled yet, which the next pass of the same call
/// fills first. Each entry is a cluster's size, or 0 for an mbuf alone.
#[derive(Debug, Default)]
pub struct Sosend {
    free: VecDeque<usize>,
}

impl Sosend {
    /// One pass of `sosend`'s copy loop: as much of `resid` as `space`
    /// takes, into mbufs allocated for the pass's size when none are in
    /// hand, until the space or the bytes run out (or, for a stream, the
    /// chain passes `sosendmaxchain` with `MINCLSIZE` or more to go).
    /// The chain, and the bytes it holds.
    pub fn pass(&mut self, mut resid: usize, mut space: usize, atomic: bool) -> (Vec<Mbuf>, usize) {
        let alloc = resid.min(space);
        let mut to_copy = alloc;
        let mut chain = 0usize;
        let mut out = Vec::new();
        loop {
            if self.free.is_empty() {
                let (n, size) = packets(alloc);
                for _ in 0..n {
                    self.free.push_back(size);
                }
            }
            let ext = self.free.pop_front().expect("allocated above");
            let room = if ext != 0 { ext } else { MLEN };
            let len = room.min(to_copy);
            out.push(Mbuf { room, ext, off: 0, len, kind: Kind::Data });
            chain += len;
            space -= len;
            resid -= len;
            if resid == 0 {
                break;
            }
            to_copy = resid.min(space);
            if !(space > 0 && (chain < SOSENDMAXCHAIN || atomic || resid < MINCLSIZE)) {
                break;
            }
        }
        (out, chain)
    }

    /// Whether mbufs are still in hand.
    pub fn holding(&self) -> bool {
        !self.free.is_empty()
    }
}

/// The mbufs `sosend` copies a datagram of `bytes` bytes into: one pass of
/// an atomic send, which takes the whole of it.
pub fn sosend_chain(bytes: usize) -> Vec<Mbuf> {
    Sosend::default().pass(bytes, bytes, true).0
}

/// A socket buffer's accounting (`struct sockbuf`): its limits, its
/// counts (`sb_ctl` the bytes of its address and control mbufs), and its
/// records' mbufs.
#[derive(Clone, Debug, Default)]
pub struct SockBuf {
    pub hiwat: usize,
    pub mbmax: usize,
    pub cc: usize,
    pub ctl: usize,
    pub mbcnt: usize,
    records: VecDeque<VecDeque<Mbuf>>,
}

impl SockBuf {
    /// A buffer `sbreserve` sized to `cc`.
    pub fn new(cc: usize) -> SockBuf {
        let mut sb = SockBuf::default();
        sb.reserve(cc);
        sb
    }

    /// `sbreserve` of a size its caller has checked against `sb_max`: its
    /// high-water mark, and its mbuf storage allowance.
    pub fn reserve(&mut self, cc: usize) {
        self.hiwat = cc;
        self.mbmax = cc * SB_EFFICIENCY;
    }

    /// `sbspace`: the least of the room for bytes and for mbuf storage.
    pub fn space(&self) -> isize {
        (self.hiwat as isize - self.cc as isize).min(self.mbmax as isize - self.mbcnt as isize)
    }

    /// `sballoc`.
    fn alloc(&mut self, m: &Mbuf) {
        self.cc += m.len;
        if m.kind != Kind::Data {
            self.ctl += m.len;
        }
        self.mbcnt += m.storage();
    }

    /// `sbfree`.
    fn free(&mut self, m: &Mbuf) {
        self.cc -= m.len;
        if m.kind != Kind::Data {
            self.ctl -= m.len;
        }
        self.mbcnt -= m.storage();
    }

    /// The records waiting (`SO_NUMRCVPKT`), and the first one's data bytes
    /// (`SO_NREAD` of an atomic protocol's).
    pub fn records(&self) -> usize {
        self.records.len()
    }

    pub fn first_record_data(&self) -> usize {
        self.records.front().map_or(0, |r| r.iter().filter(|m| m.kind == Kind::Data).map(|m| m.len).sum())
    }

    /// `sbappendaddr` of a datagram (the address of `name_len` bytes, then
    /// the control mbufs, then the data): refused when the record's bytes
    /// exceed `sbspace`, else a record of its own.
    pub fn append_addr(&mut self, name_len: usize, control: &[Mbuf], data: &[Mbuf]) -> bool {
        let need = name_len + control.iter().chain(data).map(|m| m.len).sum::<usize>();
        if need as isize > self.space() {
            return false;
        }
        let mut rec = VecDeque::new();
        rec.push_back(Mbuf::small(name_len, Kind::Name));
        rec.extend(control.iter().copied());
        rec.extend(data.iter().copied());
        for m in &rec {
            self.alloc(m);
        }
        self.records.push_back(rec);
        true
    }

    /// The bytes of the control at the head of the first record
    /// (`soreceive_ctl`'s), if it starts with control.
    pub fn head_control(&self) -> Option<usize> {
        let rec = self.records.front()?;
        let n: usize = rec.iter().take_while(|m| m.kind == Kind::Control).map(|m| m.len).sum();
        rec.front().is_some_and(|m| m.kind == Kind::Control).then_some(n)
    }

    /// `soreceive_ctl` without `MSG_PEEK`: the control at the head of the
    /// first record freed; a record with nothing after it goes.
    pub fn take_head_control(&mut self) {
        let Some(rec) = self.records.front_mut() else { return };
        while rec.front().is_some_and(|m| m.kind == Kind::Control) {
            let m = rec.pop_front().expect("just seen");
            self.cc -= m.len;
            self.ctl -= m.len;
            self.mbcnt -= m.storage();
        }
        if rec.is_empty() {
            self.records.pop_front();
        }
    }

    /// The data bytes of the first record, after any control: as far as one
    /// receive of a stream reads.
    pub fn head_data(&self) -> usize {
        self.records.front().map_or(0, |r| r.iter().filter(|m| m.kind == Kind::Data).map(|m| m.len).sum())
    }

    /// `soreceive`'s copy loop without `MSG_PEEK`, for up to `resid` bytes:
    /// from the first record's data mbufs, each all of whose bytes are
    /// taken freed (and one with none, while `resid` is left), one partly
    /// taken keeping its room; the record ends the loop. The bytes taken.
    pub fn take(&mut self, mut resid: usize) -> usize {
        let mut taken = 0;
        let Some(rec) = self.records.front_mut() else { return 0 };
        while resid > 0 {
            let Some(m) = rec.front_mut() else { break };
            if m.kind != Kind::Data {
                break;
            }
            let len = resid.min(m.len);
            resid -= len;
            taken += len;
            if len == m.len {
                let m = rec.pop_front().expect("just seen");
                self.cc -= m.len;
                self.mbcnt -= m.storage();
            } else {
                m.len -= len;
                m.off += len;
                self.cc -= len;
            }
        }
        if rec.is_empty() {
            self.records.pop_front();
        }
        taken
    }

    /// Whether it holds no records (`sb_mb` is NULL).
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// `sorflush`: every record gone, and the limits with them.
    pub fn flush(&mut self) {
        self.records.clear();
        self.cc = 0;
        self.ctl = 0;
        self.mbcnt = 0;
        self.hiwat = 0;
        self.mbmax = 0;
    }

    /// `sbdroprecord`: the first record goes.
    pub fn drop_record(&mut self) {
        if let Some(rec) = self.records.pop_front() {
            for m in &rec {
                self.free(m);
            }
        }
    }

    /// `sbappend` of a stream's data: onto the last record, each mbuf
    /// folded into the one before it when it is at most a quarter cluster
    /// and fits that one's trailing space (`sbcompress`).
    pub fn append_stream(&mut self, data: &[Mbuf]) {
        if self.records.is_empty() {
            self.records.push_back(VecDeque::new());
        }
        for m in data {
            if m.len == 0 {
                continue;
            }
            let rec = self.records.back_mut().expect("made above");
            let folds = rec.back().is_some_and(|n| n.kind == m.kind && m.len <= MCLBYTES / 4 && m.len <= n.trailing());
            if folds {
                rec.back_mut().expect("just seen").len += m.len;
                self.cc += m.len;
                if m.kind != Kind::Data {
                    self.ctl += m.len;
                }
            } else {
                rec.push_back(*m);
                self.alloc(m);
            }
        }
    }

    /// `sbappendcontrol` of a stream's data with control: a record of its
    /// own, the control then the data, each mbuf charged as it is.
    pub fn append_control(&mut self, control: &[Mbuf], data: &[Mbuf]) {
        let rec: VecDeque<Mbuf> = control.iter().chain(data).copied().collect();
        for m in &rec {
            self.alloc(m);
        }
        self.records.push_back(rec);
    }

    /// `sbdrop` of `n` bytes of data from the front, its control going with
    /// the record whose data it reaches: an mbuf all of whose bytes are
    /// read is freed, one partly read keeps its room.
    pub fn drop_bytes(&mut self, mut n: usize) {
        while n > 0 {
            let Some(rec) = self.records.front_mut() else { return };
            let Some(m) = rec.front_mut() else {
                self.records.pop_front();
                continue;
            };
            if m.kind != Kind::Data {
                let m = rec.pop_front().expect("just seen");
                self.cc -= m.len;
                self.ctl -= m.len;
                self.mbcnt -= m.storage();
                continue;
            }
            if m.len > n {
                m.len -= n;
                m.off += n;
                self.cc -= n;
                return;
            }
            n -= m.len;
            let m = rec.pop_front().expect("just seen");
            let empty = rec.is_empty();
            self.cc -= m.len;
            self.mbcnt -= m.storage();
            if empty && self.records.len() > 1 {
                self.records.pop_front();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// How many datagrams of `size` an unnamed sender fits into a 4096-byte
    /// receive buffer: what the Darwin kernel this models gives.
    fn fit(size: usize) -> usize {
        let mut sb = SockBuf::new(4096);
        let mut n = 0;
        while sb.append_addr(16, &[], &sosend_chain(size)) {
            n += 1;
        }
        n
    }

    #[test]
    fn datagrams_fit_as_measured() {
        for (size, n) in [(0, 32), (112, 32), (113, 31), (225, 16), (258, 14), (288, 13), (289, 11), (357, 10), (1009, 3), (1024, 3), (2033, 1), (2048, 1)] {
            assert_eq!(fit(size), n, "size {size}");
        }
    }

    #[test]
    fn a_pass_takes_clusters_by_its_size() {
        assert_eq!(sosend_chain(1).len(), 1);
        assert_eq!(sosend_chain(289)[0].ext, MCLBYTES);
        assert_eq!(sosend_chain(8192).iter().map(|m| m.ext).collect::<Vec<_>>(), vec![MBIGCLBYTES, MBIGCLBYTES]);
        // A remainder under MINCLSIZE: another allocation, sized by the pass.
        assert_eq!(sosend_chain(4500).iter().map(|m| (m.ext, m.len)).collect::<Vec<_>>(), vec![(MBIGCLBYTES, 4096), (MBIGCLBYTES, 404)]);
    }

    #[test]
    fn a_long_pass_stops_at_the_chain_limit_and_the_next_uses_what_is_left() {
        let mut so = Sosend::default();
        let (chain, n) = so.pass(200_000, 100_000, false);
        assert_eq!((chain.len(), n), (16, 65536));
        assert!(so.holding());
        let (chain, n) = so.pass(200_000 - 65536, 100_000 - 65536, false);
        assert_eq!(n, 100_000 - 65536);
        assert_eq!(chain.last().map(|m| (m.ext, m.len)), Some((MBIGCLBYTES, 100_000 % 4096)));
        assert!(!so.holding());
    }

    #[test]
    fn a_receive_stops_at_the_record_and_takes_its_control_first() {
        let mut sb = SockBuf::new(8192);
        sb.append_stream(&sosend_chain(2));
        sb.append_control(&[Mbuf::control(16)], &sosend_chain(2));
        sb.append_stream(&sosend_chain(2));
        assert_eq!((sb.cc, sb.ctl), (22, 16));
        assert_eq!(sb.head_control(), None);
        assert_eq!(sb.take(100), 2);
        assert_eq!(sb.head_control(), Some(16));
        sb.take_head_control();
        assert_eq!(sb.head_data(), 4);
        assert_eq!(sb.take(100), 4);
        assert!(sb.is_empty());
        assert_eq!((sb.cc, sb.ctl, sb.mbcnt), (0, 0, 0));
    }

    #[test]
    fn small_writes_fold_into_the_one_before() {
        let mut sb = SockBuf::new(8192);
        for _ in 0..8192 {
            sb.append_stream(&sosend_chain(1));
        }
        assert_eq!(sb.cc, 8192);
        sb.drop_bytes(8192);
        assert_eq!((sb.cc, sb.mbcnt), (0, 0));
    }
}
