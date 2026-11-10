//! `select` and `pselect` (`bsd/kern/sys_generic.c`), waiting as `poll` does
//! on a kqueue of their own. A vnode that is not a terminal is always ready,
//! in all three sets (measured on APFS, and of devices). For the rest
//! `fo_select` is the read and write filters' answer, and the exception set
//! is never ready: no urgent data is carried here for a socket's.

use super::kevent::{ev, evfilt, pollev, Kev, PollFd, EV_POLL};
use crate::errno::Errno;
use crate::syscalls::{Kernel, SyscallOutcome};
use crate::vfs::FileType;
use crate::GuestMem;
use std::time::Duration;

const NFDBITS: usize = 32;

/// What a select in progress hands back.
#[derive(Debug)]
pub struct Select {
    /// The guest's three sets.
    sets: [u64; 3],
    /// The bytes copied in and out of each (`ni`).
    ni: usize,
    /// For each entry of the thread's pollfds: its set and descriptor.
    which: Vec<(usize, u32)>,
    /// `uu_oldmask`, for a pselect that set a mask.
    oldmask: Option<u64>,
}

/// `select_nocancel`'s and `pselect_nocancel`'s check of the timeout.
fn valid_timeout(pselect: bool, sec: i64, frac: i64) -> bool {
    const ITIMER_MAX: i64 = 100_000_000;
    const USEC_PER_SEC: i64 = 1_000_000;
    const NSEC_PER_SEC: i64 = 1_000_000_000;
    if pselect {
        (0..=i64::from(i32::MAX)).contains(&sec) && (0..=NSEC_PER_SEC).contains(&frac)
    } else {
        (0..=ITIMER_MAX).contains(&sec) && (0..USEC_PER_SEC).contains(&frac)
    }
}

/// The end of a select: the sets written unless it failed, `uu_oldmask`
/// back unless a signal is to be taken with it (`postsig` restores it then).
pub(super) fn finish(k: &mut Kernel, m: &mut GuestMem<'_>, sel: Select, fds: &[PollFd], r: Result<(), Errno>) -> Result<u64, Errno> {
    if let Some(old) = sel.oldmask {
        if r == Err(Errno::EINTR) {
            k.signals.set_suspend_restore(Some(old));
        } else {
            k.signals.set_blocked(old);
        }
    }
    r?;
    let mut out = [vec![0u32; sel.ni / 4], vec![0u32; sel.ni / 4], vec![0u32; sel.ni / 4]];
    let mut n = 0u64;
    for (f, &(set, fd)) in fds.iter().zip(&sel.which) {
        if f.revents != 0 {
            out[set][fd as usize / NFDBITS] |= 1 << (fd as usize % NFDBITS);
            n += 1;
        }
    }
    for (bits, &to) in out.iter().zip(&sel.sets) {
        if to != 0 && sel.ni != 0 {
            let bytes: Vec<u8> = bits.iter().flat_map(|w| w.to_le_bytes()).collect();
            m.write(to, &bytes)?;
        }
    }
    Ok(n)
}

impl Kernel {
    /// `select(nd, in, ou, ex, tv)`, or `pselect(nd, in, ou, ex, ts, mask)`.
    pub(crate) fn darwin_select(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6], pselect: bool) -> SyscallOutcome {
        match self.darwin_select_start(m, a, pselect) {
            Ok(outcome) => outcome,
            Err(e) => {
                super::thread::bsd_result(m, self.ctx_addr, Err(e), false);
                SyscallOutcome::Continue
            }
        }
    }

    fn darwin_select_start(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6], pselect: bool) -> Result<SyscallOutcome, Errno> {
        let mut wait = None;
        if a[4] != 0 {
            let sec = m.read_u64(a[4])? as i64;
            // A user64_timeval's microseconds are 32 bits; a user64_timespec's
            // nanoseconds 64.
            let frac = if pselect { m.read_u64(a[4] + 8)? as i64 } else { i64::from(m.read_u32(a[4] + 8)? as i32) };
            if !valid_timeout(pselect, sec, frac) {
                return Err(Errno::EINVAL);
            }
            let nanos = if pselect { frac as u64 } else { frac as u64 * 1000 };
            wait = Some(Duration::from_secs(sec as u64) + Duration::from_nanos(nanos));
        }
        let mut oldmask = None;
        if pselect && a[5] != 0 {
            let new = super::kern::mask_to_linux(m.read_u32(a[5])?);
            let unblockable = (1u64 << (crate::signal::sig::SIGKILL - 1)) | (1u64 << (crate::signal::sig::SIGSTOP - 1));
            oldmask = Some(self.signals.blocked());
            self.signals.set_blocked(new & !unblockable);
        }
        let r = self.darwin_select_internal(m, a, wait, oldmask);
        if r.is_err() {
            if let Some(old) = oldmask {
                self.signals.set_blocked(old);
            }
        }
        r
    }

    fn darwin_select_internal(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6], wait: Option<Duration>, oldmask: Option<u64>) -> Result<SyscallOutcome, Errno> {
        let nd = a[0] as i32;
        if nd < 0 {
            return Err(Errno::EINVAL);
        }
        // "forgiving; slightly wrong"
        let nd = (nd as usize).min(self.fds.nfiles());
        let ni = nd.div_ceil(NFDBITS) * 4;
        let sets = [a[1], a[2], a[3]];
        // getbits, then selcount's check of every bit.
        let mut wanted = Vec::new();
        for (set, &from) in sets.iter().enumerate() {
            if from == 0 || ni == 0 {
                continue;
            }
            let bytes = m.read(from, ni)?.to_vec();
            for (w, word) in bytes.chunks_exact(4).enumerate() {
                let word = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
                for bit in (0..NFDBITS).filter(|b| word & (1 << b) != 0) {
                    let fd = w * NFDBITS + bit;
                    if fd < nd {
                        wanted.push((set, fd as u32));
                    }
                }
            }
        }
        for &(_, fd) in &wanted {
            self.fds.get(fd as i32).map_err(|_| Errno::EBADF)?;
        }
        let kqid = self.kq_new(0, 1, 1);
        let mut fds = Vec::with_capacity(wanted.len());
        let mut rfds = 0;
        for (i, &(set, fd)) in wanted.iter().enumerate() {
            let events = [pollev::IN, pollev::OUT, pollev::PRI][set];
            let mut revents = 0;
            if self.darwin_select_always(fd as i32, set) {
                revents = events;
                rfds += 1;
            } else if set != 2 {
                let mut kev = Kev { ident: u64::from(fd), flags: ev::ADD | ev::ONESHOT | EV_POLL, udata: i as u64, ..Kev::default() };
                kev.filter = if set == 0 { evfilt::READ } else { evfilt::WRITE };
                // A kind of file with no such filter is fo_no_select's
                // never ready.
                self.kevent_register(m, kqid, &mut kev);
            }
            fds.push(PollFd { fd: fd as i32, events, revents });
        }
        let tid = self.tid;
        let select = Select { sets, ni, which: wanted, oldmask };
        self.kev().poll.insert(tid, (0, fds));
        self.kev().select.insert(tid, select);
        Ok(self.poll_scan(m, kqid, rfds, wait))
    }

    /// Is the answer yes whatever happens? A vnode's `VNOP_SELECT` says so
    /// for everything, and `pipe_select` for writing to the read end: it
    /// looks at that end's peer's buffer, which nothing ever fills.
    fn darwin_select_always(&mut self, fd: i32, set: usize) -> bool {
        let Ok(file) = self.fds.get(fd) else { return false };
        if let Some((_, write_end)) = file.handle.pipe_end() {
            return set == 1 && !write_end;
        }
        if self.darwin_vnode_of(&file).is_none() || file.is_tty() {
            return false;
        }
        file.metadata().is_ok_and(|md| matches!(md.file_type, FileType::Regular | FileType::Directory | FileType::Symlink | FileType::CharDevice))
    }
}

#[cfg(test)]
mod tests {
    use super::valid_timeout;

    #[test]
    fn the_two_calls_check_their_timeouts_differently() {
        assert!(valid_timeout(false, 0, 999_999));
        assert!(!valid_timeout(false, 0, 1_000_000));
        assert!(!valid_timeout(false, 100_000_001, 0));
        assert!(valid_timeout(true, 100_000_001, 0));
        assert!(valid_timeout(true, 0, 1_000_000_000));
        assert!(!valid_timeout(true, 0, 1_000_000_001));
        assert!(!valid_timeout(true, -1, 0));
    }
}
