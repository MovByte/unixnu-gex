//! The parts of a Darwin task's VM map the host's mappings do not carry:
//! each entry's maximum protection (`vme_max_protection`), where a
//! `mach_vm_protect(set_maximum)` lowered it from `VM_PROT_ALL`.
//!
//! A new mapping or an unmapping over a range gives it back the default.
//! (A shared mapping of a file opened read-only, whose maximum lacks
//! write, is refused write by the host's `mprotect` as XNU refuses it.)

use std::collections::BTreeMap;

/// `VM_PROT_ALL`.
pub const PROT_ALL: u8 = 7;

/// Ranges `[start, end)` whose maximum protection is not `VM_PROT_ALL`.
#[derive(Debug, Default)]
pub struct MaxProt {
    ranges: BTreeMap<u64, (u64, u8)>,
}

impl MaxProt {
    /// Split a range at `at`, so that no range crosses it.
    fn split(&mut self, at: u64) {
        let Some((&s, &(e, p))) = self.ranges.range(..at).next_back() else { return };
        if e > at {
            self.ranges.insert(s, (at, p));
            self.ranges.insert(at, (e, p));
        }
    }

    /// `[start, end)` back to the default.
    pub fn clear(&mut self, start: u64, end: u64) {
        if start >= end {
            return;
        }
        self.split(start);
        self.split(end);
        let inside: Vec<u64> = self.ranges.range(start..end).map(|(&s, _)| s).collect();
        for s in inside {
            self.ranges.remove(&s);
        }
    }

    /// `[start, end)`'s maximum becomes `max`.
    pub fn set(&mut self, start: u64, end: u64, max: u8) {
        self.clear(start, end);
        if max != PROT_ALL {
            self.ranges.insert(start, (end, max));
        }
    }

    /// The pieces of `[start, end)` and the maximum of each.
    pub fn pieces(&self, start: u64, end: u64) -> Vec<(u64, u64, u8)> {
        let mut out = Vec::new();
        let mut at = start;
        let first = self.ranges.range(..=start).next_back().filter(|(_, &(e, _))| e > start).map(|(&s, _)| s).unwrap_or(start);
        for (&s, &(e, p)) in self.ranges.range(first..end) {
            let (s, e) = (s.max(start), e.min(end));
            if s > at {
                out.push((at, s, PROT_ALL));
            }
            out.push((s, e, p));
            at = e;
        }
        if at < end {
            out.push((at, end, PROT_ALL));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_lowered_maximum_splits_and_clears_by_range() {
        let mut m = MaxProt::default();
        m.set(0x1000, 0x5000, 1);
        assert_eq!(m.pieces(0, 0x6000), vec![(0, 0x1000, 7), (0x1000, 0x5000, 1), (0x5000, 0x6000, 7)]);
        m.clear(0x2000, 0x3000);
        assert_eq!(m.pieces(0x1000, 0x5000), vec![(0x1000, 0x2000, 1), (0x2000, 0x3000, 7), (0x3000, 0x5000, 1)]);
        m.set(0x4000, 0x6000, 0);
        assert_eq!(m.pieces(0x3000, 0x6000), vec![(0x3000, 0x4000, 1), (0x4000, 0x6000, 0)]);
    }
}
