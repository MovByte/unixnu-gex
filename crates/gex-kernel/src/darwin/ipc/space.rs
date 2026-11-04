//! A task's port name space (`osfmk/ipc/ipc_entry.c`, `ipc_space.c`): a
//! table of entries, each naming one object and the rights the task holds
//! to it.
//!
//! A name is an index into the table and a generation byte. Free entries
//! form a list in an order randomized when the table is made or grows, and
//! an entry's generation advances each time it is reused, rolling over at
//! a random point, so names are hard to predict or reuse.

use super::ObjId;

/// `IE_BITS_*`: an entry's bits hold its generation, the rights' type and
/// the user reference count.
pub mod bits {
    pub const UREFS_MASK: u32 = 0x0000_ffff;
    pub const TYPE_MASK: u32 = 0x001f_0000;
    pub const EXTYPE_MASK: u32 = 0x0020_0000;
    pub const GEN_MASK: u32 = 0xff00_0000;
    pub const GEN_ONE: u32 = 0x0400_0000;
    pub const ROLL_POS: u32 = 22;
    pub const ROLL_BITS: u32 = 2;
    pub const ROLL_MASK: u32 = ((1 << ROLL_BITS) - 1) << ROLL_POS;
    pub const RIGHT_MASK: u32 = 0x007f_ffff;
}

/// `sizeof(struct ipc_entry)` on arm64: the unit the table grows in.
const ENTRY_SIZE: u64 = 24;
/// `IPC_ENTRY_TABLE_MIN`, `IPC_ENTRY_TABLE_PERIOD`.
const TABLE_MIN: u64 = 32;
const TABLE_PERIOD: u64 = 16;
/// `CONFIG_IPC_TABLE_ENTRIES_SIZE_MAX` for the iPhoneOS RELEASE kernel
/// (its `xsmall` memory configuration).
const TABLE_SIZE_MAX: u64 = 3_145_728;
/// `CONFIG_SEMI_RANDOM_ENTRIES`: a new space's first entries are handed
/// out in order.
const NUM_SEQ_ENTRIES: u32 = 8;

// kalloc's size classes (`osfmk/kern/kalloc.h`).
const KHEAP_STEP_START: u64 = 16;
const KHEAP_MAX_SIZE: u64 = 32 * 1024;
/// The kernel's page size on these devices.
const KERNEL_PAGE: u64 = 16 * 1024;

fn log2down(x: u64) -> u32 {
    63 - x.leading_zeros()
}

/// `kalloc_next_good_size`.
fn next_good_size(size: u64, period: u64) -> u64 {
    if size < KHEAP_STEP_START {
        return KHEAP_STEP_START;
    }
    if size < 2 * KHEAP_STEP_START {
        return 2 * KHEAP_STEP_START;
    }
    let scale = log2down(size);
    let step = if size < KHEAP_MAX_SIZE {
        1 << (scale - 1)
    } else {
        let s = 1u64 << (scale - log2down(period));
        (s + KERNEL_PAGE - 1) & !(KERNEL_PAGE - 1)
    };
    (size + step) & !(step - 1)
}

/// `ipc_entry_table_next_size`: the byte size the table grows to.
fn next_size(cur_size: u64) -> u64 {
    let size = if cur_size != 0 { cur_size + ENTRY_SIZE - 1 } else { ENTRY_SIZE * TABLE_MIN - 1 };
    next_good_size(size, TABLE_PERIOD)
}

/// One table entry (`struct ipc_entry`).
#[derive(Clone, Copy, Debug, Default)]
pub struct Entry {
    pub bits: u32,
    pub object: Option<ObjId>,
    /// The next free entry while free; the dead-name request index while
    /// in use (`ie_next`/`ie_request` share the word).
    pub next: u32,
    pub request: u32,
}

impl Entry {
    pub fn ty(&self) -> u32 {
        self.bits & bits::TYPE_MASK
    }

    pub fn urefs(&self) -> u32 {
        self.bits & bits::UREFS_MASK
    }
}

/// A task's name space (`struct ipc_space`).
#[derive(Debug)]
pub struct Space {
    table: Vec<Entry>,
    /// The table's allocated byte size, as kalloc rounded it.
    size: u64,
    /// `is_table_hashed`: send-right entries in the reverse hash.
    pub hashed: u32,
    /// The reverse hash (`ipc_hash`): an object's name for a send right
    /// held without its receive right.
    rev: std::collections::HashMap<ObjId, u32>,
    /// `is_table_free`.
    free: u32,
    rng: u64,
}

impl Default for Space {
    fn default() -> Self {
        Space::new()
    }
}

/// `MACH_PORT_INDEX`, `MACH_PORT_GEN`, `MACH_PORT_MAKE`.
pub fn index(name: u32) -> u32 {
    name >> 8
}

pub fn gen(name: u32) -> u32 {
    (name & 0xff) << 24
}

pub fn make(index: u32, gen: u32) -> u32 {
    (index << 8) | (gen >> 24)
}

/// `ipc_entry_name_mask`: a name with its generation's always-set bits
/// restored (userland may use them for flags).
pub fn name_mask(name: u32) -> u32 {
    name | make(0, bits::GEN_MASK.wrapping_add(bits::GEN_ONE))
}

/// `IE_BITS_ROLL`.
fn roll_of(b: u32) -> u32 {
    ((b & bits::ROLL_MASK) << 8) ^ bits::GEN_MASK
}

/// `ipc_entry_new_gen`.
fn new_gen(old: u32) -> u32 {
    let sum = old.wrapping_add(bits::GEN_ONE) & bits::GEN_MASK;
    let roll = old & bits::ROLL_MASK;
    (sum % roll_of(old)) | roll
}

/// `ipc_entry_gen_rolled`.
fn gen_rolled(old: u32, new: u32) -> bool {
    (old & bits::GEN_MASK) > (new & bits::GEN_MASK)
}

/// `ipc_entry_new_rollpoint`.
fn new_rollpoint(rollbits: u32) -> u32 {
    let rollbits = (rollbits << bits::ROLL_POS) & bits::ROLL_MASK;
    bits::GEN_MASK.wrapping_add(bits::GEN_ONE) | rollbits
}

impl Space {
    /// `ipc_space_create`: a table of the minimum size, its free list in
    /// random order.
    pub fn new() -> Space {
        // 32 entries are 768 bytes, itself a kalloc size class.
        let size = ENTRY_SIZE * TABLE_MIN;
        let count = (size / ENTRY_SIZE) as u32;
        let mut seed = [0u8; 8];
        let _ = getrandom_fill(&mut seed);
        let mut s = Space { table: vec![Entry::default(); count as usize], size, hashed: 0, rev: Default::default(), free: count - 1, rng: u64::from_le_bytes(seed) | 1 };
        s.rand_freelist(0, count);
        s
    }

    /// `random_bool_gen_bits`: `n` random bits.
    fn random_bits(&mut self, n: u32) -> u32 {
        // xorshift64*
        let mut x = self.rng;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.rng = x;
        (x.wrapping_mul(0x2545_f491_4f6c_dd1d) >> (64 - n)) as u32
    }

    /// `ipc_space_rand_freelist`: link entries `bottom..size` into a free
    /// list taken alternately, at random, from the low and the high end; a
    /// new space's first few in order.
    fn rand_freelist(&mut self, bottom: u32, size: u32) {
        let at_start = bottom == 0;
        let mut total = 0;
        let mut curr = bottom;
        let (mut bottom, mut top) = (bottom + 1, size - 1);
        while bottom <= top {
            let which = if at_start && total < NUM_SEQ_ENTRIES {
                total += 1;
                0
            } else {
                self.random_bits(1)
            };
            let next = if which != 0 {
                top -= 1;
                top + 1
            } else {
                bottom += 1;
                bottom - 1
            };
            let e = &mut self.table[curr as usize];
            e.bits = bits::GEN_MASK;
            e.next = next;
            curr = next;
        }
        self.table[curr as usize].bits = bits::GEN_MASK;
    }

    /// `ipc_entry_lookup`: the entry `name` names, if it is in use with
    /// that generation.
    pub fn lookup(&self, name: u32) -> Option<&Entry> {
        let i = index(name);
        if i == 0 {
            return None;
        }
        let e = self.table.get(i as usize)?;
        (e.bits & bits::GEN_MASK == gen(name) && e.ty() != 0).then_some(e)
    }

    pub fn lookup_mut(&mut self, name: u32) -> Option<&mut Entry> {
        let i = index(name);
        if i == 0 {
            return None;
        }
        let e = self.table.get_mut(i as usize)?;
        (e.bits & bits::GEN_MASK == gen(name) && e.ty() != 0).then_some(e)
    }

    /// `ipc_entries_hold`: whether `n` more entries can be claimed without
    /// growing.
    fn hold(&self, n: u32) -> bool {
        let count = self.table.len() as u32;
        if self.hashed + n > count * 7 / 8 {
            return false;
        }
        let mut next = self.table[0].next;
        for _ in 0..n {
            if next == 0 {
                return false;
            }
            next = self.table[next as usize].next;
        }
        true
    }

    /// `ipc_entry_claim`: take the free list's head for `object`.
    fn claim(&mut self, object: Option<ObjId>) -> u32 {
        let first_free = self.table[0].next;
        let next = self.table[first_free as usize].next;
        self.table[0].next = next;
        self.free -= 1;
        let old = self.table[first_free as usize].bits;
        let mut g = new_gen(old);
        if gen_rolled(old, g) {
            let roll = self.random_bits(bits::ROLL_BITS);
            g = new_rollpoint(roll);
        }
        let e = &mut self.table[first_free as usize];
        e.bits = g;
        e.request = 0;
        e.next = 0;
        e.object = object;
        make(first_free, g)
    }

    /// `ipc_entry_alloc`: a new name for `object`, the table growing as it
    /// must. `None` is `KERN_NO_SPACE`.
    pub fn alloc(&mut self, object: Option<ObjId>) -> Option<u32> {
        loop {
            if self.hold(1) {
                return Some(self.claim(object));
            }
            if !self.grow(None) {
                return None;
            }
        }
    }

    /// `ipc_entry_alloc_name`: the entry for exactly `name`, claimed if
    /// free. `Err` is the `kern_return_t`.
    pub fn alloc_name(&mut self, name: u32) -> Result<bool, u64> {
        use super::kr;
        let i = index(name);
        if u64::from(i) > TABLE_SIZE_MAX / ENTRY_SIZE {
            return Err(kr::NO_SPACE);
        }
        if name != name_mask(name) {
            return Err(kr::INVALID_VALUE);
        }
        if i == 0 {
            return Err(kr::FAILURE);
        }
        loop {
            let Some(e) = self.table.get(i as usize).copied() else {
                if !self.grow(Some(u64::from(i) + 1)) {
                    return Err(kr::NO_SPACE);
                }
                continue;
            };
            if e.ty() == 0 {
                // Unlink it from the free list.
                let mut prev = 0u32;
                while self.table[prev as usize].next != i {
                    prev = self.table[prev as usize].next;
                }
                self.table[prev as usize].next = e.next;
                self.free -= 1;
                let entry = &mut self.table[i as usize];
                entry.bits = gen(name);
                entry.request = 0;
                entry.next = 0;
                return Ok(true);
            } else if e.bits & bits::GEN_MASK == gen(name) {
                return Ok(false);
            } else {
                return Err(kr::FAILURE);
            }
        }
    }

    /// `ipc_entry_dealloc`: `name`'s entry back on the free list, keeping
    /// its generation.
    pub fn dealloc(&mut self, name: u32) {
        let i = index(name);
        let head = self.table[0].next;
        let e = &mut self.table[i as usize];
        e.bits &= bits::GEN_MASK | bits::ROLL_MASK;
        e.next = head;
        e.object = None;
        e.request = 0;
        self.table[0].next = i;
        self.free += 1;
    }

    /// `ipc_entry_grow_table`: a larger table, the new entries' free list
    /// randomized and appended to the old one. False at the size limit.
    fn grow(&mut self, target_count: Option<u64>) -> bool {
        let ocount = self.table.len() as u32;
        let nsize = match target_count {
            None => next_size(self.size),
            Some(t) if t <= u64::from(ocount) => return true,
            Some(t) if t > TABLE_SIZE_MAX / ENTRY_SIZE => return false,
            Some(t) => next_size(t * ENTRY_SIZE),
        }
        .min(TABLE_SIZE_MAX);
        if nsize == self.size {
            return false;
        }
        // Past kalloc's zones the allocation is whole pages.
        let alloc = if nsize > KHEAP_MAX_SIZE { (nsize + KERNEL_PAGE - 1) & !(KERNEL_PAGE - 1) } else { nsize };
        let ncount = (alloc / ENTRY_SIZE) as u32;
        self.table.resize(ncount as usize, Entry::default());
        self.rand_freelist(ocount, ncount);
        // The old free list's last entry continues into the new ones.
        let mut free_index = 0u32;
        for _ in 0..ocount {
            if self.table[free_index as usize].object.is_some() {
                break;
            }
            let i = self.table[free_index as usize].next;
            if i == 0 || i >= ocount {
                break;
            }
            free_index = i;
        }
        self.table[free_index as usize].next = ocount;
        self.free += ncount - ocount;
        self.size = alloc;
        true
    }

    /// `ipc_hash_insert`: `name` holds a send right to `obj`.
    pub fn hash_insert(&mut self, obj: ObjId, name: u32) {
        self.rev.insert(obj, name);
        self.hashed += 1;
    }

    /// `ipc_hash_delete`.
    pub fn hash_delete(&mut self, obj: ObjId) {
        if self.rev.remove(&obj).is_some() {
            self.hashed -= 1;
        }
    }

    /// `ipc_hash_lookup`: the name holding a send right to `obj`.
    pub fn hash_lookup(&self, obj: ObjId) -> Option<u32> {
        self.rev.get(&obj).copied()
    }

    /// The entry at table index `i`, whatever its state.
    pub(crate) fn entry_at(&mut self, i: u32) -> &mut Entry {
        &mut self.table[i as usize]
    }

    /// Every name in use, with its entry.
    pub fn names(&self) -> impl Iterator<Item = (u32, &Entry)> {
        self.table.iter().enumerate().skip(1).filter(|(_, e)| e.ty() != 0).map(|(i, e)| (make(i as u32, e.bits & bits::GEN_MASK), e))
    }
}

/// The host's randomness, for the table's entropy.
fn getrandom_fill(buf: &mut [u8]) -> std::io::Result<()> {
    use std::io::Read;
    std::fs::File::open("/dev/urandom")?.read_exact(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_space_hands_out_its_first_names_in_order() {
        let mut s = Space::new();
        let names: Vec<u32> = (0..8).map(|_| s.alloc(None).unwrap()).collect();
        assert_eq!(names, vec![0x103, 0x203, 0x303, 0x403, 0x503, 0x603, 0x703, 0x803]);
    }

    #[test]
    fn a_reused_entry_gets_a_new_generation() {
        let mut s = Space::new();
        let a = s.alloc(None).unwrap();
        s.entry_at(index(a)).bits |= 0x1_0000;
        s.dealloc(a);
        let b = s.alloc(None).unwrap();
        assert_eq!(index(a), index(b));
        assert_eq!(b, a + 4, "the generation advances by one");
        assert!(s.lookup(a).is_none());
    }

    #[test]
    fn the_table_grows_by_kalloc_size_classes() {
        // 32 entries (768 bytes), then 1024 bytes: 42 entries.
        assert_eq!(next_size(768), 1024);
        let mut s = Space::new();
        for _ in 0..40 {
            let n = s.alloc(None).unwrap();
            s.table[index(n) as usize].bits |= 0x1_0000;
        }
        assert_eq!(s.table.len(), 42);
    }
}
