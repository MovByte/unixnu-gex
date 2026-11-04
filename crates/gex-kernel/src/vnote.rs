//! Vnode notes: what XNU's `VNOP_*` wrappers post to a vnode's knotes
//! (`bsd/vfs/kpi_vfs.c`'s `post_event_if_success`), said by the filesystems
//! where they make the change, for a Darwin process's EVFILT_VNODE,
//! EVFILT_READ and EVFILT_WRITE knotes on the file.
//!
//! A vnode is an inode of one filesystem, as inotify names it
//! ([`crate::inotify::Key`]). Listeners live beside the filesystems, so a
//! change made by any process reaches every process's knotes; like
//! inotify, a host-mounted tree hears only the changes gex makes to it.

use crate::inotify::Key;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

/// `NOTE_*` (`bsd/sys/event.h`).
pub mod note {
    pub const DELETE: u32 = 0x01;
    pub const WRITE: u32 = 0x02;
    pub const EXTEND: u32 = 0x04;
    pub const ATTRIB: u32 = 0x08;
    pub const LINK: u32 = 0x10;
    pub const RENAME: u32 = 0x20;
    pub const REVOKE: u32 = 0x40;
    pub const NONE: u32 = 0x80;
    pub const FUNLOCK: u32 = 0x100;
}

/// Who hears a vnode's notes.
pub type Listener = Arc<dyn Fn(u32) + Send + Sync>;

#[derive(Default)]
struct Registry {
    by_key: HashMap<Key, Vec<(u64, Listener)>>,
    keys: HashMap<u64, Key>,
    next: u64,
}

static LISTENERS: AtomicUsize = AtomicUsize::new(0);

fn registry() -> std::sync::MutexGuard<'static, Registry> {
    static R: OnceLock<Mutex<Registry>> = OnceLock::new();
    R.get_or_init(Default::default).lock().unwrap_or_else(|e| e.into_inner())
}

/// Whether anyone listens: a filesystem asks before working out a note.
#[inline]
pub fn any() -> bool {
    LISTENERS.load(Ordering::Relaxed) != 0
}

/// Hear `key`'s notes; the id to stop with.
pub fn listen(key: Key, f: Listener) -> u64 {
    let mut r = registry();
    r.next += 1;
    let id = r.next;
    r.by_key.entry(key).or_default().push((id, f));
    r.keys.insert(id, key);
    LISTENERS.fetch_add(1, Ordering::Relaxed);
    id
}

pub fn unlisten(id: u64) {
    let mut r = registry();
    if let Some(key) = r.keys.remove(&id) {
        if let Some(v) = r.by_key.get_mut(&key) {
            v.retain(|(i, _)| *i != id);
            if v.is_empty() {
                r.by_key.remove(&key);
            }
        }
        LISTENERS.fetch_sub(1, Ordering::Relaxed);
    }
}

/// `notes` happened to `key`.
pub fn post(key: Key, notes: u32) {
    if !any() {
        return;
    }
    let who: Vec<Listener> = registry().by_key.get(&key).map(|v| v.iter().map(|(_, f)| Arc::clone(f)).collect()).unwrap_or_default();
    for f in who {
        f(notes);
    }
}
