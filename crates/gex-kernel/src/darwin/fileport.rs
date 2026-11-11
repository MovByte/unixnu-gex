//! File ports (`bsd/kern/kern_descrip.c`): a descriptor's open file as a
//! Mach port, which a task sends to another and turns back into a
//! descriptor.

use super::ipc::Kobject;
use crate::errno::Errno;
use crate::file::{InFlight, OpenFile};
use crate::syscalls::Kernel;
use crate::GuestMem;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

/// The open files the file ports hold, by port number. A file stays open
/// for as long as its port lives.
fn files() -> &'static Mutex<HashMap<u32, InFlight>> {
    static FILES: OnceLock<Mutex<HashMap<u32, InFlight>>> = OnceLock::new();
    FILES.get_or_init(Default::default)
}

static NEXT: AtomicU32 = AtomicU32::new(1);

/// The last send right to file port `id` went: its open file with it
/// (`fileport_notify`).
pub fn fileport_no_senders(id: u32) {
    // The port's hold goes with it (fg_drop), out of the table's lock.
    let held = files().lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
    drop(held);
}

impl Kernel {
    /// `fileport_makeport(fd, portnamep)`.
    pub(crate) fn darwin_fileport_makeport(&mut self, m: &mut GuestMem<'_>, fd: i32, out: u64) -> Result<u64, Errno> {
        let file = self.fds.get(fd)?;
        // fg_sendable: a vnode, socket, pipe or shared memory object.
        if Arc::clone(&file.handle).as_kqueue().is_some() {
            return Err(Errno::EINVAL);
        }
        if let Some(g) = self.fds.guard(fd).filter(|g| g.has(super::guarded::attr::FILEPORT)) {
            return Err(self.darwin_fp_guard_exception(fd, g, super::guarded::flavor::FILEPORT));
        }
        // The port holds the file (fg_ref), unless its descriptor closed
        // meanwhile.
        let held = self.fds.get_held(fd)?;
        drop(file);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        files().lock().unwrap_or_else(|e| e.into_inner()).insert(id, held);
        // fileport_alloc: IPC_KOBJECT_ALLOC_MAKE_SEND | IPC_KOBJECT_ALLOC_NSREQUEST,
        // so the file goes with the last send right.
        let ipc = &mut self.ipc();
        let port = ipc.kobject_port(Kobject::FilePort(id));
        ipc.make_send(port);
        ipc.port_mut(port).nsrequest_kobject = true;
        // A copyout that fails destroys the right, and the port's last send
        // right takes the file's hold with it; a name that cannot be written
        // out is deallocated, as xnu does whatever another thread did to it.
        let name = self.darwin_copyout_send(port);
        if name == 0 {
            return Err(Errno::EINVAL);
        }
        if let Err(e) = m.write_u32(out, name) {
            let _ = self.ipc().mach_port_deallocate(name);
            return Err(e);
        }
        Ok(0)
    }

    /// The open file of the file port a send right names (a right this
    /// task's space has, as `ipc_object_copyin` takes a copy of it, and
    /// `fileport_port_to_fileglob`): EINVAL for anything else.
    pub(crate) fn darwin_fileport_file(&mut self, name: u32) -> Result<Arc<OpenFile>, Errno> {
        let ipc = &mut self.ipc();
        let Ok(port) = ipc.translate_send(name) else { return Err(Errno::EINVAL) };
        let Some(Kobject::FilePort(id)) = ipc.port(port).kobject else { return Err(Errno::EINVAL) };
        files().lock().unwrap_or_else(|e| e.into_inner()).get(&id).map(|f| Arc::clone(f)).ok_or(Errno::EINVAL)
    }

    /// The open file of the file port a send right names in process `pid`'s
    /// space (`fileport_invoke`): EINVAL for anything else, and for a
    /// process without a space (kernproc's holds no file port).
    pub(crate) fn darwin_fileport_file_in(&mut self, pid: i32, name: u32) -> Result<Arc<OpenFile>, Errno> {
        if pid == self.pid {
            return self.darwin_fileport_file(name);
        }
        let ipc = &mut self.ipc();
        let Some(key) = ipc.links.iter().find(|(_, l)| l.pid == pid).map(|(&k, _)| k) else { return Err(Errno::EINVAL) };
        let id = ipc
            .with_space(key, |ipc| {
                let port = ipc.translate_send(name).ok()?;
                match ipc.port(port).kobject {
                    Some(Kobject::FilePort(id)) => Some(id),
                    _ => None,
                }
            })
            .flatten()
            .ok_or(Errno::EINVAL)?;
        files().lock().unwrap_or_else(|e| e.into_inner()).get(&id).map(|f| Arc::clone(f)).ok_or(Errno::EINVAL)
    }

    /// `fileport_makefd(port)`: a new close-on-exec descriptor of the port's
    /// file.
    pub(crate) fn darwin_fileport_makefd(&mut self, name: u32) -> Result<u64, Errno> {
        let file = self.darwin_fileport_file(name)?;
        self.fds.insert(file, true)
    }
}
