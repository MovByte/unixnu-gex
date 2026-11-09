//! File ports (`bsd/kern/kern_descrip.c`): a descriptor's open file as a
//! Mach port, which a task sends to another and turns back into a
//! descriptor.

use super::ipc::Kobject;
use crate::errno::Errno;
use crate::file::OpenFile;
use crate::syscalls::Kernel;
use crate::GuestMem;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

/// The open files the file ports hold, by port number. A file stays open
/// for as long as its port lives.
fn files() -> &'static Mutex<HashMap<u32, Arc<OpenFile>>> {
    static FILES: OnceLock<Mutex<HashMap<u32, Arc<OpenFile>>>> = OnceLock::new();
    FILES.get_or_init(Default::default)
}

static NEXT: AtomicU32 = AtomicU32::new(1);

/// The last send right to file port `id` went: its open file with it
/// (`fileport_notify`).
pub fn fileport_no_senders(id: u32) {
    files().lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
}

impl Kernel {
    /// `fileport_makeport(fd, portnamep)`.
    pub(crate) fn darwin_fileport_makeport(&mut self, m: &mut GuestMem<'_>, fd: i32, out: u64) -> Result<u64, Errno> {
        let file = self.fds.get(fd)?;
        // fg_sendable: a vnode, socket, pipe or shared memory object.
        if Arc::clone(&file.handle).as_kqueue().is_some() {
            return Err(Errno::EINVAL);
        }
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        files().lock().unwrap_or_else(|e| e.into_inner()).insert(id, file);
        let ipc = &mut self.ipc();
        let port = ipc.kobject_port(Kobject::FilePort(id));
        ipc.make_send(port);
        let name = self.darwin_copyout_send(port);
        if name == 0 {
            return Err(Errno::EINVAL);
        }
        m.write_u32(out, name)?;
        Ok(0)
    }

    /// `fileport_makefd(port)`: a new close-on-exec descriptor of the port's
    /// file.
    pub(crate) fn darwin_fileport_makefd(&mut self, name: u32) -> Result<u64, Errno> {
        let ipc = &mut self.ipc();
        let Ok(port) = ipc.translate_send(name) else { return Err(Errno::EINVAL) };
        let Some(Kobject::FilePort(id)) = ipc.port(port).kobject else { return Err(Errno::EINVAL) };
        let Some(file) = files().lock().unwrap_or_else(|e| e.into_inner()).get(&id).cloned() else { return Err(Errno::EINVAL) };
        self.fds.insert(file, true)
    }
}
