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
        if let Some(g) = self.fds.guard(fd).filter(|g| g.has(super::guarded::attr::FILEPORT)) {
            return Err(self.darwin_fp_guard_exception(fd, g, super::guarded::flavor::FILEPORT));
        }
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        files().lock().unwrap_or_else(|e| e.into_inner()).insert(id, file);
        // fileport_alloc: IPC_KOBJECT_ALLOC_MAKE_SEND | IPC_KOBJECT_ALLOC_NSREQUEST,
        // so the file goes with the last send right.
        let ipc = &mut self.ipc();
        let port = ipc.kobject_port(Kobject::FilePort(id));
        ipc.make_send(port);
        ipc.port_mut(port).nsrequest_kobject = true;
        let name = self.darwin_copyout_send(port);
        if name == 0 {
            return Err(Errno::EINVAL);
        }
        m.write_u32(out, name)?;
        Ok(0)
    }

    /// The open file of the file port a send right names (a right this
    /// task's space has, as `ipc_object_copyin` takes a copy of it, and
    /// `fileport_port_to_fileglob`): EINVAL for anything else.
    pub(crate) fn darwin_fileport_file(&mut self, name: u32) -> Result<Arc<OpenFile>, Errno> {
        let ipc = &mut self.ipc();
        let Ok(port) = ipc.translate_send(name) else { return Err(Errno::EINVAL) };
        let Some(Kobject::FilePort(id)) = ipc.port(port).kobject else { return Err(Errno::EINVAL) };
        files().lock().unwrap_or_else(|e| e.into_inner()).get(&id).cloned().ok_or(Errno::EINVAL)
    }

    /// `fileport_makefd(port)`: a new close-on-exec descriptor of the port's
    /// file.
    pub(crate) fn darwin_fileport_makefd(&mut self, name: u32) -> Result<u64, Errno> {
        let file = self.darwin_fileport_file(name)?;
        self.fds.insert(file, true)
    }
}
