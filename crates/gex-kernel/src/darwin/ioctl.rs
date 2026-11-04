//! `ioctl` as XNU takes it (`bsd/kern/sys_generic.c`): the argument
//! copied in or out by the command's `IOC_*` size, the generic commands
//! on the descriptor, then the file type's `fo_ioctl`: `pipe_ioctl`,
//! `soo_ioctl`, `vn_ioctl`, and `fo_no_ioctl` for a kqueue or shared
//! memory.

use super::bsd::{open_flags, open_flags_back};
use crate::errno::Errno;
use crate::file::OpenFile;
use crate::syscalls::{nr, Kernel};
use crate::vfs::FileType;
use crate::GuestMem;
use std::sync::Arc;

/// `bsd/sys/ioccom.h`.
const IOCPARM_MASK: u64 = 0x1fff;
const IOCPARM_MAX: u64 = IOCPARM_MASK + 1;
const IOC_VOID: u64 = 0x2000_0000;
const IOC_OUT: u64 = 0x4000_0000;
const IOC_IN: u64 = 0x8000_0000;

/// `bsd/sys/filio.h`, `bsd/sys/ttycom.h`.
pub mod cmd {
    pub const FIOCLEX: u64 = 0x2000_6601;
    pub const FIONCLEX: u64 = 0x2000_6602;
    pub const FIONREAD: u64 = 0x4004_667f;
    pub const FIONBIO: u64 = 0x8004_667e;
    pub const FIOASYNC: u64 = 0x8004_667d;
    pub const FIOSETOWN: u64 = 0x8004_667c;
    pub const FIOGETOWN: u64 = 0x4004_667b;
    pub const FIODTYPE: u64 = 0x4004_667a;
    pub const TIOCSPGRP: u64 = 0x8004_7476;
    pub const TIOCGPGRP: u64 = 0x4004_7477;
}

/// The `FCNTLFLAGS` (`FAPPEND|FASYNC|FFSYNC|FFDSYNC|FNONBLOCK`) as Darwin
/// numbers them.
pub const FCNTLFLAGS: u64 = 0x8 | 0x40 | 0x80 | 0x40_0000 | 0x4;

/// What an open file is, for `fo_ioctl`.
enum Kind {
    Pipe(Arc<crate::pipe::Pipe>, bool),
    Socket,
    /// The host's standard stream: a terminal, or a pipe or file there.
    HostStream(bool),
    Vnode(FileType),
    NoIoctl,
    Other,
}

fn int(data: &[u8]) -> i32 {
    i32::from_le_bytes(data[..4].try_into().unwrap())
}

fn put_int(data: &mut [u8], v: i32) {
    data[..4].copy_from_slice(&v.to_le_bytes());
}

impl Kernel {
    fn darwin_file_kind(&self, file: &Arc<OpenFile>) -> Kind {
        if let Some((pipe, write)) = file.handle.pipe_end() {
            if file.path.starts_with("pipe:[") {
                return if pipe.is_xnu() { Kind::Pipe(pipe, write) } else { Kind::Other };
            }
        }
        if Arc::clone(&file.handle).as_kqueue().is_some() || Arc::clone(&file.handle).as_posix_shm().is_some() {
            return Kind::NoIoctl;
        }
        let ty = file.handle.metadata().map(|md| md.file_type);
        if matches!(file.path.as_str(), "/dev/stdin" | "/dev/stdout" | "/dev/stderr") && ty == Ok(FileType::CharDevice) {
            return Kind::HostStream(file.handle.is_tty());
        }
        match ty {
            Ok(FileType::Socket) => Kind::Socket,
            Ok(t) => Kind::Vnode(t),
            Err(_) => Kind::Other,
        }
    }

    /// `ioctl(fd, com, data)`.
    pub(crate) fn darwin_ioctl(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        let (fd, com, udata) = (a[0] as i32, a[1] as u32 as u64, a[2]);
        let size = (com >> 16) & IOCPARM_MASK;
        if size > IOCPARM_MAX {
            return Err(Errno::ENOTTY);
        }
        let mut data = vec![0u8; (size as usize).max(8)];
        if com & IOC_IN != 0 {
            if size != 0 {
                data[..size as usize].copy_from_slice(m.read(udata, size as usize)?);
            } else {
                data[..8].copy_from_slice(&udata.to_le_bytes());
            }
        } else if com & IOC_OUT != 0 && size != 0 {
            // Zeroed already: the caller gets something deterministic.
        } else if com & IOC_VOID != 0 {
            data[..8].copy_from_slice(&udata.to_le_bytes());
        }
        let file = self.fds.get(fd)?;
        if !file.readable && !file.writable {
            return Err(Errno::EBADF);
        }
        match com {
            cmd::FIONCLEX | cmd::FIOCLEX => self.fds.set_cloexec(fd, com == cmd::FIOCLEX)?,
            cmd::FIONBIO | cmd::FIOASYNC => {
                let on = int(&data) != 0;
                let lbit = if com == cmd::FIONBIO { crate::fs::oflags::O_NONBLOCK } else { LINUX_O_ASYNC };
                let f = file.flags();
                file.set_flags(if on { f | lbit } else { f & !lbit });
                let mut tmp = [0u8; 8];
                put_int(&mut tmp, i32::from(on));
                self.darwin_fo_ioctl(&file, com, &mut tmp)?;
            }
            cmd::FIOSETOWN => {
                self.darwin_setown(m, &file, int(&data))?;
            }
            cmd::FIOGETOWN => {
                let v = self.darwin_getown(&file)?;
                // FIOGETOWN is _IOR: the answer goes out.
                m.write(udata, &v.to_le_bytes())?;
            }
            _ => {
                self.darwin_fo_ioctl(&file, com, &mut data)?;
                if com & IOC_OUT != 0 && size != 0 {
                    m.write(udata, &data[..size as usize])?;
                }
            }
        }
        Ok(0)
    }

    /// FIOSETOWN and F_SETOWN: a pipe's owner as given; another file's as
    /// a process group (a pid's group, or the group a negative names).
    pub(crate) fn darwin_setown(&mut self, m: &mut GuestMem<'_>, file: &Arc<OpenFile>, owner: i32) -> Result<u64, Errno> {
        let mut tmp = owner;
        match self.darwin_file_kind(file) {
            Kind::Socket => {
                self.darwin_unimplemented("setting a socket's owner (so_pgid)".into());
                return Err(Errno::EOPNOTSUPP);
            }
            Kind::Pipe(..) => {}
            _ => {
                if tmp <= 0 {
                    tmp = -tmp;
                } else {
                    tmp = self.canonical(m, nr::GETPGID, [tmp as u64, 0, 0, 0, 0, 0])? as i32;
                }
            }
        }
        let mut b = [0u8; 8];
        put_int(&mut b, tmp);
        self.darwin_fo_ioctl(file, cmd::TIOCSPGRP, &mut b)?;
        Ok(0)
    }

    /// FIOGETOWN and F_GETOWN: TIOCGPGRP's answer, negated.
    pub(crate) fn darwin_getown(&mut self, file: &Arc<OpenFile>) -> Result<i32, Errno> {
        if matches!(self.darwin_file_kind(file), Kind::Socket) {
            self.darwin_unimplemented("a socket's owner (so_pgid)".into());
            return Err(Errno::EOPNOTSUPP);
        }
        let mut b = [0u8; 8];
        self.darwin_fo_ioctl(file, cmd::TIOCGPGRP, &mut b)?;
        Ok(-int(&b))
    }

    /// The file type's `fo_ioctl`.
    pub(crate) fn darwin_fo_ioctl(&mut self, file: &Arc<OpenFile>, com: u64, data: &mut [u8]) -> Result<(), Errno> {
        match self.darwin_file_kind(file) {
            // pipe_ioctl.
            Kind::Pipe(pipe, write) => match com {
                cmd::FIONBIO => Ok(()),
                // PIPE_ASYNC: SIGIO to the side's owner at its wakeups, sent
                // as from the process making the call.
                cmd::FIOASYNC => {
                    let procs = Arc::clone(&self.procs);
                    let send: Arc<dyn Fn(i32) + Send + Sync> = Arc::new(move |owner: i32| {
                        let _ = procs.kill(super::pipe::caller(), owner, super::kern::signal_to_linux(23));
                    });
                    pipe.set_async(write, int(data) != 0, send);
                    Ok(())
                }
                cmd::FIONREAD => {
                    put_int(data, pipe.buffered() as i32);
                    Ok(())
                }
                cmd::TIOCSPGRP => {
                    pipe.set_pgid(write, int(data));
                    Ok(())
                }
                cmd::TIOCGPGRP => {
                    put_int(data, pipe.pgid(write));
                    Ok(())
                }
                _ => Err(Errno::ENOTTY),
            },
            // soo_ioctl: the descriptor's FNONBLOCK is what the socket here
            // goes by.
            Kind::Socket => match com {
                cmd::FIONBIO => Ok(()),
                cmd::FIOASYNC if int(data) == 0 => Ok(()),
                _ => {
                    self.darwin_unimplemented(format!("ioctl {com:#x} on a socket (soo_ioctl)"));
                    Err(Errno::EOPNOTSUPP)
                }
            },
            // A terminal on the host is a tty here: FIODTYPE says D_TTY,
            // and the tty's own commands are ttioctl's.
            Kind::HostStream(true) => match com {
                cmd::FIODTYPE => {
                    put_int(data, D_TTY);
                    Ok(())
                }
                cmd::FIONBIO => Ok(()),
                _ => {
                    self.darwin_unimplemented(format!("ioctl {com:#x} on the terminal {} (ttioctl)", file.path));
                    Err(Errno::EOPNOTSUPP)
                }
            },
            // A pipe or a file on the host: none of these commands is a
            // pipe's or a regular file's but the ones both take.
            Kind::HostStream(false) => match com {
                cmd::FIONBIO => Ok(()),
                cmd::FIOASYNC if int(data) == 0 => Ok(()),
                cmd::FIONREAD | cmd::FIOASYNC => {
                    self.darwin_unimplemented(format!("ioctl {com:#x} on {}, the host's pipe or file", file.path));
                    Err(Errno::EOPNOTSUPP)
                }
                _ => Err(Errno::ENOTTY),
            },
            // vn_ioctl.
            Kind::Vnode(FileType::Regular | FileType::Directory) => match com {
                cmd::FIONREAD => {
                    let size = file.handle.metadata()?.size as i128;
                    let n = (size - file.offset() as i128).clamp(0, i32::MAX as i128);
                    put_int(data, n as i32);
                    Ok(())
                }
                cmd::FIONBIO | cmd::FIOASYNC => Ok(()),
                _ => Err(Errno::ENOTTY),
            },
            Kind::Vnode(FileType::Fifo | FileType::CharDevice) => {
                self.darwin_unimplemented(format!("ioctl {com:#x} on {} (a device's or fifofs's VNOP_IOCTL)", file.path));
                Err(Errno::EOPNOTSUPP)
            }
            Kind::Vnode(_) => Err(Errno::ENOTTY),
            // fo_no_ioctl.
            Kind::NoIoctl => Err(Errno::ENOTTY),
            Kind::Other => {
                self.darwin_unimplemented(format!("ioctl {com:#x} on {}", file.path));
                Err(Errno::EOPNOTSUPP)
            }
        }
    }

    /// `fcntl(F_GETFL)`: `OFLAGS(f_flag)`.
    pub(crate) fn darwin_getfl(&mut self, fd: i32) -> Result<u64, Errno> {
        let file = self.fds.get(fd)?;
        let waslocked = file.darwin_lflags.load(std::sync::atomic::Ordering::Acquire) & super::lockf::FWASLOCKED;
        Ok(open_flags_back(file.flags()) | u64::from(waslocked))
    }

    /// `fcntl(F_SETFL)`: the `FCNTLFLAGS` replaced, then `fo_ioctl`'s
    /// FIONBIO and FIOASYNC; a failed FIOASYNC takes FNONBLOCK back off.
    pub(crate) fn darwin_setfl(&mut self, fd: i32, arg: u64) -> Result<u64, Errno> {
        let file = self.fds.get(fd)?;
        let keep = open_flags(FCNTLFLAGS);
        let f = (file.flags() & !keep) | open_flags(arg & FCNTLFLAGS);
        file.set_flags(f);
        let mut tmp = [0u8; 8];
        put_int(&mut tmp, i32::from(f & crate::fs::oflags::O_NONBLOCK != 0));
        self.darwin_fo_ioctl(&file, cmd::FIONBIO, &mut tmp)?;
        put_int(&mut tmp, i32::from(f & LINUX_O_ASYNC != 0));
        if let Err(e) = self.darwin_fo_ioctl(&file, cmd::FIOASYNC, &mut tmp) {
            file.set_flags(file.flags() & !crate::fs::oflags::O_NONBLOCK);
            put_int(&mut tmp, 0);
            let _ = self.darwin_fo_ioctl(&file, cmd::FIONBIO, &mut tmp);
            return Err(e);
        }
        Ok(0)
    }
}

/// `D_TTY` (`bsd/sys/conf.h`).
const D_TTY: i32 = 3;

/// Linux's `O_ASYNC`.
const LINUX_O_ASYNC: u64 = 0x2000;
