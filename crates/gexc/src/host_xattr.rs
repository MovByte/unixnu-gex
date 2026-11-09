//! The host's `l*xattr`/`f*xattr` calls for gex-kernel's HostFs, which
//! forbids `unsafe` and so takes them as a hook (`set_host_xattr`).

use gex_kernel::errno::Errno;
use gex_kernel::vfs::hostfs::host_xattr::{set_host_xattr, On};
use gex_kernel::vfs::XattrOp;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;

pub fn install() {
    set_host_xattr(call);
    gex_kernel::vfs::hostfs::host_identity::set_host_identity(identity);
}

/// The effective user and group this process checks access as, and its
/// groups.
fn identity() -> (u32, u32, Vec<u32>) {
    // SAFETY: a count of zero only asks for the size, and the second call
    // writes at most `n` entries into a vector of that length.
    unsafe {
        let n = libc::getgroups(0, std::ptr::null_mut()).max(0);
        let mut groups = vec![0; n as usize];
        let got = libc::getgroups(n, groups.as_mut_ptr()).max(0);
        groups.truncate(got as usize);
        (libc::geteuid(), libc::getegid(), groups)
    }
}

fn call(on: &On<'_>, op: XattrOp<'_>) -> Result<usize, Errno> {
    let path = match on {
        On::Path(p) => Some(CString::new(p.as_os_str().as_bytes()).map_err(|_| Errno::EINVAL)?),
        On::Fd(_) => None,
    };
    let fd = match on { On::Fd(fd) => *fd, On::Path(_) => -1 };
    let name_c = |n: &str| CString::new(n).map_err(|_| Errno::EINVAL);
    // SAFETY: every pointer is a live CString or slice for the call's length.
    #[cfg(not(target_os = "macos"))]
    let r: isize = unsafe {
        match op {
            XattrOp::Get { name, buf } => {
                let n = name_c(name)?;
                // No buffer asks for the size; macOS takes one of length
                // zero as too small.
                let (b, l) = (if buf.is_empty() { std::ptr::null_mut() } else { buf.as_mut_ptr() as *mut libc::c_void }, buf.len());
                match &path {
                    Some(p) => libc::lgetxattr(p.as_ptr(), n.as_ptr(), b, l),
                    None => libc::fgetxattr(fd, n.as_ptr(), b, l),
                }
            }
            XattrOp::Set { name, value, flags } => {
                let n = name_c(name)?;
                let (v, l) = (value.as_ptr() as *const libc::c_void, value.len());
                (match &path {
                    Some(p) => libc::lsetxattr(p.as_ptr(), n.as_ptr(), v, l, flags as i32),
                    None => libc::fsetxattr(fd, n.as_ptr(), v, l, flags as i32),
                }) as isize
            }
            XattrOp::List { buf } => {
                let (b, l) = (if buf.is_empty() { std::ptr::null_mut() } else { buf.as_mut_ptr() as *mut libc::c_char }, buf.len());
                match &path {
                    Some(p) => libc::llistxattr(p.as_ptr(), b, l),
                    None => libc::flistxattr(fd, b, l),
                }
            }
            XattrOp::Remove { name } => {
                let n = name_c(name)?;
                (match &path {
                    Some(p) => libc::lremovexattr(p.as_ptr(), n.as_ptr()),
                    None => libc::fremovexattr(fd, n.as_ptr()),
                }) as isize
            }
        }
    };
    // SAFETY: as above. macOS spells the l* calls as the path calls with
    // XATTR_NOFOLLOW, and takes a position (resource forks only) and options.
    #[cfg(target_os = "macos")]
    let r: isize = unsafe {
        let nofollow = libc::XATTR_NOFOLLOW;
        match op {
            XattrOp::Get { name, buf } => {
                let n = name_c(name)?;
                // No buffer asks for the size; macOS takes one of length
                // zero as too small.
                let (b, l) = (if buf.is_empty() { std::ptr::null_mut() } else { buf.as_mut_ptr() as *mut libc::c_void }, buf.len());
                match &path {
                    Some(p) => libc::getxattr(p.as_ptr(), n.as_ptr(), b, l, 0, nofollow),
                    None => libc::fgetxattr(fd, n.as_ptr(), b, l, 0, 0),
                }
            }
            XattrOp::Set { name, value, flags } => {
                let n = name_c(name)?;
                let (v, l) = (value.as_ptr() as *const libc::c_void, value.len());
                // Linux's XATTR_CREATE (1) and XATTR_REPLACE (2) are macOS's 2 and 4.
                let f = ((flags as i32 & 1) << 1) | ((flags as i32 & 2) << 1);
                (match &path {
                    Some(p) => libc::setxattr(p.as_ptr(), n.as_ptr(), v, l, 0, f | nofollow),
                    None => libc::fsetxattr(fd, n.as_ptr(), v, l, 0, f),
                }) as isize
            }
            XattrOp::List { buf } => {
                let (b, l) = (if buf.is_empty() { std::ptr::null_mut() } else { buf.as_mut_ptr() as *mut libc::c_char }, buf.len());
                match &path {
                    Some(p) => libc::listxattr(p.as_ptr(), b, l, nofollow),
                    None => libc::flistxattr(fd, b, l, 0),
                }
            }
            XattrOp::Remove { name } => {
                let n = name_c(name)?;
                (match &path {
                    Some(p) => libc::removexattr(p.as_ptr(), n.as_ptr(), nofollow),
                    None => libc::fremovexattr(fd, n.as_ptr(), 0),
                }) as isize
            }
        }
    };
    if r < 0 {
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO);
        // Linux has one name for a missing attribute.
        #[cfg(target_os = "macos")]
        if e == libc::ENOATTR {
            return Err(Errno(61));
        }
        return Err(Errno::from_host(e));
    }
    Ok(r as usize)
}
