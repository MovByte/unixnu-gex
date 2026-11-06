//! The host's `madvise` for the guest's pages, for gex-kernel, which forbids
//! `unsafe` and so takes it as a hook (`set_host_vm`). The guest's memory is
//! the host's private anonymous memory, so the host's own advice does to it
//! what the guest asked for.

use gex_kernel::HostAdvice;

pub fn install() {
    gex_kernel::set_host_vm(advise);
    gex_kernel::set_host_map_file(map_file);
    gex_kernel::set_host_pages(pages);
}

#[cfg(target_os = "macos")]
extern "C" {
    static mach_task_self_: libc::c_uint;
    fn mach_vm_page_range_query(target: libc::c_uint, address: u64, size: u64, dispositions: u64, count: *mut u64) -> libc::c_int;
}

/// Each page's state by `mach_vm_page_range_query`, the host's own VM's
/// view of its pages (`VM_PAGE_QUERY_PAGE_*`).
#[cfg(target_os = "macos")]
fn pages(at: usize, len: usize, page: usize, out: &mut [u8]) -> bool {
    use gex_kernel::page_state as ps;
    const PRESENT: i32 = 0x1;
    const PAGED_OUT: i32 = 0x10;
    const EXTERNAL: i32 = 0x80;
    const REUSABLE: i32 = 0x800;
    if page != self::page() || at % page != 0 || len % page != 0 || out.len() < len / page {
        return false;
    }
    let n = len / page;
    let mut d = vec![0i32; n];
    let mut count = n as u64;
    // SAFETY: `d` holds `count` dispositions; the range is guest memory.
    let kr = unsafe { mach_vm_page_range_query(mach_task_self_, at as u64, len as u64, d.as_mut_ptr() as u64, &mut count) };
    if kr != 0 || count as usize != n {
        return false;
    }
    for (o, &v) in out.iter_mut().zip(&d) {
        *o = [(PRESENT, ps::PRESENT), (PAGED_OUT, ps::PAGED_OUT), (EXTERNAL, ps::EXTERNAL), (REUSABLE, ps::REUSABLE)].iter().filter(|(b, _)| v & b != 0).fold(0, |a, (_, s)| a | s);
    }
    true
}

/// No per-page query of the host's VM this side of macOS.
#[cfg(not(target_os = "macos"))]
fn pages(_at: usize, _len: usize, _page: usize, _out: &mut [u8]) -> bool {
    false
}

/// The host's page size.
fn page() -> usize {
    static PAGE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    // SAFETY: sysconf reads a constant.
    *PAGE.get_or_init(|| unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize)
}

/// A private mapping of `fd` from `offset` over the guest's pages at `at`.
/// The pages are the file's until written, then the host's copy; none lies
/// wholly past the file's end (the caller maps only what the file holds).
fn map_file(at: usize, len: usize, fd: i32, offset: u64) -> bool {
    let page = page();
    if at % page != 0 || len % page != 0 || len == 0 || offset % page as u64 != 0 {
        return false;
    }
    let Ok(off) = libc::off_t::try_from(offset) else { return false };
    // SAFETY: `at..at + len` is guest memory, mapped for the life of the
    // process; the file's pages replace what the guest just mapped there,
    // readable and writable as the guest's memory is.
    let p = unsafe { libc::mmap(at as *mut libc::c_void, len, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_FIXED | libc::MAP_PRIVATE, fd, off) };
    p as usize == at
}

/// What the host does for a piece of advice.
enum Host {
    Madvise(libc::c_int),
    /// Fresh zero pages mapped over the old.
    Remap,
    /// Nothing needs doing.
    Done,
    /// The host cannot.
    Cannot,
}

/// Darwin's `MADV_*`: the same VM as the guest's.
#[cfg(target_os = "macos")]
fn advice(a: HostAdvice) -> Host {
    Host::Madvise(match a {
        HostAdvice::Free => 5,
        HostAdvice::Reusable => 7,
        HostAdvice::Reuse => 8,
        HostAdvice::Deactivate => 4,
        HostAdvice::WillNeed => 3,
        HostAdvice::Zero => 11,
        HostAdvice::Discard => return Host::Remap,
    })
}

/// Linux's nearest: `MADV_FREE` frees lazily (a page written again is
/// kept) and `MADV_COLD` deactivates; a page is the owner's without a
/// reuse; zeroing is left to the kernel's own write.
#[cfg(not(target_os = "macos"))]
fn advice(a: HostAdvice) -> Host {
    match a {
        HostAdvice::Free | HostAdvice::Reusable => Host::Madvise(8),
        HostAdvice::Deactivate => Host::Madvise(20),
        HostAdvice::WillNeed => Host::Madvise(3),
        HostAdvice::Reuse => Host::Done,
        HostAdvice::Zero => Host::Cannot,
        HostAdvice::Discard => Host::Remap,
    }
}

fn advise(at: usize, len: usize, a: HostAdvice) -> bool {
    // The host rounds a range out to its own pages, which may be larger
    // than the guest's: a range that is not whole host pages is refused.
    let page = page();
    if at % page != 0 || len % page != 0 || len == 0 {
        return false;
    }
    match advice(a) {
        Host::Done => true,
        Host::Cannot => false,
        // SAFETY: `at..at + len` is guest memory, which the host maps for
        // the life of the process; advice changes only what its pages hold
        // (each as before or zero, as the guest asked) and how they are kept.
        Host::Madvise(adv) => unsafe { libc::madvise(at as *mut libc::c_void, len, adv) == 0 },
        // SAFETY: as above; the new pages are private, anonymous and
        // readable and writable, as the guest's memory is mapped.
        Host::Remap => unsafe {
            let p = libc::mmap(at as *mut libc::c_void, len, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_FIXED | libc::MAP_PRIVATE | libc::MAP_ANON, -1, 0);
            p as usize == at
        },
    }
}
