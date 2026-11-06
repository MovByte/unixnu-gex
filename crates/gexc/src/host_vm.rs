//! The host's `madvise` for the guest's pages, for gex-kernel, which forbids
//! `unsafe` and so takes it as a hook (`set_host_vm`). The guest's memory is
//! the host's private anonymous memory, so the host's own advice does to it
//! what the guest asked for.

use gex_kernel::HostAdvice;

pub fn install() {
    gex_kernel::set_host_vm(advise);
}


/// The host's page size.
fn page() -> usize {
    static PAGE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    // SAFETY: sysconf reads a constant.
    *PAGE.get_or_init(|| unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize)
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
