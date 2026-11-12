//! Sandbox's sandboxes (`sandbox.c`, `kext.c`, `protobox.c` of the iOS 17
//! Sandbox.kext): the label a credential carries for the policy, the
//! profiles a sandbox is made of, and how a process gets one.
//!
//! A sandbox is a process profile, from the kext's builtin collection (its
//! 272 named profiles) or its protobox collection (556 profiles named by
//! executable path), with the protobox profile stacked under it when the
//! profile's flag bit 2 asks, and the state the exec gave it: whether a
//! container is expected, the container, the byte process-attribute 0
//! reads, and its extensions. The credential's label holds it; a derived
//! credential keeps it (`mpo_cred_label_associate`), so a fork's child and
//! an exec that chooses no profile carry the parent's.
//!
//! An exec's hook (`mpo_cred_label_update_execve`, `0x...a0d20c`; its
//! check, `0x...a0d204`, always asks for it) chooses the profile: the
//! `seatbelt-profiles` entitlement's one name (AMFI's
//! `amfi_copy_seatbelt_profile_names`; two are refused), or the spawn's
//! Sandbox attributes' name, or, for an exec with neither and no sandbox of
//! its own, the profile the platform profile's process-exec-update-label
//! names (modifier 11: `container` for apps), or, for an exec its sandbox's
//! process-exec check marked (flag 3), that sandbox's choice, a mark with
//! none dropping a protobox sandbox; the protobox profile named by the
//! executable's path is looked up for every exec. A builtin profile
//! makes a new sandbox, with the executable's extension
//! (`com.apple.sandbox.executable`, for its bundle's path); with none, the
//! process keeps the sandbox it had, or gets its protobox profile alone.
//! `sandbox_init` with a builtin profile (`SANDBOX_NAMED_BUILTIN`: the
//! policy's call 1; call 22 says whether one is named so) gives the caller
//! one, once: a second is refused (`forbidden-sandbox-reinit`).
//!
//! A sandbox filters its process's calls by masks (`proc_set_syscall_filter_mask`):
//! of its Unix calls, Mach traps and kernel MIG routines, each its
//! profile's call operation's (syscall-unix, syscall-mach, syscall-mig) and-ed
//! with the platform profile's, which are a process's with no sandbox; a
//! clear bit has the call asked of the policy. Kernel MIG routines are
//! known by the indexes Sandbox gives their message ids at boot.
//!
//! The user states `policy_init` makes (the front user's and the role
//! accounts') give the HOME and PROCESS_TEMP_DIR pattern variables their
//! paths; the calls that change them, and containermanagerd's that register
//! containers, are not served (each is refused loudly), so no container is
//! ever found.
//!
//! What is not ported stops the exec (or the call) loudly at the point the
//! kext would do it: the `com.apple.private.sandbox.profile` and
//! `:embedded` entitlements' profiles, a container (one given by the spawn
//! or to `sandbox_init`, and the upcall to containermanagerd that one
//! expected and not registered makes), the extensions the
//! `com.apple.security.exception.*` entitlements issue. A process
//! whose profile filters its Mach messages (flag bit 12) stops at its first
//! message to a port that enforces filtering (`mach_msg.rs`). An
//! extension is kept as its class and path; what it is bound to and what an
//! extension filter matches it by are not ported, and such a filter stops
//! its evaluation (see `sandbox.rs`).

use std::sync::{Arc, Mutex, OnceLock};

use super::mac::{self, SbArgs, SbVnode};
use super::sandbox::{self, Profile};
use crate::syscalls::Kernel;

/// A collection the kext carries: its blob and its profiles, with their
/// names.
pub struct Collection {
    blob: Vec<u8>,
    profiles: Vec<Profile>,
    names: Vec<Vec<u8>>,
    masks: Vec<[sandbox::ProfileMask; 4]>,
}

impl Collection {
    /// The kext's `collection_load` of a blob, which the boot panics on:
    /// its profiles, with their names and the masks of their call
    /// operations (`0x...a091f0`).
    fn load(b: Vec<u8>) -> Result<Collection, String> {
        let profiles = sandbox::collection(&b).map_err(|e| format!("{e:?}"))?;
        let names = profiles.iter().map(|p| sandbox::string(&b, p, p.name).ok_or_else(|| "a profile's name".to_string())).collect::<Result<Vec<_>, _>>()?;
        let masks = profiles.iter().map(|p| profile_masks(&b, p, p.flags & 4 != 0)).collect::<Result<Vec<_>, _>>()?;
        Ok(Collection { blob: b, profiles, names, masks })
    }
}

/// The call operations whose masks a profile's loader makes, with the
/// filter type of their numbers: syscall-unix, syscall-mach, syscall-mig
/// (which a process's masks are) and system-fcntl.
pub const MASK_OPS: [(usize, u8); 4] = [(152, 65), (153, 75), (154, 76), (163, 78)];

/// The masks of profile `p` (`0x...a091f0`), whose error fails its load.
pub fn profile_masks(b: &[u8], p: &Profile, stacks_protobox: bool) -> Result<[sandbox::ProfileMask; 4], String> {
    let mut out: [sandbox::ProfileMask; 4] = Default::default();
    for (m, &(op, ty)) in out.iter_mut().zip(&MASK_OPS) {
        *m = sandbox::profile_mask(b, p, op, ty, stacks_protobox).map_err(|e| format!("the mask of {}: {e}", mac::OPERATION_NAMES[op]))?;
    }
    Ok(out)
}

/// The builtin collection (`0x...6ecab0`, named profiles) and the protobox
/// collection (`0x...7c3840`, profiles named by executable path), as the
/// boot loaded them.
static BUILTIN: OnceLock<Option<Collection>> = OnceLock::new();
static PROTOBOX: OnceLock<Option<Collection>> = OnceLock::new();

/// Load the collections (`policy_init`), once; a blob that does not load
/// fails the boot, as it panics the kernel.
pub fn set_collections(builtin: Option<Vec<u8>>, protobox: Option<Vec<u8>>) -> Result<(), String> {
    let b = builtin.map(Collection::load).transpose().map_err(|e| format!("failed to initialize builtin collection: {e}"))?;
    let p = protobox.map(Collection::load).transpose().map_err(|e| format!("failed to initialize protobox collection: {e}"))?;
    let _ = BUILTIN.set(b);
    let _ = PROTOBOX.set(p);
    Ok(())
}

/// A collection the boot payload did not have: what the kernel cannot say
/// without it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Missing(pub &'static str);

const NO_BUILTIN: Missing = Missing("the Sandbox's builtin profile collection (the boot payload's sandbox_builtin.bin)");
const NO_PROTOBOX: Missing = Missing("the Sandbox's protobox profile collection (the boot payload's sandbox_protobox.bin)");

/// Which collection a profile is of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Set {
    Builtin,
    Protobox,
}

/// A profile of a loaded collection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProfileRef {
    pub set: Set,
    index: usize,
}

impl ProfileRef {
    fn collection(self) -> &'static Collection {
        let c = match self.set {
            Set::Builtin => &BUILTIN,
            Set::Protobox => &PROTOBOX,
        };
        c.get().and_then(Option::as_ref).expect("a profile of a loaded collection")
    }

    pub fn blob(self) -> &'static [u8] {
        &self.collection().blob
    }

    pub fn profile(self) -> &'static Profile {
        &self.collection().profiles[self.index]
    }

    pub fn name(self) -> &'static [u8] {
        &self.collection().names[self.index]
    }

    /// The collection entry's flags (`+68`): bit 2, a protobox profile is
    /// stacked under it; bit 12, the process's Mach messages are filtered.
    pub fn flags(self) -> u16 {
        self.profile().flags
    }

    /// Its call operations' masks, as its load made them.
    pub fn masks(self) -> &'static [sandbox::ProfileMask; 4] {
        &self.collection().masks[self.index]
    }
}

/// `0x...a15554`: the builtin profile named exactly `name`.
pub fn builtin(name: &[u8]) -> Result<Option<ProfileRef>, Missing> {
    let Some(Some(c)) = BUILTIN.get() else { return Err(NO_BUILTIN) };
    Ok(c.names.iter().position(|n| n == name).map(|index| ProfileRef { set: Set::Builtin, index }))
}

/// `0x...a171b4`: the protobox profile of the executable at `path` (the
/// name that is the path), none on a system whose release type is Restore
/// or Darwin.
pub fn protobox_for(path: &[u8], release_type: &[u8]) -> Result<Option<ProfileRef>, Missing> {
    let word = |w: &[u8]| release_type.split(|&c| c == b' ').any(|x| x == w);
    if word(b"Restore") || word(b"Darwin") {
        return Ok(None);
    }
    let Some(Some(c)) = PROTOBOX.get() else { return Err(NO_PROTOBOX) };
    Ok(c.names.iter().position(|n| n == path).map(|index| ProfileRef { set: Set::Protobox, index }))
}

/// A user state Sandbox keeps (`0x...a0e4e8`): the home and temporary
/// directories the HOME and PROCESS_TEMP_DIR pattern variables name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserState {
    pub home: &'static str,
    pub tmp: &'static str,
}

/// The front user `policy_init` makes the first user state for.
pub const FRONT_USER: u32 = 501;

/// The role accounts `policy_init` makes user states for (`0x...f8e328`),
/// each with its home; their temporary directory is `/private/var/tmp`.
const ROLE_ACCOUNTS: [(u32, &str); 32] = [
    (0, "/private/var/root"),
    (1, "/private/var/root"),
    (24, "/private/var/networkd"),
    (25, "/private/var/wireless"),
    (33, "/private/var/installd"),
    (34, "/private/var/empty"),
    (35, "/private/var/empty"),
    (64, "/private/var/empty"),
    (65, "/private/var/empty"),
    (75, "/private/var/empty"),
    (99, "/private/var/empty"),
    (241, "/private/var/empty"),
    (245, "/private/var/db/astris"),
    (249, "/private/var/db/ondemand"),
    (254, "/private/var/db/findmydevice"),
    (257, "/private/var/db/datadetectors"),
    (258, "/private/var/empty"),
    (263, "/private/var/db/analyticsd"),
    (264, "/private/var/db/timed"),
    (267, "/private/var/db/gpsd"),
    (268, "/private/var/db/nearbyd"),
    (270, "/private/var/empty"),
    (271, "/private/var/db/diskimagesiod"),
    (272, "/private/var/db/diagnostics"),
    (276, "/private/var/empty"),
    (277, "/private/var/db/rmd"),
    (278, "/private/var/db/fud"),
    (279, "/private/var/db/knowledgegraphd"),
    (280, "/private/var/empty"),
    (281, "/private/var/empty"),
    (282, "/private/var/empty"),
    (288, "/private/var/empty"),
];

/// The user state of `uid` (`0x...a0e6a4`): the front user's, a role
/// account's, or none. The calls that add or change one (containermanagerd's
/// and the user state calls) are not served, each refused loudly.
pub fn user_state(uid: u32) -> Option<UserState> {
    if uid == FRONT_USER {
        return Some(UserState { home: "/private/var/mobile", tmp: "/private/var/mobile/tmp" });
    }
    ROLE_ACCOUNTS.iter().find(|&&(u, _)| u == uid).map(|&(_, home)| UserState { home, tmp: "/private/var/tmp" })
}

/// An extension a sandbox holds (`0x...a10d58`, `0x...a11010`): its class
/// and the path it was issued for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Extension {
    pub class: &'static [u8],
    pub path: Vec<u8>,
}

/// A sandbox (`struct sandbox`).
#[derive(Debug)]
pub struct Sandbox {
    /// Its profile (`sb[0]`) and the protobox profile stacked under it
    /// (`sb[8]`), which decides what the profile defers (flag 10).
    pub profile: ProfileRef,
    pub protobox: Option<ProfileRef>,
    /// Its shared state's byte `+59` (process-attribute 0: an extension
    /// point's sandbox), `+60` (a container is expected) and `+24` (its
    /// container).
    pub flag_3b: bool,
    pub container_expected: bool,
    pub container: Option<Vec<u8>>,
    pub extensions: Vec<Extension>,
    /// Its masks (`+40`, of the Unix calls, Mach traps, kernel MIG
    /// routines and fcntl commands; [`combine`]): none lets every call
    /// through unasked.
    pub masks: [Option<sandbox::FilterMask>; 4],
}

/// The kernel MIG routines' indexes Sandbox gives them at boot
/// (`proc_set_syscall_filter_index(SYSCALL_MASK_KOBJ, id, i)` for each id
/// of its table at `0x...6ec434`): routine id `KOBJ_IDS[i]` is index `i`,
/// the bit of a kernel MIG mask that stands for it.
const KOBJ_IDS: [u32; 343] = [
    200, 201, 202, 203, 204, 205, 206, 207, 209, 213, 215, 216, 217, 218, 219, 220, 221,
    222, 225, 227, 228, 231, 232, 233, 234, 400, 401, 402, 403, 404, 405, 406, 407, 412,
    413, 414, 415, 416, 418, 419, 420, 423, 424, 425, 600, 601, 1000, 1001, 1002, 1200,
    1201, 2401, 2402, 2403, 2405, 2406, 2407, 2800, 2801, 2802, 2803, 2804, 2805, 2806,
    2807, 2808, 2809, 2810, 2811, 2812, 2813, 2814, 2816, 2817, 2818, 2819, 2820, 2821,
    2822, 2823, 2824, 2825, 2826, 2827, 2828, 2829, 2830, 2831, 2832, 2833, 2834, 2836,
    2837, 2838, 2839, 2840, 2841, 2842, 2843, 2844, 2845, 2846, 2847, 2848, 2849, 2850,
    2851, 2852, 2853, 2854, 2855, 2856, 2857, 2858, 2859, 2860, 2861, 2862, 2863, 2864,
    2865, 2866, 2867, 2868, 2869, 2870, 2871, 2872, 2873, 2874, 2875, 2876, 2877, 2878,
    2879, 2880, 2881, 2882, 2883, 2884, 2885, 2886, 2887, 2888, 2889, 2890, 3000, 3001,
    3002, 3003, 3004, 3005, 3200, 3201, 3203, 3204, 3205, 3206, 3207, 3208, 3209, 3210,
    3211, 3212, 3213, 3214, 3215, 3216, 3217, 3218, 3219, 3220, 3221, 3222, 3223, 3224,
    3226, 3227, 3228, 3229, 3230, 3231, 3232, 3233, 3234, 3235, 3236, 3237, 3238, 3239,
    3240, 3241, 3242, 3401, 3402, 3403, 3404, 3405, 3406, 3407, 3408, 3409, 3410, 3411,
    3412, 3413, 3414, 3415, 3418, 3419, 3420, 3421, 3433, 3434, 3435, 3436, 3437, 3438,
    3439, 3440, 3441, 3442, 3443, 3444, 3445, 3446, 3447, 3448, 3449, 3450, 3451, 3452,
    3453, 3455, 3456, 3457, 3458, 3459, 3460, 3461, 3462, 3463, 3464, 3600, 3601, 3602,
    3603, 3604, 3605, 3606, 3607, 3608, 3609, 3610, 3611, 3612, 3613, 3614, 3615, 3616,
    3617, 3618, 3624, 3625, 3626, 3627, 3628, 3630, 3800, 3801, 3802, 3803, 3804, 3805,
    3806, 3807, 3808, 3809, 3810, 3811, 3812, 3813, 3814, 3815, 3816, 3817, 3818, 3819,
    3821, 3822, 3823, 3824, 3825, 3826, 3830, 3831, 3832, 4000, 4005, 4006, 4008, 4009,
    4010, 4800, 4801, 4802, 4803, 4804, 4805, 4806, 4807, 4808, 4809, 4810, 4811, 4812,
    4813, 4814, 4815, 4816, 4817, 4818, 4819, 4820, 4821, 4825, 4900, 4901, 4902, 5400,
    5401, 5402, 5403, 5404, 6200, 6201, 8000, 8001, 51471, 716200, 716201, 716202,
    716203,
];

/// The table's ids no kernel routine has (`ipc_kobject_set_kobjidx` finds
/// none, ENOENT): they stay unindexed, and are never filtered.
const KOBJ_NO_ROUTINE: [u32; 8] = [600, 601, 1200, 1201, 3832, 6200, 6201, 51471];

/// The index of the kernel MIG routine of message id `id` (its bucket's
/// `kobjidx`), none for one Sandbox gave none (`KOBJ_IDX_NOT_SET`).
pub fn kobj_index(id: u32) -> Option<usize> {
    if KOBJ_NO_ROUTINE.contains(&id) {
        return None;
    }
    KOBJ_IDS.iter().position(|&k| k == id)
}

/// `0x...9f3570`: a sandbox's mask of one kind, from its profile's
/// (`prof`, which may defer), the stacked protobox profile's (`pb`), and
/// the platform profile's (`plat`); none is no mask, which lets every call
/// through. A profile's own mask counts but for one that defers with no
/// mask stacked under it; a deferring one's is or-ed with the protobox
/// profile's (`0x...9f36b0`: either one's absence lets all through); and
/// what counts is and-ed with the platform profile's (`0x...9f37f8`), or,
/// with none of its own, the platform profile's is the sandbox's.
pub fn combine(defer: bool, prof: Option<&sandbox::FilterMask>, pb: Option<&sandbox::FilterMask>, plat: Option<&sandbox::FilterMask>) -> Option<sandbox::FilterMask> {
    let own = if pb.is_some() || !defer { prof } else { None };
    let Some(own) = own else { return plat.cloned() };
    let own = sandbox::mask_bytes(own);
    let own: [u8; sandbox::MASK_BYTES] = match (defer, pb.map(|m| sandbox::mask_bytes(m))) {
        (true, Some(pb)) => std::array::from_fn(|i| own[i] | pb[i]),
        _ => own,
    };
    Some(sandbox::mask_of(match plat.map(|m| sandbox::mask_bytes(m)) {
        Some(plat) => std::array::from_fn(|i| own[i] & plat[i]),
        None => own,
    }))
}

impl Sandbox {
    /// `0x...a0f1d0`: a sandbox of `profile`. A profile with flag bit 2
    /// stacks `protobox`, or with none given, the builtin profile named
    /// `protobox` (this collection has none).
    pub fn new(profile: ProfileRef, protobox: Option<ProfileRef>) -> Result<Sandbox, Missing> {
        let stacked = if profile.flags() & 4 != 0 {
            match protobox {
                Some(p) => Some(p),
                None => builtin(b"protobox")?,
            }
        } else {
            None
        };
        let plat = mac::platform_masks();
        let masks = std::array::from_fn(|i| {
            let own = &profile.masks()[i];
            combine(own.defer, own.mask.as_ref(), stacked.and_then(|p| p.masks()[i].mask.as_ref()), plat[i].as_ref())
        });
        Ok(Sandbox { profile, protobox: stacked, flag_3b: false, container_expected: false, container: None, extensions: Vec::new(), masks })
    }

    /// Its profile is the protobox collection's.
    pub fn protoboxed(&self) -> bool {
        self.profile.set == Set::Protobox
    }
}

/// A credential's Sandbox label slot, which the task's link shares for
/// other processes to read.
pub type Label = Arc<Mutex<Option<Arc<Sandbox>>>>;

/// The label's sandbox.
pub fn of(l: &Label) -> Option<Arc<Sandbox>> {
    l.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// `com.apple.sandbox.executable`, `com.apple.sandbox.container`.
const EXECUTABLE: &[u8] = b"com.apple.sandbox.executable";

/// The entitlements the exec issues extensions for into a sandbox of a
/// builtin profile (`0x...f8ea28`, each with its handler).
const EXTENSION_ENTITLEMENTS: [&str; 18] = [
    "com.apple.security.application-groups",
    "com.apple.security.exception.mach-lookup.global-name",
    "com.apple.security.exception.mach-lookup.local-name",
    "com.apple.security.exception.mach-register.global-name",
    "com.apple.security.exception.mach-register.local-name",
    "com.apple.security.exception.files.absolute-path.read-only",
    "com.apple.security.exception.files.absolute-path.read-write",
    "com.apple.security.exception.files.home-relative-path.read-only",
    "com.apple.security.exception.files.home-relative-path.read-write",
    "com.apple.security.exception.iokit-user-client-class",
    "com.apple.security.exception.managed-preference.read-only",
    "com.apple.security.exception.shared-preference.read-only",
    "com.apple.security.exception.shared-preference.read-write",
    "com.apple.security.exception.sysctl.read-only",
    "com.apple.security.exception.sysctl.read-write",
    "com.apple.security.system-container",
    "com.apple.security.system-groups",
    "com.apple.security.system-group-containers",
];

/// The builtin profiles of extension points: a sandbox of one has byte
/// `+59` set and expects a container.
const EXTENSION_POINTS: [&[u8]; 11] = [
    b"background-assets",
    b"keyboard",
    b"media-device-discovery-extension",
    b"message-filter",
    b"network-filter",
    b"playground-devtools",
    b"plugin",
    b"quicklookd",
    b"quicklook-preview",
    b"quicklook-thumbnail",
    b"sessions-extension",
];

/// The bundle suffixes the executable's path is searched for, from its
/// end, and an app extension's.
const BUNDLES: [&[u8]; 7] = [b".app", b".xpc", b".dext", b".bundle", b".plugin", b".framework", b".pluginkit"];
const APPEX: &[u8] = b".appex";

/// Where the executable's bundle ends in its path (`0x...a0d890`): at the
/// `/` after the last component with a bundle suffix; an app extension's
/// own is skipped when it is in a bundle's `PlugIns` or `Extensions`,
/// which marks the sandbox an extension point's. The whole path when it is
/// in no bundle.
fn bundle_end(path: &[u8]) -> (usize, bool) {
    let ends = |i: usize, s: &[u8]| i >= s.len() && &path[i - s.len()..i] == s;
    let mut i = path.len();
    while i > 0 {
        i -= 1;
        if path[i] != b'/' {
            continue;
        }
        if BUNDLES.iter().any(|s| ends(i, s)) {
            return (i, false);
        }
        if ends(i, APPEX) {
            return appex_end(path, i);
        }
    }
    (path.len(), false)
}

/// An app extension's bundle at `i` (`0x...a0e018`): out past each
/// `PlugIns` or `Extensions` directory an `.appex` is in.
fn appex_end(path: &[u8], mut i: usize) -> (usize, bool) {
    let ends = |i: usize, s: &[u8]| i >= s.len() && &path[i - s.len()..i] == s;
    let mut nested = false;
    let mut end = i;
    loop {
        if !ends(i, APPEX) {
            return (end, nested);
        }
        // Back to the `/` before the extension's own component.
        let mut j = i - APPEX.len();
        loop {
            if j == 0 {
                return (end, nested);
            }
            j -= 1;
            if path[j] == b'/' {
                break;
            }
        }
        i = j;
        if let Some(d) = [&b"/Extensions"[..], b"/PlugIns"].iter().find(|d| ends(i, d)) {
            nested = true;
            i -= d.len();
            end = i;
        }
    }
}

/// The items of an entitlement the exec walks (`0x...a1adc0`): a string, an
/// array's strings up to the first that is not one, or `true` for the
/// boolean true.
fn items(e: &super::codesign::Ent) -> Vec<Vec<u8>> {
    use super::codesign::Ent;
    match e {
        Ent::String(s) => vec![s.clone()],
        Ent::Array(a) => a
            .iter()
            .map_while(|x| match x {
                Ent::String(s) => Some(s.clone()),
                _ => None,
            })
            .collect(),
        Ent::Bool(true) => vec![b"true".to_vec()],
        _ => Vec::new(),
    }
}

/// The spawn's Sandbox attributes (`sandbox_spawnattrs`, `0x...a0a2ec`):
/// version 0 and 1104 bytes, a profile name of up to 63 bytes at 16 and a
/// container of up to 1023 at 80, each with its length; EINVAL otherwise.
fn spawnattrs(b: &[u8]) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>), ()> {
    const SIZE: usize = 1104;
    let word = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap()) as usize;
    if b.len() < SIZE || word(0) != 0 || word(4) != SIZE || word(8) > 63 || word(12) > 1023 {
        return Err(());
    }
    // Each string ends at its length (the kext writes the NUL there).
    let cstr = |at: usize, n: usize| {
        let s = &b[at..at + n];
        s[..s.iter().position(|&c| c == 0).unwrap_or(n)].to_vec()
    };
    let profile = (word(8) != 0).then(|| cstr(16, word(8)));
    let container = (word(12) != 0).then(|| cstr(80, word(12)));
    Ok((profile, container))
}

/// What an exec activated keeps for Sandbox's hook until its image starts:
/// the script's path for a script, and the spawn's Sandbox attributes (its
/// `_ps_mac_policy_extension` named `Sandbox`).
#[derive(Clone, Debug, Default)]
pub struct Pending {
    pub script: Option<String>,
    pub spawnattrs: Option<Vec<u8>>,
    /// The exec's last process-exec check marked it (flag 3).
    pub marked: bool,
}

/// What an exec gives Sandbox's hook beyond its process: the path of the
/// vnode it names (the script's for a script, else the executable's),
/// canonical, and the spawn's Sandbox attributes.
pub struct Exec<'a> {
    pub path: &'a str,
    pub spawnattrs: Option<&'a [u8]>,
    pub marked: bool,
}

/// What the exec's hook gathered (`sp+96` on): the profile chosen, its
/// container, the bundle's end, whether a container is expected, the
/// extension point's byte, and the containers the entitlements ask for
/// that are not registered.
#[derive(Default)]
struct Spec {
    profile: Option<Vec<u8>>,
    container: Option<Vec<u8>>,
    protobox: Option<ProfileRef>,
    bundle_end: usize,
    container_expected: bool,
    extension_point: bool,
    container_required: Option<Vec<u8>>,
    groups: bool,
    system_container: bool,
    system_groups: bool,
}

/// The exec's end: Sandbox kills it, with its message (the hook returns 1).
pub struct Kill(pub String);

impl Kernel {
    /// The current credential's sandbox.
    pub(crate) fn darwin_sandbox(&self) -> Option<Arc<Sandbox>> {
        of(&self.dtask.sandbox)
    }

    /// Set the current credential's sandbox (`mac_cred_label_update` of
    /// Sandbox's label).
    fn darwin_set_sandbox(&mut self, sb: Option<Arc<Sandbox>>) {
        *self.dtask.sandbox.lock().unwrap_or_else(|e| e.into_inner()) = sb;
    }

    /// A gap the hook meets: reported, and the exec killed.
    fn darwin_sb_unported(&mut self, what: String) -> Kill {
        self.darwin_unimplemented(what.clone());
        Kill(format!("not implemented: {what}"))
    }

    /// Sandbox's `mpo_cred_label_update_execve` (`0x...a0d20c`) for the
    /// exec of `ex`, its credential already the new image's: the profile
    /// chosen and the sandbox the credential takes, or the kill.
    pub(crate) fn darwin_sb_label_update_execve(&mut self, ex: &Exec<'_>) -> Result<(), Kill> {
        let path = ex.path.as_bytes();
        let sig = self.dtask.codesign.clone();
        let ents = sig.as_ref().map(|c| c.ents.clone()).unwrap_or_default();
        let sigid = sig.as_ref().and_then(|c| c.identity.clone());
        // amfi_copy_seatbelt_profile_names: the names, and whether the code
        // is trusted to be out of a container.
        let (names, trusted) = match &sig {
            Some(_) => super::amfi::seatbelt_profile_names(self.darwin_task_platform_binary(), &ents),
            None => (Ok(Vec::new()), false),
        };
        let Ok(names) = names else { return Err(Kill("amfi_copy_seatbelt_profile_names() failed".into())) };
        if !trusted && self.procs.ppid(self.pid) != 1 {
            return Err(Kill("only launchd is allowed to spawn untrusted binaries".into()));
        }
        if names.len() >= 2 {
            return Err(Kill("stacked profiles not supported".into()));
        }
        let mut s = Spec { profile: names.into_iter().next(), ..Spec::default() };
        // The spawn's attributes: a profile name and a container.
        let mut attrs = (None, None);
        if let Some(b) = ex.spawnattrs {
            attrs = spawnattrs(b).map_err(|()| Kill("invalid spawn attributes (err=22)".into()))?;
        }
        // The profiles the private entitlements carry.
        for key in ["com.apple.private.sandbox.profile", "com.apple.private.sandbox.profile:embedded"] {
            if ents.present(key.as_bytes()) {
                return Err(self.darwin_sb_unported(format!("Sandbox: the profile of the {key} entitlement ({})", ex.path)));
            }
        }
        if s.profile.is_none() {
            s.profile = attrs.0;
        }
        s.container = attrs.1;
        s.protobox = match protobox_for(path, &super::sysctl::os_release_type()) {
            Ok(p) => p,
            Err(Missing(what)) => return Err(self.darwin_sb_unported(what.into())),
        };
        // With no profile, process-exec-update-label of the vnode may name
        // one: with no sandbox carried over, the platform profile's; with
        // one, the sandbox is asked only for an exec its process-exec check
        // marked. A mark with no profile named leaves the exec to escape a
        // protobox sandbox (`sp+96` being 1).
        let inherited = self.darwin_sandbox();
        let mut escape = false;
        if s.profile.is_none() {
            escape = ex.marked;
            if inherited.is_none() || escape {
                let md = self.vfs.metadata(ex.path).map_err(|e| Kill(format!("failed to get executable path (err={})", e.0)))?;
                let a = SbArgs { kind: sandbox::kind::VNODE, vnode: Some(SbVnode::at(ex.path, 1, false, md.mode, 0)), ..Default::default() };
                if let (0, _, fx) = self.darwin_sb_evaluate_with(inherited.as_ref(), mac::op::PROCESS_EXEC_UPDATE_LABEL, &a) {
                    if fx.profile.is_some() {
                        s.profile = fx.profile;
                        escape = false;
                    }
                }
            }
        }
        let (end, nested) = bundle_end(path);
        s.bundle_end = end;
        s.extension_point = nested;
        // The container-required entitlement: a string names the container,
        // the boolean says, anything else expects one.
        if let Some(e) = ents.get(b"com.apple.private.security.container-required") {
            use super::codesign::Ent;
            match e {
                Ent::String(v) => {
                    s.container_required = Some(v.clone());
                    s.container_expected = true;
                }
                Ent::Bool(b) => s.container_expected = *b,
                _ => s.container_expected = true,
            }
        }
        // Only a protobox sandbox is escaped.
        if escape && !inherited.as_ref().is_some_and(|i| i.protoboxed()) {
            escape = false;
        }
        if let Some(p) = &s.profile {
            if EXTENSION_POINTS.contains(&p.as_slice()) {
                s.extension_point = true;
            }
        }
        if s.extension_point {
            s.container_expected = true;
        }
        if matches!(s.profile.as_deref(), Some(b"container2" | b"plugin")) {
            s.profile = Some(b"container".to_vec());
        }
        if escape {
            s.container_expected = false;
            s.container = None;
        }
        if s.profile.as_deref() == Some(b"container") {
            s.container_expected = true;
        }
        if s.container_expected {
            if s.profile.is_none() {
                s.profile = Some(b"container".to_vec());
            }
        } else if !trusted && self.dtask.platform.0 != 10 {
            return Err(Kill("outside of container && not a driver && !i_can_has_debugger".into()));
        }
        if s.profile.is_some() {
            self.darwin_sb_containers(&mut s, &ents);
            if (s.container.is_none() && s.container_expected) || s.groups || s.system_container || s.system_groups {
                if sigid.is_none() {
                    return Err(Kill("attempting to use a container without a code signing identity.".into()));
                }
                let named = s.container_required.as_deref().map_or(String::new(), |c| format!(" ({})", String::from_utf8_lossy(c)));
                return Err(self.darwin_sb_unported(format!("Sandbox's upcall to containermanagerd for the containers of {}{named}", ex.path)));
            }
        }
        let new = match s.profile.clone() {
            Some(name) => {
                let prof = match builtin(&name) {
                    Ok(Some(p)) => p,
                    Ok(None) => return Err(Kill("failed to assign builtin profile (err=22)".into())),
                    Err(Missing(what)) => return Err(self.darwin_sb_unported(what.into())),
                };
                Sandbox::new(prof, s.protobox).map_err(|Missing(what)| self.darwin_sb_unported(what.into()))?
            }
            // The escape: the platform profile's filtering and masks, and no
            // sandbox.
            None if escape => {
                self.dtask.filter_msg = false;
                self.darwin_sb_apply_masks(None);
                self.darwin_set_sandbox(None);
                return Ok(());
            }
            None => {
                if let Some(inh) = inherited {
                    // The carried sandbox, applied again.
                    self.darwin_sb_apply_masks(Some(&inh));
                    return Ok(());
                }
                match s.protobox {
                    Some(p) => Sandbox::new(p, None).map_err(|Missing(what)| self.darwin_sb_unported(what.into()))?,
                    None => {
                        self.darwin_sb_apply_masks(None);
                        return Ok(());
                    }
                }
            }
        };
        self.darwin_sb_attach(new, &s, ex, &ents)
    }

    /// The containers a profile's process asks for (`0x...a1b028`): the
    /// one expected from the user's containers, the application groups',
    /// the system container, the system groups'. Sandbox keeps those that
    /// containermanagerd registered (by calls not served here, each refused
    /// loudly), so none is found and each one asked for is marked missing.
    fn darwin_sb_containers(&mut self, s: &mut Spec, ents: &super::codesign::Entitlements) {
        let ustate = user_state(self.creds.uid());
        if s.container_expected && s.container.is_none() && ustate.is_none() {
            if self.trace {
                eprintln!("[gex:{}] Sandbox: missing user state for uid {}", self.pid, self.creds.uid());
            }
            return;
        }
        // Each group is walked with a user state only.
        if let Some(e) = ents.get(b"com.apple.security.application-groups") {
            s.groups = ustate.is_some() && !items(e).is_empty();
        }
        s.system_container = ents.bool_true(b"com.apple.security.system-container");
        let groups = ents.get(b"com.apple.security.system-groups").or_else(|| ents.get(b"com.apple.security.system-group-containers"));
        if let Some(e) = groups {
            s.system_groups = ustate.is_some() && !items(e).is_empty();
        }
    }

    /// The new sandbox's set up (`0x...a0dfa4`): its container, its
    /// executable's extension, its byte `+59`, the entitlements' extensions;
    /// then the credential takes it, the process's messages are filtered or
    /// not, and its masks apply.
    fn darwin_sb_attach(&mut self, mut sb: Sandbox, s: &Spec, ex: &Exec<'_>, ents: &super::codesign::Entitlements) -> Result<(), Kill> {
        if s.container_expected {
            sb.container_expected = true;
        }
        if let Some(c) = &s.container {
            return Err(self.darwin_sb_unported(format!("Sandbox: the container {} of {} (its com.apple.sandbox.container extension)", String::from_utf8_lossy(c), ex.path)));
        }
        // The executable's extension, for its bundle (or itself), which
        // must be found.
        let bundle = &ex.path[..s.bundle_end];
        if let Err(e) = self.vfs.metadata(bundle) {
            return Err(Kill(format!("failed to set executable path (err={})", e.0)));
        }
        sb.extensions.push(Extension { class: EXECUTABLE, path: bundle.as_bytes().to_vec() });
        sb.flag_3b = s.extension_point;
        // Each item of the entitlements' (walked with a user state only).
        if !sb.protoboxed() && user_state(self.creds.uid()).is_some() {
            if let Some(key) = EXTENSION_ENTITLEMENTS.iter().find(|k| ents.get(k.as_bytes()).is_some_and(|e| !items(e).is_empty())) {
                return Err(self.darwin_sb_unported(format!("Sandbox: the extensions the {key} entitlement issues ({})", ex.path)));
            }
        }
        if self.trace {
            let name = if sb.protoboxed() { "(apply-protobox)".into() } else { String::from_utf8_lossy(sb.profile.name()).into_owned() };
            eprintln!("[gex:{}] Sandbox: {}[{}] ==> {name}", self.pid, ex.path, self.pid);
        }
        // Filtered when its profile says, unless translated (never on iOS),
        // or when the platform profile says (its flags are 0).
        let filter = sb.profile.flags() & 0x1000 != 0;
        let sb = Arc::new(sb);
        self.darwin_set_sandbox(Some(Arc::clone(&sb)));
        self.dtask.filter_msg = filter;
        self.darwin_sb_apply_masks(Some(&sb));
        Ok(())
    }

    /// `0x...9f5cdc`: the process's Unix call mask, and its task's Mach trap
    /// and kernel MIG routine masks (`proc_set_syscall_filter_mask`, each
    /// of the size the kernel gives it, so none is refused): its sandbox's,
    /// or with none the platform profile's.
    fn darwin_sb_apply_masks(&mut self, sb: Option<&Sandbox>) {
        let [unix, mach, kobj, _] = match sb {
            Some(sb) => sb.masks.clone(),
            None => mac::platform_masks(),
        };
        self.dtask.syscall_mask = unix;
        self.dtask.mach_trap_mask = mach;
        self.dtask.kobj_mask = kobj;
    }

    /// `mpo_proc_notify_exec_complete` (`0x...9fa188`): a driver extension
    /// with no sandbox is killed.
    pub(crate) fn darwin_sb_exec_complete(&mut self) -> Result<(), String> {
        if self.dtask.platform.0 == 10 && self.darwin_sandbox().is_none() {
            return Err("driver extensions must be sandboxed".into());
        }
        Ok(())
    }

    /// The policy's call 1 (`0x...a00e00`): `{name, container, length}`, a
    /// builtin profile for the caller, which must have no sandbox yet.
    pub(crate) fn darwin_sb_apply_builtin(&mut self, m: &mut crate::GuestMem<'_>, arg: u64) -> Result<(), i32> {
        const EPERM: i32 = 1;
        const EINVAL: i32 = 22;
        const ENOTSUP: i32 = 45;
        const ENAMETOOLONG: i32 = 63;
        if self.darwin_sandbox().is_some() {
            self.darwin_sb_report("forbidden-sandbox-reinit");
            return Err(EPERM);
        }
        let fault = |_| 14;
        let (name_at, container_at, container_len) = (m.read_u64(arg).map_err(fault)?, m.read_u64(arg + 8).map_err(fault)?, m.read_u64(arg + 16).map_err(fault)?);
        let mut buf = vec![0u8; 1024];
        let name = match m.read_cstr_into(name_at, &mut buf).map_err(fault)? {
            Some(n) => buf[..n].to_vec(),
            None => return Err(ENAMETOOLONG),
        };
        if name.first() == Some(&b'/') {
            return Err(ENOTSUP);
        }
        let prof = match builtin(&name) {
            Ok(Some(p)) => p,
            Ok(None) => return Err(EINVAL),
            Err(Missing(what)) => {
                self.darwin_unimplemented(what.into());
                return Err(EPERM);
            }
        };
        // A profile that stacks a protobox profile takes the executable's.
        let protobox = if prof.flags() & 4 != 0 {
            let exe = self.vfs.canonical(&self.vfs.absolute(&self.exe_path.clone()));
            match protobox_for(exe.as_bytes(), &super::sysctl::os_release_type()) {
                Ok(p) => p,
                Err(Missing(what)) => {
                    self.darwin_unimplemented(what.into());
                    return Err(EPERM);
                }
            }
        } else {
            None
        };
        let sb = match Sandbox::new(prof, protobox) {
            Ok(sb) => sb,
            Err(Missing(what)) => {
                self.darwin_unimplemented(what.into());
                return Err(EPERM);
            }
        };
        if container_len != 0 {
            let mut c = vec![0u8; container_len as usize];
            let Some(n) = m.read_cstr_into(container_at, &mut c).map_err(fault)? else { return Err(ENAMETOOLONG) };
            self.darwin_unimplemented(format!("Sandbox: sandbox_init's container {} (its com.apple.sandbox.container extension)", String::from_utf8_lossy(&c[..n])));
            return Err(EPERM);
        }
        self.darwin_sb_apply_process(sb)
    }

    /// `0x...9f59c8`: the credential takes the sandbox; its host port is
    /// revoked when the sandbox denies mach-priv-host-port; its messages
    /// are filtered when its profile says; its masks apply.
    fn darwin_sb_apply_process(&mut self, sb: Sandbox) -> Result<(), i32> {
        let sb = Arc::new(sb);
        self.darwin_set_sandbox(Some(Arc::clone(&sb)));
        // mach-priv-host-port, quietly: a denial makes the task's host port
        // the host's (`task_set_special_port(TASK_HOST_PORT)`), which is
        // what the task's host port answers from now on (kobject.rs).
        let a = SbArgs { quiet: true, ..Default::default() };
        self.darwin_sb_evaluate_with(Some(&sb), mac::op::MACH_PRIV_HOST_PORT, &a);
        self.dtask.filter_msg = sb.profile.flags() & 0x1000 != 0;
        self.darwin_sb_apply_masks(Some(&sb));
        if self.trace {
            eprintln!("[gex:{}] Sandbox apply: {}[{}] {}", self.pid, self.exe_path, self.pid, String::from_utf8_lossy(sb.profile.name()));
        }
        Ok(())
    }

    /// The policy's call 22 (`0x...a155e4`): `{name}`: 0 when a builtin
    /// profile is named so, ENOENT when none is.
    pub(crate) fn darwin_sb_builtin_exists(&mut self, m: &mut crate::GuestMem<'_>, arg: u64) -> Result<(), i32> {
        let fault = |_| 14;
        let at = m.read_u64(arg).map_err(fault)?;
        let mut buf = [0u8; 255];
        let Some(n) = m.read_cstr_into(at, &mut buf).map_err(fault)? else { return Err(63) };
        match builtin(&buf[..n]) {
            Ok(Some(_)) => Ok(()),
            Ok(None) => Err(2),
            Err(Missing(what)) => {
                self.darwin_unimplemented(what.into());
                Err(2)
            }
        }
    }

    /// A violation of a forbidden pseudo-operation (`0x...9f4ca4`, kind 3),
    /// to the kernel's log.
    pub(crate) fn darwin_sb_report(&self, what: &str) {
        if self.trace {
            eprintln!("[gex:{}] Sandbox: {}({}) deny(1) {what}", self.pid, self.exe_path, self.pid);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sandboxs_masks_combine_its_profiles_with_the_platforms() {
        let m = |bytes: &[u8]| {
            let mut a = [0u8; sandbox::MASK_BYTES];
            a[..bytes.len()].copy_from_slice(bytes);
            sandbox::mask_of(a)
        };
        let (prof, pb, plat) = (m(&[0b0011]), m(&[0b0101]), m(&[0b0110]));
        // No mask anywhere: none; the platform's alone: the platform's.
        assert!(combine(false, None, None, None).is_none());
        assert!(combine(false, None, None, Some(&plat)).is_some_and(|x| Arc::ptr_eq(&x, &plat)));
        // Its own and-ed with the platform's, or alone.
        let first = |m: Option<sandbox::FilterMask>| sandbox::mask_bytes(&m.unwrap())[0];
        assert_eq!(first(combine(false, Some(&prof), Some(&pb), Some(&plat))), 0b0010);
        assert_eq!(first(combine(false, Some(&prof), None, None)), 0b0011);
        // Deferring: or-ed with the protobox profile's first; with none
        // stacked, its own does not count.
        assert_eq!(first(combine(true, Some(&prof), Some(&pb), Some(&plat))), 0b0110);
        assert!(combine(true, Some(&prof), None, Some(&plat)).is_some_and(|x| Arc::ptr_eq(&x, &plat)));
        assert!(combine(true, Some(&prof), None, None).is_none());
    }

    #[test]
    fn kernel_mig_routines_have_sandboxs_indexes() {
        assert_eq!(kobj_index(200), Some(0));
        assert_eq!(kobj_index(2405), Some(54));
        assert_eq!(kobj_index(600), None);
        assert_eq!(kobj_index(3201), KOBJ_IDS.iter().position(|&k| k == 3201));
        assert_eq!(kobj_index(9999), None);
    }

    #[test]
    fn a_bundles_end_is_found_from_the_paths_end() {
        assert_eq!(bundle_end(b"/private/var/tmp/x"), (18, false));
        assert_eq!(bundle_end(b"/Applications/Maps.app/Maps"), (22, false));
        assert_eq!(bundle_end(b"/System/Library/Frameworks/X.framework/XPCServices/Y.xpc/Y"), (56, false));
        // An app extension in an app's PlugIns: the app's bundle, an
        // extension point's.
        let p = b"/private/var/containers/Bundle/Application/U/A.app/PlugIns/E.appex/E";
        let app = p.windows(6).position(|w| w == b"A.app/").unwrap() + 5;
        assert_eq!(bundle_end(p), (app, true));
        // One alone is its own bundle.
        let q = b"/x/E.appex/E";
        assert_eq!(bundle_end(q), (10, false));
    }

    #[test]
    fn spawn_attributes_are_checked_and_read() {
        let mut b = vec![0u8; 1104];
        b[4..8].copy_from_slice(&1104u32.to_le_bytes());
        b[8..12].copy_from_slice(&9u32.to_le_bytes());
        b[16..25].copy_from_slice(b"container");
        assert_eq!(spawnattrs(&b), Ok((Some(b"container".to_vec()), None)));
        b[12..16].copy_from_slice(&4u32.to_le_bytes());
        b[80..84].copy_from_slice(b"/c/d");
        assert_eq!(spawnattrs(&b), Ok((Some(b"container".to_vec()), Some(b"/c/d".to_vec()))));
        b[8..12].copy_from_slice(&64u32.to_le_bytes());
        assert_eq!(spawnattrs(&b), Err(()));
        assert_eq!(spawnattrs(&b[..1103]), Err(()));
    }

    #[test]
    fn an_entitlements_items() {
        use super::super::codesign::Ent;
        assert_eq!(items(&Ent::Bool(true)), vec![b"true".to_vec()]);
        assert!(items(&Ent::Bool(false)).is_empty());
        let a = Ent::Array(vec![Ent::String(b"a".to_vec()), Ent::Int(1), Ent::String(b"b".to_vec())]);
        assert_eq!(items(&a), vec![b"a".to_vec()]);
    }
}
