//! AMFI's launch constraints (`mpo_proc_check_launch_constraints`, the hook
//! at `0xfffffff005ab167c` in iOS 17.7.11's AppleMobileFileIntegrity; XNU
//! calls it from `process_signature` through
//! `mac_proc_check_launch_constraints`).
//!
//! A launch is judged on three processes: the one launched, the one that
//! forked it (`p_original_ppid`), and the one responsible for it
//! (`p_responsible_pid`). Each has its facts, the system's and the
//! launch's. What constrains them, in this order (`0xfffffff005ab2634`):
//!
//! - the launch type a spawn asked for, which only some parents may ask
//!   for;
//! - an AMFI constraint the spawn passed (its MAC extension named `AMFI`),
//!   which only platform code may pass;
//! - the constraint category of the image's trust cache entry, which names
//!   what the image and its parent must be ([`cc_self`], [`cc_parent`]);
//! - the image's own constraints on itself, its parent and its responsible
//!   process (code signature slots 8, 9 and 10);
//! - what the launch type requires of the categories met.
//!
//! A violation is logged; an enforced one fails the launch with a
//! description, which XNU puts in the process's exit reason
//! (`OS_REASON_CODESIGNING`, `CODESIGNING_EXIT_REASON_LAUNCH_CONSTRAINT_VIOLATION`)
//! as it kills it. A release kernel enforces every category type
//! (`launch_constraints_enforced` 1, `launch_constraints_cc_types_enforced`
//! 0xf, third-party constraints refused: `0xfffffff005aae84c` reads no
//! boot-arg it acts on).

use super::codesign::{CodeSign, Ent};
use super::lwcr::{self, Fact, Facts, Value, Verdict};
use std::sync::Arc;

/// `CS_LAUNCH_TYPE_*`.
pub mod launch_type {
    pub const NONE: u8 = 0;
    pub const SYSTEM_SERVICE: u8 = 1;
    pub const SYSDIAGNOSE: u8 = 2;
    pub const APPLICATION: u8 = 3;
}

/// What a spawn gave the hook: its attributes' launch type
/// (`psa_launch_type`) and the data of its MAC extension named `AMFI`.
#[derive(Clone, Debug, Default)]
pub struct Spawn {
    pub launch_type: u8,
    pub amfi: Option<Vec<u8>>,
}

// The category tables (`0xfffffff005aaccd0`, `0xfffffff005aacf1c`): each
// entry a CoreEntitlements dictionary of requirements.

/// `0xfffffff0052e4ff3`, 119 bytes.
const CC_E4FF3: &[u8] = &[
    0x70, 0x75, 0x02, 0x01, 0x01, 0xb0, 0x70, 0x30, 0x42, 0x0c, 0x03, 0x24, 0x6f, 0x72, 0xb0, 0x3b,
    0x30, 0x22, 0x0c, 0x1d, 0x6f, 0x6e, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65,
    0x64, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x61, 0x70, 0x66, 0x73, 0x2d, 0x76, 0x6f, 0x6c, 0x75, 0x6d,
    0x65, 0x01, 0x01, 0xff, 0x30, 0x15, 0x0c, 0x10, 0x6f, 0x6e, 0x2d, 0x73, 0x79, 0x73, 0x74, 0x65,
    0x6d, 0x2d, 0x76, 0x6f, 0x6c, 0x75, 0x6d, 0x65, 0x01, 0x01, 0xff, 0x30, 0x10, 0x0c, 0x0b, 0x6c,
    0x61, 0x75, 0x6e, 0x63, 0x68, 0x2d, 0x74, 0x79, 0x70, 0x65, 0x02, 0x01, 0x01, 0x30, 0x18, 0x0c,
    0x13, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2d, 0x63, 0x61, 0x74, 0x65,
    0x67, 0x6f, 0x72, 0x79, 0x02, 0x01, 0x01,
];
/// `0xfffffff0052e506a`, 75 bytes.
const CC_E506A: &[u8] = &[
    0x70, 0x49, 0x02, 0x01, 0x01, 0xb0, 0x44, 0x30, 0x42, 0x0c, 0x03, 0x24, 0x6f, 0x72, 0xb0, 0x3b,
    0x30, 0x22, 0x0c, 0x1d, 0x6f, 0x6e, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65,
    0x64, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x61, 0x70, 0x66, 0x73, 0x2d, 0x76, 0x6f, 0x6c, 0x75, 0x6d,
    0x65, 0x01, 0x01, 0xff, 0x30, 0x15, 0x0c, 0x10, 0x6f, 0x6e, 0x2d, 0x73, 0x79, 0x73, 0x74, 0x65,
    0x6d, 0x2d, 0x76, 0x6f, 0x6c, 0x75, 0x6d, 0x65, 0x01, 0x01, 0xff,
];
/// `0xfffffff0052e50b5`, 134 bytes.
const CC_E50B5: &[u8] = &[
    0x70, 0x81, 0x83, 0x02, 0x01, 0x01, 0xb0, 0x7e, 0x30, 0x42, 0x0c, 0x03, 0x24, 0x6f, 0x72, 0xb0,
    0x3b, 0x30, 0x22, 0x0c, 0x1d, 0x6f, 0x6e, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a,
    0x65, 0x64, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x61, 0x70, 0x66, 0x73, 0x2d, 0x76, 0x6f, 0x6c, 0x75,
    0x6d, 0x65, 0x01, 0x01, 0xff, 0x30, 0x15, 0x0c, 0x10, 0x6f, 0x6e, 0x2d, 0x73, 0x79, 0x73, 0x74,
    0x65, 0x6d, 0x2d, 0x76, 0x6f, 0x6c, 0x75, 0x6d, 0x65, 0x01, 0x01, 0xff, 0x30, 0x1e, 0x0c, 0x0b,
    0x6c, 0x61, 0x75, 0x6e, 0x63, 0x68, 0x2d, 0x74, 0x79, 0x70, 0x65, 0xb0, 0x0f, 0x30, 0x0d, 0x0c,
    0x03, 0x24, 0x69, 0x6e, 0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01, 0x30, 0x18, 0x0c, 0x13,
    0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2d, 0x63, 0x61, 0x74, 0x65, 0x67,
    0x6f, 0x72, 0x79, 0x02, 0x01, 0x01,
];
/// `0xfffffff0052e513b`, 134 bytes.
const CC_E513B: &[u8] = &[
    0x70, 0x81, 0x83, 0x02, 0x01, 0x01, 0xb0, 0x7e, 0x30, 0x42, 0x0c, 0x03, 0x24, 0x6f, 0x72, 0xb0,
    0x3b, 0x30, 0x22, 0x0c, 0x1d, 0x6f, 0x6e, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a,
    0x65, 0x64, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x61, 0x70, 0x66, 0x73, 0x2d, 0x76, 0x6f, 0x6c, 0x75,
    0x6d, 0x65, 0x01, 0x01, 0xff, 0x30, 0x15, 0x0c, 0x10, 0x6f, 0x6e, 0x2d, 0x73, 0x79, 0x73, 0x74,
    0x65, 0x6d, 0x2d, 0x76, 0x6f, 0x6c, 0x75, 0x6d, 0x65, 0x01, 0x01, 0xff, 0x30, 0x1e, 0x0c, 0x0b,
    0x6c, 0x61, 0x75, 0x6e, 0x63, 0x68, 0x2d, 0x74, 0x79, 0x70, 0x65, 0xb0, 0x0f, 0x30, 0x0d, 0x0c,
    0x03, 0x24, 0x69, 0x6e, 0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01, 0x30, 0x18, 0x0c, 0x13,
    0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2d, 0x63, 0x61, 0x74, 0x65, 0x67,
    0x6f, 0x72, 0x79, 0x02, 0x01, 0x01,
];
/// `0xfffffff0052e51c1`, 33 bytes.
const CC_E51C1: &[u8] = &[
    0x70, 0x1f, 0x02, 0x01, 0x01, 0xb0, 0x1a, 0x30, 0x18, 0x0c, 0x13, 0x76, 0x61, 0x6c, 0x69, 0x64,
    0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2d, 0x63, 0x61, 0x74, 0x65, 0x67, 0x6f, 0x72, 0x79, 0x02, 0x01,
    0x01,
];
/// `0xfffffff0052e51e2`, 181 bytes.
const CC_E51E2: &[u8] = &[
    0x70, 0x81, 0xb2, 0x02, 0x01, 0x01, 0xb0, 0x81, 0xac, 0x30, 0x7e, 0x0c, 0x03, 0x24, 0x6f, 0x72,
    0xb0, 0x77, 0x30, 0x23, 0x0c, 0x1e, 0x69, 0x6e, 0x2d, 0x74, 0x63, 0x2d, 0x77, 0x69, 0x74, 0x68,
    0x2d, 0x63, 0x6f, 0x6e, 0x73, 0x74, 0x72, 0x61, 0x69, 0x6e, 0x74, 0x2d, 0x63, 0x61, 0x74, 0x65,
    0x67, 0x6f, 0x72, 0x79, 0x01, 0x01, 0x00, 0x30, 0x15, 0x0c, 0x10, 0x69, 0x73, 0x2d, 0x73, 0x69,
    0x70, 0x2d, 0x70, 0x72, 0x6f, 0x74, 0x65, 0x63, 0x74, 0x65, 0x64, 0x01, 0x01, 0xff, 0x30, 0x22,
    0x0c, 0x1d, 0x6f, 0x6e, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x64, 0x2d,
    0x61, 0x75, 0x74, 0x68, 0x61, 0x70, 0x66, 0x73, 0x2d, 0x76, 0x6f, 0x6c, 0x75, 0x6d, 0x65, 0x01,
    0x01, 0xff, 0x30, 0x15, 0x0c, 0x10, 0x6f, 0x6e, 0x2d, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x2d,
    0x76, 0x6f, 0x6c, 0x75, 0x6d, 0x65, 0x01, 0x01, 0xff, 0x30, 0x10, 0x0c, 0x0b, 0x6c, 0x61, 0x75,
    0x6e, 0x63, 0x68, 0x2d, 0x74, 0x79, 0x70, 0x65, 0x02, 0x01, 0x01, 0x30, 0x18, 0x0c, 0x13, 0x76,
    0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2d, 0x63, 0x61, 0x74, 0x65, 0x67, 0x6f,
    0x72, 0x79, 0x02, 0x01, 0x01,
];
/// `0xfffffff0052e5297`, 33 bytes.
const CC_E5297: &[u8] = &[
    0x70, 0x1f, 0x02, 0x01, 0x01, 0xb0, 0x1a, 0x30, 0x18, 0x0c, 0x13, 0x76, 0x61, 0x6c, 0x69, 0x64,
    0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2d, 0x63, 0x61, 0x74, 0x65, 0x67, 0x6f, 0x72, 0x79, 0x02, 0x01,
    0x01,
];
/// `0xfffffff0052e52b8`, 119 bytes.
const CC_E52B8: &[u8] = &[
    0x70, 0x75, 0x02, 0x01, 0x01, 0xb0, 0x70, 0x30, 0x42, 0x0c, 0x03, 0x24, 0x6f, 0x72, 0xb0, 0x3b,
    0x30, 0x22, 0x0c, 0x1d, 0x6f, 0x6e, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65,
    0x64, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x61, 0x70, 0x66, 0x73, 0x2d, 0x76, 0x6f, 0x6c, 0x75, 0x6d,
    0x65, 0x01, 0x01, 0xff, 0x30, 0x15, 0x0c, 0x10, 0x6f, 0x6e, 0x2d, 0x73, 0x79, 0x73, 0x74, 0x65,
    0x6d, 0x2d, 0x76, 0x6f, 0x6c, 0x75, 0x6d, 0x65, 0x01, 0x01, 0xff, 0x30, 0x10, 0x0c, 0x0b, 0x6c,
    0x61, 0x75, 0x6e, 0x63, 0x68, 0x2d, 0x74, 0x79, 0x70, 0x65, 0x02, 0x01, 0x02, 0x30, 0x18, 0x0c,
    0x13, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2d, 0x63, 0x61, 0x74, 0x65,
    0x67, 0x6f, 0x72, 0x79, 0x02, 0x01, 0x01,
];
/// `0xfffffff0052e532f`, 219 bytes.
const CC_E532F: &[u8] = &[
    0x70, 0x81, 0xd8, 0x02, 0x01, 0x01, 0xb0, 0x81, 0xd2, 0x30, 0x81, 0x95, 0x0c, 0x0a, 0x24, 0x61,
    0x6e, 0x64, 0x2d, 0x61, 0x72, 0x72, 0x61, 0x79, 0x30, 0x81, 0x86, 0x30, 0x40, 0x0c, 0x03, 0x24,
    0x6f, 0x72, 0xb0, 0x39, 0x30, 0x13, 0x0c, 0x0e, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x2d, 0x69, 0x6e,
    0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x01, 0x01, 0xff, 0x30, 0x22, 0x0c, 0x0e, 0x6f, 0x73, 0x2d,
    0x65, 0x6e, 0x76, 0x69, 0x72, 0x6f, 0x6e, 0x6d, 0x65, 0x6e, 0x74, 0x0c, 0x10, 0x64, 0x61, 0x72,
    0x77, 0x69, 0x6e, 0x6f, 0x73, 0x2d, 0x72, 0x61, 0x6d, 0x64, 0x69, 0x73, 0x6b, 0x30, 0x42, 0x0c,
    0x03, 0x24, 0x6f, 0x72, 0xb0, 0x3b, 0x30, 0x22, 0x0c, 0x1d, 0x6f, 0x6e, 0x2d, 0x61, 0x75, 0x74,
    0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x64, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x61, 0x70, 0x66, 0x73,
    0x2d, 0x76, 0x6f, 0x6c, 0x75, 0x6d, 0x65, 0x01, 0x01, 0xff, 0x30, 0x15, 0x0c, 0x10, 0x6f, 0x6e,
    0x2d, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x2d, 0x76, 0x6f, 0x6c, 0x75, 0x6d, 0x65, 0x01, 0x01,
    0xff, 0x30, 0x1e, 0x0c, 0x0b, 0x6c, 0x61, 0x75, 0x6e, 0x63, 0x68, 0x2d, 0x74, 0x79, 0x70, 0x65,
    0xb0, 0x0f, 0x30, 0x0d, 0x0c, 0x03, 0x24, 0x69, 0x6e, 0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01,
    0x02, 0x30, 0x18, 0x0c, 0x13, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2d,
    0x63, 0x61, 0x74, 0x65, 0x67, 0x6f, 0x72, 0x79, 0x02, 0x01, 0x01,
];
/// `0xfffffff0052e540a`, 134 bytes.
const CC_E540A: &[u8] = &[
    0x70, 0x81, 0x83, 0x02, 0x01, 0x01, 0xb0, 0x7e, 0x30, 0x42, 0x0c, 0x03, 0x24, 0x6f, 0x72, 0xb0,
    0x3b, 0x30, 0x22, 0x0c, 0x1d, 0x6f, 0x6e, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a,
    0x65, 0x64, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x61, 0x70, 0x66, 0x73, 0x2d, 0x76, 0x6f, 0x6c, 0x75,
    0x6d, 0x65, 0x01, 0x01, 0xff, 0x30, 0x15, 0x0c, 0x10, 0x6f, 0x6e, 0x2d, 0x73, 0x79, 0x73, 0x74,
    0x65, 0x6d, 0x2d, 0x76, 0x6f, 0x6c, 0x75, 0x6d, 0x65, 0x01, 0x01, 0xff, 0x30, 0x1e, 0x0c, 0x0b,
    0x6c, 0x61, 0x75, 0x6e, 0x63, 0x68, 0x2d, 0x74, 0x79, 0x70, 0x65, 0xb0, 0x0f, 0x30, 0x0d, 0x0c,
    0x03, 0x24, 0x69, 0x6e, 0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x02, 0x30, 0x18, 0x0c, 0x13,
    0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2d, 0x63, 0x61, 0x74, 0x65, 0x67,
    0x6f, 0x72, 0x79, 0x02, 0x01, 0x01,
];
/// `0xfffffff0052e5490`, 101 bytes.
const CC_E5490: &[u8] = &[
    0x70, 0x63, 0x02, 0x01, 0x01, 0xb0, 0x5e, 0x30, 0x42, 0x0c, 0x03, 0x24, 0x6f, 0x72, 0xb0, 0x3b,
    0x30, 0x22, 0x0c, 0x1d, 0x6f, 0x6e, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65,
    0x64, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x61, 0x70, 0x66, 0x73, 0x2d, 0x76, 0x6f, 0x6c, 0x75, 0x6d,
    0x65, 0x01, 0x01, 0xff, 0x30, 0x15, 0x0c, 0x10, 0x6f, 0x6e, 0x2d, 0x73, 0x79, 0x73, 0x74, 0x65,
    0x6d, 0x2d, 0x76, 0x6f, 0x6c, 0x75, 0x6d, 0x65, 0x01, 0x01, 0xff, 0x30, 0x18, 0x0c, 0x13, 0x76,
    0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2d, 0x63, 0x61, 0x74, 0x65, 0x67, 0x6f,
    0x72, 0x79, 0x02, 0x01, 0x01,
];
/// `0xfffffff0052e54f5`, 138 bytes.
const CC_E54F5: &[u8] = &[
    0x70, 0x81, 0x87, 0x02, 0x01, 0x01, 0xb0, 0x81, 0x81, 0x30, 0x42, 0x0c, 0x03, 0x24, 0x6f, 0x72,
    0xb0, 0x3b, 0x30, 0x22, 0x0c, 0x1d, 0x6f, 0x6e, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69,
    0x7a, 0x65, 0x64, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x61, 0x70, 0x66, 0x73, 0x2d, 0x76, 0x6f, 0x6c,
    0x75, 0x6d, 0x65, 0x01, 0x01, 0xff, 0x30, 0x15, 0x0c, 0x10, 0x6f, 0x6e, 0x2d, 0x73, 0x79, 0x73,
    0x74, 0x65, 0x6d, 0x2d, 0x76, 0x6f, 0x6c, 0x75, 0x6d, 0x65, 0x01, 0x01, 0xff, 0x30, 0x21, 0x0c,
    0x0b, 0x6c, 0x61, 0x75, 0x6e, 0x63, 0x68, 0x2d, 0x74, 0x79, 0x70, 0x65, 0xb0, 0x12, 0x30, 0x10,
    0x0c, 0x03, 0x24, 0x69, 0x6e, 0x30, 0x09, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02,
    0x30, 0x18, 0x0c, 0x13, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2d, 0x63,
    0x61, 0x74, 0x65, 0x67, 0x6f, 0x72, 0x79, 0x02, 0x01, 0x01,
];
/// `0xfffffff0052e557f`, 65 bytes.
const CC_E557F: &[u8] = &[
    0x70, 0x3f, 0x02, 0x01, 0x01, 0xb0, 0x3a, 0x30, 0x1e, 0x0c, 0x0b, 0x6c, 0x61, 0x75, 0x6e, 0x63,
    0x68, 0x2d, 0x74, 0x79, 0x70, 0x65, 0xb0, 0x0f, 0x30, 0x0d, 0x0c, 0x03, 0x24, 0x69, 0x6e, 0x30,
    0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x02, 0x30, 0x18, 0x0c, 0x13, 0x76, 0x61, 0x6c, 0x69, 0x64,
    0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2d, 0x63, 0x61, 0x74, 0x65, 0x67, 0x6f, 0x72, 0x79, 0x02, 0x01,
    0x01,
];
/// `0xfffffff0052e55c0`, 119 bytes.
const CC_E55C0: &[u8] = &[
    0x70, 0x75, 0x02, 0x01, 0x01, 0xb0, 0x70, 0x30, 0x42, 0x0c, 0x03, 0x24, 0x6f, 0x72, 0xb0, 0x3b,
    0x30, 0x22, 0x0c, 0x1d, 0x6f, 0x6e, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65,
    0x64, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x61, 0x70, 0x66, 0x73, 0x2d, 0x76, 0x6f, 0x6c, 0x75, 0x6d,
    0x65, 0x01, 0x01, 0xff, 0x30, 0x15, 0x0c, 0x10, 0x6f, 0x6e, 0x2d, 0x73, 0x79, 0x73, 0x74, 0x65,
    0x6d, 0x2d, 0x76, 0x6f, 0x6c, 0x75, 0x6d, 0x65, 0x01, 0x01, 0xff, 0x30, 0x10, 0x0c, 0x0b, 0x6c,
    0x61, 0x75, 0x6e, 0x63, 0x68, 0x2d, 0x74, 0x79, 0x70, 0x65, 0x02, 0x01, 0x03, 0x30, 0x18, 0x0c,
    0x13, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2d, 0x63, 0x61, 0x74, 0x65,
    0x67, 0x6f, 0x72, 0x79, 0x02, 0x01, 0x01,
];
/// `0xfffffff0052e5637`, 134 bytes.
const CC_E5637: &[u8] = &[
    0x70, 0x81, 0x83, 0x02, 0x01, 0x01, 0xb0, 0x7e, 0x30, 0x42, 0x0c, 0x03, 0x24, 0x6f, 0x72, 0xb0,
    0x3b, 0x30, 0x22, 0x0c, 0x1d, 0x6f, 0x6e, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a,
    0x65, 0x64, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x61, 0x70, 0x66, 0x73, 0x2d, 0x76, 0x6f, 0x6c, 0x75,
    0x6d, 0x65, 0x01, 0x01, 0xff, 0x30, 0x15, 0x0c, 0x10, 0x6f, 0x6e, 0x2d, 0x73, 0x79, 0x73, 0x74,
    0x65, 0x6d, 0x2d, 0x76, 0x6f, 0x6c, 0x75, 0x6d, 0x65, 0x01, 0x01, 0xff, 0x30, 0x1e, 0x0c, 0x0b,
    0x6c, 0x61, 0x75, 0x6e, 0x63, 0x68, 0x2d, 0x74, 0x79, 0x70, 0x65, 0xb0, 0x0f, 0x30, 0x0d, 0x0c,
    0x03, 0x24, 0x69, 0x6e, 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x03, 0x30, 0x18, 0x0c, 0x13,
    0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2d, 0x63, 0x61, 0x74, 0x65, 0x67,
    0x6f, 0x72, 0x79, 0x02, 0x01, 0x01,
];
/// `0xfffffff0052e56bd`, 51 bytes.
const CC_E56BD: &[u8] = &[
    0x70, 0x31, 0x02, 0x01, 0x01, 0xb0, 0x2c, 0x30, 0x10, 0x0c, 0x0b, 0x6c, 0x61, 0x75, 0x6e, 0x63,
    0x68, 0x2d, 0x74, 0x79, 0x70, 0x65, 0x02, 0x01, 0x03, 0x30, 0x18, 0x0c, 0x13, 0x76, 0x61, 0x6c,
    0x69, 0x64, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2d, 0x63, 0x61, 0x74, 0x65, 0x67, 0x6f, 0x72, 0x79,
    0x02, 0x01, 0x01,
];
/// `0xfffffff0052e56f0`, 186 bytes.
const CC_E56F0: &[u8] = &[
    0x70, 0x81, 0xb7, 0x02, 0x01, 0x01, 0xb0, 0x81, 0xb1, 0x30, 0x81, 0x9c, 0x0c, 0x03, 0x24, 0x6f,
    0x72, 0xb0, 0x81, 0x94, 0x30, 0x7d, 0x0c, 0x04, 0x24, 0x61, 0x6e, 0x64, 0xb0, 0x75, 0x30, 0x59,
    0x0c, 0x03, 0x24, 0x6f, 0x72, 0xb0, 0x52, 0x30, 0x15, 0x0c, 0x10, 0x69, 0x73, 0x2d, 0x73, 0x69,
    0x70, 0x2d, 0x70, 0x72, 0x6f, 0x74, 0x65, 0x63, 0x74, 0x65, 0x64, 0x01, 0x01, 0xff, 0x30, 0x22,
    0x0c, 0x1d, 0x6f, 0x6e, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x64, 0x2d,
    0x61, 0x75, 0x74, 0x68, 0x61, 0x70, 0x66, 0x73, 0x2d, 0x76, 0x6f, 0x6c, 0x75, 0x6d, 0x65, 0x01,
    0x01, 0xff, 0x30, 0x15, 0x0c, 0x10, 0x6f, 0x6e, 0x2d, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x2d,
    0x76, 0x6f, 0x6c, 0x75, 0x6d, 0x65, 0x01, 0x01, 0xff, 0x30, 0x18, 0x0c, 0x13, 0x76, 0x61, 0x6c,
    0x69, 0x64, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2d, 0x63, 0x61, 0x74, 0x65, 0x67, 0x6f, 0x72, 0x79,
    0x02, 0x01, 0x01, 0x30, 0x13, 0x0c, 0x0e, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x2d, 0x69, 0x6e, 0x74,
    0x65, 0x72, 0x6e, 0x61, 0x6c, 0x01, 0x01, 0xff, 0x30, 0x10, 0x0c, 0x0b, 0x6c, 0x61, 0x75, 0x6e,
    0x63, 0x68, 0x2d, 0x74, 0x79, 0x70, 0x65, 0x02, 0x01, 0x02,
];
/// `0xfffffff0052e57aa`, 122 bytes.
const CC_E57AA: &[u8] = &[
    0x70, 0x78, 0x02, 0x01, 0x01, 0xb0, 0x73, 0x30, 0x42, 0x0c, 0x03, 0x24, 0x6f, 0x72, 0xb0, 0x3b,
    0x30, 0x22, 0x0c, 0x1d, 0x6f, 0x6e, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65,
    0x64, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x61, 0x70, 0x66, 0x73, 0x2d, 0x76, 0x6f, 0x6c, 0x75, 0x6d,
    0x65, 0x01, 0x01, 0xff, 0x30, 0x15, 0x0c, 0x10, 0x6f, 0x6e, 0x2d, 0x73, 0x79, 0x73, 0x74, 0x65,
    0x6d, 0x2d, 0x76, 0x6f, 0x6c, 0x75, 0x6d, 0x65, 0x01, 0x01, 0xff, 0x30, 0x13, 0x0c, 0x0e, 0x64,
    0x65, 0x76, 0x65, 0x6c, 0x6f, 0x70, 0x65, 0x72, 0x2d, 0x6d, 0x6f, 0x64, 0x65, 0x01, 0x01, 0xff,
    0x30, 0x18, 0x0c, 0x13, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2d, 0x63,
    0x61, 0x74, 0x65, 0x67, 0x6f, 0x72, 0x79, 0x02, 0x01, 0x01,
];
/// `0xfffffff0052e5824`, 138 bytes.
const CC_E5824: &[u8] = &[
    0x70, 0x81, 0x87, 0x02, 0x01, 0x01, 0xb0, 0x81, 0x81, 0x30, 0x42, 0x0c, 0x03, 0x24, 0x6f, 0x72,
    0xb0, 0x3b, 0x30, 0x22, 0x0c, 0x1d, 0x6f, 0x6e, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69,
    0x7a, 0x65, 0x64, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x61, 0x70, 0x66, 0x73, 0x2d, 0x76, 0x6f, 0x6c,
    0x75, 0x6d, 0x65, 0x01, 0x01, 0xff, 0x30, 0x15, 0x0c, 0x10, 0x6f, 0x6e, 0x2d, 0x73, 0x79, 0x73,
    0x74, 0x65, 0x6d, 0x2d, 0x76, 0x6f, 0x6c, 0x75, 0x6d, 0x65, 0x01, 0x01, 0xff, 0x30, 0x21, 0x0c,
    0x0b, 0x6c, 0x61, 0x75, 0x6e, 0x63, 0x68, 0x2d, 0x74, 0x79, 0x70, 0x65, 0xb0, 0x12, 0x30, 0x10,
    0x0c, 0x03, 0x24, 0x69, 0x6e, 0x30, 0x09, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01, 0x02, 0x01, 0x03,
    0x30, 0x18, 0x0c, 0x13, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2d, 0x63,
    0x61, 0x74, 0x65, 0x67, 0x6f, 0x72, 0x79, 0x02, 0x01, 0x01,
];
/// `0xfffffff0052e58ae`, 26 bytes.
const CC_E58AE: &[u8] = &[
    0x70, 0x18, 0x02, 0x01, 0x01, 0xb0, 0x13, 0x30, 0x11, 0x0c, 0x0c, 0x69, 0x73, 0x2d, 0x69, 0x6e,
    0x69, 0x74, 0x2d, 0x70, 0x72, 0x6f, 0x63, 0x01, 0x01, 0xff,
];
/// `0xfffffff0052e58c8`, 141 bytes.
const CC_E58C8: &[u8] = &[
    0x70, 0x81, 0x8a, 0x02, 0x01, 0x01, 0xb0, 0x81, 0x84, 0x30, 0x81, 0x81, 0x0c, 0x03, 0x24, 0x6f,
    0x72, 0xb0, 0x7a, 0x30, 0x65, 0x0c, 0x04, 0x24, 0x61, 0x6e, 0x64, 0xb0, 0x5d, 0x30, 0x15, 0x0c,
    0x10, 0x6f, 0x6e, 0x2d, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x2d, 0x76, 0x6f, 0x6c, 0x75, 0x6d,
    0x65, 0x01, 0x01, 0xff, 0x30, 0x2a, 0x0c, 0x12, 0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x2d,
    0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x66, 0x69, 0x65, 0x72, 0x0c, 0x14, 0x63, 0x6f, 0x6d, 0x2e,
    0x61, 0x70, 0x70, 0x6c, 0x65, 0x2e, 0x6d, 0x62, 0x66, 0x6c, 0x6f, 0x61, 0x67, 0x65, 0x6e, 0x74,
    0x30, 0x18, 0x0c, 0x13, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2d, 0x63,
    0x61, 0x74, 0x65, 0x67, 0x6f, 0x72, 0x79, 0x02, 0x01, 0x01, 0x30, 0x11, 0x0c, 0x0c, 0x69, 0x73,
    0x2d, 0x69, 0x6e, 0x69, 0x74, 0x2d, 0x70, 0x72, 0x6f, 0x63, 0x01, 0x01, 0xff,
];
/// `0xfffffff0052e5955`, 141 bytes.
const CC_E5955: &[u8] = &[
    0x70, 0x81, 0x8a, 0x02, 0x01, 0x01, 0xb0, 0x81, 0x84, 0x30, 0x81, 0x81, 0x0c, 0x03, 0x24, 0x6f,
    0x72, 0xb0, 0x7a, 0x30, 0x65, 0x0c, 0x04, 0x24, 0x61, 0x6e, 0x64, 0xb0, 0x5d, 0x30, 0x15, 0x0c,
    0x10, 0x6f, 0x6e, 0x2d, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x2d, 0x76, 0x6f, 0x6c, 0x75, 0x6d,
    0x65, 0x01, 0x01, 0xff, 0x30, 0x2a, 0x0c, 0x12, 0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x2d,
    0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x66, 0x69, 0x65, 0x72, 0x0c, 0x14, 0x63, 0x6f, 0x6d, 0x2e,
    0x61, 0x70, 0x70, 0x6c, 0x65, 0x2e, 0x6d, 0x62, 0x66, 0x6c, 0x6f, 0x61, 0x67, 0x65, 0x6e, 0x74,
    0x30, 0x18, 0x0c, 0x13, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2d, 0x63,
    0x61, 0x74, 0x65, 0x67, 0x6f, 0x72, 0x79, 0x02, 0x01, 0x01, 0x30, 0x11, 0x0c, 0x0c, 0x69, 0x73,
    0x2d, 0x69, 0x6e, 0x69, 0x74, 0x2d, 0x70, 0x72, 0x6f, 0x63, 0x01, 0x01, 0xff,
];
/// `0xfffffff0052e59e2`, 157 bytes.
const CC_E59E2: &[u8] = &[
    0x70, 0x81, 0x9a, 0x02, 0x01, 0x01, 0xb0, 0x81, 0x94, 0x30, 0x81, 0x91, 0x0c, 0x03, 0x24, 0x6f,
    0x72, 0xb0, 0x81, 0x89, 0x30, 0x74, 0x0c, 0x04, 0x24, 0x61, 0x6e, 0x64, 0xb0, 0x6c, 0x30, 0x13,
    0x0c, 0x0e, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x2d, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c,
    0x01, 0x01, 0xff, 0x30, 0x55, 0x0c, 0x0c, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x6c, 0x65, 0x6d, 0x65,
    0x6e, 0x74, 0x73, 0xb0, 0x45, 0x30, 0x43, 0x0c, 0x06, 0x24, 0x71, 0x75, 0x65, 0x72, 0x79, 0x30,
    0x39, 0x30, 0x2f, 0x02, 0x01, 0x01, 0x0c, 0x2a, 0x63, 0x6f, 0x6d, 0x2e, 0x61, 0x70, 0x70, 0x6c,
    0x65, 0x2e, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x2e, 0x73, 0x65, 0x74, 0x2d, 0x6c, 0x61,
    0x75, 0x6e, 0x63, 0x68, 0x2d, 0x74, 0x79, 0x70, 0x65, 0x2e, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e,
    0x61, 0x6c, 0x30, 0x06, 0x02, 0x01, 0x0a, 0x02, 0x01, 0x01, 0x30, 0x11, 0x0c, 0x0c, 0x69, 0x73,
    0x2d, 0x69, 0x6e, 0x69, 0x74, 0x2d, 0x70, 0x72, 0x6f, 0x63, 0x01, 0x01, 0xff,
];
/// `0xfffffff0052e5a7f`, 149 bytes.
const CC_E5A7F: &[u8] = &[
    0x70, 0x81, 0x92, 0x02, 0x01, 0x01, 0xb0, 0x81, 0x8c, 0x30, 0x42, 0x0c, 0x03, 0x24, 0x6f, 0x72,
    0xb0, 0x3b, 0x30, 0x22, 0x0c, 0x1d, 0x6f, 0x6e, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69,
    0x7a, 0x65, 0x64, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x61, 0x70, 0x66, 0x73, 0x2d, 0x76, 0x6f, 0x6c,
    0x75, 0x6d, 0x65, 0x01, 0x01, 0xff, 0x30, 0x15, 0x0c, 0x10, 0x6f, 0x6e, 0x2d, 0x73, 0x79, 0x73,
    0x74, 0x65, 0x6d, 0x2d, 0x76, 0x6f, 0x6c, 0x75, 0x6d, 0x65, 0x01, 0x01, 0xff, 0x30, 0x2c, 0x0c,
    0x12, 0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x2d, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x66,
    0x69, 0x65, 0x72, 0x0c, 0x16, 0x63, 0x6f, 0x6d, 0x2e, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x2e, 0x73,
    0x79, 0x73, 0x64, 0x69, 0x61, 0x67, 0x6e, 0x6f, 0x73, 0x65, 0x64, 0x30, 0x18, 0x0c, 0x13, 0x76,
    0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2d, 0x63, 0x61, 0x74, 0x65, 0x67, 0x6f,
    0x72, 0x79, 0x02, 0x01, 0x01,
];
/// `0xfffffff0052e5b14`, 448 bytes.
const CC_E5B14: &[u8] = &[
    0x70, 0x82, 0x01, 0xbc, 0x02, 0x01, 0x01, 0xb0, 0x82, 0x01, 0xb5, 0x30, 0x82, 0x01, 0xb1, 0x0c,
    0x09, 0x24, 0x6f, 0x72, 0x2d, 0x61, 0x72, 0x72, 0x61, 0x79, 0x30, 0x82, 0x01, 0xa2, 0x30, 0x1d,
    0x0c, 0x04, 0x24, 0x61, 0x6e, 0x64, 0xb0, 0x15, 0x30, 0x13, 0x0c, 0x0e, 0x61, 0x70, 0x70, 0x6c,
    0x65, 0x2d, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x01, 0x01, 0xff, 0x30, 0x81, 0xd6,
    0x0c, 0x04, 0x24, 0x61, 0x6e, 0x64, 0xb0, 0x81, 0xcd, 0x30, 0x10, 0x0c, 0x0b, 0x6c, 0x61, 0x75,
    0x6e, 0x63, 0x68, 0x2d, 0x74, 0x79, 0x70, 0x65, 0x02, 0x01, 0x00, 0x30, 0x81, 0x9e, 0x0c, 0x12,
    0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x2d, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x66, 0x69,
    0x65, 0x72, 0xb0, 0x81, 0x87, 0x30, 0x81, 0x84, 0x0c, 0x03, 0x24, 0x69, 0x6e, 0x30, 0x7d, 0x0c,
    0x17, 0x63, 0x6f, 0x6d, 0x2e, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x2e, 0x77, 0x69, 0x66, 0x69, 0x76,
    0x65, 0x6c, 0x6f, 0x63, 0x69, 0x74, 0x79, 0x64, 0x0c, 0x1d, 0x63, 0x6f, 0x6d, 0x2e, 0x61, 0x70,
    0x70, 0x6c, 0x65, 0x2e, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x64, 0x69, 0x61, 0x67, 0x6e,
    0x6f, 0x73, 0x74, 0x69, 0x63, 0x73, 0x64, 0x0c, 0x0f, 0x63, 0x6f, 0x6d, 0x2e, 0x61, 0x70, 0x70,
    0x6c, 0x65, 0x2e, 0x62, 0x72, 0x63, 0x74, 0x6c, 0x0c, 0x0c, 0x63, 0x6f, 0x6d, 0x2e, 0x61, 0x70,
    0x70, 0x6c, 0x65, 0x2e, 0x73, 0x68, 0x0c, 0x0e, 0x63, 0x6f, 0x6d, 0x2e, 0x61, 0x70, 0x70, 0x6c,
    0x65, 0x2e, 0x62, 0x61, 0x73, 0x68, 0x0c, 0x14, 0x63, 0x6f, 0x6d, 0x2e, 0x61, 0x70, 0x70, 0x6c,
    0x65, 0x2e, 0x62, 0x62, 0x73, 0x77, 0x62, 0x79, 0x70, 0x61, 0x73, 0x73, 0x30, 0x18, 0x0c, 0x13,
    0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2d, 0x63, 0x61, 0x74, 0x65, 0x67,
    0x6f, 0x72, 0x79, 0x02, 0x01, 0x01, 0x30, 0x81, 0xa7, 0x0c, 0x04, 0x24, 0x61, 0x6e, 0x64, 0xb0,
    0x81, 0x9e, 0x30, 0x42, 0x0c, 0x03, 0x24, 0x6f, 0x72, 0xb0, 0x3b, 0x30, 0x22, 0x0c, 0x1d, 0x6f,
    0x6e, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x64, 0x2d, 0x61, 0x75, 0x74,
    0x68, 0x61, 0x70, 0x66, 0x73, 0x2d, 0x76, 0x6f, 0x6c, 0x75, 0x6d, 0x65, 0x01, 0x01, 0xff, 0x30,
    0x15, 0x0c, 0x10, 0x6f, 0x6e, 0x2d, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x2d, 0x76, 0x6f, 0x6c,
    0x75, 0x6d, 0x65, 0x01, 0x01, 0xff, 0x30, 0x10, 0x0c, 0x0b, 0x6c, 0x61, 0x75, 0x6e, 0x63, 0x68,
    0x2d, 0x74, 0x79, 0x70, 0x65, 0x02, 0x01, 0x02, 0x30, 0x2c, 0x0c, 0x12, 0x73, 0x69, 0x67, 0x6e,
    0x69, 0x6e, 0x67, 0x2d, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x66, 0x69, 0x65, 0x72, 0x0c, 0x16,
    0x63, 0x6f, 0x6d, 0x2e, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x2e, 0x73, 0x79, 0x73, 0x64, 0x69, 0x61,
    0x67, 0x6e, 0x6f, 0x73, 0x65, 0x64, 0x30, 0x18, 0x0c, 0x13, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61,
    0x74, 0x69, 0x6f, 0x6e, 0x2d, 0x63, 0x61, 0x74, 0x65, 0x67, 0x6f, 0x72, 0x79, 0x02, 0x01, 0x01,
];
/// `0xfffffff0052e5cd4`, 26 bytes.
const CC_E5CD4: &[u8] = &[
    0x70, 0x18, 0x02, 0x01, 0x01, 0xb0, 0x13, 0x30, 0x11, 0x0c, 0x0c, 0x69, 0x73, 0x2d, 0x69, 0x6e,
    0x69, 0x74, 0x2d, 0x70, 0x72, 0x6f, 0x63, 0x01, 0x01, 0xff,
];
/// `0xfffffff0052e5cee`, 26 bytes.
const CC_E5CEE: &[u8] = &[
    0x70, 0x18, 0x02, 0x01, 0x01, 0xb0, 0x13, 0x30, 0x11, 0x0c, 0x0c, 0x69, 0x73, 0x2d, 0x69, 0x6e,
    0x69, 0x74, 0x2d, 0x70, 0x72, 0x6f, 0x63, 0x01, 0x01, 0xff,
];
/// `0xfffffff0052e5d08`, 26 bytes.
const CC_E5D08: &[u8] = &[
    0x70, 0x18, 0x02, 0x01, 0x01, 0xb0, 0x13, 0x30, 0x11, 0x0c, 0x0c, 0x69, 0x73, 0x2d, 0x69, 0x6e,
    0x69, 0x74, 0x2d, 0x70, 0x72, 0x6f, 0x63, 0x01, 0x01, 0xff,
];
/// `0xfffffff0052e5d22`, 163 bytes.
const CC_E5D22: &[u8] = &[
    0x70, 0x81, 0xa0, 0x02, 0x01, 0x01, 0xb0, 0x81, 0x9a, 0x30, 0x81, 0x97, 0x0c, 0x03, 0x24, 0x6f,
    0x72, 0xb0, 0x81, 0x8f, 0x30, 0x78, 0x0c, 0x04, 0x24, 0x61, 0x6e, 0x64, 0xb0, 0x70, 0x30, 0x54,
    0x0c, 0x03, 0x24, 0x6f, 0x72, 0xb0, 0x4d, 0x30, 0x11, 0x0c, 0x0c, 0x69, 0x73, 0x2d, 0x69, 0x6e,
    0x69, 0x74, 0x2d, 0x70, 0x72, 0x6f, 0x63, 0x01, 0x01, 0xff, 0x30, 0x38, 0x0c, 0x12, 0x73, 0x69,
    0x67, 0x6e, 0x69, 0x6e, 0x67, 0x2d, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x66, 0x69, 0x65, 0x72,
    0x0c, 0x22, 0x63, 0x6f, 0x6d, 0x2e, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x2e, 0x43, 0x6f, 0x72, 0x65,
    0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x64, 0x74, 0x64, 0x65, 0x62, 0x75, 0x67, 0x70, 0x72,
    0x6f, 0x78, 0x79, 0x64, 0x30, 0x18, 0x0c, 0x13, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x69,
    0x6f, 0x6e, 0x2d, 0x63, 0x61, 0x74, 0x65, 0x67, 0x6f, 0x72, 0x79, 0x02, 0x01, 0x01, 0x30, 0x13,
    0x0c, 0x0e, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x2d, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c,
    0x01, 0x01, 0xff,
];

/// `CC_Self` (`0xfffffff005aaccd0`): what a category requires of the
/// launched process. None for category 0; an unknown category is logged
/// and requires nothing.
fn cc_self(cat: i32, log: &mut Vec<String>) -> Option<&'static [u8]> {
    Some(match cat {
        0 => return None,
        1 => CC_E4FF3,
        2 | 0x13 => CC_E506A,
        3 => CC_E50B5,
        4 => CC_E513B,
        5 => CC_E51C1,
        6 => CC_E51E2,
        7 => CC_E5297,
        8 => CC_E52B8,
        9 => CC_E532F,
        10 => CC_E540A,
        0xb => CC_E5490,
        0xc => CC_E54F5,
        0xd => CC_E557F,
        0xe => CC_E55C0,
        0xf => CC_E5637,
        0x10 => CC_E56BD,
        0x11 => CC_E56F0,
        0x12 => CC_E57AA,
        0x14 => CC_E5824,
        _ => {
            log.push(format!("AMFI: CC_Self: Unknown Constraint category: {cat}"));
            return None;
        }
    })
}

/// `CC_Parent` (`0xfffffff005aacf1c`): what a category requires of the
/// launched process's parent.
fn cc_parent(cat: i32, log: &mut Vec<String>) -> Option<&'static [u8]> {
    Some(match cat {
        0 | 2 | 3 | 7 | 9 | 10 | 0xc | 0xd | 0x13 | 0x14 => return None,
        1 => CC_E58AE,
        4 => CC_E58C8,
        5 => CC_E5955,
        6 => CC_E59E2,
        8 | 0x11 => CC_E5A7F,
        0xb => CC_E5B14,
        0xe => CC_E5CD4,
        0xf => CC_E5CEE,
        0x10 => CC_E5D08,
        0x12 => CC_E5D22,
        _ => {
            log.push(format!("AMFI: CC_Parent: Unknown Constraint category: {cat}"));
            return None;
        }
    })
}

/// `CC_Responsible` (`0xfffffff005aad030`): no category constrains the
/// responsible process on this release.
fn cc_responsible(cat: i32, log: &mut Vec<String>) -> Option<&'static [u8]> {
    if cat as u32 > 0x14 {
        log.push(format!("AMFI: CC_Responsible: Unknown Constraint category: {cat}"));
    }
    None
}

/// `0xfffffff005aad0a4`: whether a category's violations are enforced,
/// by the type it belongs to (`launch_constraints_cc_types_enforced`, all
/// four on a release kernel). 0x7f, the category an LWCR names to have
/// its failures only logged, is of the first type.
fn enforced(cat: i32) -> bool {
    type_enforced(match cat {
        0 | 2 | 0x12 | 0x13 | 0x7f => 1,
        1 | 3..=7 => 2,
        8..=0xd | 0x11 => 4,
        0xe..=0x10 | 0x14 => 8,
        // "Should not reach here, uncategorized constraint category": no
        // category without constraints can fail.
        _ => return true,
    })
}

/// `0xfffffff005aaeeb0`: a category type is enforced
/// (`launch_constraints_cc_types_enforced`, 0xf on a release kernel).
fn type_enforced(t: u32) -> bool {
    const CC_TYPES_ENFORCED: u32 = 0xf;
    CC_TYPES_ENFORCED & t != 0
}

/// A category as the hook passes it on: the byte sign-extended (the
/// trust cache's entry, `0xfffffff005aadb04`, and an LWCR's `ccat`, read as
/// a `char`).
fn category_of(byte: i64) -> i32 {
    i32::from(byte as u8 as i8)
}

// The processes.

/// What AMFI's process encyclopedia finds for a pid (`0xfffffff005aab138`
/// is `proc_find`'s).
#[derive(Clone, Debug)]
pub enum Proc {
    /// No process (it is gone, or a zombie).
    None(i32),
    /// The kernel's (`kernproc`): `CS_VALID`, platform 0, no executable.
    Kernel,
    /// Pid 1 when it is this kernel's own, standing for launchd: it is
    /// `initproc`, but what else launchd would show is not known here.
    StandIn,
    Live(Live),
}

/// A live process, as the facts read it.
#[derive(Clone, Debug)]
pub struct Live {
    pub pid: i32,
    pub is_init: bool,
    /// `proc_platform`.
    pub platform: u32,
    /// `p_csflags`.
    pub csflags: u32,
    /// `p_textvp`: its path, and whether it is on the root volume (`None`
    /// where this kernel cannot say which mount it is on).
    pub exe: Option<(String, Option<bool>)>,
    /// `csproc_get_blob`: its signature, when `CS_SIGNED`.
    pub sig: Option<Arc<CodeSign>>,
}

impl Proc {
    fn pid(&self) -> i32 {
        match self {
            Proc::None(pid) => *pid,
            Proc::Kernel => 0,
            Proc::StandIn => 1,
            Proc::Live(l) => l.pid,
        }
    }

    /// `0xfffffff005aad670`: the signature's validation category, 0 with
    /// none.
    fn vc(&self) -> Result<i64, String> {
        match self {
            Proc::Live(l) => Ok(l.sig.as_ref().map_or(0, |s| i64::from(s.category))),
            Proc::StandIn => Err("AMFI launch constraints: the validation category of pid 1, which is not launchd here".into()),
            _ => Ok(0),
        }
    }

    /// `0xfffffff005aad588`: the signing identifier, "N/A" with none.
    fn identity(&self) -> Result<Vec<u8>, String> {
        match self {
            Proc::Live(l) => Ok(l.sig.as_ref().and_then(|s| identity(s)).unwrap_or_else(|| b"N/A".to_vec())),
            Proc::StandIn => Err("AMFI launch constraints: the signing identifier of pid 1, which is not launchd here".into()),
            _ => Ok(b"N/A".to_vec()),
        }
    }

    /// `0xfffffff005aab384`: `proc_isinitproc`.
    fn is_init(&self) -> bool {
        match self {
            Proc::Live(l) => l.is_init,
            Proc::StandIn => true,
            _ => false,
        }
    }

    /// `0xfffffff005ab8c44`: the executable's path (`vn_getpath`), empty
    /// with none.
    fn path(&self) -> Result<String, String> {
        match self {
            Proc::Live(l) => Ok(l.exe.as_ref().map_or_else(String::new, |(p, _)| p.clone())),
            Proc::StandIn => Err("AMFI launch constraints: the executable of pid 1, which is not launchd here".into()),
            _ => Ok(String::new()),
        }
    }

    /// `0xfffffff005aada60`: whether the cdhash is in a trust cache, whether
    /// that trust cache records categories, and the category.
    fn trust_cache(&self) -> Result<(bool, bool, i32), String> {
        match self {
            Proc::Live(l) => Ok(match l.sig.as_ref().and_then(|s| s.cdhash).and_then(|h| super::trustcache::platform(&h)) {
                Some(e) => (true, e.category.is_some(), category_of(i64::from(e.category.unwrap_or(0)))),
                None => (false, false, 0),
            }),
            Proc::StandIn => Err("AMFI launch constraints: the trust cache entry of pid 1, which is not launchd here".into()),
            _ => Ok((false, false, 0)),
        }
    }
}

/// `csblob_get_identity`: the identifier of the CodeDirectory in slot 0.
fn identity(s: &CodeSign) -> Option<Vec<u8>> {
    let cd = super::codesign::find_blob(&s.blob, 0, 0xfade_0c02)?;
    let off = u32::from_be_bytes(cd.get(20..24)?.try_into().ok()?) as usize;
    if off == 0 {
        return None;
    }
    let t = cd.get(off..)?;
    Some(t[..t.iter().position(|&c| c == 0).unwrap_or(t.len())].to_vec())
}

/// The best CodeDirectory's special slot `slot` hash, when it has that
/// many and it is not all zeros (`0xfffffff005aad7f4`), its size by the
/// blob's hash type (`0xfffffff005aad788`).
fn special_slot(s: &CodeSign, slot: usize) -> Option<Vec<u8>> {
    let size = match s.hash_type {
        1 | 3 => 20,
        2 => 32,
        4 => 48,
        _ => return None,
    };
    let (off, len) = super::codesign::validate_csblob(&s.blob).ok()?;
    let cd = s.blob.get(off..off + len)?;
    let be = |o: usize| cd.get(o..o + 4).map(|b| u32::from_be_bytes(b.try_into().unwrap()) as usize);
    if slot == 0 || slot > be(0x18)? {
        return None;
    }
    let at = be(0x10)?.checked_sub(size * slot)?;
    let h = cd.get(at..at + size)?;
    h.iter().any(|&b| b != 0).then(|| h.to_vec())
}

/// The system's facts (`0xfffffff005ab875c`).
#[derive(Clone, Debug)]
pub struct System {
    /// `kern.osreleasetype` is "Internal".
    pub apple_internal: bool,
    /// `developer_mode_state()`.
    pub developer_mode: bool,
    /// `/chosen/osenvironment`, to its first NUL.
    pub os_environment: Vec<u8>,
}

/// What AMFI's library encyclopedia (`0xfffffff005aac54c`) reads of a
/// file being mapped: its vnode, its signature at the slice
/// (`csfg_get_csblob`) and the team identifier of its first one
/// (`csfg_get_teamid`).
#[derive(Clone, Debug)]
pub struct Lib {
    pub exe: (String, Option<bool>),
    pub sig: Option<Arc<CodeSign>>,
    pub teamid: Option<Vec<u8>>,
}

/// Whose facts an encyclopedia gives.
#[derive(Clone, Copy)]
enum Subject<'a> {
    Proc(&'a Proc),
    Lib(&'a Lib),
}

/// An encyclopedia with the system's after it, and the launch's for a
/// process's (`0xfffffff005ab21dc` builds one for each of the three
/// processes; a library's has no launch type).
struct Meta<'a> {
    subject: Subject<'a>,
    system: &'a System,
    launch_type: Option<u8>,
    /// The process being launched or mapping (`csproc_get_teamid` of
    /// `current_proc()`).
    cur_teamid: Option<&'a [u8]>,
}

/// `0xfffffff005ab8e14`: the facts of a vnode, a process's executable or
/// a mapped file; `None` (no vnode) reads as off any volume.
fn vnode_fact(exe: Option<&(String, Option<bool>)>, name: &[u8]) -> Option<Fact> {
    use lwcr::ty;
    let k = |v: Value| Some(Fact::Known(v));
    match name {
        // vfs_flags(vnode_mount(vp)) & MNT_ROOTFS.
        b"on-system-volume" => match exe {
            Some((_, Some(r))) => k(Value::Bool(*r)),
            Some((p, None)) => Some(Fact::Unknown(ty::BOOL, format!("on-system-volume of {p}, on a mount this kernel does not describe"))),
            None => k(Value::Bool(false)),
        },
        // APFS's answer to ioctl 0x80084118 on the vnode: its volume's
        // authorization, which this kernel does not model.
        b"on-authorized-authapfs-volume" => match exe {
            Some((p, _)) => Some(Fact::Unknown(ty::BOOL, format!("on-authorized-authapfs-volume of {p} (APFS's ioctl 0x80084118)"))),
            None => k(Value::Bool(false)),
        },
        b"is-sip-protected" => k(Value::Bool(false)),
        _ => None,
    }
}

/// `0xfffffff005aadb34`: a signature's facts; `team` is its owner's team
/// identifier as its accessor gives it ("N/A" for a process with none,
/// "none" for a file with none).
fn blob_fact(sig: &CodeSign, name: &[u8], team: Vec<u8>, cur_teamid: Option<&[u8]>) -> Option<Fact> {
    let k = |v: Value| Some(Fact::Known(v));
    match name {
        b"signing-identifier" => k(Value::Str(identity(sig).unwrap_or_else(|| b"N/A".to_vec()))),
        b"validation-category" => k(Value::Int(i64::from(sig.category))),
        // The entitlements AMFI validated: a CoreEntitlements context when
        // the signature had DER entitlements.
        b"entitlements" => k(Value::Dict(sig.der.as_ref().map(|_| sig.ents.0.clone()))),
        // 0xfffffff005aad608: equal to the current process's, which it has.
        b"team-identifier-for-current-process" => k(Value::Bool(cur_teamid.is_some_and(|t| t == team))),
        b"team-identifier" => k(Value::Str(team)),
        b"info-plist-hash" => special_slot(sig, 1).map(|h| Fact::Known(Value::Data(h))),
        b"in-tc-with-constraint-category" => {
            let e = sig.cdhash.and_then(|h| super::trustcache::platform(&h));
            k(Value::Bool(e.is_some_and(|e| e.category.is_some())))
        }
        b"cdhash" => sig.cdhash.map(|h| Fact::Known(Value::Data(h.to_vec()))),
        b"platform-identifier" => k(Value::Int(i64::from(sig.platform))),
        b"is-main-binary" => k(Value::Bool(sig.cd_version >= 0x20400 && sig.exec_seg_flags & super::amfi::cs::EXECSEG_MAIN_BINARY != 0)),
        b"code-signing-flags" => k(Value::Int(i64::from(sig.flags))),
        _ => None,
    }
}

impl Meta<'_> {
    /// `0xfffffff005aab420`: a process's facts, then its executable's and
    /// its signature's; `None` for a name it does not have.
    fn process(&self, p: &Proc, name: &[u8]) -> Option<Fact> {
        use lwcr::ty;
        let k = |v: Value| Some(Fact::Known(v));
        let unknown = |t: u32, n: &[u8]| Some(Fact::Unknown(t, format!("{} of pid 1, which is not launchd here", String::from_utf8_lossy(n))));
        match name {
            b"is-init-proc" => return k(Value::Bool(p.is_init())),
            b"platform" => {
                return match p {
                    Proc::None(_) => k(Value::Int(0xffff_ffff)),
                    Proc::Kernel => k(Value::Int(0)),
                    Proc::StandIn => unknown(ty::INTEGER, name),
                    Proc::Live(l) => k(Value::Int(i64::from(l.platform))),
                };
            }
            b"code-signing-flags" => {
                return match p {
                    // proc_csflags of none fails: 0.
                    Proc::None(_) => k(Value::Int(0)),
                    Proc::Kernel => k(Value::Int(i64::from(super::amfi::cs::VALID))),
                    Proc::StandIn => unknown(ty::INTEGER, name),
                    Proc::Live(l) => k(Value::Int(i64::from(l.csflags))),
                };
            }
            _ => {}
        }
        match p {
            Proc::StandIn => match name {
                b"on-system-volume" | b"on-authorized-authapfs-volume" | b"team-identifier-for-current-process" | b"in-tc-with-constraint-category" | b"is-main-binary" => unknown(ty::BOOL, name),
                b"is-sip-protected" => k(Value::Bool(false)),
                b"signing-identifier" | b"team-identifier" => unknown(ty::STRING, name),
                b"validation-category" | b"platform-identifier" => unknown(ty::INTEGER, name),
                b"entitlements" => unknown(ty::DICTIONARY, name),
                b"cdhash" => unknown(ty::DATA, name),
                b"info-plist-hash" => Some(Fact::Unported("AMFI launch constraints: whether pid 1, which is not launchd here, has an Info.plist hash".into())),
                _ => None,
            },
            Proc::Live(l) => {
                if let Some(f) = vnode_fact(l.exe.as_ref(), name) {
                    return Some(f);
                }
                let sig = l.sig.as_ref()?;
                // 0xfffffff005aad5c8: its team identifier, "N/A" with none.
                blob_fact(sig, name, sig.team_id.clone().unwrap_or_else(|| b"N/A".to_vec()), self.cur_teamid)
            }
            _ => vnode_fact(None, name),
        }
    }

    /// `0xfffffff005aac68c`: a mapped file's facts.
    fn library(&self, l: &Lib, name: &[u8]) -> Option<Fact> {
        if let Some(f) = vnode_fact(Some(&l.exe), name) {
            return Some(f);
        }
        let sig = l.sig.as_ref()?;
        // 0xfffffff005aac5f0: the vnode's team identifier, "none" with none.
        blob_fact(sig, name, l.teamid.clone().unwrap_or_else(|| b"none".to_vec()), self.cur_teamid)
    }
}

impl Facts for Meta<'_> {
    fn fact(&self, name: &[u8]) -> Fact {
        let own = match self.subject {
            Subject::Proc(p) => self.process(p, name),
            Subject::Lib(l) => self.library(l, name),
        };
        if let Some(f) = own {
            return f;
        }
        let k = |v: Value| Fact::Known(v);
        match name {
            b"sip-enabled" => k(Value::Bool(false)),
            b"apple-internal" => k(Value::Bool(self.system.apple_internal)),
            b"developer-mode" => k(Value::Bool(self.system.developer_mode)),
            b"os-environment" => k(Value::Str(self.system.os_environment.clone())),
            // 0xfffffff005aacb88: launch_constraint_data_get_launch_type.
            b"launch-type" => match self.launch_type {
                Some(lt) => k(Value::Int(i64::from(lt))),
                None => Fact::Missing,
            },
            _ => Fact::Missing,
        }
    }
}

// The hook.

/// The violation being built (the hook's error record): the constraint's
/// source `c`, the process that failed `p`, how it failed `m`, an error
/// code or category `e`, a message, and whether it is only logged.
#[derive(Clone, Debug, Default)]
struct Viol {
    c: u8,
    p: u8,
    m: u8,
    e: i32,
    msg: Option<String>,
    nonenforcing: bool,
}

impl Viol {
    fn set(&mut self, c: u8, p: u8, m: u8, e: i32, msg: &str) {
        (self.c, self.p, self.m, self.e, self.msg) = (c, p, m, e, Some(msg.into()));
    }
}

/// The launch type's policy (`0xfffffff005aab8fc`): which categories it
/// expects, and whether one of them was met.
struct Policy {
    lt: u8,
    met: bool,
    /// Sysdiagnose's: category 0x11 was met.
    met_11: bool,
}

/// How the hook ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Nothing violated.
    Allowed { log: Vec<String> },
    /// A violation, logged; enforced, with the description the launch
    /// fails with (1024 bytes, as `0xfffffff005ab8954` makes it).
    Violation { log: Vec<String>, desc: Option<Vec<u8>> },
    /// The device's answer turns on what this kernel cannot supply.
    Unported(String),
}

/// What the hook is given: the three processes, the system, and the
/// launch.
pub struct Input<'a> {
    pub cur: &'a Proc,
    pub parent: &'a Proc,
    pub resp: &'a Proc,
    pub system: &'a System,
    pub launch_type: u8,
    pub spawnattr: Option<&'a [u8]>,
}

struct Hook<'a> {
    i: &'a Input<'a>,
    policy: Policy,
    log: Vec<String>,
}

/// A step that may stop on what this kernel cannot supply.
type Step<T> = Result<T, String>;

impl Hook<'_> {
    fn meta<'b>(&'b self, p: &'b Proc) -> Meta<'b> {
        let cur_teamid = match self.i.cur {
            Proc::Live(l) => l.sig.as_ref().and_then(|s| s.team_id.as_deref()),
            _ => None,
        };
        Meta { subject: Subject::Proc(p), system: self.i.system, launch_type: Some(self.i.launch_type), cur_teamid }
    }

    /// `0xfffffff005aac08c`: requirements on one process's facts; false
    /// with the violation's `m`, `e` and message set.
    fn reqs(&self, reqs: &Ent, p: &Proc, v: &mut Viol) -> Step<bool> {
        match lwcr::evaluate(reqs, &self.meta(p)) {
            Verdict::Matched(true) => Ok(true),
            Verdict::Matched(false) => {
                v.m = 1;
                v.msg = Some("Constraint not matched".into());
                Ok(false)
            }
            Verdict::Build(f) => {
                (v.m, v.e, v.msg) = (2, f.code as i32, Some(f.msg));
                Ok(false)
            }
            Verdict::Eval(f) => {
                (v.m, v.e, v.msg) = (5, f.code as i32, Some(f.msg));
                Ok(false)
            }
            Verdict::Unported(why) => Err(why),
        }
    }

    /// A category table entry's requirements.
    fn table(blob: &[u8]) -> Ent {
        Ent::Dict(lwcr::ce_validate(blob, true).expect("AMFI's category tables are valid"))
    }

    /// `0xfffffff005ab8b34`: a category's constraints on the launched
    /// process, its parent and its responsible process; on a failure `c`
    /// is `source`, `p` the process, and `e` the category when unset.
    fn category(&mut self, cat: i32, source: u8, v: &mut Viol) -> Step<bool> {
        let tables: [(fn(i32, &mut Vec<String>) -> Option<&'static [u8]>, u8); 3] = [(cc_self, 1), (cc_parent, 2), (cc_responsible, 3)];
        for (table, p) in tables {
            let Some(blob) = table(cat, &mut self.log) else { continue };
            let proc = [self.i.cur, self.i.parent, self.i.resp][p as usize - 1];
            if !self.reqs(&Self::table(blob), proc, v)? {
                (v.p, v.c) = (p, source);
                if v.e == 0 {
                    v.e = cat;
                }
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// `0xfffffff005ab253c`: a category applied; met, the launch type's
    /// policy is told; failed, whether it is enforced.
    fn apply_category(&mut self, cat: i32, source: u8, v: &mut Viol) -> Step<bool> {
        let ok = self.category(cat, source, v)?;
        if ok {
            self.mark(cat);
        } else {
            v.nonenforcing = !enforced(cat);
        }
        Ok(ok)
    }

    /// `0xfffffff005ab25bc`: a recoveryOS agent may launch what it needs
    /// whatever the category says.
    fn recovery_exception(&self, cat: i32) -> Step<bool> {
        if self.i.parent.vc()? != 1 {
            return Ok(false);
        }
        let name: &[u8] = if (0..0x15).contains(&cat) && 0x11_c000u32 >> cat & 1 != 0 {
            b"com.apple.recoveryos_agent"
        } else if cat == 8 {
            b"com.apple.RecoveryDiagnose.recoverydiagnosed"
        } else {
            return Ok(false);
        };
        Ok(self.i.parent.identity()? == name)
    }

    /// The policy's `+0x18`: a category met.
    fn mark(&mut self, cat: i32) {
        let p = &mut self.policy;
        let c = cat as u32;
        match p.lt {
            launch_type::NONE => p.met = true,
            launch_type::SYSTEM_SERVICE => p.met |= c < 0x14 && 0x890ba >> c & 1 != 0,
            launch_type::SYSDIAGNOSE => {
                if cat == 0x11 {
                    p.met_11 = true;
                } else {
                    p.met |= c < 0x14 && 0xa3f80 >> c & 1 != 0;
                }
            }
            _ => p.met |= c < 0x15 && 0x19c080 >> c & 1 != 0,
        }
    }

    /// The policy's `+0x10`: whether the parent may ask for the launch
    /// type.
    fn launch_type_allowed(&mut self, v: &mut Viol) -> Step<bool> {
        let ok = match self.policy.lt {
            launch_type::NONE => true,
            launch_type::SYSTEM_SERVICE => {
                if !self.i.parent.is_init() {
                    self.log.push("AMFI: Only launchd can set the system service launch type".into());
                }
                self.i.parent.is_init()
            }
            launch_type::SYSDIAGNOSE => {
                let ok = self.i.parent.vc()? == 1 && self.i.parent.identity()? == b"com.apple.sysdiagnosed";
                if !ok {
                    self.log.push("AMFI: only sysdiagnose can set the sysdiagnose launch type".into());
                }
                ok
            }
            _ => {
                if !self.i.parent.is_init() {
                    self.log.push("AMFI: Only launchd can set the application launch type".into());
                }
                self.i.parent.is_init()
            }
        };
        if !ok {
            v.set(7, 2, 3, 0xff, "Caller provided a disallowed launch type");
        }
        Ok(ok)
    }

    /// The policy's `+0x20`: what the launch type requires once the
    /// constraints are met.
    fn launch_type_final(&mut self, v: &mut Viol) -> Step<bool> {
        if self.policy.met {
            return Ok(true);
        }
        match self.policy.lt {
            launch_type::NONE => Ok(true),
            // 0xfffffff005ab94b8: a process launched as a system service
            // that met no system service category is checked against
            // category 6's.
            launch_type::SYSTEM_SERVICE => {
                if self.category(6, 8, v)? {
                    v.set(6, 2, 3, 0xff, "Process was launched as a system service unexpectedly but met System Service constraints");
                    v.nonenforcing = true;
                } else {
                    v.nonenforcing = !type_enforced(2);
                }
                Ok(false)
            }
            launch_type::SYSDIAGNOSE => {
                v.set(9, 2, 3, 0xff, "Process was launched as a sysdiagnose helper unexpectedly");
                v.nonenforcing = self.policy.met_11 || !type_enforced(4);
                Ok(false)
            }
            _ => {
                let (in_tc, has_category, _) = self.i.cur.trust_cache()?;
                if in_tc && has_category {
                    v.set(6, 2, 3, 0xff, "System process was launched as an application unexpectedly");
                    v.nonenforcing = true;
                    return Ok(false);
                }
                Ok(true)
            }
        }
    }

    /// The launched image's LWCR in signature slot `slot`.
    fn embedded(&mut self, slot: u32) -> (i64, Option<Ent>) {
        embedded(self.i.cur, slot, &mut self.log)
    }

    /// `0xfffffff005ab246c`: constraints in its own signature are honored
    /// only for platform code (third-party ones are not allowed on a
    /// release kernel).
    fn platform_only(&self, ccat: i64, reqs: &Option<Ent>, msg: &str, v: &mut Viol) -> Step<bool> {
        if self.i.cur.vc()? == 1 {
            return Ok(true);
        }
        let has_reqs = reqs.is_some();
        let low = ccat as u8;
        if !has_reqs && (low == 0xff || low == 0) {
            return Ok(true);
        }
        v.set(4, 1, 3, 0xff, msg);
        Ok(false)
    }

    /// `0xfffffff005ab8ae4`: an LWCR's requirements on a process.
    fn lwcr_reqs(&self, reqs: &Option<Ent>, c: u8, p: u8, proc: &Proc, v: &mut Viol) -> Step<bool> {
        let Some(r) = reqs else { return Ok(true) };
        let ok = self.reqs(r, proc, v)?;
        if !ok {
            (v.p, v.c) = (p, c);
        }
        Ok(ok)
    }

    /// `0xfffffff005ab2634`.
    fn run(&mut self, v: &mut Viol) -> Step<bool> {
        if self.policy.lt > launch_type::APPLICATION {
            self.log.push(format!("AMFI: Unknown Launch Type: {}", self.policy.lt));
            v.set(7, 2, 3, 0xff, "Unknown launch type");
            return Ok(false);
        }
        if !self.launch_type_allowed(v)? {
            return Ok(false);
        }
        // The spawn's constraint (0xfffffff005ab89e0).
        let mut nonenforcing = false;
        let mut from_spawn = None;
        if let Some(a) = self.i.spawnattr.filter(|a| !a.is_empty()) {
            let parsed = match lwcr::ce_validate(a, true) {
                Ok(d) => match lwcr::load(&d) {
                    (ccat, reqs, None) => Ok((ccat, reqs)),
                    (_, _, Some(e)) => {
                        self.log.push(format!("AMFI: Error: expected light weight code requirement, but data is not valid: {}", e.msg));
                        Err(2)
                    }
                },
                Err(_) => {
                    self.log.push("AMFI: Error: expected light weight code requirement, but data is not valid".into());
                    Err(1)
                }
            };
            match parsed {
                Err(e) => {
                    v.set(5, 2, 4, e, "Caller provided an invalid constraint as a spawnattr");
                    return Ok(false);
                }
                Ok(l) => from_spawn = Some(l),
            }
        }
        if let Some((ccat, reqs)) = from_spawn {
            // 0xfffffff005ab2a58: only platform code may pass one (the
            // kernel's launch of initproc aside).
            let parent_pid = self.i.parent.pid();
            if self.i.parent.vc()? != 1 && (parent_pid != 0 || !self.i.cur.is_init()) {
                v.set(5, 2, 3, 0xff, "Only platform code can set launch constraints");
                return Ok(false);
            }
            let low = ccat as u8;
            if low != 0xff && low != 0 {
                let cat = category_of(ccat);
                // 0xfffffff005aad084.
                if !matches!(cat, 0 | 0x11 | 0x7f) {
                    v.set(3, 2, 3, cat, "Constraint category disallowed in spawn attr");
                    return Ok(false);
                }
                if cat == 0x7f {
                    nonenforcing = true;
                } else {
                    if !self.apply_category(cat, 3, v)? {
                        return Ok(false);
                    }
                    nonenforcing = false;
                }
            }
            if !self.lwcr_reqs(&reqs, 5, 1, self.i.cur, v)? {
                v.nonenforcing = nonenforcing;
                return Ok(false);
            }
        }
        // The image: a process with no signature has only the launch
        // type's requirements.
        let has_sig = matches!(self.i.cur, Proc::Live(Live { sig: Some(_), .. }));
        if has_sig {
            let (_, _, tc_cat) = self.i.cur.trust_cache()?;
            if tc_cat != 0 && !self.apply_category(tc_cat, 1, v)? && !self.recovery_exception(tc_cat)? {
                return Ok(false);
            }
            let (ccat, reqs) = self.embedded(8);
            if !self.platform_only(ccat, &reqs, "Only platform code can set launch constraints on itself", v)? {
                return Ok(false);
            }
            nonenforcing = false;
            let low = ccat as u8;
            if low != 0xff && low != 0 {
                let cat = category_of(ccat);
                if cat == 0x7f {
                    nonenforcing = true;
                } else {
                    if !self.apply_category(cat, 2, v)? {
                        return Ok(false);
                    }
                    nonenforcing = false;
                }
            }
            let slots: [(u32, u8, &Proc, &str); 3] = [
                (8, 1, self.i.cur, ""),
                (9, 2, self.i.parent, "Only platform code can set launch constraints on its parent"),
                (10, 3, self.i.resp, "Only platform code can set launch constraints on its responsible process"),
            ];
            let mut reqs = reqs;
            for (slot, p, proc, msg) in slots {
                if slot != 8 {
                    let (ccat, r) = self.embedded(slot);
                    if !self.platform_only(ccat, &r, msg, v)? {
                        return Ok(false);
                    }
                    reqs = r;
                }
                if !self.lwcr_reqs(&reqs, 4, p, proc, v)? {
                    v.nonenforcing = nonenforcing;
                    return Ok(false);
                }
            }
        }
        self.launch_type_final(v)
    }
}

/// `0xfffffff005aae014`: the LWCR in a process's signature slot `slot`, or
/// an empty one (one that does not parse is logged and ignored; the
/// category a failed load read is kept, as the kext keeps it).
fn embedded(p: &Proc, slot: u32, log: &mut Vec<String>) -> (i64, Option<Ent>) {
    let Proc::Live(l) = p else { return (0, None) };
    let Some(sig) = &l.sig else { return (0, None) };
    let Some(b) = super::codesign::find_blob(&sig.blob, slot, super::codesign::CSMAGIC_EMBEDDED_LAUNCH_CONSTRAINT) else { return (0, None) };
    let ident = identity(sig).map(|i| String::from_utf8_lossy(&i).into_owned()).unwrap_or_default();
    match lwcr::ce_validate(&b[8..], true) {
        Ok(d) => {
            let (ccat, reqs, err) = lwcr::load(&d);
            if let Some(e) = err {
                log.push(format!("AMFI: file ({ident}) failed to parse a launch constraint on in slot {slot} ({}), ignoring", e.msg));
            }
            (ccat, reqs)
        }
        Err(_) => {
            log.push(format!("AMFI: file ({ident}) contains an invalid launch constraint on in slot {slot}, ignoring"));
            (0, None)
        }
    }
}

/// The hook (`0xfffffff005ab167c`): the violation it found, logged and,
/// when enforced, described (`0xfffffff005ab2ae4`).
pub fn check(i: &Input<'_>) -> Outcome {
    let mut h = Hook { i, policy: Policy { lt: i.launch_type, met: false, met_11: false }, log: Vec::new() };
    let mut v = Viol::default();
    let ok = match h.run(&mut v) {
        Ok(ok) => ok,
        Err(why) => return Outcome::Unported(why),
    };
    if ok {
        return Outcome::Allowed { log: h.log };
    }
    match report(&h, &v) {
        Ok((line, desc)) => {
            h.log.push(line);
            Outcome::Violation { log: h.log, desc }
        }
        Err(why) => Outcome::Unported(why),
    }
}

/// `0xfffffff005ab2ae4`: the violation's log line and, enforced, its
/// description.
fn report(h: &Hook<'_>, v: &Viol) -> Result<(String, Option<Vec<u8>>), String> {
    let i = h.i;
    // A release kernel enforces (launch_constraints_enforced).
    let enforcing = !v.nonenforcing;
    let msg = v.msg.as_deref().unwrap_or("No error message set");
    let fail: &Proc = match v.p {
        1 => i.cur,
        2 => i.parent,
        3 => i.resp,
        _ => &Proc::None(0),
    };
    let (fail_vc, fail_path) = (fail.vc()?, fail.path()?);
    let line = format!(
        "AMFI: Launch Constraint Violation ({}enforcing), error info: c[{}]p[{}]m[{}]e[{}], ({}) launching proc[vc: {} pid: {}]: {}, launch type {}, failure proc [vc: {} pid: {}]: {}",
        if enforcing { "" } else { "not " },
        v.c,
        v.p,
        v.m,
        v.e,
        msg,
        i.cur.vc()?,
        i.cur.pid(),
        i.cur.path()?,
        i.launch_type,
        fail_vc,
        fail.pid(),
        fail_path
    );
    let desc = enforcing.then(|| {
        let text = format!("Launch Constraint Violation, error info: c[{}]p[{}]m[{}]e[{}], ({}) launch type {}, failure proc [vc: {}]: {}", v.c, v.p, v.m, v.e, msg, i.launch_type, fail_vc, fail_path);
        // vsnprintf into a zeroed 1024-byte buffer: at most 1023 bytes and
        // a NUL; the whole buffer is the description.
        let mut buf = vec![0u8; DESC_LEN];
        let n = text.len().min(DESC_LEN - 1);
        buf[..n].copy_from_slice(&text.as_bytes()[..n]);
        buf
    });
    Ok((line, desc))
}

/// How `mpo_file_check_library_validation` (`0xfffffff005ab0c9c`) ended:
/// the mapping allowed, or refused with the message it copies out and
/// what it logged; or turning on what this kernel cannot supply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LibOutcome {
    Allowed { log: Vec<String> },
    Denied { msg: &'static str, log: Vec<String> },
    Unported(String),
}

/// A process's or a file's description in the library logs: its path, team
/// identifier and whether it is platform code.
fn describe(path: &str, team: &[u8], platform: bool) -> String {
    format!("'{path}' (Team ID: {}, platform: {})", String::from_utf8_lossy(team), if platform { "yes" } else { "no" })
}

/// `0xfffffff005ab0c9c`: the process `cur` (live) mapping the file `lib`:
/// the process's library load constraint (signature slot 11), when it is
/// signed, then library validation (`cs_require_lv` is 1 on this kernel).
pub fn library_check(cur: &Proc, lib: &Lib, system: &System) -> LibOutcome {
    let Proc::Live(p) = cur else { return LibOutcome::Allowed { log: Vec::new() } };
    let mut log = Vec::new();
    let cur_team = p.sig.as_ref().and_then(|s| s.team_id.clone()).unwrap_or_else(|| b"N/A".to_vec());
    let lib_team = lib.teamid.clone().unwrap_or_else(|| b"none".to_vec());
    let cur_path = p.exe.as_ref().map_or_else(String::new, |e| e.0.clone());
    let who = |log: &mut Vec<String>, what: &str, reason: &str| {
        let (lp, cp) = (lib.sig.as_ref().is_some_and(|s| s.platform_binary), p.sig.as_ref().is_some_and(|s| s.platform_binary));
        log.push(format!("{what}: Rejecting {} for process '{}({})' (Team ID: {}, platform: {}), reason: {reason}", describe(&lib.exe.0, &lib_team, lp), cur_path.rsplit('/').next().unwrap_or(""), p.pid, String::from_utf8_lossy(&cur_team), if cp { "yes" } else { "no" }));
    };
    let lib_vc = lib.sig.as_ref().map_or(0, |s| s.category);
    // 0xfffffff005ab053c: the library load constraint, which platform
    // code always meets.
    if p.sig.is_some() && lib_vc != 1 {
        let (_, reqs) = embedded(cur, 11, &mut log);
        if let Some(r) = reqs {
            let meta = Meta { subject: Subject::Lib(lib), system, launch_type: None, cur_teamid: p.sig.as_ref().and_then(|s| s.team_id.as_deref()) };
            let reason = match lwcr::evaluate(&r, &meta) {
                Verdict::Matched(true) => None,
                Verdict::Matched(false) => Some("Constraint not matched".to_string()),
                Verdict::Build(f) | Verdict::Eval(f) => Some(f.msg),
                Verdict::Unported(why) => return LibOutcome::Unported(why),
            };
            if let Some(reason) = reason {
                who(&mut log, "Library Load Constraint Rejection", &reason);
                return LibOutcome::Denied { msg: "Library violates process' library load contraint", log };
            }
        }
    }
    // 0xfffffff005ab07ac: library validation. A signature here is either
    // a trust cache's or none (no signer type is set, so none is
    // CS_SIGNER_TYPE_LEGACYVPN's 5).
    let fail = |log: &mut Vec<String>, msg: &'static str| {
        // 0xfffffff005ab0e18: overridden only for a cdhash the compilation
        // service registered, of which there are none.
        who(log, "Library Validation failed", msg);
        LibOutcome::Denied { msg, log: std::mem::take(log) }
    };
    let Some(ls) = &lib.sig else {
        return fail(&mut log, "mapped file has no cdhash, completely unsigned? Code has to be at least ad-hoc signed.");
    };
    if ls.category == 9 {
        return LibOutcome::Unported("AMFI library validation of an OOP-JIT mapping".into());
    }
    if !ls.platform_binary {
        if cur.vc().unwrap_or(0) == 1 {
            return fail(&mut log, "mapping process is a platform binary, but mapped file is not");
        }
        if cur_team != lib_team {
            return fail(&mut log, "mapping process and mapped file (non-platform) have different Team IDs");
        }
        // 0xfffffff005ab0ff0: development and production code do not mix.
        let (pv, lv) = (cur.vc().unwrap_or(0), i64::from(ls.category));
        let same = match (p.platform, pv) {
            (7 | 8 | 9 | 12, _) => true,
            (1 | 6, _) => return LibOutcome::Unported("AMFI library validation for a macOS process".into()),
            (_, 2..=5 | 7) => pv == lv,
            _ => return LibOutcome::Unported(format!("AMFI library validation of a process of validation category {pv} (the kext panics)")),
        };
        if !same {
            return fail(&mut log, "not allowing mapping of development code into production process");
        }
    }
    LibOutcome::Allowed { log }
}

/// The description's buffer (`0xfffffff005ab8954`'s allocation).
pub const DESC_LEN: usize = 0x400;

impl crate::syscalls::Kernel {
    /// `mac_proc_check_launch_constraints` (`security/mac_process.c`), from
    /// `process_signature`, for the image `exe_path` this process is
    /// starting: AMFI's hook on the process, its original parent and its
    /// responsible process, the spawn's launch type and AMFI extension. An
    /// enforced violation kills the process as `process_signature` does
    /// (`CS_KILLED`, then SIGKILL carrying `OS_REASON_CODESIGNING`'s
    /// `CODESIGNING_EXIT_REASON_LAUNCH_CONSTRAINT_VIOLATION` with the
    /// description, `GENERATE_CRASH_REPORT` and `CONSISTENT_FAILURE`); the
    /// image goes on starting and the signal takes the process before it
    /// runs. An answer this kernel cannot give as the device would is
    /// reported, and the start refused.
    pub(crate) fn darwin_launch_constraints(&mut self, exe_path: &str) -> Result<(), crate::errno::Errno> {
        use super::amfi::cs;
        use std::sync::atomic::Ordering;
        let spawn = self.dtask.exec_launch.take().unwrap_or_default();
        let csflags = self.dtask.csflags.load(Ordering::Acquire);
        let cur = Proc::Live(Live {
            pid: self.pid,
            // The process being started as pid 1 is launchd, initproc.
            is_init: self.pid == crate::proc::INIT_PID,
            platform: self.dtask.platform.0,
            csflags,
            exe: Some(self.darwin_lc_exe(exe_path)),
            sig: (csflags & cs::SIGNED != 0).then(|| self.dtask.codesign.clone().map(Arc::new)).flatten(),
        });
        let parent = self.darwin_lc_proc(self.dtask.original_ppid);
        let resp = self.darwin_lc_proc(self.dtask.responsible_pid);
        let system = System {
            apple_internal: super::sysctl::os_release_type() == b"Internal",
            developer_mode: super::amfi::DEVELOPER_MODE,
            // /chosen/osenvironment, zero on a normal boot (hw.osenvironment).
            os_environment: Vec::new(),
        };
        let input = Input { cur: &cur, parent: &parent, resp: &resp, system: &system, launch_type: spawn.launch_type, spawnattr: spawn.amfi.as_deref() };
        match check(&input) {
            Outcome::Allowed { log } => {
                self.darwin_lc_log(&log);
                Ok(())
            }
            Outcome::Violation { log, desc } => {
                self.darwin_lc_log(&log);
                if let Some(desc) = desc {
                    self.dtask.csflags.fetch_or(cs::KILLED, Ordering::AcqRel);
                    use super::reason::{flag, ns, OsReason, CODESIGNING_EXIT_REASON_LAUNCH_CONSTRAINT_VIOLATION};
                    let r = OsReason::with_desc(ns::CODESIGNING, CODESIGNING_EXIT_REASON_LAUNCH_CONSTRAINT_VIOLATION, flag::GENERATE_CRASH_REPORT | flag::CONSISTENT_FAILURE, &desc);
                    self.darwin_psignal_try_thread(super::signal::dsig::SIGKILL, Some(Arc::new(r)));
                }
                Ok(())
            }
            Outcome::Unported(what) => {
                self.darwin_unimplemented(what);
                Err(crate::errno::Errno::EPERM)
            }
        }
    }

    /// AMFI's kernel log lines, shown when tracing.
    fn darwin_lc_log(&self, log: &[String]) {
        if self.trace {
            for l in log {
                eprintln!("[gex:{}] {l}", self.pid);
            }
        }
    }

    /// An executable's vnode as the facts read it: its path (`vn_getpath`,
    /// links resolved) and whether its mount is the root volume
    /// (`MNT_ROOTFS`); unsaid for a file on a mount the kernel's list does
    /// not describe (a bind mount).
    fn darwin_lc_exe(&self, path: &str) -> (String, Option<bool>) {
        let canonical = self.vfs.canonical(&self.vfs.absolute(path));
        let mnt = super::kern::mount_of(&canonical);
        let described = self.vfs.mount_id_of(&canonical) == self.vfs.mount_id_of(mnt.on);
        let rootfs = described.then_some(mnt.flags & super::kern::MNT_ROOTFS != 0);
        (canonical, rootfs)
    }

    /// `proc_find(pid)` for the facts: the kernel's process for 0, none
    /// for one gone or a zombie, and pid 1 when it is this kernel's own.
    fn darwin_lc_proc(&self, pid: i32) -> Proc {
        use std::sync::atomic::Ordering;
        if pid == 0 {
            return Proc::Kernel;
        }
        if pid == crate::proc::INIT_PID && self.procs.virtual_init() {
            return Proc::StandIn;
        }
        match self.darwin_public(pid) {
            Some((p, false)) => {
                let csflags = p.csflags.load(Ordering::Acquire);
                let path = String::from_utf8_lossy(&p.path).into_owned();
                Proc::Live(Live {
                    pid,
                    is_init: pid == crate::proc::INIT_PID,
                    platform: p.platform,
                    csflags,
                    exe: (!path.is_empty()).then(|| self.darwin_lc_exe(&path)),
                    sig: (csflags & super::amfi::cs::SIGNED != 0).then_some(p.codesign).flatten(),
                })
            }
            Some((_, true)) | None => Proc::None(pid),
        }
    }

    /// `mac_file_check_library_validation` (`security/mac_file.c`): AMFI's
    /// hook for this process mapping the file on `vnode` at `path`, its
    /// slice at `file_start`; a refusal copies its message out
    /// (`copyoutstr`: at most `msg_size` bytes, its NUL with them when they
    /// hold it) and is EPERM.
    pub(crate) fn darwin_library_validation(&mut self, m: &mut crate::GuestMem<'_>, vnode: (u64, u64), path: &str, file_start: i64, msg: u64, msg_size: u64) -> Result<u64, crate::errno::Errno> {
        use std::sync::atomic::Ordering;
        let csflags = self.dtask.csflags.load(Ordering::Acquire);
        let cur = Proc::Live(Live {
            pid: self.pid,
            is_init: self.pid == crate::proc::INIT_PID,
            platform: self.dtask.platform.0,
            csflags,
            exe: Some(self.darwin_lc_exe(&self.exe_path.clone())),
            sig: (csflags & super::amfi::cs::SIGNED != 0).then(|| self.dtask.codesign.clone().map(Arc::new)).flatten(),
        });
        let lib = Lib { exe: self.darwin_lc_exe(path), sig: super::codesign::vnode_blob(vnode, file_start), teamid: super::codesign::vnode_teamid(vnode) };
        let system = System { apple_internal: super::sysctl::os_release_type() == b"Internal", developer_mode: super::amfi::DEVELOPER_MODE, os_environment: Vec::new() };
        match library_check(&cur, &lib, &system) {
            LibOutcome::Allowed { log } => {
                self.darwin_lc_log(&log);
                Ok(0)
            }
            LibOutcome::Denied { msg: text, log } => {
                self.darwin_lc_log(&log);
                if msg != 0 && msg_size != 0 {
                    let mut b = text.as_bytes().to_vec();
                    b.push(0);
                    b.truncate(msg_size.min(b.len() as u64) as usize);
                    // A copy that faults is logged by the kext, not failed.
                    let _ = m.write(msg, &b);
                }
                Err(crate::errno::Errno::EPERM)
            }
            LibOutcome::Unported(what) => {
                self.darwin_unimplemented(what);
                Err(crate::errno::Errno::EPERM)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_category_tables_are_valid_coreentitlements() {
        let mut log = Vec::new();
        for c in 0..0x15 {
            for t in [cc_self(c, &mut log), cc_parent(c, &mut log)].into_iter().flatten() {
                assert!(lwcr::ce_validate(t, true).is_ok(), "category {c}");
            }
        }
        assert!(log.is_empty());
    }

    fn sys() -> System {
        System { apple_internal: false, developer_mode: false, os_environment: Vec::new() }
    }

    fn live(pid: i32, sig: Option<CodeSign>) -> Proc {
        Proc::Live(Live { pid, is_init: pid == 1, platform: 2, csflags: super::super::amfi::cs::VALID | super::super::amfi::cs::SIGNED, exe: Some((format!("/bin/p{pid}"), Some(true))), sig: sig.map(Arc::new) })
    }

    #[test]
    fn a_platform_library_meets_library_validation_and_an_unsigned_one_does_not() {
        let cur = live(5, None);
        let s = sys();
        let signed = Lib { exe: ("/usr/lib/x.dylib".into(), Some(true)), sig: Some(Arc::new(CodeSign { platform_binary: true, category: 1, ..Default::default() })), teamid: None };
        assert!(matches!(library_check(&cur, &signed, &s), LibOutcome::Allowed { .. }));
        let unsigned = Lib { sig: None, ..signed };
        match library_check(&cur, &unsigned, &s) {
            LibOutcome::Denied { msg, .. } => assert_eq!(msg, "mapped file has no cdhash, completely unsigned? Code has to be at least ad-hoc signed."),
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn an_application_launch_type_takes_launchd_as_its_parent() {
        let (cur, parent, resp) = (live(5, None), live(4, None), Proc::Kernel);
        let s = sys();
        let i = Input { cur: &cur, parent: &parent, resp: &resp, system: &s, launch_type: launch_type::APPLICATION, spawnattr: None };
        match check(&i) {
            Outcome::Violation { desc: Some(d), .. } => {
                let text = String::from_utf8_lossy(&d[..d.iter().position(|&c| c == 0).unwrap()]).into_owned();
                assert_eq!(text, "Launch Constraint Violation, error info: c[7]p[2]m[3]e[255], (Caller provided a disallowed launch type) launch type 3, failure proc [vc: 0]: /bin/p4");
                assert_eq!(d.len(), DESC_LEN);
            }
            o => panic!("{o:?}"),
        }
        let parent = live(1, None);
        let i = Input { parent: &parent, ..i };
        assert!(matches!(check(&i), Outcome::Allowed { .. }));
    }
}
