//! `mach_msg2` and `mach_msg` (`osfmk/ipc/mach_msg.c`, `ipc_kmsg.c`): a
//! message read from the sender's memory, its rights and out-of-line data
//! copied in, sent or handed to the kernel object it is for, and a received
//! message copied out to the receiver's buffer with its trailer.

use super::ipc::msg::{bits, mr, opt, Desc, Kmsg, RcvWait, Received, Sender};
use super::ipc::right::{msgt, Carried, CopyinFlags};
use super::ipc::{kr, ty, Guard, ObjId, Receiver};
use super::wait::{Wait, WaitResult};
use crate::syscalls::{Kernel, SyscallOutcome};
use crate::GuestMem;
use std::time::{Duration, Instant};

/// `sizeof(mach_msg_user_header_t)`, `sizeof(mach_msg_user_base_t)`.
const HEADER: u32 = 24;
const BASE: u32 = 28;
/// `IPC_KMSG_MAX_BODY_SPACE`: 48 MiB less the largest trailer.
const MAX_BODY: u32 = 64 * 1024 * 1024 * 3 / 4 - 68;
/// `IPC_KMSG_MAX_AUX_DATA_SPACE`.
const MAX_AUX: u32 = 1024;
/// `sizeof(mach_msg_aux_header_t)`.
const AUX_HEADER: u32 = 8;
/// `IPC_KMSG_MAX_OOL_PORT_COUNT`.
const MAX_OOL_PORTS: u64 = 16383;
/// `IPC_KOBJECT_DESC_MAX`.
const KOBJECT_DESC_MAX: u32 = 3;
/// `ipc_kmsg_max_vm_space`: 7/8 of the 8 MiB kernel copy map.
const MAX_VM_SPACE: u64 = 8 * 1024 * 1024 * 7 / 8;
/// `msg_ool_size_small` (`KHEAP_MAX_SIZE` on arm64).
const OOL_SIZE_SMALL: u64 = 32 * 1024;
/// `PLATFORM_IOS`.
const PLATFORM_IOS: u32 = 2;

/// Descriptor types (`MACH_MSG_*_DESCRIPTOR`).
mod dtype {
    pub const PORT: u8 = 0;
    pub const OOL: u8 = 1;
    pub const OOL_PORTS: u8 = 2;
    pub const OOL_VOLATILE: u8 = 3;
    pub const GUARDED_PORT: u8 = 4;
}

/// `MACH_MSG_PHYSICAL_COPY`, `MACH_MSG_VIRTUAL_COPY`.
const PHYSICAL_COPY: u8 = 0;
const VIRTUAL_COPY: u8 = 1;
/// `MACH_MSG_GUARD_FLAGS_MASK`.
const GUARD_FLAGS_MASK: u32 = 0x3;

/// The options user space may pass (`MACH64_MSG_OPTION_USER`).
const OPTION_USER: u64 = opt::SEND_MSG
    | opt::SEND_TIMEOUT
    | opt::SEND_NOTIFY
    | opt::SEND_OVERRIDE
    | opt::SEND_TRAILER
    | opt::SEND_NOIMPORTANCE
    | opt::SEND_SYNC_OVERRIDE
    | opt::SEND_PROPAGATE_QOS
    | opt::SEND_FILTER_NONFATAL
    | opt::SEND_SYNC_BOOTSTRAP_CHECKIN
    | opt::MSG_STRICT_REPLY
    | opt::RCV_GUARDED_DESC
    | opt::RCV_MSG
    | opt::RCV_TIMEOUT
    | opt::RCV_LARGE
    | opt::RCV_LARGE_IDENTITY
    | opt::RCV_VOUCHER
    | (0xf << opt::RCV_TRAILER_ELEMENTS_SHIFT)
    | opt::RCV_SYNC_WAIT
    | opt::RCV_SYNC_PEEK
    | opt::MSG_VECTOR
    | opt::CFI_MASK;

/// `MACH64_MACH_MSG2`: the call came by `mach_msg2`.
const MACH_MSG2: u64 = 0x8000_0000_0000_0000;

/// A send's user context (`mach_msg_send_uctx_t`).
#[derive(Clone, Copy, Debug, Default)]
struct SendUctx {
    bits: u32,
    remote: u32,
    local: u32,
    voucher: u32,
    id: i32,
    dsc_count: u32,
    msg_addr: u64,
    msg_size: u32,
    aux_addr: u64,
    aux_size: u32,
    /// The `mach_msg_priority_t` the send passed.
    priority: u32,
}

/// What a receive put where (`mach_msg_recv_result_t`): the message's,
/// trailer's and auxiliary data's sizes, the receiving name of a message
/// too large, and the message's priority and QoS.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Msgr {
    pub msg_size: u32,
    pub trailer_size: u32,
    pub aux_size: u32,
    pub recv_name: u32,
    pub priority: u32,
    pub qos_ovrd: u8,
}

/// A receive's buffers (`mach_msg_recv_bufs_t`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecvBufs {
    pub msg_addr: u64,
    pub msg_size: u32,
    pub aux_addr: u64,
    pub aux_size: u32,
}

/// What a blocked `mach_msg` was doing when it slept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cont {
    /// Waiting for room on `port`; the receive half follows if `then`.
    Send { port: ObjId, then: Option<RecvArgs> },
    /// Waiting for a message.
    Receive { object: ObjId, bufs: RecvBufs, options: u64 },
}

/// A receive still to do after a send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecvArgs {
    pub rcv_name: u32,
    pub bufs: RecvBufs,
    pub options: u64,
    pub timeout_ms: u32,
}

/// `mach_msg_priority_qos`, `mach_msg_priority_overide_qos`: the QoS
/// fields of a `mach_msg_priority_t`, nothing past the last.
fn msg_priority_qos(p: u32) -> u8 {
    let q = (p >> 16) & 0xf;
    if q <= 6 { q as u8 } else { 0 }
}

fn msg_priority_override_qos(p: u32) -> u8 {
    let q = (p >> 20) & 0xf;
    if q <= 6 { q as u8 } else { 0 }
}

fn rd32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

fn rd64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

impl Kernel {
    /// `ipc_current_user_policy`, as far as it touches messages here: the
    /// options user space may pass.
    fn user_policy(&self, options: u64) -> u64 {
        options & OPTION_USER
    }

    /// `ipc_kmsg_set_qos`: the message's priority and QoS, from the send's
    /// override (`MACH_SEND_OVERRIDE`) or the sending thread
    /// (`MACH_SEND_PROPAGATE_QOS`). Vouchers carry no priority here: iOS's
    /// kernel has no deprecated voucher managers.
    fn kmsg_set_qos(&self, kmsg: &mut Kmsg, options: u64, priority: u32) {
        use super::thread::pp;
        if options & opt::SEND_OVERRIDE != 0 && priority & 0xff != 0xff {
            let q = msg_priority_qos(priority);
            let relpri = if q != 0 { i32::from((priority >> 8) as u8 as i8) + 1 } else { 0 };
            let ovr = msg_priority_override_qos(priority);
            kmsg.ppriority = pp::from_qos(q, relpri, 0) as u32;
            kmsg.qos_override = q.max(ovr);
        } else {
            kmsg.ppriority = if options & opt::SEND_PROPAGATE_QOS != 0 { self.ipc_current_thread_priority() } else { 0 };
            kmsg.qos_override = if options & opt::SEND_OVERRIDE != 0 {
                pp::qos(u64::from(kmsg.ppriority)).max(pp::qos(u64::from(priority)))
            } else {
                pp::qos(u64::from(kmsg.ppriority))
            };
        }
    }

    /// `ipc_get_current_thread_priority`: the calling thread's requested
    /// QoS, else the QoS its base priority would be promoted to.
    fn ipc_current_thread_priority(&self) -> u32 {
        use super::thread::pp;
        let (q, relpri) = self.darwin_thread_requested_qos(self.tid);
        let (q, relpri) = if q != 0 { (q, relpri) } else { (super::workq::promotion_qos_for_pri(self.darwin_thread_base_pri(self.tid)), 0) };
        pp::from_qos(q, relpri, 0) as u32
    }

    /// `ipc_preflight_msg_option64`.
    fn preflight(&mut self, options: u64) -> u32 {
        if options & opt::SEND_MSG != 0 && options & MACH_MSG2 != 0 {
            // SEND_ANY is macOS's only.
            let cfi = options & opt::CFI_MASK & !opt::SEND_ANY;
            let ok = cfi != 0 && cfi & (cfi - 1) == 0 && !(options & (opt::SEND_MQ_CALL | opt::SEND_ANY) == 0 && options & opt::MSG_VECTOR != 0);
            if !ok {
                self.ipc().guard_exception(0, Guard::InvalidOptions, 0);
                return mr::SEND_INVALID_OPTIONS;
            }
        }
        mr::SUCCESS
    }

    /// `mach_msg2_trap(data, options, bits|send_size, remote|local,
    /// voucher|id, desc_count|rcv_name, rcv_size|priority, timeout)`.
    pub(crate) fn darwin_mach_msg2(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> SyscallOutcome {
        let x = |m: &GuestMem<'_>, k: &Kernel, i: u8| m.read_u64(k.ctx_addr + gex_abi::ctx::x(i) as u64).unwrap_or(0);
        let (data, options, mb_ss, mr_lp, mv_id, dc_rn) = (a[0], a[1], a[2], a[3], a[4], a[5]);
        let (rs_pr, timeout) = (x(m, self, 6), x(m, self, 7) as u32);
        let options = self.user_policy(options) | MACH_MSG2;
        let r = self.preflight(options);
        if r != mr::SUCCESS {
            return self.mach_result(m, r);
        }
        let (mut msg_vec, mut aux_vec) = ([0u64; 4], [0u64; 4]);
        if options & opt::MSG_VECTOR != 0 {
            let (snd_count, rcv_count) = ((mb_ss >> 32) as u32, rs_pr as u32);
            let count = snd_count.max(rcv_count);
            let send = options & opt::SEND_MSG != 0;
            if count > 2 {
                return self.mach_result(m, if send { mr::SEND_INVALID_DATA } else { mr::RCV_INVALID_ARGUMENTS });
            }
            if count == 0 {
                return self.mach_result(m, if send { mr::SEND_MSG_TOO_SMALL } else { mr::RCV_INVALID_ARGUMENTS });
            }
            // mach_msg_vector_t: data, rcv_addr, send_size|rcv_size.
            let Ok(v) = m.read(data, 24 * count as usize).map(|b| b.to_vec()) else {
                return self.mach_result(m, if send { mr::SEND_INVALID_DATA } else { mr::RCV_INVALID_ARGUMENTS });
            };
            msg_vec = [rd64(&v, 0), rd64(&v, 8), u64::from(rd32(&v, 16)), u64::from(rd32(&v, 20))];
            if count == 2 {
                aux_vec = [rd64(&v, 24), rd64(&v, 32), u64::from(rd32(&v, 40)), u64::from(rd32(&v, 44))];
            }
        }
        let mut then = None;
        if options & opt::RCV_MSG != 0 {
            let rcv_name = (dc_rn >> 32) as u32;
            let bufs = if options & opt::MSG_VECTOR != 0 {
                let rcv_count = rs_pr as u32;
                if rcv_count == 0 {
                    return self.mach_result(m, mr::RCV_INVALID_ARGUMENTS);
                }
                let mut aux = RecvBufs { msg_addr: 0, msg_size: 0, aux_addr: 0, aux_size: 0 };
                if rcv_count == 2 {
                    let rcv_addr = if aux_vec[1] != 0 { aux_vec[1] } else { aux_vec[0] };
                    if rcv_addr == 0 || (aux_vec[3] as u32) < AUX_HEADER {
                        return self.mach_result(m, mr::RCV_INVALID_ARGUMENTS);
                    }
                    aux.aux_addr = rcv_addr;
                    aux.aux_size = aux_vec[3] as u32;
                }
                RecvBufs { msg_addr: if msg_vec[1] != 0 { msg_vec[1] } else { msg_vec[0] }, msg_size: msg_vec[3] as u32, ..aux }
            } else {
                RecvBufs { msg_addr: data, msg_size: rs_pr as u32, aux_addr: 0, aux_size: 0 }
            };
            then = Some(RecvArgs { rcv_name, bufs, options, timeout_ms: timeout });
        }
        if options & opt::SEND_MSG != 0 {
            let mut u = SendUctx {
                bits: mb_ss as u32,
                remote: mr_lp as u32,
                local: (mr_lp >> 32) as u32,
                voucher: mv_id as u32,
                id: (mv_id >> 32) as u32 as i32,
                dsc_count: dc_rn as u32,
                ..Default::default()
            };
            if options & opt::MSG_VECTOR != 0 {
                let snd_count = (mb_ss >> 32) as u32;
                if msg_vec[0] == 0 {
                    return self.mach_result(m, mr::SEND_INVALID_DATA);
                }
                u.msg_addr = msg_vec[0];
                u.msg_size = msg_vec[2] as u32;
                if u.msg_size < HEADER || u.msg_size & 3 != 0 {
                    return self.mach_result(m, mr::SEND_MSG_TOO_SMALL);
                }
                if u.msg_size > MAX_BODY {
                    return self.mach_result(m, mr::SEND_TOO_LARGE);
                }
                if snd_count == 2 {
                    u.aux_size = aux_vec[2] as u32;
                    if u.aux_size != 0 && aux_vec[0] == 0 {
                        return self.mach_result(m, mr::SEND_INVALID_DATA);
                    }
                    if u.aux_size != 0 && u.aux_size < AUX_HEADER {
                        return self.mach_result(m, mr::SEND_AUX_TOO_SMALL);
                    }
                    if u.aux_size > MAX_AUX {
                        return self.mach_result(m, mr::SEND_AUX_TOO_LARGE);
                    }
                    if u.aux_size != 0 {
                        u.aux_addr = aux_vec[0];
                    }
                }
            } else {
                u.msg_addr = data;
                u.msg_size = (mb_ss >> 32) as u32;
            }
            u.priority = (rs_pr >> 32) as u32;
            return self.mach_msg_send(m, u, options, timeout, then);
        }
        match then {
            Some(r) => self.mach_msg_receive(m, r),
            None => self.mach_result(m, mr::SUCCESS),
        }
    }

    /// `mach_msg_overwrite_trap(msg, option, send_size, rcv_size, rcv_name,
    /// timeout, priority, rcv_msg)`: the legacy trap, refused to programs
    /// built for a newer SDK (`ipc_policy_allow_legacy_send_trap`).
    pub(crate) fn darwin_mach_msg_trap(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6], overwrite: bool) -> SyscallOutcome {
        let x = |m: &GuestMem<'_>, k: &Kernel, i: u8| m.read_u64(k.ctx_addr + gex_abi::ctx::x(i) as u64).unwrap_or(0);
        let options = self.user_policy(a[1] & 0xffff_ffff);
        let (msg, send_size, rcv_size, rcv_name, timeout) = (a[0], a[2] as u32, a[3] as u32, a[4] as u32, a[5] as u32);
        let priority = x(m, self, 6) as u32;
        let rcv_msg = if overwrite { x(m, self, 7) } else { 0 };
        let mut then = None;
        if options & opt::RCV_MSG != 0 {
            let addr = if rcv_msg != 0 { rcv_msg } else { msg };
            then = Some(RecvArgs { rcv_name, bufs: RecvBufs { msg_addr: addr, msg_size: rcv_size, aux_addr: 0, aux_size: 0 }, options, timeout_ms: timeout });
        }
        if options & opt::SEND_MSG != 0 {
            // mach_msg_copyin_user_header
            if send_size < HEADER || send_size & 3 != 0 {
                return self.mach_result(m, mr::SEND_MSG_TOO_SMALL);
            }
            if send_size > MAX_BODY {
                return self.mach_result(m, mr::SEND_TOO_LARGE);
            }
            let n = if send_size < BASE { HEADER } else { BASE } as usize;
            let Ok(h) = m.read(msg, n).map(|b| b.to_vec()) else { return self.mach_result(m, mr::SEND_INVALID_DATA) };
            let mut u = SendUctx { bits: rd32(&h, 0), remote: rd32(&h, 8), local: rd32(&h, 12), voucher: rd32(&h, 16), id: rd32(&h, 20) as i32, msg_addr: msg, msg_size: send_size, ..Default::default() };
            if u.bits & bits::COMPLEX != 0 {
                if send_size < BASE {
                    return self.mach_result(m, mr::SEND_MSG_TOO_SMALL);
                }
                u.dsc_count = rd32(&h, 24);
            }
            // ipc_policy_allow_legacy_send_trap: only for iOS programs
            // built with SDK 15 or older, and a few message ids.
            let (platform, sdk) = self.dtask.platform;
            let allowed = platform == PLATFORM_IOS && sdk != 0 && sdk >> 16 <= 15 && matches!(u.id, 0xd4a | 0xd4d | 0xe13 | 0x12c4 | 0x12c8);
            if !allowed {
                self.ipc().guard_exception(u.id as u32, Guard::InvalidOptions, 0);
                return self.mach_result(m, mr::KERN_NOT_SUPPORTED);
            }
            u.priority = priority;
            return self.mach_msg_send(m, u, options, timeout, then);
        }
        match then {
            Some(r) => self.mach_msg_receive(m, r),
            None => self.mach_result(m, mr::SUCCESS),
        }
    }

    /// A `mach_msg` result in x0, the guard exceptions and notifications it
    /// raised dealt with.
    fn mach_result(&mut self, m: &mut GuestMem<'_>, r: u32) -> SyscallOutcome {
        let _ = super::set_mach_result(m, self.ctx_addr, u64::from(r));
        self.darwin_ipc_settle(m);
        SyscallOutcome::Continue
    }

    /// `mach_msg_trap_send`: copy the message in and send it; then the
    /// receive half, if asked.
    fn mach_msg_send(&mut self, m: &mut GuestMem<'_>, u: SendUctx, options: u64, timeout: u32, then: Option<RecvArgs>) -> SyscallOutcome {
        if u.msg_size < HEADER || u.msg_size & 3 != 0 {
            return self.mach_result(m, mr::SEND_MSG_TOO_SMALL);
        }
        if u.msg_size > MAX_BODY {
            return self.mach_result(m, mr::SEND_TOO_LARGE);
        }
        if u.bits & bits::COMPLEX != 0 {
            if u.msg_size < BASE {
                return self.mach_result(m, mr::SEND_MSG_TOO_SMALL);
            }
            if u.dsc_count > (u.msg_size - BASE) / 12 {
                return self.mach_result(m, mr::SEND_MSG_TOO_SMALL);
            }
        } else if u.dsc_count != 0 {
            return self.mach_result(m, mr::SEND_TOO_LARGE);
        }
        // Copying the header in may add MACH64_SEND_ALWAYS.
        let (kmsg, options) = match self.kmsg_copyin(m, u, options) {
            Ok(k) => k,
            Err(r) => return self.mach_result(m, r),
        };
        match self.kmsg_send(Box::new(kmsg), options, timeout == 0) {
            Ok(()) => {}
            Err(SendWait::Room(port)) => {
                let deadline = (options & opt::SEND_TIMEOUT != 0).then(|| Instant::now() + Duration::from_millis(u64::from(timeout)));
                let tid = self.tid;
                let me = self.ipc().waiter(tid);
                self.ipc().mqueue_wait_room(port, me);
                self.dtask.pending_send_buf.insert(self.tid, (u.msg_addr, u.msg_size));
                self.darwin_ipc_settle(m);
                return self.darwin_block(m, Wait { deadline, cont: super::thread::Finish::MachMsg(Cont::Send { port, then }) });
            }
            Err(SendWait::Failed(r, k)) => {
                let r = match k {
                    Some(k) => r | self.pseudo_receive(m, k, u.msg_addr, u.msg_size),
                    None => r,
                };
                return self.mach_result(m, r);
            }
        }
        match then {
            Some(r) => self.mach_msg_receive(m, r),
            None => self.mach_result(m, mr::SUCCESS),
        }
    }

    /// `ipc_kmsg_copyin_from_user`: the message at `u` read and its rights
    /// taken from the sender's space.
    fn kmsg_copyin(&mut self, m: &mut GuestMem<'_>, u: SendUctx, options: u64) -> Result<(Kmsg, u64), u32> {
        // ipc_validate_kmsg_header_schema_from_user
        if options & opt::SEND_KOBJECT_CALL != 0 && u.dsc_count > KOBJECT_DESC_MAX {
            return Err(mr::SEND_TOO_LARGE);
        }
        let body_len = (u.msg_size - HEADER) as usize;
        let body = m.read(u.msg_addr + u64::from(HEADER), body_len).map_err(|_| mr::SEND_INVALID_DATA)?.to_vec();
        let aux = if u.aux_size != 0 {
            let mut a = m.read(u.aux_addr, u.aux_size as usize).map_err(|_| mr::SEND_INVALID_DATA)?.to_vec();
            a[0..4].copy_from_slice(&u.aux_size.to_le_bytes());
            a[4..8].copy_from_slice(&0u32.to_le_bytes());
            a
        } else {
            Vec::new()
        };
        // Measure and check the descriptors (ipc_kmsg_measure_descriptors
        // and the inflate checks) before any right moves.
        let mut port_count = 0u64;
        let mut vm_size = 0u64;
        let mut descs_raw = Vec::new();
        let mut pos = if u.bits & bits::COMPLEX != 0 { 4usize } else { 0 };
        for _ in 0..u.dsc_count {
            if pos + 12 > body.len() {
                return Err(mr::SEND_MSG_TOO_SMALL);
            }
            let t = body[pos + 11];
            let valid = match t {
                dtype::PORT | dtype::OOL | dtype::OOL_PORTS => true,
                dtype::OOL_VOLATILE | dtype::GUARDED_PORT => options & (opt::SEND_KOBJECT_CALL | opt::SEND_DK_CALL) == 0,
                _ => false,
            };
            if !valid {
                return Err(mr::SEND_INVALID_TYPE);
            }
            let size = if t == dtype::PORT { 12 } else { 16 };
            if pos + size > body.len() {
                return Err(mr::SEND_MSG_TOO_SMALL);
            }
            match t {
                dtype::PORT => port_count += 1,
                dtype::OOL | dtype::OOL_VOLATILE => {
                    let (len, dealloc, copy) = (u64::from(rd32(&body, pos + 12)), body[pos + 8], body[pos + 9]);
                    if copy != PHYSICAL_COPY && copy != VIRTUAL_COPY {
                        return Err(mr::SEND_INVALID_TYPE);
                    }
                    if len > OOL_SIZE_SMALL && copy == PHYSICAL_COPY && dealloc == 0 {
                        vm_size += (len + 0x3fff) & !0x3fff;
                    }
                }
                dtype::OOL_PORTS => port_count += u64::from(rd32(&body, pos + 12)),
                dtype::GUARDED_PORT => {
                    port_count += 1;
                    let (flags, disp, context) = (u32::from(u16::from_le_bytes([body[pos + 8], body[pos + 9]])), u32::from(body[pos + 10]), rd64(&body, pos));
                    if disp != msgt::MOVE_RECEIVE {
                        return Err(mr::SEND_INVALID_TYPE);
                    }
                    if flags == 0 || flags & !GUARD_FLAGS_MASK != 0 || (flags & super::ipc::right::guard_flags::UNGUARDED_ON_SEND != 0 && context != 0) {
                        return Err(mr::SEND_INVALID_TYPE);
                    }
                }
                _ => unreachable!(),
            }
            descs_raw.push((pos, t));
            pos += size;
        }
        // ipc_validate_kmsg_schema_from_user
        if port_count > MAX_OOL_PORTS {
            return Err(mr::SEND_TOO_LARGE);
        }
        if vm_size + port_count * 8 > MAX_VM_SPACE {
            return Err(mr::MSG_VM_KERNEL);
        }
        let (dest, reply, voucher, out_bits, options) = self.kmsg_copyin_header(u, options)?;
        // ipc_validate_kmsg_header_from_user: the destination's kind must
        // match the call's.
        if options & MACH_MSG2 != 0 {
            let r = self.validate_dest(dest, options, reply.is_some());
            if r != mr::SUCCESS {
                self.ipc().guard_exception(0, Guard::InvalidOptions, 0);
                self.clean_header(dest, out_bits, reply, voucher);
                return Err(r);
            }
        }
        if port_count != 0 && self.ipc().port(dest).no_grant {
            self.clean_header(dest, out_bits, reply, voucher);
            return Err(0x1000_0016);
        }
        let mut kmsg = Kmsg { bits: out_bits, size: u.msg_size, dest, reply, voucher, voucher_raw: u.voucher, id: u.id, body, descs: Vec::new(), sender: self.darwin_sender(), aux, keep_alive: false, ppriority: 0, qos_override: 0 };
        self.kmsg_set_qos(&mut kmsg, options, u.priority);
        if u.bits & bits::COMPLEX != 0 {
            // A message to a dead port or to a kernel object may carry
            // immovable send rights.
            let p = self.ipc().port(dest);
            let allow_imm_send = !p.active || p.receiver == Receiver::Kernel;
            if let Err(r) = self.kmsg_copyin_body(m, &mut kmsg, &descs_raw, allow_imm_send) {
                self.clean_header(dest, out_bits, reply, voucher);
                return Err(r);
            }
        }
        Ok((kmsg, options))
    }

    /// `ipc_validate_kmsg_dest_from_user` on iOS.
    fn validate_dest(&mut self, dest: ObjId, options: u64, has_reply: bool) -> u32 {
        let p = self.ipc().port(dest);
        match &p.kobject {
            Some(super::ipc::Kobject::Timer) => mr::SEND_INVALID_OPTIONS,
            // A thread's kernel reply port is no kernel object
            // (IKOT_NONE): its messages queue for the kernel's receive.
            Some(super::ipc::Kobject::RpcReply(_)) if options & opt::SEND_MQ_CALL == 0 => mr::SEND_INVALID_OPTIONS,
            Some(super::ipc::Kobject::RpcReply(_)) => mr::SUCCESS,
            Some(_) => {
                if options & opt::SEND_KOBJECT_CALL == 0 {
                    return mr::SEND_INVALID_OPTIONS;
                }
                if options & opt::RCV_MSG == 0 {
                    // ipc_policy_allow_send_only_kobject_calls: iOS SDK 17
                    // and older, from a task that is not hardened.
                    let (platform, sdk) = self.dtask.platform;
                    let allowed = platform == PLATFORM_IOS && sdk != 0 && sdk >> 16 <= 17;
                    if self.darwin_hardened() || has_reply || !allowed {
                        return mr::SEND_INVALID_OPTIONS;
                    }
                }
                mr::SUCCESS
            }
            None if options & opt::SEND_MQ_CALL == 0 => mr::SEND_INVALID_OPTIONS,
            None => mr::SUCCESS,
        }
    }

    /// The sending task's tokens (`task_get_sec_token`,
    /// `task_get_audit_token`).
    fn darwin_sender(&self) -> Sender {
        Sender { sec: [self.creds.uid(), self.creds.gid()], audit: self.darwin_audit_token() }
    }

    /// Undo a header copyin (`ipc_kmsg_clean_header`).
    fn clean_header(&mut self, dest: ObjId, b: u32, reply: Option<Carried>, voucher: Option<ObjId>) {
        let ipc = &mut self.ipc();
        ipc.object_destroy(Carried::Port(dest), bits::remote(b));
        if let Some(r) = reply {
            ipc.object_destroy(r, bits::local(b));
        }
        if let Some(v) = voucher {
            ipc.object_destroy(Carried::Port(v), msgt::PORT_SEND);
        }
    }

    /// `ipc_kmsg_copyin_header`: the destination, reply and voucher rights
    /// taken from the space.
    fn kmsg_copyin_header(&mut self, u: SendUctx, options: u64) -> Result<(ObjId, Option<Carried>, Option<ObjId>, u32, u64), u32> {
        let mbits = u.bits & bits::USER;
        let (dest_name, reply_name) = (u.remote, u.local);
        let (dest_type, reply_type, mut voucher_type) = (bits::remote(mbits), bits::local(mbits), bits::voucher(mbits));
        let reply_ok = |t: u32, n: u32| if t == 0 { n == 0 } else { msgt::any_send(t) };
        if mbits != u.bits || !msgt::any_send(dest_type) || !reply_ok(reply_type, reply_name) {
            return Err(mr::SEND_INVALID_HEADER);
        }
        if !super::ipc::name_valid(dest_name) {
            return Err(mr::SEND_INVALID_DEST);
        }
        let ipc = &mut self.ipc();
        let mut voucher_name = 0;
        if voucher_type != 0 {
            voucher_name = u.voucher;
            if voucher_name == super::ipc::PORT_DEAD || (voucher_type != msgt::MOVE_SEND && voucher_type != msgt::COPY_SEND) {
                ipc.guard_exception(voucher_name, Guard::SendInvalidVoucher, 0);
                return Err(mr::SEND_INVALID_VOUCHER);
            }
            if voucher_name != 0 {
                let ok = ipc.space.lookup(voucher_name).is_some_and(|e| e.bits & ty::SEND != 0 && e.object.is_some_and(|o| ipc.is_port(o) && matches!(ipc.port(o).kobject, Some(super::ipc::Kobject::Voucher(_)))));
                if !ok {
                    ipc.guard_exception(voucher_name, Guard::SendInvalidVoucher, 0);
                    return Err(mr::SEND_INVALID_VOUCHER);
                }
            } else {
                voucher_type = msgt::MOVE_SEND;
            }
        }
        let dest_flags = CopyinFlags { allow_reply_make_send_once: true, allow_reply_move_send_once: true, ..Default::default() };
        let reply_flags = CopyinFlags { allow_reply_make_send_once: true, deadok: true, ..Default::default() };
        let invalid_reply = |ipc: &mut super::ipc::Ipc| {
            ipc.guard_exception(reply_name, Guard::SendInvalidReply, 0);
            Err(mr::SEND_INVALID_REPLY)
        };
        let (dest, reply, voucher, mut sorights);
        if dest_name == voucher_name {
            if ipc.space.lookup(dest_name).is_none() {
                return Err(mr::SEND_INVALID_DEST);
            }
            if super::ipc::name_valid(reply_name) {
                if voucher_name == reply_name || ipc.space.lookup(reply_name).is_none() || !self.copyin_check_reply(reply_name, reply_type, dest_name) {
                    return invalid_reply(&mut self.ipc());
                }
            }
            let ipc = &mut self.ipc();
            let (d, so) = ipc.right_copyin_two(dest_name, dest_type, voucher_type).map_err(|_| mr::SEND_INVALID_DEST)?;
            dest = d;
            sorights = vec![(so, dest_name)];
            voucher = match d {
                Carried::Port(p) => Some(p),
                Carried::Dead => None,
            };
            if let Carried::Port(p) = d {
                ipc.copy_send(p);
            }
            reply = if super::ipc::name_valid(reply_name) {
                let (r, so2) = ipc.right_copyin(reply_name, reply_type, reply_flags, 0, None).expect("reply checked");
                sorights.push((so2, reply_name));
                Some(r)
            } else {
                (reply_name != 0).then_some(Carried::Dead)
            };
        } else if dest_name == reply_name {
            if ipc.space.lookup(dest_name).is_none() {
                return Err(mr::SEND_INVALID_DEST);
            }
            if dest_type == msgt::MOVE_SEND_ONCE || reply_type == msgt::MOVE_SEND_ONCE {
                return Err(mr::SEND_INVALID_DEST);
            }
            if !self.copyin_check_reply(reply_name, reply_type, dest_name) {
                return invalid_reply(&mut self.ipc());
            }
            let ipc = &mut self.ipc();
            let (d, so) = match ipc.right_copyin_two(dest_name, dest_type, reply_type) {
                Ok(v) => v,
                Err(e) if e == kr::INVALID_CAPABILITY => return invalid_reply(ipc),
                Err(_) => return Err(mr::SEND_INVALID_DEST),
            };
            dest = d;
            reply = Some(d);
            sorights = vec![(so, dest_name)];
            voucher = None;
            let _ = &mut voucher_type;
        } else {
            if ipc.space.lookup(dest_name).is_none() {
                return Err(mr::SEND_INVALID_DEST);
            }
            if super::ipc::name_valid(reply_name) {
                if reply_name == voucher_name || ipc.space.lookup(reply_name).is_none() || !self.copyin_check_reply(reply_name, reply_type, dest_name) {
                    return invalid_reply(&mut self.ipc());
                }
            }
            let ipc = &mut self.ipc();
            let f = CopyinFlags { allow_immovable_send: true, allow_dead_send_once: true, ..dest_flags };
            let (d, so) = ipc.right_copyin(dest_name, dest_type, f, 0, None).map_err(|_| mr::SEND_INVALID_DEST)?;
            dest = d;
            sorights = vec![(so, dest_name)];
            reply = if super::ipc::name_valid(reply_name) {
                let (r, so2) = ipc.right_copyin(reply_name, reply_type, reply_flags, 0, None).expect("reply checked");
                sorights.push((so2, reply_name));
                Some(r)
            } else {
                (reply_name != 0).then_some(Carried::Dead)
            };
            voucher = if voucher_name != 0 {
                let (v, so3) = ipc.right_copyin(voucher_name, voucher_type, CopyinFlags::default(), 0, None).expect("voucher checked");
                sorights.push((so3, voucher_name));
                match v {
                    Carried::Port(p) => Some(p),
                    Carried::Dead => None,
                }
            } else {
                None
            };
        }
        let ipc = &mut self.ipc();
        for (so, name) in sorights {
            if let Some(to) = so {
                ipc.outbox.push(super::ipc::Notify::PortDeleted { to, name });
            }
        }
        let Carried::Port(dport) = dest else {
            // A dead destination: the message goes nowhere.
            return Err(mr::SEND_INVALID_DEST);
        };
        // MACH_SEND_NOTIFY on a full port arms its send-possible request.
        let mut opts = options;
        if options & opt::SEND_NOTIFY != 0 && bits::remote(mbits) != msgt::MOVE_SEND_ONCE {
            if let Some(e) = ipc.space.lookup(dest_name).copied() {
                if e.request != 0 && ipc.port(dport).active && ipc.port(dport).receiver != Receiver::Kernel {
                    if ipc.port(dport).msgcount >= ipc.port(dport).qlimit {
                        let qos_ovr = if u.priority & 0xff == 0xff { super::thread::pp::qos(u64::from(u.priority)) } else { msg_priority_override_qos(u.priority) };
                        ipc.request_sparm(dport, e.request, options, qos_ovr);
                    } else {
                        // The port has room: the request armed now cannot
                        // be missed, so the send ignores the limit.
                        opts |= opt::SEND_ALWAYS;
                    }
                }
            }
        }
        let dt = msgt::copyin_type(dest_type);
        let rt = msgt::copyin_type(reply_type);
        let vt = if voucher.is_some() { msgt::MOVE_SEND } else { voucher_type };
        Ok((dport, reply, voucher, bits::set(dt, rt, vt, mbits), opts))
    }

    /// `ipc_right_copyin_check_reply`.
    fn copyin_check_reply(&mut self, reply_name: u32, reply_type: u32, dest_name: u32) -> bool {
        let ipc = &mut self.ipc();
        let Some(re) = ipc.space.lookup(reply_name).copied() else { return false };
        let b = re.bits;
        match reply_type {
            msgt::MAKE_SEND | msgt::MAKE_SEND_ONCE => {
                if b & ty::RECEIVE == 0 {
                    return false;
                }
            }
            msgt::MOVE_RECEIVE => return false,
            msgt::COPY_SEND | msgt::MOVE_SEND | msgt::MOVE_SEND_ONCE => {
                if b & ty::DEAD_NAME == 0 {
                    if b & ty::SEND_RIGHTS == 0 {
                        return false;
                    }
                    let rp = re.object.expect("a port");
                    if ipc.port(rp).active {
                        if ipc.port(rp).immovable_send {
                            ipc.guard_exception(reply_name, Guard::Immovable, 0);
                            return false;
                        }
                        let need = if reply_type == msgt::MOVE_SEND_ONCE { ty::SEND_ONCE } else { ty::SEND };
                        if b & need == 0 {
                            return false;
                        }
                    }
                }
            }
            _ => panic!("ipc_right_copyin_check: strange rights {reply_type}"),
        }
        let de = ipc.space.lookup(dest_name).copied();
        if de.is_some_and(|d| d.ty() == ty::PORT_SET) || re.ty() == ty::PORT_SET {
            return true;
        }
        if let Some(rp) = re.object.filter(|&o| ipc.is_port(o)) {
            if ipc.port(rp).active {
                use super::ipc::ReplySemantics as Rs;
                let rs = ipc.port(rp).reply_semantics;
                if rs == Rs::ReplyPort && reply_type != msgt::MAKE_SEND_ONCE {
                    return false;
                }
                // ip_violates_reply_port_semantics: a destination that
                // enforces them takes a reply port, or a provisional one,
                // as the reply (reply_port_semantics is on). A rigid
                // destination's violations are only counted.
                if let Some(dp) = de.and_then(|d| d.object).filter(|&o| ipc.is_port(o)) {
                    if ipc.port(dp).active && ipc.port(dp).reply_semantics == Rs::Enforce && rs != Rs::ReplyPort && rs != Rs::Provisional {
                        ipc.guard_exception(reply_name, Guard::RequireReplyPortSemantics, 0);
                        return false;
                    }
                }
            }
        }
        true
    }

    /// `ipc_kmsg_copyin_body`: each descriptor's rights and memory.
    fn kmsg_copyin_body(&mut self, m: &mut GuestMem<'_>, kmsg: &mut Kmsg, raw: &[(usize, u8)], allow_imm_send: bool) -> Result<(), u32> {
        let flags = CopyinFlags { allow_immovable_send: allow_imm_send, allow_conn_immovable_receive: true, ..Default::default() };
        for &(off, t) in raw {
            let b = &kmsg.body;
            let d = match t {
                dtype::PORT => {
                    let (name, disp) = (rd32(b, off), u32::from(b[off + 10]));
                    let r = self.copyin_desc_right(name, disp, 0, None, flags);
                    match r {
                        Ok(right) => Desc::Port { off, right, raw: name, disp: msgt::copyin_type(disp) },
                        Err(e) => {
                            self.ipc().descs_destroy(&kmsg.descs);
                            return Err(e);
                        }
                    }
                }
                dtype::OOL | dtype::OOL_VOLATILE => {
                    let (addr, len, dealloc, copy) = (rd64(b, off), rd32(b, off + 12), b[off + 8], b[off + 9]);
                    let data = if len == 0 {
                        Vec::new()
                    } else {
                        match m.read(addr, len as usize) {
                            Ok(d) => d.to_vec(),
                            Err(_) => {
                                self.ipc().descs_destroy(&kmsg.descs);
                                return Err(mr::SEND_INVALID_MEMORY);
                            }
                        }
                    };
                    // vm_map_copyin with src_destroy: the sender's pages go
                    // when it asked them to.
                    if dealloc != 0 && len != 0 && !(u64::from(len) > OOL_SIZE_SMALL && copy == PHYSICAL_COPY && dealloc == 0) {
                        let _ = self.darwin_vm_deallocate(m, addr, u64::from(len));
                    }
                    Desc::Ool { off, data, copy }
                }
                dtype::OOL_PORTS => {
                    let (addr, dealloc, copy, disp, count) = (rd64(b, off), b[off + 8], b[off + 9], u32::from(b[off + 10]), rd32(b, off + 12));
                    let names: Vec<u32> = match m.read(addr, 4 * count as usize) {
                        Ok(n) => n.chunks(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect(),
                        Err(_) => {
                            self.ipc().descs_destroy(&kmsg.descs);
                            return Err(mr::SEND_INVALID_MEMORY);
                        }
                    };
                    if dealloc != 0 {
                        let _ = self.darwin_vm_deallocate(m, addr, 4 * u64::from(count));
                    }
                    let mut rights = Vec::with_capacity(names.len());
                    for &n in &names {
                        match self.copyin_desc_right(n, disp, 0, None, flags) {
                            Ok(r) => rights.push((r, n)),
                            Err(e) => {
                                let rt = msgt::copyin_type(disp);
                                for (r, _) in rights {
                                    if let Some(r) = r {
                                        self.ipc().object_destroy(r, rt);
                                    }
                                }
                                self.ipc().descs_destroy(&kmsg.descs);
                                return Err(e);
                            }
                        }
                    }
                    Desc::OolPorts { off, rights, disp: msgt::copyin_type(disp), copy }
                }
                dtype::GUARDED_PORT => {
                    let (context, mut gflags, disp, name) = (rd64(b, off), u32::from(u16::from_le_bytes([b[off + 8], b[off + 9]])), u32::from(b[off + 10]), rd32(b, off + 12));
                    match self.copyin_desc_right(name, disp, context, Some(&mut gflags), flags) {
                        Ok(right) => Desc::Guarded { off, right, raw: name, disp: msgt::copyin_type(disp), flags: gflags },
                        Err(e) => {
                            self.ipc().descs_destroy(&kmsg.descs);
                            return Err(e);
                        }
                    }
                }
                _ => unreachable!(),
            };
            kmsg.descs.push(d);
        }
        Ok(())
    }

    /// One descriptor's right (`ipc_kmsg_copyin_port_descriptor`): a valid
    /// name's right taken, any other name carried as it is.
    fn copyin_desc_right(&mut self, name: u32, disp: u32, context: u64, guard: Option<&mut u32>, flags: CopyinFlags) -> Result<Option<Carried>, u32> {
        if !super::ipc::name_valid(name) {
            return Ok(None);
        }
        match self.ipc().object_copyin(name, disp, flags, context, guard) {
            Ok(c) => Ok(Some(c)),
            Err(e) => {
                if e == kr::INVALID_RIGHT {
                    self.ipc().guard_exception(name, Guard::SendInvalidRight, 0);
                }
                Err(mr::SEND_INVALID_RIGHT)
            }
        }
    }

    /// `ipc_kmsg_send`: to a dead port the message is destroyed and the
    /// send succeeds; to a kernel object, the object's server answers; else
    /// it is queued or handed to a receiver.
    fn kmsg_send(&mut self, mut kmsg: Box<Kmsg>, options: u64, timeout_zero: bool) -> Result<(), SendWait> {
        if let Some(vp) = kmsg.voucher {
            kmsg.voucher = Some(self.ipc_voucher_send_preprocessing(vp));
        }
        let port = kmsg.dest;
        let ipc = &mut self.ipc();
        if !ipc.port(port).active {
            ipc.release(port);
            ipc.kmsg_destroy(kmsg, true);
            return Ok(());
        }
        if ipc.port(port).receiver == Receiver::Kernel {
            let owner = ipc.port(port).owner;
            if owner != 0 && owner != ipc.task {
                // ipc_kobject_server, for another task's object: its kernel
                // holds the object's state, and serves the request.
                let caller = ipc.task;
                if !ipc.remote(owner, super::ipc::Remote::Kobject { kmsg, options, caller }) {
                    unreachable!("an active kernel port's task has its link");
                }
                return Ok(());
            }
            return self.kobject_send(port, kmsg, options, timeout_zero);
        }
        self.mqueue_send(kmsg, options, timeout_zero)
    }

    /// `ipc_kobject_server` for a request to this task's (or the kernel's)
    /// object `port`, and the reply sent.
    fn kobject_send(&mut self, port: ObjId, kmsg: Box<Kmsg>, options: u64, timeout_zero: bool) -> Result<(), SendWait> {
        if let Some(super::ipc::Kobject::RpcReply(tid)) = self.ipc().port(port).kobject {
            self.darwin_rpc_reply_arrived(port, tid, kmsg);
            return Ok(());
        }
        {
            let ipc = &mut self.ipc();
            ipc.port_mut(port).seqno = ipc.port(port).seqno.wrapping_add(1);
            let Some(reply) = self.kobject_server(port, kmsg) else { return Ok(()) };
            let rport = reply.dest;
            let ipc = &mut self.ipc();
            if !ipc.port(rport).active {
                ipc.release(rport);
                ipc.kmsg_destroy(reply, true);
                return Ok(());
            }
            // A kernel reply that cannot be queued is destroyed.
            match self.mqueue_send(reply, options | opt::SEND_ALWAYS, timeout_zero) {
                Err(SendWait::Failed(_, Some(k))) => {
                    let ipc = &mut self.ipc();
                    ipc.release(k.dest);
                    ipc.kmsg_destroy(k, true);
                    Ok(())
                }
                _ => Ok(()),
            }
        }
    }

    /// `ipc_mqueue_send_locked` and the post.
    fn mqueue_send(&mut self, kmsg: Box<Kmsg>, options: u64, timeout_zero: bool) -> Result<(), SendWait> {
        let port = kmsg.dest;
        let send_once = bits::remote(kmsg.bits) == msgt::PORT_SEND_ONCE;
        match self.ipc().mqueue_reserve(port, send_once, options, timeout_zero) {
            Ok(()) => {
                let size = kmsg.size;
                self.ipc().mqueue_post(port, kmsg, size);
                Ok(())
            }
            Err(Some(r)) => Err(SendWait::Failed(r, Some(kmsg))),
            Err(None) => {
                self.dtask.pending_send.insert(self.tid, kmsg);
                Err(SendWait::Room(port))
            }
        }
    }

    /// `mach_msg_trap_receive`: receive on `r.rcv_name`, or wait.
    fn mach_msg_receive(&mut self, m: &mut GuestMem<'_>, r: RecvArgs) -> SyscallOutcome {
        let object = match self.ipc().mqueue_copyin(r.rcv_name) {
            Ok(o) => o,
            Err(e) => return self.mach_result(m, e),
        };
        let w = RcvWait { object, options: r.options, rcv_size: r.bufs.msg_size, aux_size: r.bufs.aux_size };
        let size_of = |k: &Kmsg| k.size;
        let tid = self.tid;
        let me = self.ipc().waiter(tid);
        match self.ipc().mqueue_receive(me, object, w, r.timeout_ms == 0, &size_of) {
            Some(rcv) => {
                let res = self.receive_results(m, object, rcv, r.bufs, r.options);
                self.mach_result(m, res)
            }
            None => {
                let deadline = (r.options & opt::RCV_TIMEOUT != 0).then(|| Instant::now() + Duration::from_millis(u64::from(r.timeout_ms)));
                self.darwin_ipc_settle(m);
                self.darwin_block(m, Wait { deadline, cont: super::thread::Finish::MachMsg(Cont::Receive { object, bufs: r.bufs, options: r.options }) })
            }
        }
    }

    /// A blocked `mach_msg` has woken.
    pub(crate) fn darwin_mach_msg_wait_done(&mut self, m: &mut GuestMem<'_>, c: Cont, res: WaitResult) -> Option<SyscallOutcome> {
        let tid = self.tid;
        let me = self.ipc().waiter(tid);
        match c {
            Cont::Send { port, then } => {
                let ready = self.ipc().queues.send_ready.remove(&me);
                let kmsg = self.dtask.pending_send.remove(&tid).expect("a waiting send keeps its message");
                let r = match (res, ready) {
                    (WaitResult::Awakened, Some(true)) => {
                        let size = kmsg.size;
                        self.ipc().mqueue_post(port, kmsg, size);
                        mr::SUCCESS
                    }
                    (WaitResult::Awakened, _) | (WaitResult::Restart, _) => {
                        self.ipc().mqueue_cancel_room(port, me);
                        let ipc = &mut self.ipc();
                        ipc.release(port);
                        ipc.kmsg_destroy(kmsg, true);
                        mr::SUCCESS
                    }
                    (WaitResult::TimedOut | WaitResult::Interrupted, _) => {
                        self.ipc().mqueue_cancel_room(port, me);
                        let r = if res == WaitResult::TimedOut { mr::SEND_TIMED_OUT } else { mr::SEND_INTERRUPTED };
                        let (addr, size) = self.dtask.pending_send_buf.remove(&tid).expect("a waiting send keeps its buffer");
                        r | self.pseudo_receive(m, kmsg, addr, size)
                    }
                };
                self.dtask.pending_send_buf.remove(&tid);
                if r == mr::SUCCESS {
                    if let Some(rcv) = then {
                        self.darwin_ipc_settle(m);
                        return match self.mach_msg_receive(m, rcv) {
                            out @ SyscallOutcome::Blocking(_) => Some(out),
                            _ => None,
                        };
                    }
                }
                let _ = super::set_mach_result(m, self.ctx_addr, u64::from(r));
            }
            Cont::Receive { object, bufs, options } => {
                let got = self.ipc().queues.received.remove(&me);
                let rcv = match (got, res) {
                    (Some(r), _) => r,
                    (None, res) => {
                        self.ipc().mqueue_cancel_receive(me);
                        let state = match res {
                            WaitResult::TimedOut => mr::RCV_TIMED_OUT,
                            WaitResult::Interrupted => mr::RCV_INTERRUPTED,
                            _ => mr::RCV_PORT_CHANGED,
                        };
                        Received { state, kmsg: None, seqno: 0, msize: 0, asize: 0, receiver_name: 0 }
                    }
                };
                let r = self.receive_results(m, object, rcv, bufs, options);
                let _ = super::set_mach_result(m, self.ctx_addr, u64::from(r));
            }
        }
        self.darwin_ipc_settle(m);
        None
    }

    /// `mach_msg_receive_results`.
    fn receive_results(&mut self, m: &mut GuestMem<'_>, object: ObjId, rcv: Received, bufs: RecvBufs, options: u64) -> u32 {
        self.receive_results_msgr(m, object, rcv, bufs, options).0
    }

    /// `mach_msg_receive_results`, with what it put where.
    pub(crate) fn receive_results_msgr(&mut self, m: &mut GuestMem<'_>, object: ObjId, rcv: Received, bufs: RecvBufs, options: u64) -> (u32, Msgr) {
        self.ipc().release(object);
        let mut msgr = Msgr::default();
        let mut r = rcv.state;
        if r == mr::RCV_TOO_LARGE {
            msgr.msg_size = rcv.msize;
            msgr.aux_size = rcv.asize;
            msgr.recv_name = rcv.receiver_name;
            if options & opt::RCV_LARGE != 0 {
                // mach_msg_receive_too_large: a linear vector receive has
                // the sizes in its result alone; another gets the size,
                // and the port's name with MACH_RCV_LARGE_IDENTITY.
                if options & opt::RCV_LINEAR_VECTOR != 0 {
                    return (r, msgr);
                }
                if options & opt::RCV_LARGE_IDENTITY != 0 && bufs.msg_size >= 16 && m.write_u32(bufs.msg_addr + 12, rcv.receiver_name).is_err() {
                    r = mr::RCV_INVALID_DATA;
                }
                if bufs.msg_size >= 8 && m.write_u32(bufs.msg_addr + 4, rcv.msize).is_err() {
                    r = mr::RCV_INVALID_DATA;
                }
                if bufs.aux_addr != 0 && m.write_u32(bufs.aux_addr, rcv.asize).is_err() {
                    r = mr::RCV_INVALID_DATA;
                }
                return (r, msgr);
            }
            let kmsg = rcv.kmsg.expect("a too-large message taken off the queue");
            let r = self.receive_error(m, kmsg, rcv.seqno, bufs, options, r, &mut msgr);
            return (r, msgr);
        }
        if r != mr::SUCCESS {
            return (r, msgr);
        }
        let mut kmsg = rcv.kmsg.expect("a received message");
        if options & opt::RCV_VOUCHER != 0 {
            // ipc_importance_receive, then ipc_voucher_receive_postprocessing.
            if let Some(vp) = kmsg.voucher {
                let vp = self.ipc_importance_receive_voucher(Some(vp)).expect("a voucher");
                kmsg.bits |= msgt::MOVE_SEND << 16;
                kmsg.voucher = Some(self.ipc_voucher_receive_postprocessing(vp));
            }
        }
        let context = self.ipc().port(kmsg.dest).context;
        let (priority, qos_ovrd) = (kmsg.ppriority, kmsg.qos_override);
        let r = match self.kmsg_copyout(m, *kmsg, options) {
            Ok(out) => {
                msgr.priority = priority;
                msgr.qos_ovrd = qos_ovrd;
                self.put_to_user(m, out, rcv.seqno, context, bufs, options, mr::SUCCESS, &mut msgr)
            }
            Err((out, e)) => self.put_to_user(m, out, rcv.seqno, context, bufs, options, e, &mut msgr),
        };
        (r, msgr)
    }

    /// `mach_msg_receive_error`: the message's header copied out with its
    /// body's rights destroyed (`ipc_kmsg_copyout_dest_to_user`), then put.
    #[allow(clippy::too_many_arguments)]
    fn receive_error(&mut self, m: &mut GuestMem<'_>, kmsg: Box<Kmsg>, seqno: u32, bufs: RecvBufs, options: u64, r: u32, msgr: &mut Msgr) -> u32 {
        let k = *kmsg;
        let ipc = &mut self.ipc();
        let dest_name = if ipc.port(k.dest).active {
            ipc.object_copyout_dest(k.dest, bits::remote(k.bits))
        } else {
            ipc.release(k.dest);
            super::ipc::PORT_DEAD
        };
        let reply_name = match k.reply {
            Some(c) => {
                ipc.object_destroy(c, bits::local(k.bits));
                0
            }
            None => 0,
        };
        if let Some(v) = k.voucher {
            ipc.object_destroy(Carried::Port(v), msgt::PORT_SEND);
        }
        ipc.descs_destroy(&k.descs);
        let mut body = k.body.clone();
        for d in &k.descs {
            match d {
                Desc::Port { off, .. } => body[*off..*off + 4].copy_from_slice(&0u32.to_le_bytes()),
                Desc::Guarded { off, .. } => body[*off + 12..*off + 16].copy_from_slice(&0u32.to_le_bytes()),
                Desc::Ool { off, .. } | Desc::OolPorts { off, .. } => {
                    body[*off..*off + 8].copy_from_slice(&0u64.to_le_bytes());
                    if matches!(d, Desc::Ool { .. }) {
                        body[*off + 12..*off + 16].copy_from_slice(&0u32.to_le_bytes());
                    }
                }
            }
        }
        let header_bits = bits::set(bits::local(k.bits), bits::remote(k.bits), 0, k.bits);
        let out = Out { bits: header_bits, remote: reply_name, local: dest_name, voucher: 0, id: k.id, body, sender: k.sender, aux: k.aux };
        let context = 0;
        self.put_to_user(m, out, seqno, context, bufs, options, r, msgr)
    }

    /// `ipc_kmsg_copyout`: header and body into the receiver's space.
    fn kmsg_copyout(&mut self, m: &mut GuestMem<'_>, k: Kmsg, options: u64) -> Result<Out, (Out, u32)> {
        let ipc = &mut self.ipc();
        let (dest_type, reply_type, voucher_type) = (bits::remote(k.bits), bits::local(k.bits), bits::voucher(k.bits));
        // ipc_kmsg_copyout_header
        ipc.spnotify(k.dest);
        let mut reply_name = 0;
        let mut rt = reply_type;
        if let Some(r) = k.reply {
            reply_name = match r {
                Carried::Port(p) if ipc.port(p).active => match ipc.object_copyout(r, reply_type, None) {
                    Ok(n) => n,
                    Err(_) => super::ipc::PORT_DEAD,
                },
                Carried::Port(p) => {
                    ipc.port_mut(p).reply_context = 0;
                    ipc.object_destroy(r, reply_type);
                    super::ipc::PORT_DEAD
                }
                Carried::Dead => super::ipc::PORT_DEAD,
            };
        } else {
            rt = reply_type;
        }
        let mut vt = voucher_type;
        let voucher_name = match k.voucher {
            Some(v) if options & opt::RCV_VOUCHER != 0 => ipc.object_copyout(Carried::Port(v), msgt::PORT_SEND, None).unwrap_or(0),
            Some(v) => {
                vt = 0;
                ipc.object_destroy(Carried::Port(v), msgt::PORT_SEND);
                0
            }
            None if vt != 0 => {
                if options & opt::RCV_VOUCHER == 0 {
                    vt = 0;
                }
                0
            }
            None => k.voucher_raw,
        };
        let dest_name = if ipc.port(k.dest).active {
            ipc.object_copyout_dest(k.dest, dest_type)
        } else {
            let dts = ipc.port(k.dest).timestamp;
            ipc.release(k.dest);
            match k.reply {
                Some(Carried::Port(r)) if ipc.objects.contains_key(&r) && (ipc.port(r).active || dts.wrapping_sub(ipc.port(r).timestamp) as i32 <= 0) => super::ipc::PORT_DEAD,
                Some(Carried::Port(_)) => 0,
                _ => super::ipc::PORT_DEAD,
            }
        };
        let header_bits = bits::set(rt, dest_type, vt, k.bits);
        let mut body = k.body;
        let err = self.copyout_descriptors(m, &mut body, k.descs, options);
        let out = Out { bits: header_bits, remote: reply_name, local: dest_name, voucher: voucher_name, id: k.id, body, sender: k.sender, aux: k.aux };
        if err != 0 {
            return Err((out, mr::RCV_BODY_ERROR | err));
        }
        Ok(out)
    }

    /// `ipc_kmsg_copyout_descriptors`: each descriptor's rights and memory
    /// into the receiver; the error bits of what failed.
    fn copyout_descriptors(&mut self, m: &mut GuestMem<'_>, body: &mut [u8], descs: Vec<Desc>, options: u64) -> u32 {
        let mut err = 0u32;
        for d in descs {
            match d {
                Desc::Port { off, right, raw, disp } => {
                    let name = match right {
                        Some(c) => self.copyout_object(c, disp, None, &mut err),
                        None => raw,
                    };
                    body[off..off + 4].copy_from_slice(&name.to_le_bytes());
                    body[off + 10] = disp as u8;
                }
                Desc::Guarded { off, right, raw, disp, mut flags } => {
                    let mut ctx = 0u64;
                    let name = match right {
                        Some(c) if options & opt::RCV_GUARDED_DESC != 0 => {
                            let recv_addr = 0;
                            self.copyout_object(c, disp, Some((&mut flags, &mut ctx, recv_addr)), &mut err)
                        }
                        Some(c) => self.copyout_object(c, disp, None, &mut err),
                        None => raw,
                    };
                    if options & opt::RCV_GUARDED_DESC != 0 {
                        body[off..off + 8].copy_from_slice(&ctx.to_le_bytes());
                        body[off + 8..off + 10].copy_from_slice(&(flags as u16).to_le_bytes());
                        body[off + 10] = disp as u8;
                        body[off + 12..off + 16].copy_from_slice(&name.to_le_bytes());
                    } else {
                        // A receiver that did not ask for guarded
                        // descriptors gets a plain port descriptor, its
                        // 16 bytes kept.
                        body[off..off + 4].copy_from_slice(&name.to_le_bytes());
                        body[off + 4..off + 10].copy_from_slice(&[0; 6]);
                        body[off + 10] = disp as u8;
                        body[off + 11] = dtype::PORT;
                    }
                }
                Desc::Ool { off, data, copy } => {
                    let (addr, size) = if data.is_empty() {
                        (0, 0)
                    } else {
                        match self.darwin_vm_allocate_anywhere(m, data.len() as u64) {
                            Ok(a) if m.write(a, &data).is_ok() => (a, data.len() as u32),
                            _ => {
                                err |= mr::MSG_VM_SPACE;
                                (0, 0)
                            }
                        }
                    };
                    body[off..off + 8].copy_from_slice(&addr.to_le_bytes());
                    body[off + 8] = u8::from(copy == VIRTUAL_COPY);
                    body[off + 9] = copy;
                    body[off + 12..off + 16].copy_from_slice(&size.to_le_bytes());
                }
                Desc::OolPorts { off, rights, disp, copy } => {
                    let count = rights.len();
                    let mut addr = 0;
                    if count != 0 {
                        match self.darwin_vm_allocate_anywhere(m, 4 * count as u64) {
                            Ok(a) => {
                                addr = a;
                                for (i, (r, raw)) in rights.into_iter().enumerate() {
                                    let name = match r {
                                        Some(c) => self.copyout_object(c, disp, None, &mut err),
                                        None => raw,
                                    };
                                    if m.write_u32(a + 4 * i as u64, name).is_err() {
                                        err |= mr::MSG_VM_SPACE;
                                    }
                                }
                            }
                            Err(_) => {
                                for (r, _) in rights {
                                    if let Some(c) = r {
                                        self.ipc().object_destroy(c, disp);
                                    }
                                }
                                err |= mr::MSG_VM_SPACE;
                            }
                        }
                    }
                    body[off..off + 8].copy_from_slice(&addr.to_le_bytes());
                    body[off + 8] = u8::from(copy == VIRTUAL_COPY);
                    body[off + 9] = copy;
                    body[off + 10] = disp as u8;
                    body[off + 12..off + 16].copy_from_slice(&(count as u32).to_le_bytes());
                }
            }
        }
        err
    }

    /// `ipc_kmsg_copyout_pseudo`: a message whose send failed, given back
    /// to its sender: every right returns to the sender's space (the
    /// destination as the right it was sent with) and the message is
    /// written over the send buffer, with no trailer.
    fn pseudo_receive(&mut self, m: &mut GuestMem<'_>, k: Box<Kmsg>, msg_addr: u64, msg_size: u32) -> u32 {
        let k = *k;
        let mut err = 0u32;
        let (dest_type, mut reply_type, voucher_type) = (bits::remote(k.bits), bits::local(k.bits), bits::voucher(k.bits));
        let dest_name = self.copyout_object(Carried::Port(k.dest), dest_type, None, &mut err);
        let reply_name = match k.reply {
            None => 0,
            Some(Carried::Dead) => super::ipc::PORT_DEAD,
            Some(Carried::Port(p)) if self.ipc().port(p).reply_semantics == super::ipc::ReplySemantics::ReplyPort => {
                // ipc_kmsg_copyout_reply_object: the send-once right goes;
                // the receive right's name stands for it.
                let ipc = &mut self.ipc();
                let task = ipc.task;
                let name = if !ipc.port(p).active {
                    super::ipc::PORT_DEAD
                } else {
                    // ipc_right_reverse: its receive right in this space.
                    match ipc.port(p).receiver {
                        Receiver::Space(n) if ipc.port(p).owner == task => {
                            reply_type = msgt::MAKE_SEND_ONCE;
                            n
                        }
                        _ => 0,
                    }
                };
                ipc.port_mut(p).sorights -= 1;
                ipc.release(p);
                name
            }
            Some(c) => self.copyout_object(c, reply_type, None, &mut err),
        };
        let mut b = bits::set(dest_type, reply_type, voucher_type, k.bits) & bits::USER;
        let mut voucher_name = k.voucher_raw;
        if let Some(v) = k.voucher {
            voucher_name = self.copyout_object(Carried::Port(v), msgt::PORT_SEND, None, &mut err);
        } else if voucher_type != 0 {
            b = bits::set(dest_type, reply_type, msgt::COPY_SEND, b);
        }
        let mut body = k.body;
        err |= self.copyout_descriptors(m, &mut body, k.descs, 0);
        let out = Out { bits: b, remote: dest_name, local: reply_name, voucher: voucher_name, id: k.id, body, sender: k.sender, aux: Vec::new() };
        let bufs = RecvBufs { msg_addr, msg_size, aux_addr: 0, aux_size: 0 };
        self.put_pseudo(m, out, bufs) | err
    }

    /// `ipc_kmsg_put_to_user` for a pseudo-receive: no trailer.
    fn put_pseudo(&mut self, m: &mut GuestMem<'_>, out: Out, bufs: RecvBufs) -> u32 {
        let msg_size = HEADER + out.body.len() as u32;
        if msg_size > bufs.msg_size {
            return mr::RCV_INVALID_DATA;
        }
        let mut msg = Vec::with_capacity(msg_size as usize);
        for w in [out.bits, msg_size, out.remote, out.local, out.voucher, out.id as u32] {
            msg.extend_from_slice(&w.to_le_bytes());
        }
        msg.extend_from_slice(&out.body);
        if m.write(bufs.msg_addr, &msg).is_err() {
            return mr::RCV_INVALID_DATA;
        }
        mr::SUCCESS
    }

    /// `ipc_kmsg_copyout_object`: a right into the space; dead or failed
    /// copyouts become `MACH_PORT_DEAD` or null with the error bits.
    fn copyout_object(&mut self, c: Carried, t: u32, guard: Option<(&mut u32, &mut u64, u64)>, err: &mut u32) -> u32 {
        if c == Carried::Dead {
            return super::ipc::PORT_DEAD;
        }
        match self.ipc().object_copyout(c, t, guard) {
            Ok(n) => n,
            Err(e) if e == kr::INVALID_CAPABILITY => super::ipc::PORT_DEAD,
            Err(e) => {
                *err |= if e == kr::RESOURCE_SHORTAGE { mr::MSG_IPC_KERNEL } else { mr::MSG_IPC_SPACE };
                0
            }
        }
    }

    /// `ipc_kmsg_put_to_user`: the message, its trailer and aux data written
    /// to the receive buffers.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_arguments)]
    fn put_to_user(&mut self, m: &mut GuestMem<'_>, out: Out, seqno: u32, context: u64, bufs: RecvBufs, options: u64, mut r: u32, msgr: &mut Msgr) -> u32 {
        let msg_size = HEADER + out.body.len() as u32;
        let full_tsize = super::ipc::msg::trailer_size(options);
        msgr.msg_size = msg_size;
        msgr.trailer_size = full_tsize;
        msgr.aux_size = out.aux.len() as u32;
        let invalid = |msgr: &mut Msgr| {
            *msgr = Msgr { recv_name: msgr.recv_name, priority: msgr.priority, qos_ovrd: msgr.qos_ovrd, ..Msgr::default() };
            mr::RCV_INVALID_DATA
        };
        let mut aux = out.aux;
        let (msg_addr, aux_addr, tsize) = if options & opt::RCV_LINEAR_VECTOR != 0 {
            // The auxiliary data follows the message and its trailer in
            // the one buffer, all of it at the buffer's end for a stack
            // receive.
            let usize_ = msg_size + full_tsize;
            if usize_ + aux.len() as u32 > bufs.msg_size {
                return invalid(msgr);
            }
            let at = if options & opt::RCV_STACK != 0 { bufs.msg_addr + u64::from(bufs.msg_size - (usize_ + aux.len() as u32)) } else { bufs.msg_addr };
            (at, at + u64::from(usize_), full_tsize)
        } else {
            if msg_size > bufs.msg_size {
                return invalid(msgr);
            }
            let tsize = if msg_size + full_tsize > bufs.msg_size { bufs.msg_size - msg_size } else { full_tsize };
            // A receiver with an auxiliary buffer gets an empty header when
            // there is no data, and nothing when its buffer is too small.
            if bufs.aux_addr != 0 && aux.is_empty() {
                aux = vec![0u8; AUX_HEADER as usize];
                msgr.aux_size = AUX_HEADER;
            }
            if aux.len() as u32 > bufs.aux_size {
                aux.clear();
                msgr.aux_size = 0;
            }
            (bufs.msg_addr, if aux.is_empty() { 0 } else { bufs.aux_addr }, tsize)
        };
        let mut msg = Vec::with_capacity((msg_size + 68) as usize);
        for w in [out.bits, msg_size, out.remote, out.local, out.voucher, out.id as u32] {
            msg.extend_from_slice(&w.to_le_bytes());
        }
        msg.extend_from_slice(&out.body);
        // mach_msg_max_trailer_t: format 0, size, seqno, sender, audit,
        // context, then zeroes.
        let mut trailer = vec![0u8; 68];
        trailer[0..4].copy_from_slice(&0u32.to_le_bytes());
        trailer[4..8].copy_from_slice(&full_tsize.to_le_bytes());
        trailer[8..12].copy_from_slice(&seqno.to_le_bytes());
        trailer[12..16].copy_from_slice(&out.sender.sec[0].to_le_bytes());
        trailer[16..20].copy_from_slice(&out.sender.sec[1].to_le_bytes());
        for (i, a) in out.sender.audit.iter().enumerate() {
            trailer[20 + 4 * i..24 + 4 * i].copy_from_slice(&a.to_le_bytes());
        }
        trailer[52..60].copy_from_slice(&context.to_le_bytes());
        msg.extend_from_slice(&trailer[..tsize as usize]);
        if m.write(msg_addr, &msg).is_err() {
            return invalid(msgr);
        }
        if !aux.is_empty() && m.write(aux_addr, &aux).is_err() {
            r = invalid(msgr);
        }
        r
    }

    /// After an IPC operation: owed notifications sent, woken threads
    /// woken, guard exceptions raised.
    pub(crate) fn darwin_ipc_settle(&mut self, m: &mut GuestMem<'_>) {
        self.darwin_ipc_notify_drain();
        // Threads and knotes of other tasks are theirs to act on: their
        // kernels hear of them (`Remote`).
        let me = self.ipc().task;
        for w in std::mem::take(&mut self.ipc().queues.wake) {
            let (task, tid) = (super::ipc::waiter_task(w), super::ipc::waiter_tid(w));
            if task == me {
                self.darwin_wake(m, tid, WaitResult::Awakened);
            } else {
                self.ipc().remote(task, super::ipc::Remote::Wake(tid));
            }
        }
        let ipc = self.ipc();
        let knotes = std::mem::take(&mut ipc.queues.knotes);
        for p in knotes {
            match ipc.port(p).owner {
                o if o == me => ipc.queues.knotes.push(p),
                o => {
                    ipc.remote(o, super::ipc::Remote::Knote(p));
                }
            }
        }
        let psets = std::mem::take(&mut ipc.queues.pset_knotes);
        for (s, p) in psets {
            match ipc.pset(s).owner {
                o if o == me => ipc.queues.pset_knotes.push((s, p)),
                o => {
                    ipc.remote(o, super::ipc::Remote::PsetKnote(s, p));
                }
            }
        }
        for (name, g, portguard) in std::mem::take(&mut self.ipc().guards) {
            self.darwin_guard_exception(name, g, portguard);
        }
        // The EVFILT_MACHPORT knotes of what changed, and the threads
        // their kqueues wake; then the thread requests they made.
        self.darwin_kevent_owed(m);
        self.darwin_workq_settle(m);
    }

    /// What other tasks' calls left for this task ([`super::ipc::Remote`]):
    /// its threads woken, its ports' and sets' knotes told.
    pub(crate) fn darwin_ipc_remote(&mut self, m: &mut GuestMem<'_>) {
        let Some(link) = self.dtask.ipc_raw.link.clone() else { return };
        let got = std::mem::take(&mut *link.mailbox.lock().unwrap_or_else(|e| e.into_inner()));
        if got.is_empty() {
            return;
        }
        for r in got {
            let ipc = self.ipc();
            match r {
                super::ipc::Remote::Wake(tid) => {
                    let w = ipc.waiter(tid);
                    ipc.queues.wake.push(w);
                }
                super::ipc::Remote::Knote(p) => ipc.queues.knotes.push(p),
                super::ipc::Remote::PsetKnote(s, p) => ipc.queues.pset_knotes.push((s, p)),
                // Served as from no thread of this task, for the caller.
                super::ipc::Remote::Kobject { kmsg, options, caller } => {
                    let (tid, kcaller) = (self.tid, self.dtask.kcaller);
                    self.tid = 0;
                    self.dtask.kcaller = caller;
                    let port = kmsg.dest;
                    if let Err(SendWait::Failed(_, Some(k))) = self.kobject_send(port, kmsg, options, false) {
                        self.ipc().kmsg_destroy(k, false);
                    }
                    self.tid = tid;
                    self.dtask.kcaller = kcaller;
                }
            }
        }
        self.darwin_pending_ready(m);
        self.darwin_ipc_settle(m);
    }

    /// The notifications owed, sent, with those their sending owes.
    pub(crate) fn darwin_ipc_notify_drain(&mut self) {
        loop {
            let outbox = std::mem::take(&mut self.ipc().outbox);
            if outbox.is_empty() {
                break;
            }
            for n in outbox {
                self.send_notification(n);
            }
        }
    }

    /// `mach_port_guard_exception` for a task without exception-guard
    /// behavior (`task_exc_guard` 0 when not hardened): the fatal kinds
    /// (`<= MAX_FATAL_kGUARD_EXC_CODE`) end the task, the rest are
    /// dropped.
    fn darwin_guard_exception(&mut self, name: u32, g: Guard, portguard: u64) {
        const MAX_FATAL: u32 = 1 << 7;
        if (g as u32) <= MAX_FATAL {
            eprintln!("[gex:{}] EXC_GUARD (GUARD_TYPE_MACH_PORT, flavor {:#x}, name {name:#x}, guard {portguard:#x}): the task is killed", self.pid, g as u32);
            self.dtask.guard_kill = true;
        }
    }

    /// A notification (`mach_notify_*`, `notify.defs`) sent to its
    /// send-once right as the kernel sends it (`MACH_SEND_KERNEL_DEFAULT`).
    fn send_notification(&mut self, n: super::ipc::Notify) {
        use super::ipc::port::notify_id as id;
        use super::ipc::Notify;
        let ndr = super::mig::NDR_RECORD;
        let (to, msgid, body, descs) = match n {
            Notify::PortDeleted { to, name } => (to, id::PORT_DELETED, [&ndr[..], &name.to_le_bytes()].concat(), Vec::new()),
            Notify::SendPossible { to, name } => (to, id::SEND_POSSIBLE, [&ndr[..], &name.to_le_bytes()].concat(), Vec::new()),
            Notify::DeadName { to, name } => (to, id::DEAD_NAME, [&ndr[..], &name.to_le_bytes()].concat(), Vec::new()),
            Notify::NoSenders { to, mscount } => (to, id::NO_SENDERS, [&ndr[..], &mscount.to_le_bytes()].concat(), Vec::new()),
            Notify::SendOnce { to } => (to, id::SEND_ONCE, Vec::new(), Vec::new()),
            Notify::PortDestroyed { to, port } => {
                let mut b = 1u32.to_le_bytes().to_vec();
                b.extend_from_slice(&[0u8; 12]);
                (to, id::PORT_DESTROYED, b, vec![Desc::Port { off: 4, right: Some(Carried::Port(port)), raw: 0, disp: msgt::PORT_RECEIVE }])
            }
            Notify::KobjectNoSenders { port, mscount } => {
                self.kobject_no_senders(port, mscount);
                return;
            }
            Notify::KobjectDestroyed { port } => {
                self.mk_timer_port_destroy(port);
                return;
            }
            Notify::KobjectSendOnce { port } => {
                self.kobject_send_once(port);
                return;
            }
        };
        let complex = if descs.is_empty() { 0 } else { bits::COMPLEX };
        let k = Kmsg { bits: bits::set(msgt::PORT_SEND_ONCE, 0, 0, complex), size: HEADER + body.len() as u32, dest: to, reply: None, voucher: None, voucher_raw: 0, id: msgid, body, descs, sender: Sender::KERNEL, aux: Vec::new(), keep_alive: false, ppriority: 0, qos_override: 0 };
        self.darwin_kernel_send(Box::new(k));
    }

    /// `kernel_mach_msg_send_kmsg` with `MACH_SEND_KERNEL_DEFAULT`: a
    /// message the kernel sends; one that cannot be queued is destroyed.
    pub(crate) fn darwin_kernel_send(&mut self, k: Box<Kmsg>) {
        if let Err(SendWait::Failed(_, Some(k))) = self.kmsg_send(k, opt::SEND_MSG | opt::SEND_ALWAYS | opt::SEND_NOIMPORTANCE, false) {
            self.ipc().kmsg_destroy(k, false);
        }
    }
}

/// A message on its way to user space: header fields as received.
struct Out {
    bits: u32,
    remote: u32,
    local: u32,
    voucher: u32,
    id: i32,
    body: Vec<u8>,
    sender: Sender,
    aux: Vec<u8>,
}

/// A send that could not finish now.
enum SendWait {
    Room(ObjId),
    /// Failed with the message still to give back (the pseudo-receive).
    Failed(u32, Option<Box<Kmsg>>),
}
