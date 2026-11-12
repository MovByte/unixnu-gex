//! The WebMetal connection: the accelerator's user client of type 0, over
//! which the WebMetal plugin exchanges wire protocol records with the host
//! executor (WebMetal `wire/README.md`, "Channels" and "Transport").
//!
//! Its selectors take and return 64-bit scalars:
//!
//! | Selector | Inputs | Outputs |
//! | --- | --- | --- |
//! | 0 `control` | request address, request length, reply address, reply capacity | reply length |
//! | 1 `fetch_reply` | reply address, reply capacity | reply length |
//! | 2 `register_event_port` (asynchronous) | queue handle (0: device-level events) | |
//!
//! The records go to the host executor and come back from it; with no
//! executor attached yet there is nothing to run a request, so a request
//! stops at that point, loudly.

use super::super::iokit::{dispatch_check, no_method, ret, Dispatch, MethodArgs};
use super::super::ipc::ObjId;
use crate::syscalls::Kernel;

/// The connection's type.
pub const TYPE: u32 = 0;

/// The selectors' argument counts: scalars in, structure in, scalars out,
/// structure out.
const METHODS: [Dispatch; 3] = [
    Dispatch { scalar_in: 4, struct_in: 0, scalar_out: 1, struct_out: 0 },
    Dispatch { scalar_in: 2, struct_in: 0, scalar_out: 1, struct_out: 0 },
    Dispatch { scalar_in: 1, struct_in: 0, scalar_out: 0, struct_out: 0 },
];

/// The record header's size: opcode, flags, length.
const HEADER: u64 = 8;

/// A registration of `register_event_port`: the queue handle, the wake
/// port's send right (the async reference's port) and the reference, which
/// the host's completion carries back.
struct EventPort {
    queue: u64,
    wake: ObjId,
    #[allow(dead_code)]
    reference: Vec<u64>,
}

/// The connection's state: the event ports registered.
pub struct Wire {
    events: Vec<EventPort>,
}

impl Wire {
    pub fn new() -> Wire {
        Wire { events: Vec::new() }
    }

    /// The client's methods.
    pub fn external_method(&mut self, k: &mut Kernel, a: &mut MethodArgs) -> i32 {
        let Some(d) = METHODS.get(a.selector as usize) else { return no_method(a) };
        if let Err(e) = dispatch_check(d, a) {
            return e;
        }
        let asynchronous = a.is_async;
        match (a.selector, asynchronous) {
            (0, false) => self.control(k, a),
            (1, false) => {
                // No request has run, so none has a reply pending.
                k.darwin_unimplemented("WebMetal fetch_reply with no reply pending (the wire protocol defines no answer for it)".to_string());
                ret::NOT_READY
            }
            (2, true) => self.register_event_port(k, a),
            (s, _) => {
                k.darwin_unimplemented(format!("WebMetal selector {s} called {} (the wire protocol defines it {})", if asynchronous { "asynchronously" } else { "synchronously" }, if s == 2 { "asynchronous" } else { "synchronous" }));
                ret::BAD_ARGUMENT
            }
        }
    }

    /// `control(request, length, reply, capacity)`: the request read from
    /// the caller's memory and handed to the host executor.
    fn control(&mut self, k: &mut Kernel, a: &mut MethodArgs) -> i32 {
        let (addr, len) = (a.scalar_in[0], a.scalar_in[1]);
        let mut header = [0u8; HEADER as usize];
        let read = len >= HEADER && k.darwin_own_memory(|_, m| m.read(addr, HEADER as usize).map(|b| header.copy_from_slice(b)).is_ok()).unwrap_or(false);
        if !read {
            k.darwin_unimplemented(format!("a WebMetal control request the host cannot read ({len} bytes at {addr:#x}; the wire protocol defines no answer for it)"));
            return ret::BAD_ARGUMENT;
        }
        let opcode = u16::from_le_bytes([header[0], header[1]]);
        k.darwin_unimplemented(format!("WebMetal control request (opcode {opcode:#06x}, {len} bytes): no host executor is attached to run it"));
        ret::UNSUPPORTED
    }

    /// `register_event_port(queue)`: the async reference kept, to complete
    /// with the queue handle when the host has events for that queue; a
    /// queue registered again keeps the new port.
    fn register_event_port(&mut self, k: &mut Kernel, a: &mut MethodArgs) -> i32 {
        // A null wake port: no port to send the completion to.
        let Some(wake) = a.wake.take() else {
            k.darwin_unimplemented("WebMetal register_event_port with a null wake port (the wire protocol defines no answer for it)".to_string());
            return ret::BAD_ARGUMENT;
        };
        let queue = a.scalar_in[0];
        if let Some(i) = self.events.iter().position(|e| e.queue == queue) {
            let old = self.events.remove(i);
            k.ipc().release_send(old.wake);
        }
        self.events.push(EventPort { queue, wake, reference: a.reference.clone() });
        ret::SUCCESS
    }

    /// The async references let go (`releaseAsyncReference64`).
    pub fn close(&mut self, k: &mut Kernel) {
        for e in self.events.drain(..) {
            k.ipc().release_send(e.wake);
        }
    }
}
