//! The `mach_port_*` routines (`osfmk/ipc/mach_port.c`): what a task asks
//! of its own name space, by trap or by MIG message.

use super::space::bits;
use super::{kr, name_valid, port_right, ty, Guard, Ipc, Object, ObjId, Receiver, PORT_DEAD};

impl Ipc {
    /// `ipc_port_translate_receive`: the port whose receive right `name`
    /// holds.
    pub fn translate_receive(&self, name: u32) -> Result<ObjId, u64> {
        let e = self.space.lookup(name).ok_or(kr::INVALID_NAME)?;
        if e.bits & ty::RECEIVE == 0 {
            return Err(kr::INVALID_RIGHT);
        }
        Ok(e.object.expect("a receive right names a port"))
    }

    /// `ipc_port_translate_send`: the live port `name` holds a send right
    /// to.
    pub fn translate_send(&mut self, name: u32) -> Result<ObjId, u64> {
        let e = *self.space.lookup(name).ok_or(kr::INVALID_NAME)?;
        if e.bits & ty::SEND == 0 {
            return Err(kr::INVALID_RIGHT);
        }
        let port = e.object.ok_or(kr::INVALID_RIGHT)?;
        if !self.port(port).active {
            return Err(kr::INVALID_RIGHT);
        }
        Ok(port)
    }

    /// `ipc_object_translate` for a port set.
    pub fn translate_pset(&self, name: u32) -> Result<ObjId, u64> {
        let e = self.space.lookup(name).ok_or(kr::INVALID_NAME)?;
        if e.bits & ty::PORT_SET == 0 {
            return Err(kr::INVALID_RIGHT);
        }
        Ok(e.object.expect("a set right names a set"))
    }

    /// `mach_port_type`.
    pub fn mach_port_type(&mut self, name: u32) -> Result<u32, u64> {
        if name == 0 {
            return Err(kr::INVALID_NAME);
        }
        if name == PORT_DEAD {
            return Ok(ty::DEAD_NAME);
        }
        if self.space.lookup(name).is_none() {
            return Err(kr::INVALID_NAME);
        }
        let (t, _) = self.right_info(name);
        Ok(t & !(ty::SPREQUEST | ty::SPREQUEST_DELAYED))
    }

    /// `mach_port_allocate_full`: a right of kind `right`, under `name`
    /// when given (`mach_port_allocate_name`).
    pub fn mach_port_allocate(&mut self, right: u32, name: Option<u32>) -> Result<u32, u64> {
        if let Some(n) = name {
            if !name_valid(n) {
                return Err(kr::INVALID_VALUE);
            }
        }
        match right {
            port_right::RECEIVE => match name {
                Some(n) => self.port_alloc_name(n).map(|_| n),
                None => self.port_alloc(false).map(|(n, _)| n),
            },
            port_right::PORT_SET => match name {
                Some(n) => self.pset_alloc_name(n).map(|_| n),
                None => self.pset_alloc().map(|(n, _)| n),
            },
            port_right::DEAD_NAME => {
                let n = self.space.alloc(None).ok_or(kr::NO_SPACE)?;
                self.space.lookup_mut_any(n).bits |= ty::DEAD_NAME | 1;
                Ok(n)
            }
            _ => Err(kr::INVALID_VALUE),
        }
    }

    /// `ipc_port_alloc_name`.
    pub fn port_alloc_name(&mut self, name: u32) -> Result<ObjId, u64> {
        let claimed = self.space.alloc_name(name)?;
        if !claimed {
            return Err(kr::NAME_EXISTS);
        }
        let id = self.new_object(Object::Port(super::Port::new(Receiver::Space(name))));
        let e = self.space.lookup_mut_any(name);
        e.object = Some(id);
        e.bits |= ty::RECEIVE;
        Ok(id)
    }

    /// `ipc_pset_alloc_name`.
    pub fn pset_alloc_name(&mut self, name: u32) -> Result<ObjId, u64> {
        let claimed = self.space.alloc_name(name)?;
        if !claimed {
            return Err(kr::NAME_EXISTS);
        }
        let id = self.new_object(Object::Pset(super::Pset { active: true, name, members: Vec::new(), refs: 1 }));
        let e = self.space.lookup_mut_any(name);
        e.object = Some(id);
        e.bits |= ty::PORT_SET;
        Ok(id)
    }

    /// `mach_port_destroy`.
    pub fn mach_port_destroy(&mut self, name: u32) -> u64 {
        if !name_valid(name) {
            return kr::SUCCESS;
        }
        if self.space.lookup(name).is_none() {
            self.guard_exception(name, Guard::InvalidName, 0);
            return kr::INVALID_NAME;
        }
        self.right_destroy(name, true, 0)
    }

    /// `mach_port_deallocate`.
    pub fn mach_port_deallocate(&mut self, name: u32) -> u64 {
        if !name_valid(name) {
            return kr::SUCCESS;
        }
        if self.space.lookup(name).is_none() {
            self.guard_exception(name, Guard::InvalidName, 0);
            return kr::INVALID_NAME;
        }
        self.right_dealloc(name)
    }

    /// `mach_port_get_refs`.
    pub fn mach_port_get_refs(&mut self, name: u32, right: u32) -> Result<u32, u64> {
        if right >= port_right::NUMBER {
            return Err(kr::INVALID_VALUE);
        }
        if !name_valid(name) {
            if right == port_right::SEND || right == port_right::SEND_ONCE {
                return Ok(1);
            }
            return Err(kr::INVALID_NAME);
        }
        if self.space.lookup(name).is_none() {
            return Err(kr::INVALID_NAME);
        }
        let (t, urefs) = self.right_info(name);
        if t & (1 << (16 + right)) == 0 {
            return Ok(0);
        }
        Ok(match right {
            port_right::SEND_ONCE | port_right::PORT_SET | port_right::RECEIVE => 1,
            port_right::DEAD_NAME | port_right::SEND => urefs,
            _ => panic!("mach_port_get_refs: strange rights"),
        })
    }

    /// `mach_port_mod_refs`.
    pub fn mach_port_mod_refs(&mut self, name: u32, right: u32, delta: i32) -> u64 {
        if right >= port_right::NUMBER {
            return kr::INVALID_VALUE;
        }
        if !name_valid(name) {
            if right == port_right::SEND || right == port_right::SEND_ONCE {
                return kr::SUCCESS;
            }
            return kr::INVALID_NAME;
        }
        if self.space.lookup(name).is_none() {
            self.guard_exception(name, Guard::InvalidName, 0);
            return kr::INVALID_NAME;
        }
        self.right_delta(name, right, delta)
    }

    /// `mach_port_set_mscount`.
    pub fn mach_port_set_mscount(&mut self, name: u32, mscount: u32) -> u64 {
        if !name_valid(name) {
            return kr::INVALID_RIGHT;
        }
        match self.translate_receive(name) {
            Ok(port) => {
                self.port_mut(port).mscount = mscount;
                kr::SUCCESS
            }
            Err(e) => e,
        }
    }

    /// `mach_port_set_seqno`.
    pub fn mach_port_set_seqno(&mut self, name: u32, seqno: u32) -> u64 {
        if !name_valid(name) {
            return kr::INVALID_RIGHT;
        }
        match self.translate_receive(name) {
            Ok(port) => {
                self.port_mut(port).seqno = seqno;
                kr::SUCCESS
            }
            Err(e) => e,
        }
    }

    /// A new object in the table, with one reference.
    pub(crate) fn new_object(&mut self, o: Object) -> ObjId {
        let id = self.new_id_pub();
        self.objects.insert(id, o);
        id
    }

    /// The user references the entry `name` holds (`IE_BITS_UREFS`).
    pub fn urefs(&self, name: u32) -> u32 {
        self.space.lookup(name).map_or(0, |e| e.bits & bits::UREFS_MASK)
    }

    /// `mach_port_get_context`.
    pub fn mach_port_get_context(&self, name: u32) -> Result<u64, u64> {
        if !name_valid(name) {
            return Err(kr::INVALID_RIGHT);
        }
        let p = self.port(self.translate_receive(name)?);
        Ok(if p.strict_guard { 0 } else { p.context })
    }

    /// `mach_port_set_context`.
    pub fn mach_port_set_context(&mut self, name: u32, context: u64) -> u64 {
        if !name_valid(name) {
            return kr::INVALID_RIGHT;
        }
        let port = match self.translate_receive(name) {
            Ok(p) => p,
            Err(e) => return e,
        };
        if self.port(port).strict_guard {
            let g = self.port(port).context;
            self.guard_exception(name, Guard::SetContext, g);
            return kr::INVALID_ARGUMENT;
        }
        self.port_mut(port).context = context;
        kr::SUCCESS
    }

    /// `mach_port_get_set_status`: the names of a set's members, sorted.
    pub fn mach_port_get_set_status(&self, name: u32) -> Result<Vec<u32>, u64> {
        if !name_valid(name) {
            return Err(kr::INVALID_RIGHT);
        }
        let set = self.translate_pset(name)?;
        let Object::Pset(s) = &self.objects[&set] else { unreachable!() };
        let mut names: Vec<u32> = s.members.iter().map(|&m| match self.port(m).receiver {
            Receiver::Space(n) => n,
            _ => 0,
        }).collect();
        names.sort_unstable();
        Ok(names)
    }

    /// `ipc_mqueue_add_locked`: `port` joins `set`.
    fn mqueue_add(&mut self, port: ObjId, set: ObjId) -> u64 {
        if self.port(port).psets.contains(&set) {
            return kr::ALREADY_IN_SET;
        }
        self.port_mut(port).psets.push(set);
        self.pset_mut(set).members.push(port);
        kr::SUCCESS
    }

    /// Take `port` out of every set but `keep` (`waitq_unlink_all_locked`).
    fn unlink_all_but(&mut self, port: ObjId, keep: Option<ObjId>) {
        let sets = std::mem::take(&mut self.port_mut(port).psets);
        for s in sets {
            if Some(s) == keep {
                self.port_mut(port).psets.push(s);
            } else {
                self.pset_mut(s).members.retain(|&m| m != port);
            }
        }
    }

    /// `mach_port_move_member`: `member` into set `after` alone, or out of
    /// every set with a null `after`.
    pub fn mach_port_move_member(&mut self, member: u32, after: u32) -> u64 {
        if !name_valid(member) || after == PORT_DEAD {
            return kr::INVALID_RIGHT;
        }
        let port = match self.translate_receive(member) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let mut r = kr::SUCCESS;
        let keep = if after != 0 {
            let set = match self.translate_pset(after) {
                Ok(s) => s,
                Err(e) => return e,
            };
            self.mqueue_add(port, set);
            Some(set)
        } else {
            if self.port(port).psets.is_empty() {
                r = kr::NOT_IN_SET;
            }
            None
        };
        self.unlink_all_but(port, keep);
        r
    }

    /// `mach_port_insert_member`.
    pub fn mach_port_insert_member(&mut self, name: u32, psname: u32) -> u64 {
        if !name_valid(name) || !name_valid(psname) {
            return kr::INVALID_RIGHT;
        }
        let port = match self.translate_receive(name) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let set = match self.translate_pset(psname) {
            Ok(s) => s,
            Err(e) => return e,
        };
        self.mqueue_add(port, set)
    }

    /// `mach_port_extract_member`.
    pub fn mach_port_extract_member(&mut self, name: u32, psname: u32) -> u64 {
        if !name_valid(name) || !name_valid(psname) {
            return kr::INVALID_RIGHT;
        }
        let port = match self.translate_receive(name) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let set = match self.translate_pset(psname) {
            Ok(s) => s,
            Err(e) => return e,
        };
        if !self.port(port).psets.contains(&set) {
            return kr::NOT_IN_SET;
        }
        self.port_mut(port).psets.retain(|&s| s != set);
        self.pset_mut(set).members.retain(|&m| m != port);
        kr::SUCCESS
    }

    /// `mach_port_request_notification` for `id`; the previous request's
    /// send-once right.
    pub fn mach_port_request_notification(&mut self, name: u32, id: i32, sync: u32, notify: super::right::Carried) -> Result<Option<ObjId>, u64> {
        use super::right::Carried;
        let notify = match notify {
            Carried::Dead => return Err(kr::INVALID_CAPABILITY),
            Carried::Port(p) => Some(p).filter(|&p| p != 0),
        };
        match id {
            notify_id::PORT_DESTROYED => {
                if sync != 0 {
                    return Err(kr::INVALID_VALUE);
                }
                if !name_valid(name) {
                    return Err(kr::INVALID_RIGHT);
                }
                let port = self.translate_receive(name)?;
                let p = self.port(port);
                if p.kobject.is_some() || p.specialreply || p.reply_port {
                    self.guard_exception(name, Guard::InvalidRight, 0);
                    return Err(kr::INVALID_RIGHT);
                }
                if p.pdrequest.is_some() {
                    self.guard_exception(name, Guard::KernFailure, 0);
                    return Err(kr::FAILURE);
                }
                self.port_mut(port).pdrequest = notify;
                Ok(None)
            }
            notify_id::NO_SENDERS => {
                if !name_valid(name) {
                    return Err(kr::INVALID_RIGHT);
                }
                let port = self.translate_receive(name)?;
                if self.port(port).reply_port {
                    self.guard_exception(name, Guard::InvalidRight, 0);
                    return Err(kr::INVALID_RIGHT);
                }
                // ipc_port_nsrequest
                let p = self.port_mut(port);
                let previous = p.nsrequest.take();
                if p.srights == 0 && sync <= p.mscount && notify.is_some() {
                    let mscount = p.mscount;
                    self.outbox.push(super::Notify::NoSenders { to: notify.expect("checked"), mscount });
                } else {
                    self.port_mut(port).nsrequest = notify;
                }
                Ok(previous)
            }
            notify_id::SEND_POSSIBLE | notify_id::DEAD_NAME => {
                if !name_valid(name) {
                    return Err(kr::INVALID_ARGUMENT);
                }
                let mut opts = 0;
                if id == notify_id::SEND_POSSIBLE {
                    opts |= super::IPR_SOR_SPREQ_MASK;
                    if sync != 0 {
                        opts |= super::IPR_SOR_SPARM_MASK;
                    }
                }
                self.right_request_alloc(name, opts, notify)
            }
            _ => Err(kr::INVALID_VALUE),
        }
    }

    /// `mach_port_get_attributes` for `flavor`: the info words.
    pub fn mach_port_get_attributes(&self, name: u32, flavor: i32, count: u32) -> Result<Vec<u32>, u64> {
        let status = |p: &super::Port| -> Vec<u32> {
            let mut flags = 0;
            if p.impdonation {
                flags |= status_flag::IMP_DONATION;
                if p.tempowner {
                    flags |= status_flag::TEMPOWNER;
                }
            }
            if p.guarded {
                flags |= status_flag::GUARDED;
                if p.strict_guard {
                    flags |= status_flag::STRICT_GUARD;
                }
                if p.immovable_receive {
                    flags |= status_flag::GUARD_IMMOVABLE_RECEIVE;
                }
            }
            if p.no_grant {
                flags |= status_flag::NO_GRANT;
            }
            vec![u32::from(!p.psets.is_empty()), p.seqno, p.mscount, p.qlimit, p.messages.len() as u32, p.sorights, u32::from(p.srights > 0), u32::from(p.pdrequest.is_some()), u32::from(p.nsrequest.is_some() || p.nsrequest_kobject), flags]
        };
        match flavor {
            attr::LIMITS_INFO => {
                if count < 1 {
                    return Err(kr::FAILURE);
                }
                if !name_valid(name) {
                    return Ok(Vec::new());
                }
                Ok(vec![self.port(self.translate_receive(name)?).qlimit])
            }
            attr::RECEIVE_STATUS => {
                if count < 10 {
                    return Err(kr::FAILURE);
                }
                if !name_valid(name) {
                    return Err(kr::INVALID_RIGHT);
                }
                Ok(status(self.port(self.translate_receive(name)?)))
            }
            attr::DNREQUESTS_SIZE => {
                if count < 1 {
                    return Err(kr::FAILURE);
                }
                if !name_valid(name) {
                    return Ok(vec![0]);
                }
                let p = self.port(self.translate_receive(name)?);
                Ok(vec![p.requests.as_ref().map_or(0, |t| t.len() as u32)])
            }
            attr::INFO_EXT => {
                if count < 17 {
                    return Err(kr::FAILURE);
                }
                if !name_valid(name) {
                    return Err(kr::INVALID_RIGHT);
                }
                let mut v = status(self.port(self.translate_receive(name)?));
                // mpie_boost_cnt (no importance donation here), reserved[6]
                v.extend([0u32; 7]);
                Ok(v)
            }
            attr::SERVICE_THROTTLED => {
                if !name_valid(name) {
                    return Err(kr::INVALID_RIGHT);
                }
                let p = self.port(self.translate_receive(name)?);
                if !p.service_port {
                    return Err(kr::INVALID_CAPABILITY);
                }
                Err(kr::FAILURE)
            }
            _ => Err(kr::INVALID_ARGUMENT),
        }
    }

    /// `mach_port_set_attributes` for `flavor`.
    pub fn mach_port_set_attributes(&mut self, name: u32, flavor: i32, info: &[u32]) -> u64 {
        match flavor {
            attr::LIMITS_INFO => {
                if info.is_empty() {
                    return kr::FAILURE;
                }
                if info[0] > super::QLIMIT_MAX {
                    return kr::INVALID_VALUE;
                }
                if !name_valid(name) {
                    return kr::INVALID_RIGHT;
                }
                match self.translate_receive(name) {
                    Ok(port) => {
                        self.port_mut(port).qlimit = info[0];
                        kr::SUCCESS
                    }
                    Err(e) => e,
                }
            }
            attr::DNREQUESTS_SIZE => {
                if info.is_empty() {
                    return kr::FAILURE;
                }
                if !name_valid(name) {
                    return kr::INVALID_RIGHT;
                }
                self.translate_receive(name).err().unwrap_or(kr::SUCCESS)
            }
            attr::TEMPOWNER | attr::DENAP_RECEIVER => {
                if !name_valid(name) {
                    return kr::INVALID_RIGHT;
                }
                let port = match self.translate_receive(name) {
                    Ok(p) => p,
                    Err(e) => return e,
                };
                let p = self.port_mut(port);
                if p.kobject.is_some() || p.specialreply {
                    return kr::INVALID_ARGUMENT;
                }
                p.impdonation = true;
                if flavor == attr::TEMPOWNER {
                    p.tempowner = true;
                }
                kr::SUCCESS
            }
            attr::SERVICE_THROTTLED => {
                if !name_valid(name) {
                    return kr::INVALID_RIGHT;
                }
                match self.translate_receive(name) {
                    Ok(port) if !self.port(port).service_port => kr::INVALID_CAPABILITY,
                    Ok(_) => kr::FAILURE,
                    Err(e) => e,
                }
            }
            _ => kr::INVALID_ARGUMENT,
        }
    }

    /// `mach_port_guard_locked`.
    fn guard_locked(&mut self, port: ObjId, guard: u64, flags: u64) -> u64 {
        let p = self.port_mut(port);
        if p.context != 0 {
            return kr::INVALID_ARGUMENT;
        }
        p.context = guard;
        p.guarded = true;
        p.strict_guard = flags & mpg::STRICT != 0;
        if !p.immovable_receive {
            p.immovable_receive = flags & mpg::IMMOVABLE_RECEIVE != 0;
        }
        kr::SUCCESS
    }

    /// The receive right `name` holds, with the guard exception XNU raises
    /// when it holds none.
    fn receive_or_guard(&mut self, name: u32) -> Result<ObjId, u64> {
        self.translate_receive(name).map_err(|e| {
            let g = if e == kr::INVALID_NAME { Guard::InvalidName } else { Guard::InvalidRight };
            self.guard_exception(name, g, 0);
            e
        })
    }

    /// `mach_port_guard` and `mach_port_guard_with_flags`.
    pub fn mach_port_guard(&mut self, name: u32, guard: u64, flags: u64) -> u64 {
        if !name_valid(name) {
            return kr::INVALID_NAME;
        }
        let port = match self.receive_or_guard(name) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let r = self.guard_locked(port, guard, flags);
        if r == kr::INVALID_ARGUMENT {
            self.guard_exception(name, Guard::InvalidArgument, 0);
        }
        r
    }

    /// `mach_port_unguard`.
    pub fn mach_port_unguard(&mut self, name: u32, guard: u64) -> u64 {
        if !name_valid(name) {
            return kr::INVALID_NAME;
        }
        let port = match self.receive_or_guard(name) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let p = self.port(port);
        if !p.guarded {
            self.guard_exception(name, Guard::Unguarded, 0);
            return kr::INVALID_ARGUMENT;
        }
        if p.context != guard {
            let c = p.context;
            self.guard_exception(name, Guard::IncorrectGuard, c);
            return kr::INVALID_ARGUMENT;
        }
        let p = self.port_mut(port);
        p.context = 0;
        p.guarded = false;
        p.strict_guard = false;
        kr::SUCCESS
    }

    /// `mach_port_swap_guard`.
    pub fn mach_port_swap_guard(&mut self, name: u32, old: u64, new: u64) -> u64 {
        if !name_valid(name) {
            return kr::INVALID_NAME;
        }
        let port = match self.receive_or_guard(name) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let p = self.port(port);
        let c = p.context;
        if !p.guarded {
            self.guard_exception(name, Guard::Unguarded, 0);
            return kr::INVALID_ARGUMENT;
        }
        if p.strict_guard {
            self.guard_exception(name, Guard::SetContext, c);
            return kr::INVALID_ARGUMENT;
        }
        if c != old {
            self.guard_exception(name, Guard::IncorrectGuard, c);
            return kr::INVALID_ARGUMENT;
        }
        self.port_mut(port).context = new;
        kr::SUCCESS
    }

    /// `mach_port_construct(options, context)`: a new receive right shaped
    /// by `options` (flags, qlimit). `hardened`: the task is a platform
    /// binary or has the hardened runtime (`task_is_hardened_binary`).
    pub fn mach_port_construct(&mut self, flags: u32, qlimit: u32, context: u64, hardened: bool) -> Result<u32, u64> {
        let one_of = |m: u32| {
            let f = flags & m;
            f & f.wrapping_sub(1) != 0
        };
        if one_of(mpo::SERVICE_PORT | mpo::CONNECTION_PORT | mpo::TG_BLOCK_TRACKING) {
            return Err(kr::INVALID_ARGUMENT);
        }
        if one_of(mpo::REPLY_PORT | mpo::ENFORCE_REPLY_PORT_SEMANTICS | mpo::PROVISIONAL_ID_PROT_OPTOUT | mpo::PROVISIONAL_REPLY_PORT) {
            return Err(kr::INVALID_ARGUMENT);
        }
        if flags & mpo::TG_BLOCK_TRACKING != 0 {
            // Only a graphics server's task may; no task here is one.
            return Err(kr::DENIED);
        }
        if flags & (mpo::SERVICE_PORT | mpo::CONNECTION_PORT) != 0 {
            return Err(kr::UNIMPLEMENTED_SERVICE_PORT);
        }
        if flags & mpo::QLIMIT != 0 && qlimit > super::QLIMIT_MAX {
            return Err(kr::INVALID_VALUE);
        }
        let (name, port) = self.port_alloc(flags & mpo::INSERT_SEND_RIGHT != 0)?;
        let p = self.port_mut(port);
        // ipc_port_init's reply-port marking (`IPC_PORT_INIT_REPLY`, and
        // MPO_PROVISIONAL_REPLY_PORT while not enforced): a reply port in a
        // hardened task, else a provisional one.
        if flags & mpo::REPLY_PORT != 0 && hardened {
            p.immovable_receive = true;
            p.reply_port = true;
        }
        if flags & mpo::PROVISIONAL_ID_PROT_OPTOUT != 0 {
            p.immovable_receive = true;
        }
        if flags & mpo::ENFORCE_REPLY_PORT_SEMANTICS != 0 {
            p.enforce_reply_port_semantics = true;
        }
        if flags & mpo::QLIMIT != 0 {
            p.qlimit = qlimit;
        }
        if flags & (mpo::IMPORTANCE_RECEIVER | mpo::DENAP_RECEIVER | mpo::TEMPOWNER) != 0 {
            p.impdonation = true;
            if flags & mpo::TEMPOWNER != 0 {
                p.tempowner = true;
            }
        }
        if flags & mpo::CONTEXT_AS_GUARD != 0 {
            let mut g = 0;
            if flags & mpo::STRICT != 0 {
                g |= mpg::STRICT;
            }
            if flags & mpo::IMMOVABLE_RECEIVE != 0 {
                g |= mpg::IMMOVABLE_RECEIVE;
            }
            self.guard_locked(port, context, g);
        } else {
            self.port_mut(port).context = context;
        }
        Ok(name)
    }

    /// `mach_port_destruct`.
    pub fn mach_port_destruct(&mut self, name: u32, srdelta: i32, guard: u64) -> u64 {
        if !name_valid(name) {
            return kr::INVALID_NAME;
        }
        if self.space.lookup(name).is_none() {
            self.guard_exception(name, Guard::InvalidName, 0);
            return kr::INVALID_NAME;
        }
        self.right_destruct(name, srdelta, guard)
    }

    /// `mach_port_insert_right`: right `t` (`poly`) into exactly `name`.
    pub fn mach_port_insert_right(&mut self, name: u32, poly: super::right::Carried, t: u32) -> u64 {
        if !name_valid(name) || !super::right::msgt::any_right(t) {
            return kr::INVALID_VALUE;
        }
        if poly == super::right::Carried::Dead {
            return kr::INVALID_CAPABILITY;
        }
        match self.object_copyout_name(poly, t, name) {
            Ok(()) => kr::SUCCESS,
            Err(e) => e,
        }
    }

    /// `mach_port_extract_right`: take `t` out of `name`; the carried right
    /// and its type.
    pub fn mach_port_extract_right(&mut self, name: u32, t: u32) -> Result<(super::right::Carried, u32), u64> {
        if !super::right::msgt::any(t) {
            return Err(kr::INVALID_VALUE);
        }
        if !name_valid(name) {
            return Err(kr::INVALID_RIGHT);
        }
        let flags = super::right::CopyinFlags { allow_immovable_send: t == super::right::msgt::COPY_SEND, ..Default::default() };
        let c = self.object_copyin(name, t, flags, 0, None)?;
        Ok((c, super::right::msgt::copyin_type(t)))
    }

    /// `mach_port_names`: every name and its type.
    pub fn mach_port_names(&mut self) -> (Vec<u32>, Vec<u32>) {
        let names: Vec<u32> = self.space.names().map(|(n, _)| n).collect();
        let mut types = Vec::with_capacity(names.len());
        for &n in &names {
            types.push(self.right_info(n).0);
        }
        (names, types)
    }
}

/// `MACH_NOTIFY_*` message ids.
pub mod notify_id {
    pub const PORT_DELETED: i32 = 0o101;
    pub const SEND_POSSIBLE: i32 = 0o102;
    pub const PORT_DESTROYED: i32 = 0o105;
    pub const NO_SENDERS: i32 = 0o106;
    pub const SEND_ONCE: i32 = 0o107;
    pub const DEAD_NAME: i32 = 0o110;
}

/// `MACH_PORT_*` attribute flavors.
pub mod attr {
    pub const LIMITS_INFO: i32 = 1;
    pub const RECEIVE_STATUS: i32 = 2;
    pub const DNREQUESTS_SIZE: i32 = 3;
    pub const TEMPOWNER: i32 = 4;
    pub const IMPORTANCE_RECEIVER: i32 = 5;
    pub const DENAP_RECEIVER: i32 = 6;
    pub const INFO_EXT: i32 = 7;
    pub const GUARD_INFO: i32 = 8;
    pub const SERVICE_THROTTLED: i32 = 9;
}

/// `MACH_PORT_STATUS_FLAG_*`.
pub mod status_flag {
    pub const TEMPOWNER: u32 = 0x01;
    pub const GUARDED: u32 = 0x02;
    pub const STRICT_GUARD: u32 = 0x04;
    pub const IMP_DONATION: u32 = 0x08;
    pub const GUARD_IMMOVABLE_RECEIVE: u32 = 0x40;
    pub const NO_GRANT: u32 = 0x80;
}

/// `MPO_*`: `mach_port_construct`'s options.
pub mod mpo {
    pub const CONTEXT_AS_GUARD: u32 = 0x01;
    pub const QLIMIT: u32 = 0x02;
    pub const TEMPOWNER: u32 = 0x04;
    pub const IMPORTANCE_RECEIVER: u32 = 0x08;
    pub const INSERT_SEND_RIGHT: u32 = 0x10;
    pub const STRICT: u32 = 0x20;
    pub const DENAP_RECEIVER: u32 = 0x40;
    pub const IMMOVABLE_RECEIVE: u32 = 0x80;
    pub const FILTER_MSG: u32 = 0x100;
    pub const TG_BLOCK_TRACKING: u32 = 0x200;
    pub const SERVICE_PORT: u32 = 0x400;
    pub const CONNECTION_PORT: u32 = 0x800;
    pub const REPLY_PORT: u32 = 0x1000;
    pub const ENFORCE_REPLY_PORT_SEMANTICS: u32 = 0x2000;
    pub const PROVISIONAL_REPLY_PORT: u32 = 0x4000;
    pub const PROVISIONAL_ID_PROT_OPTOUT: u32 = 0x8000;
}

/// `MPG_*`: guard flags.
pub mod mpg {
    pub const STRICT: u64 = 0x01;
    pub const IMMOVABLE_RECEIVE: u64 = 0x02;
}
