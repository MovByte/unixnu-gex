//! IOKit as a task reaches it (`iokit/Kernel/IOUserClient.cpp`), over the
//! device's own device tree: the registry's `IODeviceTree` plane. Of the
//! `IOService` plane's drivers, those on the path to the GPU
//! ([`super::platform`], [`super::accel`]) and APFS's are here; what would
//! need the others is reported.

use std::sync::OnceLock;

/// One entry of the device tree.
#[derive(Debug)]
pub struct Node {
    pub name: String,
    pub props: Vec<(String, Vec<u8>)>,
    /// A service's class (the `IOService` plane), and its typed properties;
    /// a device tree node is empty and has `OSData` properties only.
    pub class: &'static str,
    pub service_props: Vec<(String, Prop)>,
    pub parent: Option<u32>,
    pub children: Vec<u32>,
    /// A `kernel-only` node: a release kernel's `IODeviceTreeAlloc` makes
    /// each of its properties unserializable, so a task reads them empty.
    pub kernel_only: bool,
    /// A device tree entry a driver made a nub of: the nub's class, and its
    /// provider in the `IOService` plane.
    pub nub: Option<(&'static str, u32)>,
}

/// A property of a service, as `OSSerialize` writes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Prop {
    Str(String),
    Bool(bool),
    Strs(Vec<String>),
    /// An `OSNumber`: its value and its size in bits.
    Num(u64, u32),
    Data(Vec<u8>),
    /// An `OSSymbol` (what `setProperty(const char *, const char *)` sets).
    Sym(String),
}

/// The classes a service belongs to, most derived first.
pub fn superclasses(class: &str) -> &'static [&'static str] {
    match class {
        "AppleAPFSVolume" => &["AppleAPFSVolume", "IOMedia", "IOStorage", "IOService", "IORegistryEntry"],
        "AppleAPFSContainerScheme" => &["AppleAPFSContainerScheme", "IOPartitionScheme", "IOStorage", "IOService", "IORegistryEntry"],
        "AppleAPFSMedia" => &["AppleAPFSMedia", "IOMedia", "IOStorage", "IOService", "IORegistryEntry"],
        "AppleAPFSContainer" => &["AppleAPFSContainer", "IOStorage", "IOService", "IORegistryEntry"],
        "IOMedia" => &["IOMedia", "IOStorage", "IOService", "IORegistryEntry"],
        "IOPlatformExpertDevice" => &["IOPlatformExpertDevice", "IOService", "IORegistryEntry"],
        "IORegistryEntry" => &["IORegistryEntry"],
        "IOUserClient" => &["IOUserClient", "IOService", "IORegistryEntry"],
        "AppleAPFSUserClient" => &["AppleAPFSUserClient", "IOUserClient", "IOService", "IORegistryEntry"],
        _ => match super::platform::superclasses(class) {
            [] => super::accel::superclasses(class),
            s => s,
        },
    }
}

static TREE: OnceLock<Vec<Node>> = OnceLock::new();

/// Parse the flattened device tree (`DeviceTree.im4p`'s payload): each node
/// a count of properties and of children, each property a name of 32 bytes
/// and a length whose top bit iBoot uses, its value padded to 4 bytes.
pub fn parse(b: &[u8]) -> Result<Vec<Node>, String> {
    fn node(b: &[u8], at: &mut usize, parent: Option<u32>, out: &mut Vec<Node>) -> Result<u32, String> {
        let word = |o: usize| b.get(o..o + 4).map(|w| u32::from_le_bytes(w.try_into().unwrap())).ok_or("the device tree ends early".to_string());
        let (nprops, nchildren) = (word(*at)?, word(*at + 4)?);
        *at += 8;
        let mut props = Vec::with_capacity(nprops as usize);
        for _ in 0..nprops {
            let raw = b.get(*at..*at + 32).ok_or("the device tree ends early")?;
            let name = String::from_utf8_lossy(&raw[..raw.iter().position(|&c| c == 0).unwrap_or(32)]).into_owned();
            let len = (word(*at + 32)? & 0x7fff_ffff) as usize;
            *at += 36;
            props.push((name, b.get(*at..*at + len).ok_or("the device tree ends early")?.to_vec()));
            *at += (len + 3) & !3;
        }
        let name = props.iter().find(|(k, _)| k == "name").map_or(String::new(), |(_, v)| String::from_utf8_lossy(&v[..v.iter().position(|&c| c == 0).unwrap_or(v.len())]).into_owned());
        let id = out.len() as u32;
        let kernel_only = props.iter().any(|(k, _)| k == "kernel-only");
        out.push(Node { name, props, class: "", service_props: Vec::new(), parent, children: Vec::new(), kernel_only, nub: None });
        for _ in 0..nchildren {
            let c = node(b, at, Some(id), out)?;
            out[id as usize].children.push(c);
        }
        Ok(id)
    }
    let mut out = Vec::new();
    let mut at = 0;
    node(b, &mut at, None, &mut out)?;
    Ok(out)
}

/// Install the device tree the boot payload carries, and the volumes its
/// file system table names as the services APFS publishes for them.
pub fn set_tree(b: &[u8]) -> Result<(), String> {
    let mut t = parse(b)?;
    add_volumes(&mut t);
    if let Some(gpu) = super::platform::add(&mut t) {
        super::accel::add_service(&mut t, gpu);
    }
    add_root(&mut t);
    let _ = TREE.set(t);
    Ok(())
}

/// `IORegistryEntry::initialize`: the registry's root, "Root"; the device
/// tree hangs from it in the `IODeviceTree` plane.
fn add_root(t: &mut Vec<Node>) {
    t.push(Node { name: "Root".to_string(), props: Vec::new(), class: "IORegistryEntry", service_props: Vec::new(), parent: None, children: vec![0], kernel_only: false, nub: None });
}

/// Whether the kernel sets the root entry's property `name`: the planes
/// (`IORegistryEntry::initialize`), IOKit's build version and diagnostics
/// and the OS build version (`StartIOKit`), the console's lock and users
/// (`IOService::updateConsoleUsers`), and the kernel's CPU type and the
/// kernel collection's kext count (`OSKext`). The root has no other.
pub fn root_has(name: &str) -> bool {
    matches!(
        name,
        "IORegistryPlanes" | "IOKitBuildVersion" | "IOKitDiagnostics" | "OS Build Version" | "IOConsoleLocked" | "IOConsoleUsers" | "OSKernelCPUType" | "OSKernelCPUSubtype" | "OSPrelinkKextCount"
    )
}

/// The registry's root entry (`IORegistryEntry::getRegistryRoot`), the
/// last of the tree; none when the boot payload had no device tree.
pub fn root() -> Option<u32> {
    tree().len().checked_sub(1).map(|i| i as u32)
}

/// A registry plane (`IORegistryEntry::getPlane`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plane {
    Service,
    DeviceTree,
}

/// The plane of a name; `Err` for one whose links are not here: the power
/// plane, and the planes families make (and a name that is none, which
/// xnu answers as no plane).
pub fn plane(name: &[u8]) -> Result<Plane, String> {
    match name {
        b"IOService" => Ok(Plane::Service),
        b"IODeviceTree" => Ok(Plane::DeviceTree),
        _ => Err(format!("the {} plane", String::from_utf8_lossy(name))),
    }
}

/// `getParentSetReference` or `getChildSetReference` in `plane`: the
/// entries the entry is linked to there, in the order they were attached;
/// `Err` for links that drivers make. The device tree is all of the
/// `IODeviceTree` plane (the platform expert's `deleteList` takes none
/// away). Its root is the `IOPlatformExpertDevice`, also the root's child
/// in the `IOService` plane, where the platform's drivers hang from it and
/// the other device tree entries are its nubs or not.
pub fn links(t: &[Node], i: u32, plane: Plane, parents: bool) -> Result<Vec<u32>, String> {
    let Some(n) = t.get(i as usize) else { return Ok(Vec::new()) };
    let root = t.len() as u32 - 1;
    if i == root {
        return match (plane, parents) {
            (_, true) => Ok(Vec::new()),
            (Plane::DeviceTree, false) => Ok(n.children.clone()),
            (Plane::Service, false) => Err("the registry root's children in the IOService plane (IOResources, IOUserResources and the platform)".to_string()),
        };
    }
    if n.class.is_empty() {
        return match (plane, parents) {
            (Plane::DeviceTree, true) => Ok(vec![n.parent.unwrap_or(root)]),
            (Plane::DeviceTree, false) => Ok(n.children.clone()),
            (Plane::Service, true) => provider(t, i).map(|p| p.into_iter().collect()),
            (Plane::Service, false) if i == 0 => Err("the platform expert device's children in the IOService plane (its drivers)".to_string()),
            (Plane::Service, false) if n.nub.is_some() => Err(format!("the drivers matched on {} (its children in the IOService plane)", n.name)),
            (Plane::Service, false) => Err(format!("whether the platform made {} a nub in the IOService plane", n.name)),
        };
    }
    match (plane, parents) {
        (Plane::DeviceTree, _) => Ok(Vec::new()),
        (Plane::Service, true) => provider(t, i).map(|p| p.into_iter().collect()),
        // The user clients a service has opened are attached to it, and
        // they are not registry entries here.
        (Plane::Service, false) if n.class == super::accel::CLASS => Err(format!("the user clients of {} as its children in the IOService plane", n.name)),
        (Plane::Service, false) if super::platform::is_driver(n.class) => Err(format!("the nubs and clients of {} (its children in the IOService plane)", n.name)),
        (Plane::Service, false) => Ok(n.children.clone()),
    }
}

/// The entry's provider, its parent in the `IOService` plane: none for the
/// registry's root; the root for the platform expert device; a nub's
/// driver; a driver's nub. `Err` for a device tree entry the platform's
/// drivers here did not make a nub of.
pub fn provider(t: &[Node], i: u32) -> Result<Option<u32>, String> {
    let Some(n) = t.get(i as usize) else { return Ok(None) };
    let root = t.len() as u32 - 1;
    if i == root {
        return Ok(None);
    }
    if n.class.is_empty() {
        return match n.nub {
            _ if i == 0 => Ok(Some(root)),
            Some((_, p)) => Ok(Some(p)),
            None => Err(format!("whether the platform made {} a nub in the IOService plane", n.name)),
        };
    }
    n.parent.map(Some).ok_or_else(|| format!("the provider of {} (the storage controller)", n.name))
}

/// `IORegistryEntry::getName()`: the device tree root's is its first
/// `compatible` name (`IODeviceTreeAlloc`), its `IODeviceTree` plane name
/// staying `device-tree`.
pub fn name(t: &[Node], i: u32) -> String {
    let Some(n) = t.get(i as usize) else { return String::new() };
    if i == 0 {
        if let Some((_, v)) = n.props.iter().find(|(k, _)| k == "compatible") {
            return String::from_utf8_lossy(&v[..v.iter().position(|&c| c == 0).unwrap_or(v.len())]).into_owned();
        }
    }
    n.name.clone()
}

/// The entry's class: a device tree entry other than the root is an
/// `IOService` that a driver may have replaced with a nub of its own class:
/// those the drivers here made ([`super::platform`]) have theirs, and the
/// others' are the platform's to say.
pub fn class(t: &[Node], i: u32) -> Result<&'static str, String> {
    let Some(n) = t.get(i as usize) else { return Err("no such entry".to_string()) };
    if !n.class.is_empty() {
        return Ok(n.class);
    }
    if i == 0 {
        return Ok("IOPlatformExpertDevice");
    }
    if let Some((class, _)) = n.nub {
        return Ok(class);
    }
    Err(format!("the class of the device tree entry {}", n.name))
}

/// One `AppleAPFSVolume` for each volume of `/filesystems/fstab`, in its
/// order: `disk1s1` and on, the numbers this device's container would give
/// them being iBoot's and the storage's to know.
fn add_volumes(t: &mut Vec<Node>) {
    let Some(Some(fstab)) = from_path(t, "IODeviceTree:/filesystems/fstab").ok() else { return };
    let vols: Vec<(String, Vec<(String, Vec<u8>)>)> = t[fstab as usize].children.iter().map(|&c| (t[c as usize].name.clone(), t[c as usize].props.clone())).collect();
    // `physical_store_to_container` and `APFSContainerGetBootDevice`'s walk:
    // the physical store's IOMedia, its AppleAPFSContainerScheme, the
    // AppleAPFSMedia that is the synthesized disk, its AppleAPFSContainer,
    // and the volumes under that.
    let service = |name: &str, class: &'static str, parent: Option<u32>, bsd: Option<&str>| Node {
        name: name.to_string(),
        props: Vec::new(),
        class,
        service_props: bsd.map_or(Vec::new(), |b| vec![("BSD Name".to_string(), Prop::Str(b.to_string()))]),
        parent,
        children: Vec::new(),
        kernel_only: false,
        nub: None,
    };
    let store = t.len() as u32;
    t.push(service("disk0s1", "IOMedia", None, Some("disk0s1")));
    let scheme = t.len() as u32;
    t.push(service("AppleAPFSContainerScheme", "AppleAPFSContainerScheme", Some(store), None));
    t[store as usize].children.push(scheme);
    let media = t.len() as u32;
    t.push(service("AppleAPFSMedia", "AppleAPFSMedia", Some(scheme), Some("disk1")));
    t[scheme as usize].children.push(media);
    let container = t.len() as u32;
    t.push(service("AppleAPFSContainer", "AppleAPFSContainer", Some(media), None));
    t[media as usize].children.push(container);
    for (n, (_, props)) in vols.iter().enumerate() {
        let text = |k: &str| props.iter().find(|(p, _)| p == k).map_or(String::new(), |(_, v)| String::from_utf8_lossy(&v[..v.iter().position(|&c| c == 0).unwrap_or(v.len())]).into_owned());
        let name = text("vol.fs_name");
        let bsd = format!("disk1s{}", n + 1);
        let service_props = vec![
            ("BSD Name".to_string(), Prop::Str(bsd)),
            ("FullName".to_string(), Prop::Str(name.clone())),
            // The volume's role by name (`vol.fs_role` agrees with them).
            ("Role".to_string(), Prop::Strs(vec![name.clone()])),
        ];
        let id = t.len() as u32;
        t.push(Node { name, props: Vec::new(), class: "AppleAPFSVolume", service_props, parent: Some(container), children: Vec::new(), kernel_only: false, nub: None });
        t[container as usize].children.push(id);
    }
}

/// Whether a property entry `i` lacks may yet be one the device's entry
/// has, which is reported rather than answered missing:
/// - The registry's root has only the properties [`root_has`] names.
/// - A device tree entry that no driver here made a nub of has only its
///   own.
/// - The accelerator's are [`super::accel::property_unknown`]'s.
/// - Every other entry has properties its drivers set that are not
///   modelled. The exception is `IOClassNameOverride` on the entries from
///   the platform expert device to the GPU. In the kernelcache, only
///   IOSkywalkFamily sets it, on its own objects (0xfffffff00593be08); the
///   kernel only reads it (`skipKey`, 0xfffffff007816644).
pub fn property_unknown(t: &[Node], i: u32, name: &str) -> bool {
    let Some(n) = t.get(i as usize) else { return false };
    if i as usize + 1 == t.len() {
        return root_has(name);
    }
    if n.class.is_empty() && n.nub.is_none() && i != 0 {
        return false;
    }
    if n.class == super::accel::CLASS {
        return super::accel::property_unknown(name);
    }
    let on_gpu_path = i == 0 || n.nub.is_some() || super::platform::is_driver(n.class);
    !(on_gpu_path && name == "IOClassNameOverride")
}

/// The services a matching dictionary asks for: `IOProviderClass` by class
/// (and its superclasses), any other string by the service's property of
/// that name; `Err` for what is not a string.
pub fn matching(tree: &[Node], dict: &[(String, DictValue)]) -> Result<Vec<u32>, String> {
    let mut class = None;
    let mut props = Vec::new();
    for (k, v) in dict {
        match (k.as_str(), v) {
            ("IOProviderClass", DictValue::Str(c)) => class = Some(c.as_str()),
            (_, DictValue::Str(s)) => props.push((k.as_str(), s.as_str())),
            _ => return Err(format!("the matching key {k} ({v:?})")),
        }
    }
    // The platform expert device is registered (`IOPlatformExpertDevice`
    // calls `registerService`); its properties are partly the platform's.
    if class == Some("IOPlatformExpertDevice") {
        if !props.is_empty() {
            return Err(format!("the platform expert device by its properties {props:?}"));
        }
        return Ok(if tree.is_empty() { Vec::new() } else { vec![0] });
    }
    let wanted = |n: &Node| {
        superclasses(n.class).contains(&"IOService")
            && class.map_or(true, |c| superclasses(n.class).contains(&c))
            && props.iter().all(|&(k, v)| n.service_props.iter().any(|(pk, pv)| pk == k && matches!(pv, Prop::Str(s) if s == v)))
    };
    let found: Vec<u32> = tree.iter().enumerate().filter(|(_, n)| wanted(n)).map(|(i, _)| i as u32).collect();
    // APFS's own classes are all here, and so are the accelerator's (one
    // GPU, one accelerator). Of the classes above them (and of services by
    // property alone) the storage drivers' and the whole disk's are not, so
    // those are answered only by a BSD name found here.
    let complete = matches!(class, Some("AppleAPFSVolume" | "AppleAPFSContainer" | "AppleAPFSMedia" | "AppleAPFSContainerScheme")) || class.is_some_and(super::accel::class_complete);
    let by_name = props.iter().any(|&(k, _)| k == "BSD Name");
    if !complete && !(by_name && !found.is_empty()) {
        return Err(format!("the services of class {class:?} with {props:?}: the drivers' own are not here"));
    }
    Ok(found)
}

/// `OSObject::metaCast`: whether the entry is, or inherits from, `class`.
/// Every device tree entry is an `IOService`, whatever nub replaced it.
pub fn conforms(t: &[Node], i: u32, class: &str) -> Result<bool, String> {
    match self::class(t, i) {
        Ok(c) => Ok(superclasses(c).contains(&class)),
        Err(_) if matches!(class, "IOService" | "IORegistryEntry") => Ok(true),
        Err(what) => Err(what),
    }
}

/// `IORegistryEntry::getLocation`: of a volume, its index in the container,
/// one less than the number ending its BSD name.
pub fn location(n: &Node) -> Option<String> {
    let Some((_, Prop::Str(bsd))) = n.service_props.iter().find(|(k, _)| k == "BSD Name") else { return None };
    let at = bsd.rfind('s')? + 1;
    let digits = &bsd[at..];
    // Zero-based: `disk1s1` is index 0.
    digits.parse::<u32>().ok()?.checked_sub(1).map(|i| i.to_string())
}

/// The role (`vol.fs_role`) of the volume at `index` in the container.
pub fn volume_role(index: u64) -> Option<u16> {
    let tree = tree();
    let fstab = from_path(tree, "IODeviceTree:/filesystems/fstab").ok()??;
    let vol = tree[fstab as usize].children.get(usize::try_from(index).ok()?)?;
    let (_, v) = tree[*vol as usize].props.iter().find(|(k, _)| k == "vol.fs_role")?;
    Some(u16::from_le_bytes(v.get(..2)?.try_into().ok()?))
}

/// `IOGetBootManifestHash`: `/chosen`'s `boot-manifest-hash`.
pub fn boot_manifest_hash() -> Option<&'static [u8]> {
    let t = tree();
    let chosen = from_path(t, "IODeviceTree:/chosen").ok()??;
    t[chosen as usize].props.iter().find(|(k, _)| k == "boot-manifest-hash").map(|(_, v)| v.as_slice())
}

/// A value in a matching dictionary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DictValue {
    Str(String),
    Other(u32),
}

/// `OSUnserializeBinary` of a matching dictionary of strings: `None` for
/// anything else's framing.
pub fn unserialize_dict(b: &[u8]) -> Option<Vec<(String, DictValue)>> {
    const DICTIONARY: u32 = 0x01;
    const SYMBOL: u32 = 0x08;
    const STRING: u32 = 0x09;
    let word = |o: usize| b.get(o..o + 4).map(|w| u32::from_le_bytes(w.try_into().unwrap()));
    if word(0)? != 0xd3 {
        return None;
    }
    let head = word(4)?;
    if (head >> 24) & 0x7f != DICTIONARY {
        return None;
    }
    let count = head & 0x00ff_ffff;
    let mut at = 8;
    let mut out = Vec::new();
    for _ in 0..count {
        let k = word(at)?;
        if (k >> 24) & 0x7f != SYMBOL {
            return None;
        }
        let klen = (k & 0x00ff_ffff) as usize;
        let key = b.get(at + 4..at + 4 + klen)?;
        let key = String::from_utf8_lossy(&key[..key.iter().position(|&c| c == 0).unwrap_or(klen)]).into_owned();
        at += 4 + ((klen + 3) & !3);
        let v = word(at)?;
        let kind = (v >> 24) & 0x7f;
        let vlen = (v & 0x00ff_ffff) as usize;
        let value = if kind == STRING || kind == SYMBOL {
            let bytes = b.get(at + 4..at + 4 + vlen)?;
            DictValue::Str(String::from_utf8_lossy(&bytes[..bytes.iter().position(|&c| c == 0).unwrap_or(vlen)]).into_owned())
        } else {
            DictValue::Other(kind)
        };
        at += 4 + ((vlen + 3) & !3);
        out.push((key, value));
    }
    Some(out)
}

/// An iterator handed out: an `OSCollectionIterator` over a fixed set,
/// or an `IORegistryIterator`.
enum Iter {
    Set(Vec<u32>, usize),
    Registry(RegistryIter),
}

/// `IORegistryIterator`: its root and plane, its options, the stack of
/// cursors entered (`where`, the first being `start`), and the entries
/// already recursed into (`done`).
struct RegistryIter {
    root: u32,
    plane: Plane,
    options: u32,
    cursors: Vec<Cursor>,
    done: Vec<u32>,
}

/// `IORegCursor`: the entry whose links it walks, or last gave, and the
/// links once it has started on them.
struct Cursor {
    current: Option<u32>,
    links: Option<(Vec<u32>, usize)>,
}

const K_IO_REGISTRY_ITERATE_RECURSIVELY: u32 = 1;
const K_IO_REGISTRY_ITERATE_PARENTS: u32 = 2;
/// `kIORegistryIteratorInvalidFlag`, which `iterateOver` clears.
const K_IO_REGISTRY_ITERATOR_INVALID_FLAG: u32 = 0x8000_0000;

impl RegistryIter {
    /// `getNextObjectFlat`: the next link of the cursor's entry, which it
    /// then holds as its current.
    fn next_flat(&mut self, t: &[Node]) -> Result<Option<u32>, String> {
        let parents = self.options & K_IO_REGISTRY_ITERATE_PARENTS != 0;
        let w = self.cursors.last_mut().expect("the start cursor");
        if w.links.is_none() {
            if let Some(c) = w.current {
                w.links = Some((links(t, c, self.plane, parents)?, 0));
            }
        }
        let next = match &mut w.links {
            Some((l, at)) => {
                let n = l.get(*at).copied();
                if n.is_some() {
                    *at += 1;
                }
                n
            }
            None => None,
        };
        w.current = next;
        Ok(next)
    }

    /// `getNextObjectRecursive`: depth first, each entry entered the first
    /// time it is given.
    fn next_recursive(&mut self, t: &[Node]) -> Result<Option<u32>, String> {
        let next = loop {
            let n = self.next_flat(t)?;
            if n.is_some() || !self.exit() {
                break n;
            }
        };
        if let Some(n) = next {
            if !self.done.contains(&n) {
                self.done.push(n);
                self.enter();
            }
        }
        Ok(next)
    }

    fn next(&mut self, t: &[Node]) -> Result<Option<u32>, String> {
        if self.options & K_IO_REGISTRY_ITERATE_RECURSIVELY != 0 { self.next_recursive(t) } else { self.next_flat(t) }
    }

    fn new(root: u32, plane: Plane, options: u32) -> Self {
        let start = Cursor { current: Some(root), links: None };
        RegistryIter { root, plane, options: options & !K_IO_REGISTRY_ITERATOR_INVALID_FLAG, cursors: vec![start], done: Vec::new() }
    }

    /// `enterEntry`: a cursor over the links of the entry last given.
    fn enter(&mut self) {
        let current = self.cursors.last().expect("the start cursor").current;
        self.cursors.push(Cursor { current, links: None });
    }

    /// `exitEntry`: the cursor's links dropped, and it popped unless it is
    /// the start; whether it was.
    fn exit(&mut self) -> bool {
        self.cursors.last_mut().expect("the start cursor").links = None;
        if self.cursors.len() > 1 {
            self.cursors.pop();
            true
        } else {
            false
        }
    }

    /// `reset`: every cursor exited, the done set dropped, and the start
    /// back on the root.
    fn reset(&mut self) {
        while self.exit() {}
        self.done.clear();
        self.cursors[0].current = Some(self.root);
        self.options &= !K_IO_REGISTRY_ITERATOR_INVALID_FLAG;
    }
}

static ITERATORS: std::sync::Mutex<Vec<Iter>> = std::sync::Mutex::new(Vec::new());

fn iterator_add(it: Iter) -> u32 {
    let mut t = ITERATORS.lock().unwrap_or_else(|e| e.into_inner());
    t.push(it);
    (t.len() - 1) as u32
}

/// A new iterator over `items`, by number.
pub fn iterator_new(items: Vec<u32>) -> u32 {
    iterator_add(Iter::Set(items, 0))
}

/// `IORegistryIterator::iterateOver(root, plane, options)`, by number.
pub fn registry_iterator_new(root: u32, plane: Plane, options: u32) -> u32 {
    iterator_add(Iter::Registry(RegistryIter::new(root, plane, options)))
}

/// The iterator's next entry; `Err` for links that are not here.
pub fn iterator_next(id: u32) -> Result<Option<u32>, String> {
    let mut t = ITERATORS.lock().unwrap_or_else(|e| e.into_inner());
    match t.get_mut(id as usize) {
        Some(Iter::Set(items, at)) => {
            let next = items.get(*at).copied();
            if next.is_some() {
                *at += 1;
            }
            Ok(next)
        }
        Some(Iter::Registry(r)) => r.next(tree()),
        None => Ok(None),
    }
}

/// `OSIterator::reset`: back to the first entry.
pub fn iterator_reset(id: u32) {
    match ITERATORS.lock().unwrap_or_else(|e| e.into_inner()).get_mut(id as usize) {
        Some(Iter::Set(_, at)) => *at = 0,
        Some(Iter::Registry(r)) => r.reset(),
        None => {}
    }
}

/// `enterEntry` on a registry iterator; `false` for another iterator.
pub fn iterator_enter(id: u32) -> bool {
    match ITERATORS.lock().unwrap_or_else(|e| e.into_inner()).get_mut(id as usize) {
        Some(Iter::Registry(r)) => {
            r.enter();
            true
        }
        _ => false,
    }
}

/// `exitEntry` on a registry iterator: whether it left an entry; `None`
/// for another iterator.
pub fn iterator_exit(id: u32) -> Option<bool> {
    match ITERATORS.lock().unwrap_or_else(|e| e.into_inner()).get_mut(id as usize) {
        Some(Iter::Registry(r)) => Some(r.exit()),
        _ => None,
    }
}

/// An `IOServiceUserNotification`: the services its matching notification
/// has handed it and not yet given out (`newSet`, taken from its end), and
/// the send right to the port it would ping (`remotePort`). No service
/// comes or goes once the registry is built, so after the services already
/// there none is added and no ping is owed.
struct Notification {
    new_set: Vec<u32>,
    wake: Option<u64>,
}

static NOTIFICATIONS: std::sync::Mutex<Vec<Option<Notification>>> = std::sync::Mutex::new(Vec::new());

/// `kMaxOutstanding`: a notification holds at most this many services.
const MAX_OUTSTANDING: usize = 1024;

/// A notification of the services `existing` hands it, in that order, and
/// the right `wake` it keeps; its number.
pub fn notification_new(existing: Vec<u32>, wake: Option<u64>) -> u32 {
    let new_set = existing.into_iter().take(MAX_OUTSTANDING).collect();
    let mut t = NOTIFICATIONS.lock().unwrap_or_else(|e| e.into_inner());
    t.push(Some(Notification { new_set, wake }));
    (t.len() - 1) as u32
}

/// `copyNextObject`: the last service handed it, or none (and it is armed
/// again).
pub fn notification_next(id: u32) -> Option<u32> {
    NOTIFICATIONS.lock().unwrap_or_else(|e| e.into_inner()).get_mut(id as usize)?.as_mut()?.new_set.pop()
}

/// The notification freed: the right it kept, to release.
pub fn notification_free(id: u32) -> Option<u64> {
    NOTIFICATIONS.lock().unwrap_or_else(|e| e.into_inner()).get_mut(id as usize)?.take()?.wake
}

/// `serialize_str` and `serialize_bool`'s common frame.
pub fn serialize_prop(p: &Prop) -> Vec<u8> {
    const K_OS_SERIALIZE_BINARY_SIGNATURE: &[u8; 4] = b"\xd3\0\0\0";
    const K_OS_SERIALIZE_STRING: u32 = 0x0900_0000;
    const K_OS_SERIALIZE_BOOLEAN: u32 = 0x0b00_0000;
    const K_OS_SERIALIZE_END_COLLECTION: u32 = 0x8000_0000;
    let mut b = K_OS_SERIALIZE_BINARY_SIGNATURE.to_vec();
    match p {
        Prop::Str(s) => {
            b.extend_from_slice(&(K_OS_SERIALIZE_END_COLLECTION | K_OS_SERIALIZE_STRING | s.len() as u32).to_le_bytes());
            b.extend_from_slice(s.as_bytes());
            b.resize((b.len() + 3) & !3, 0);
        }
        Prop::Bool(v) => b.extend_from_slice(&(K_OS_SERIALIZE_END_COLLECTION | K_OS_SERIALIZE_BOOLEAN | u32::from(*v)).to_le_bytes()),
        // The number's size in bits, then its 64-bit value.
        Prop::Num(v, bits) => {
            const K_OS_SERIALIZE_NUMBER: u32 = 0x0400_0000;
            b.extend_from_slice(&(K_OS_SERIALIZE_END_COLLECTION | K_OS_SERIALIZE_NUMBER | bits).to_le_bytes());
            b.extend_from_slice(&v.to_le_bytes());
        }
        Prop::Data(d) => return serialize_data(d),
        // The symbol's characters and NUL.
        Prop::Sym(s) => {
            const K_OS_SERIALIZE_SYMBOL: u32 = 0x0800_0000;
            b.extend_from_slice(&(K_OS_SERIALIZE_END_COLLECTION | K_OS_SERIALIZE_SYMBOL | (s.len() as u32 + 1)).to_le_bytes());
            b.extend_from_slice(s.as_bytes());
            b.push(0);
            b.resize((b.len() + 3) & !3, 0);
        }
        Prop::Strs(items) => {
            const K_OS_SERIALIZE_ARRAY: u32 = 0x0200_0000;
            b.extend_from_slice(&(K_OS_SERIALIZE_END_COLLECTION | K_OS_SERIALIZE_ARRAY | items.len() as u32).to_le_bytes());
            for (i, s) in items.iter().enumerate() {
                let end = if i + 1 == items.len() { K_OS_SERIALIZE_END_COLLECTION } else { 0 };
                b.extend_from_slice(&(end | K_OS_SERIALIZE_STRING | s.len() as u32).to_le_bytes());
                b.extend_from_slice(s.as_bytes());
                b.resize((b.len() + 3) & !3, 0);
            }
        }
    }
    b
}

/// IOReturn codes (`IOReturn.h`).
pub mod ret {
    pub const SUCCESS: i32 = 0;
    pub const ERROR: i32 = 0xe00002bc_u32 as i32;
    pub const NO_MEMORY: i32 = 0xe00002bd_u32 as i32;
    pub const NO_RESOURCES: i32 = 0xe00002be_u32 as i32;
    pub const IPC_ERROR: i32 = 0xe00002bf_u32 as i32;
    pub const NO_DEVICE: i32 = 0xe00002c0_u32 as i32;
    pub const NOT_PRIVILEGED: i32 = 0xe00002c1_u32 as i32;
    pub const BAD_ARGUMENT: i32 = 0xe00002c2_u32 as i32;
    pub const UNSUPPORTED: i32 = 0xe00002c7_u32 as i32;
    pub const VM_ERROR: i32 = 0xe00002c8_u32 as i32;
    pub const NOT_READY: i32 = 0xe00002d8_u32 as i32;
    pub const NOT_FOUND: i32 = 0xe00002f0_u32 as i32;
    pub const NOT_PERMITTED: i32 = 0xe00002e2_u32 as i32;
    pub const NO_COMPLETION: i32 = 0xe00002ea_u32 as i32;
    pub const UNDERRUN: i32 = 0xe00002e7_u32 as i32;
}

/// `kIOUCVariableStructureSize`: a dispatch count that is not checked.
pub const VARIABLE: u32 = 0xffff_ffff;

/// `sizeof(io_struct_inband_t)`.
pub const STRUCT_INBAND_MAX: usize = 4096;

/// An `IOExternalMethodDispatch`'s checks: the scalar input count, the
/// structure input size, the scalar output count and the structure output
/// size a selector takes, each [`VARIABLE`] or exact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dispatch {
    pub scalar_in: u32,
    pub struct_in: u32,
    pub scalar_out: u32,
    pub struct_out: u32,
}

/// `IOExternalMethodArguments` as a method sees them: the inputs, and the
/// outputs sized to what the caller has room for (a method lowers the
/// counts it fills less of). An out-of-line structure is its address and
/// size in the calling task, the `IOMemoryDescriptor` over it.
#[derive(Clone, Debug, Default)]
pub struct MethodArgs {
    pub selector: u32,
    /// An asynchronous call (io_connect_async_method: `asyncReference` set),
    /// its `asyncWakePort` (a send right the kernel holds; none for a null
    /// port) and its reference.
    pub is_async: bool,
    pub wake: Option<super::ipc::ObjId>,
    pub reference: Vec<u64>,
    pub scalar_in: Vec<u64>,
    pub struct_in: Vec<u8>,
    pub ool_in: Option<(u64, u64)>,
    pub scalar_out: Vec<u64>,
    pub struct_out: Vec<u8>,
    pub ool_out: Option<(u64, u64)>,
}

impl MethodArgs {
    /// The structure input's size: the descriptor's length, else the inband
    /// bytes'.
    pub fn struct_in_size(&self) -> u64 {
        self.ool_in.map_or(self.struct_in.len() as u64, |(_, n)| n)
    }

    pub fn struct_out_size(&self) -> u64 {
        self.ool_out.map_or(self.struct_out.len() as u64, |(_, n)| n)
    }
}

/// `IOUserClient::externalMethod`'s checks of a dispatch entry: every count
/// that is not [`VARIABLE`] must be the caller's (kIOReturnBadArgument).
pub fn dispatch_check(d: &Dispatch, a: &MethodArgs) -> Result<(), i32> {
    let ok = |want: u32, got: u64| want == VARIABLE || u64::from(want) == got;
    if !ok(d.scalar_in, a.scalar_in.len() as u64) || !ok(d.struct_in, a.struct_in_size()) || !ok(d.scalar_out, a.scalar_out.len() as u64) || !ok(d.struct_out, a.struct_out_size()) {
        return Err(ret::BAD_ARGUMENT);
    }
    Ok(())
}

/// `IOUserClient::externalMethod` without a dispatch entry: the
/// pre-Leopard method vector, which takes no out-of-line structure
/// (kIOReturnIPCError); a client with no vector (`getTargetAndMethodForIndex`
/// and `getAsyncTargetAndMethodForIndex` answering none) has no method
/// (kIOReturnUnsupported).
pub fn no_method(a: &MethodArgs) -> i32 {
    if a.ool_in.is_some() || a.ool_out.is_some() {
        return ret::IPC_ERROR;
    }
    ret::UNSUPPORTED
}

/// What kind of user client one is, and its own state.
pub enum Kind {
    /// AppleAPFSContainer's.
    Apfs,
    /// One of the accelerator's ([`super::accel`]).
    Accel(super::accel::Client),
}

/// An `IOUserClient` a task opened: the service it is attached to, its
/// class, its registry entry id, `IOUserClientCreator`, whether
/// `IOUserClientDefaultLocking` was set on it, whether it has been closed
/// (`closed`: io_service_close or clientDied ran clientClose), and its
/// kind's state.
pub struct UserClient {
    pub service: u32,
    pub class: &'static str,
    pub id: u64,
    pub creator: String,
    pub default_locking: bool,
    pub closed: bool,
    pub kind: Kind,
}

/// The user clients, each behind its own lock: a call on a client holds it
/// for the call, as IOUserClient's default locking (`ipcEnter`) does, while
/// other clients' calls go on.
static CLIENTS: std::sync::Mutex<Vec<Option<std::sync::Arc<std::sync::Mutex<UserClient>>>>> = std::sync::Mutex::new(Vec::new());

/// The next registry entry id: the entries of the device tree have theirs
/// in creation order (`gIORegistryLastID`), and each user client the next.
static NEXT_CLIENT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// `kIORegistryEntryIDPrefix`, the first registry entry id.
pub const REGISTRY_ID_PREFIX: u64 = 0x1_0000_0000;

/// The registry entry id of entry `i` of the tree.
pub fn registry_id(i: u32) -> u64 {
    REGISTRY_ID_PREFIX + u64::from(i)
}

/// A new user client of `service`, by its number.
pub fn client_add(service: u32, class: &'static str, creator: String, default_locking: bool, kind: Kind) -> u32 {
    let serial = NEXT_CLIENT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let id = REGISTRY_ID_PREFIX + tree().len() as u64 + serial;
    let c = UserClient { service, class, id, creator, default_locking, closed: false, kind };
    let mut t = CLIENTS.lock().unwrap_or_else(|e| e.into_inner());
    t.push(Some(std::sync::Arc::new(std::sync::Mutex::new(c))));
    (t.len() - 1) as u32
}

/// The user client numbered `id`; none once it is freed.
pub fn client(id: u32) -> Option<std::sync::Arc<std::sync::Mutex<UserClient>>> {
    CLIENTS.lock().unwrap_or_else(|e| e.into_inner()).get(id as usize)?.clone()
}

/// The client freed: out of the table, nothing naming it any more.
fn client_remove(id: u32) -> Option<std::sync::Arc<std::sync::Mutex<UserClient>>> {
    CLIENTS.lock().unwrap_or_else(|e| e.into_inner()).get_mut(id as usize)?.take()
}

/// `is_io_service_open_extended` after its checks: the service's
/// `newUserClient(owningTask, securityID, type, properties)`, and the
/// properties the open sets on the new client: `IOUserClientCreator`
/// (`IOCopyLogNameForPID`: "pid N, " and the process's `p_comm`), and
/// `IOUserClientDefaultLocking` for a client of a kext that does not depend
/// on IOSurface and set no locking property itself.
pub fn open_user_client(k: &mut crate::syscalls::Kernel, service: u32, ty: u32) -> Result<u32, i32> {
    let t = tree();
    let Some(n) = t.get(service as usize) else { return Err(ret::BAD_ARGUMENT) };
    let pid = k.pid;
    let comm = k.darwin_public(pid).map(|(p, _)| String::from_utf8_lossy(&p.comm).into_owned()).unwrap_or_default();
    let creator = format!("pid {pid}, {comm}");
    let (class, kind, default_locking) = match n.class {
        // IOService::newUserClient by the container's IOUserClientClass
        // (its personality's), for any type; the apfs kext does not depend
        // on IOSurface.
        "AppleAPFSContainer" => ("AppleAPFSUserClient", Kind::Apfs, true),
        c if c == super::accel::CLASS => {
            let (class, client) = super::accel::new_user_client(k, service, ty)?;
            // IOGPUFamily depends on IOSurface; the WebMetal client is
            // the kernel's own and depends on nothing.
            let locking = class == super::accel::WIRE_CLASS;
            (class, Kind::Accel(client), locking)
        }
        _ => {
            k.darwin_unimplemented(format!("newUserClient of {} (type {ty:#x})", name(t, service)));
            return Err(ret::UNSUPPORTED);
        }
    };
    Ok(client_add(service, class, creator, default_locking, kind))
}

/// The client's `clientClose`.
pub fn client_close(k: &mut crate::syscalls::Kernel, c: &mut UserClient) {
    match &mut c.kind {
        // AppleAPFSUserClient's (0xfffffff00666facc) closes what the client
        // opened on its container and terminates it; neither has a state
        // here, the container's opens not being modelled.
        Kind::Apfs => {}
        Kind::Accel(a) => super::accel::client_close(k, a),
    }
}

/// `clientDied`, when the connection's last send right goes
/// (`iokit_client_died`): clientClose unless the client was closed; then
/// the client is gone, nothing naming it any more.
pub fn client_died(k: &mut crate::syscalls::Kernel, id: u32) {
    let Some(cell) = client_remove(id) else { return };
    let mut c = cell.lock().unwrap_or_else(|e| e.into_inner());
    if !c.closed {
        c.closed = true;
        client_close(k, &mut c);
    }
    if let Kind::Accel(a) = &mut c.kind {
        super::accel::client_free(k, a);
    }
}

/// `getService`: the provider for the accelerator's clients, none for
/// IOUserClient's default.
pub fn client_service(c: &UserClient) -> Option<u32> {
    match &c.kind {
        Kind::Apfs => None,
        Kind::Accel(a) => super::accel::client_service(c.service, a),
    }
}

/// `clientMemoryForType`: no client here has memory of any type
/// (IOUserClient's default, kIOReturnUnsupported).
pub fn client_memory_for_type(_k: &mut crate::syscalls::Kernel, _c: &mut UserClient, _ty: u32) -> Result<std::convert::Infallible, i32> {
    Err(ret::UNSUPPORTED)
}

/// `registerNotificationPort(port, type, refCon)`.
pub fn register_notification_port(k: &mut crate::syscalls::Kernel, c: &mut UserClient, port: Option<super::ipc::ObjId>, ty: u32, reference: u64) -> i32 {
    match &mut c.kind {
        Kind::Apfs => {
            k.darwin_unimplemented("AppleAPFSUserClient::registerNotificationPort".to_string());
            ret::UNSUPPORTED
        }
        Kind::Accel(a) => super::accel::register_notification_port(k, a, port, ty, reference),
    }
}

/// `callExternalMethod`: the client's externalMethod.
pub fn external_method(k: &mut crate::syscalls::Kernel, c: &mut UserClient, a: &mut MethodArgs) -> i32 {
    match &mut c.kind {
        Kind::Apfs => apfs_method(k, c.service, a),
        Kind::Accel(x) => super::accel::external_method(k, x, a),
    }
}

/// AppleAPFSUserClient's methods: of them, selector 9, a volume's
/// information by its index, which APFSVolumeRoleFind reads the role from
/// (the first two bytes).
fn apfs_method(k: &mut crate::syscalls::Kernel, _service: u32, a: &mut MethodArgs) -> i32 {
    if a.selector == 9 && a.struct_in.len() == 8 && a.ool_in.is_none() {
        let index = u64::from_le_bytes(a.struct_in[..8].try_into().unwrap());
        let Some(role) = volume_role(index) else { return ret::NOT_FOUND };
        a.struct_out.iter_mut().for_each(|b| *b = 0);
        if a.struct_out.len() >= 2 {
            a.struct_out[..2].copy_from_slice(&role.to_le_bytes());
        }
        return ret::SUCCESS;
    }
    k.darwin_unimplemented(format!("IOConnectCallMethod on AppleAPFSContainer: selector {}, {} scalars, {} bytes in: {:x?}", a.selector, a.scalar_in.len(), a.struct_in.len(), &a.struct_in[..a.struct_in.len().min(64)]));
    ret::UNSUPPORTED
}

/// A property of user client `c`: what is_io_service_open_extended sets,
/// and the client's own. `Err`: one whose value is not modelled.
pub fn client_property(c: &UserClient, name: &str) -> Result<Option<Prop>, String> {
    match name {
        "IOUserClientCreator" => Ok(Some(Prop::Str(c.creator.clone()))),
        "IOUserClientDefaultLocking" if c.default_locking => Ok(Some(Prop::Bool(true))),
        _ => super::accel::client_property(c, name),
    }
}

/// `is_io_registry_entry_get_property_bytes`'s bytes of a property: an
/// OSString's characters and NUL, an OSBoolean's "Yes" or "No", an
/// OSData's bytes, an OSNumber's low `numberOfBytes` bytes; a collection
/// has none (`None`: kIOReturnBadArgument).
pub fn prop_bytes(p: &Prop) -> Option<Vec<u8>> {
    match p {
        Prop::Str(s) | Prop::Sym(s) => Some([s.as_bytes(), b"\0"].concat()),
        Prop::Bool(b) => Some(if *b { b"Yes\0".to_vec() } else { b"No\0".to_vec() }),
        Prop::Data(d) => Some(d.clone()),
        Prop::Num(v, bits) => Some(v.to_le_bytes()[..((*bits as usize + 7) / 8).min(8)].to_vec()),
        Prop::Strs(_) => None,
    }
}

/// The device tree; empty when the boot payload had none.
pub fn tree() -> &'static [Node] {
    TREE.get().map_or(&[], Vec::as_slice)
}

/// `IORegistryEntry::fromPath` in the `IODeviceTree` plane; `Err` for a
/// plane whose entries are not here.
pub fn from_path(tree: &[Node], path: &str) -> Result<Option<u32>, String> {
    let Some((plane, rest)) = path.split_once(':') else { return Err(format!("a registry path with no plane: {path}")) };
    if plane != "IODeviceTree" {
        return Err(format!("the {plane} plane ({path})"));
    }
    if tree.is_empty() {
        return Ok(None);
    }
    let Some(rest) = rest.strip_prefix('/') else { return Err(format!("a device tree alias: {path}")) };
    let mut at = 0u32;
    for part in rest.split('/').filter(|p| !p.is_empty()) {
        match tree[at as usize].children.iter().find(|&&c| tree[c as usize].name == part) {
            Some(&c) => at = c,
            None => return Ok(None),
        }
    }
    Ok(Some(at))
}

/// `OSData::serialize` into OSSerializeBinary: the signature, then the
/// one object's header (its type and length, the end of the outermost
/// collection) and bytes, padded to 4.
pub fn serialize_data(value: &[u8]) -> Vec<u8> {
    const K_OS_SERIALIZE_BINARY_SIGNATURE: &[u8; 4] = b"\xd3\0\0\0";
    const K_OS_SERIALIZE_DATA: u32 = 0x0a00_0000;
    const K_OS_SERIALIZE_END_COLLECTION: u32 = 0x8000_0000;
    let mut b = K_OS_SERIALIZE_BINARY_SIGNATURE.to_vec();
    b.extend_from_slice(&(K_OS_SERIALIZE_END_COLLECTION | K_OS_SERIALIZE_DATA | value.len() as u32).to_le_bytes());
    b.extend_from_slice(value);
    b.resize((b.len() + 3) & !3, 0);
    b
}

impl crate::syscalls::Kernel {
    /// `iokit_user_client_trap(userClientRef, index, p1, ...)`: a trap of
    /// the user client the caller's name `userClientRef` sends to. A name
    /// with bit 0 clear or bit 32 set names a DriverKit (`uext`) object,
    /// which none is here; one that sends to no user client, or null or
    /// dead, is kIOReturnBadArgument. A client with no trap at the index
    /// answers kIOReturnSuccess (`trap` stays null).
    pub(crate) fn darwin_iokit_user_client_trap(&mut self, a: &[u64; 6]) -> i32 {
        const MACH_PORT_DEAD: u64 = 0xffff_ffff;
        let reference = a[0];
        if reference == 0 || reference == MACH_PORT_DEAD {
            return ret::BAD_ARGUMENT;
        }
        if reference & (1 << 32) != 0 || reference & 1 == 0 {
            return ret::BAD_ARGUMENT;
        }
        let ipc = self.ipc();
        let id = match ipc.translate_send(reference as u32) {
            Ok(p) => match ipc.port(p).kobject {
                Some(super::ipc::Kobject::IoConnect(id)) => id,
                _ => return ret::BAD_ARGUMENT,
            },
            Err(_) => return ret::BAD_ARGUMENT,
        };
        let Some(cell) = client(id) else { return ret::BAD_ARGUMENT };
        let mut c = cell.lock().unwrap_or_else(|e| e.into_inner());
        let index = a[1] as u32;
        let r = match &mut c.kind {
            Kind::Apfs => {
                self.darwin_unimplemented(format!("AppleAPFSUserClient trap {index}"));
                ret::UNSUPPORTED
            }
            Kind::Accel(x) => super::accel::trap(self, x, index, [a[2], a[3], a[4], a[5]]),
        };
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prop(out: &mut Vec<u8>, name: &str, value: &[u8]) {
        let mut n = [0u8; 32];
        n[..name.len()].copy_from_slice(name.as_bytes());
        out.extend_from_slice(&n);
        out.extend_from_slice(&(value.len() as u32).to_le_bytes());
        out.extend_from_slice(value);
        out.resize((out.len() + 3) & !3, 0);
    }

    #[test]
    fn paths_walk_the_device_tree_by_name() {
        let mut b = Vec::new();
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(&1u32.to_le_bytes());
        prop(&mut b, "name", b"device-tree\0");
        b.extend_from_slice(&2u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        prop(&mut b, "name", b"chosen\0");
        prop(&mut b, "boot-type", b"local\0");
        let t = parse(&b).unwrap();
        assert_eq!(t[0].name, "device-tree");
        assert_eq!(from_path(&t, "IODeviceTree:/").unwrap(), Some(0));
        assert_eq!(from_path(&t, "IODeviceTree:/chosen").unwrap(), Some(1));
        assert_eq!(from_path(&t, "IODeviceTree:/nothing").unwrap(), None);
        assert!(from_path(&t, "IOService:/").is_err());
        assert_eq!(t[1].props[1].1, b"local\0");
    }

    fn node(b: &mut Vec<u8>, name: &str, props: &[(&str, &[u8])], children: u32) {
        b.extend_from_slice(&(props.len() as u32 + 1).to_le_bytes());
        b.extend_from_slice(&children.to_le_bytes());
        prop(b, "name", format!("{name}\0").as_bytes());
        for (k, v) in props {
            prop(b, k, v);
        }
    }

    /// device-tree { chosen { memory-map }, arm-io }, under the root.
    fn small_tree() -> Vec<Node> {
        let mut b = Vec::new();
        node(&mut b, "device-tree", &[("compatible", b"J120AP\0iPad7,1\0AppleARM\0")], 2);
        node(&mut b, "chosen", &[], 1);
        node(&mut b, "memory-map", &[("kernel-only", b"")], 0);
        node(&mut b, "arm-io", &[], 0);
        let mut t = parse(&b).unwrap();
        add_root(&mut t);
        t
    }

    fn all(t: &[Node], r: &mut RegistryIter) -> Vec<u32> {
        std::iter::from_fn(|| r.next(t).unwrap()).collect()
    }

    #[test]
    fn registry_iterators_walk_the_device_tree_plane() {
        let t = small_tree();
        let root = t.len() as u32 - 1;
        assert_eq!(name(&t, 0), "J120AP");
        assert_eq!(t[0].name, "device-tree");
        assert_eq!(class(&t, 0), Ok("IOPlatformExpertDevice"));
        assert_eq!(class(&t, root), Ok("IORegistryEntry"));
        assert!(t[2].kernel_only && !t[1].kernel_only);
        assert!(class(&t, 1).is_err());
        assert_eq!(conforms(&t, 1, "IOService"), Ok(true));
        assert_eq!(conforms(&t, root, "IOService"), Ok(false));
        // Flat: the root's one child; recursive: depth first.
        let mut flat = RegistryIter::new(root, Plane::DeviceTree, 0);
        assert_eq!(all(&t, &mut flat), vec![0]);
        let mut deep = RegistryIter::new(root, Plane::DeviceTree, K_IO_REGISTRY_ITERATE_RECURSIVELY);
        assert_eq!(all(&t, &mut deep), vec![0, 1, 2, 3]);
        deep.reset();
        assert_eq!(all(&t, &mut deep), vec![0, 1, 2, 3]);
        // Entered by hand: the children of the entry last given, and out
        // again to its siblings; no way out of the start.
        let mut hand = RegistryIter::new(0, Plane::DeviceTree, 0);
        assert_eq!(hand.next(&t).unwrap(), Some(1));
        hand.enter();
        assert_eq!(hand.next(&t).unwrap(), Some(2));
        assert_eq!(hand.next(&t).unwrap(), None);
        assert!(hand.exit());
        assert_eq!(hand.next(&t).unwrap(), Some(3));
        assert_eq!(hand.next(&t).unwrap(), None);
        assert!(!hand.exit());
        // Parents: up to the root, and none above it.
        let mut up = RegistryIter::new(2, Plane::DeviceTree, K_IO_REGISTRY_ITERATE_PARENTS | K_IO_REGISTRY_ITERATE_RECURSIVELY);
        assert_eq!(all(&t, &mut up), vec![1, 0, root]);
        // The IOService plane below the root is the drivers'.
        let mut svc = RegistryIter::new(root, Plane::Service, 0);
        assert!(svc.next(&t).is_err());
        assert_eq!(links(&t, 0, Plane::Service, true), Ok(vec![root]));
        assert!(links(&t, 1, Plane::Service, false).is_err());
    }

    /// The path to the GPU: device-tree { chosen, arm-io { sgx, uart0 } }.
    #[test]
    fn the_gpu_path_is_the_devices() {
        let mut b = Vec::new();
        node(&mut b, "device-tree", &[("compatible", b"J120AP\0iPad7,1\0AppleARM\0")], 2);
        node(&mut b, "chosen", &[], 0);
        node(&mut b, "arm-io", &[("compatible", b"arm-io,t8011\0"), ("device_type", b"t8011-io\0")], 2);
        node(&mut b, "sgx", &[("compatible", b"gpu,t8011\0")], 0);
        node(&mut b, "uart0", &[("compatible", b"uart-1,samsung\0")], 0);
        let mut t = parse(&b).unwrap();
        let (chosen, arm_io, sgx, uart) = (1, 2, 3, 4);
        let gpu = super::super::platform::add(&mut t).unwrap();
        assert_eq!(gpu, sgx);
        super::super::accel::add_service(&mut t, gpu);
        add_root(&mut t);
        let root = t.len() as u32 - 1;
        let accel = root - 1;
        // Up the IOService plane, each entry's class.
        let mut up = vec![accel];
        while let Some(p) = provider(&t, *up.last().unwrap()).unwrap() {
            up.push(p);
        }
        let classes: Vec<&str> = up.iter().map(|&i| class(&t, i).unwrap()).collect();
        assert_eq!(classes, ["WebMetalAccelerator", "AppleARMIODevice", "AppleT8011IO", "IOPlatformDevice", "AppleARMPE", "IOPlatformExpertDevice", "IORegistryEntry"]);
        assert_eq!((up[1], up[3], up[5], up[6]), (sgx, arm_io, 0, root));
        assert_eq!(name(&t, up[2]), "AppleT8011IO");
        assert_eq!(superclasses("WebMetalAccelerator")[1..], ["IOGPU", "IOAcceleratorES", "IOService", "IORegistryEntry"]);
        assert_eq!(conforms(&t, up[4], "IODTPlatformExpert"), Ok(true));
        assert_eq!(conforms(&t, up[2], "AppleARMIO"), Ok(true));
        assert_eq!(links(&t, sgx, Plane::Service, true), Ok(vec![up[2]]));
        // The device tree plane is as it was; the drivers' other nubs and
        // the entries no driver here published are not known.
        assert_eq!(links(&t, sgx, Plane::DeviceTree, true), Ok(vec![arm_io]));
        assert!(class(&t, uart).is_err() && provider(&t, uart).is_err() && provider(&t, chosen).is_err());
        assert!(links(&t, arm_io, Plane::Service, false).is_err() && links(&t, up[2], Plane::Service, false).is_err());
        // Properties a driver here may have set are reported, but for
        // IOClassNameOverride; a plain device tree entry has only its own.
        assert!(property_unknown(&t, accel, "PerformanceStatistics") && property_unknown(&t, sgx, "IODeviceMemory"));
        assert!(!property_unknown(&t, accel, "IOClassNameOverride") && !property_unknown(&t, up[4], "IOClassNameOverride") && !property_unknown(&t, 0, "IOClassNameOverride"));
        assert!(property_unknown(&t, 0, "IOPlatformSerialNumber"));
        assert!(!property_unknown(&t, uart, "anything") && property_unknown(&t, root, "IOKitBuildVersion") && !property_unknown(&t, root, "anything"));
        // Without the platform's compatible name, no expert here matches.
        let mut b = Vec::new();
        node(&mut b, "device-tree", &[("compatible", b"Other\0")], 0);
        assert_eq!(super::super::platform::add(&mut parse(&b).unwrap()), None);
    }
}
