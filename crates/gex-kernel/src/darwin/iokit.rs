//! IOKit as a task reaches it (`iokit/Kernel/IOUserClient.cpp`), over the
//! device's own device tree: the registry's `IODeviceTree` plane. The
//! `IOService` plane's drivers are not here, and what would need them is
//! reported.

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
}

/// A property of a service, as `OSSerialize` writes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Prop {
    Str(String),
    Bool(bool),
    Strs(Vec<String>),
}

/// The classes a service belongs to, most derived first.
fn superclasses(class: &str) -> &'static [&'static str] {
    match class {
        "AppleAPFSVolume" => &["AppleAPFSVolume", "IOMedia", "IOStorage", "IOService", "IORegistryEntry"],
        "AppleAPFSContainerScheme" => &["AppleAPFSContainerScheme", "IOPartitionScheme", "IOStorage", "IOService", "IORegistryEntry"],
        "AppleAPFSMedia" => &["AppleAPFSMedia", "IOMedia", "IOStorage", "IOService", "IORegistryEntry"],
        "AppleAPFSContainer" => &["AppleAPFSContainer", "IOStorage", "IOService", "IORegistryEntry"],
        "IOMedia" => &["IOMedia", "IOStorage", "IOService", "IORegistryEntry"],
        _ => &[],
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
        out.push(Node { name, props, class: "", service_props: Vec::new(), parent, children: Vec::new() });
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
    let _ = TREE.set(t);
    Ok(())
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
        t.push(Node { name, props: Vec::new(), class: "AppleAPFSVolume", service_props, parent: Some(container), children: Vec::new() });
        t[container as usize].children.push(id);
    }
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
    let wanted = |n: &Node| {
        !n.class.is_empty()
            && class.map_or(true, |c| superclasses(n.class).contains(&c))
            && props.iter().all(|&(k, v)| n.service_props.iter().any(|(pk, pv)| pk == k && matches!(pv, Prop::Str(s) if s == v)))
    };
    Ok(tree.iter().enumerate().filter(|(_, n)| wanted(n)).map(|(i, _)| i as u32).collect())
}

/// `OSObject::metaCast`: whether the node is, or inherits from, `class`.
pub fn conforms(n: &Node, class: &str) -> bool {
    if n.class.is_empty() {
        return matches!(class, "IOPlatformDevice" | "IOService" | "IORegistryEntry");
    }
    superclasses(n.class).contains(&class)
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

/// The iterators handed out, each the entries still to come.
static ITERATORS: std::sync::Mutex<Vec<Vec<u32>>> = std::sync::Mutex::new(Vec::new());

/// A new iterator over `items`, by number.
pub fn iterator_new(mut items: Vec<u32>) -> u32 {
    items.reverse();
    let mut t = ITERATORS.lock().unwrap_or_else(|e| e.into_inner());
    t.push(items);
    (t.len() - 1) as u32
}

/// The iterator's next entry.
pub fn iterator_next(id: u32) -> Option<u32> {
    ITERATORS.lock().unwrap_or_else(|e| e.into_inner()).get_mut(id as usize)?.pop()
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
}
