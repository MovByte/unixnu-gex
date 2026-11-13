//! libkern's containers as a task hands them to the kernel and takes them
//! back: `OSUnserializeBinary` and `OSSerialize`'s binary form
//! (`libkern/c++/OSSerializeBinary.cpp`), and the entry point that picks it
//! (`OSUnserializeXML(buffer, size)` in `OSUnserializeXML.y`).
//!
//! The objects live in an arena ([`Graph`]) so that each keeps its
//! identity, which both directions observe: a reference
//! (`kOSSerializeObject`) names an object already read, a set refuses an
//! object it holds already, and the serializer writes an object it has
//! written once as a reference to it. Symbols are uniqued system-wide and
//! the booleans are two constants, so the arena holds one of each value.

/// `OSSerializeBinary.h`.
pub const DICTIONARY: u32 = 0x0100_0000;
pub const ARRAY: u32 = 0x0200_0000;
pub const SET: u32 = 0x0300_0000;
pub const NUMBER: u32 = 0x0400_0000;
pub const SYMBOL: u32 = 0x0800_0000;
pub const STRING: u32 = 0x0900_0000;
pub const DATA: u32 = 0x0a00_0000;
pub const BOOLEAN: u32 = 0x0b00_0000;
pub const OBJECT: u32 = 0x0c00_0000;
pub const TYPE_MASK: u32 = 0x7f00_0000;
pub const DATA_MASK: u32 = 0x00ff_ffff;
pub const END_COLLECTION: u32 = 0x8000_0000;
/// `kOSSerializeBinarySignature`, "\323\0\0" with its terminator.
pub const SIGNATURE: [u8; 4] = [0xd3, 0, 0, 0];
/// `kOSSerializeIndexedBinarySignature`, the first byte of the indexed form.
pub const INDEXED_SIGNATURE: u8 = 0xd4;

/// `OSString::kMaxStringLength`.
const MAX_STRING_LENGTH: usize = 262_142;
/// `OSUnserializeBinary`'s `stackCapacityMax` and `objsCapacityMax`.
const STACK_CAPACITY_MAX: u32 = 64;
const OBJS_CAPACITY_MAX: u32 = 16 * 1024 * 1024;

/// An object of the arena, by its index.
pub type Id = u32;

/// A libkern object.
#[derive(Clone, Debug, PartialEq)]
pub enum Obj {
    /// An `OSDictionary`: its keys (symbols' bytes) and values, in the order
    /// `setObject` left them (a new key goes last; `kSort` is not set).
    Dict(Vec<(Vec<u8>, Id)>),
    Array(Vec<Id>),
    Set(Vec<Id>),
    /// An `OSNumber`: its size in bits and its value, masked to the size;
    /// a size of 63 (`withDouble`) or 31 (`withFloat`) holds a double's
    /// bits instead.
    Number { size: u32, value: u64 },
    /// An `OSSymbol`'s characters, without the NUL.
    Symbol(Vec<u8>),
    /// An `OSString`'s characters, without the NUL.
    String(Vec<u8>),
    Data(Vec<u8>),
    Bool(bool),
}

/// Objects and their identities.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Graph {
    pub objs: Vec<Obj>,
}

impl Graph {
    pub fn get(&self, id: Id) -> &Obj {
        &self.objs[id as usize]
    }

    pub fn get_mut(&mut self, id: Id) -> &mut Obj {
        &mut self.objs[id as usize]
    }

    /// A new object (one `with...` call makes).
    pub fn add(&mut self, o: Obj) -> Id {
        match &o {
            // The symbol pool's object for the characters, and the boolean
            // constants: one each.
            Obj::Symbol(_) | Obj::Bool(_) => {
                if let Some(i) = self.objs.iter().position(|x| *x == o) {
                    return i as Id;
                }
            }
            _ => {}
        }
        self.objs.push(o);
        (self.objs.len() - 1) as Id
    }

    /// `OSNumber::withNumber(value, bits)`: the value masked to its size.
    pub fn number(&mut self, value: u64, bits: u32) -> Id {
        let mask = if bits >= 64 { u64::MAX } else { u64::MAX >> (64 - bits) };
        self.add(Obj::Number { size: bits, value: value & mask })
    }

    /// The value `dict` (a dictionary) has for `key`
    /// (`OSDictionary::getObject(const char *)`).
    pub fn lookup(&self, dict: Id, key: &[u8]) -> Option<Id> {
        match self.get(dict) {
            Obj::Dict(e) => e.iter().find(|(k, _)| k.as_slice() == key).map(|&(_, v)| v),
            _ => None,
        }
    }

    /// `OSDictionary::setObject(key, value)`: an existing key's value
    /// replaced in place, else the pair appended.
    pub fn dict_set(&mut self, dict: Id, key: &[u8], value: Id) {
        if let Obj::Dict(e) = self.get_mut(dict) {
            match e.iter_mut().find(|(k, _)| k.as_slice() == key) {
                Some(slot) => slot.1 = value,
                None => e.push((key.to_vec(), value)),
            }
        }
    }

    /// `OSDictionary::removeObject(key)`: whether it held one.
    pub fn dict_remove(&mut self, dict: Id, key: &[u8]) -> bool {
        if let Obj::Dict(e) = self.get_mut(dict) {
            if let Some(i) = e.iter().position(|(k, _)| k.as_slice() == key) {
                e.remove(i);
                return true;
            }
        }
        false
    }

    /// `OSNumber::unsigned64BitValue`: a floating-point number's value
    /// truncated toward zero, as the C conversion does (saturating here,
    /// where arm64's `fcvtzu` saturates too).
    pub fn u64_value(&self, id: Id) -> Option<u64> {
        match *self.get(id) {
            Obj::Number { size: 63 | 31, value } => Some(f64::from_bits(value) as u64),
            Obj::Number { value, .. } => Some(value),
            _ => None,
        }
    }

    /// `OSNumber::unsigned32BitValue`: the low 32 bits, or a floating-point
    /// number converted to 32 bits (`fcvtzu` to a W register saturates).
    pub fn u32_value(&self, id: Id) -> Option<u32> {
        match *self.get(id) {
            Obj::Number { size: 63 | 31, value } => Some(f64::from_bits(value) as u32),
            Obj::Number { value, .. } => Some(value as u32),
            _ => None,
        }
    }

    /// `object` of graph `from` and everything it holds, copied into this
    /// graph (each object once, so what it shared stays shared); its id
    /// here. Objects made by separate calls are separate objects, so
    /// nothing but symbols and booleans can be one already here.
    pub fn import(&mut self, from: &Graph, object: Id) -> Id {
        let mut map: Vec<Option<Id>> = vec![None; from.objs.len()];
        self.import_with(from, object, &mut map)
    }

    fn import_with(&mut self, from: &Graph, object: Id, map: &mut Vec<Option<Id>>) -> Id {
        if let Some(id) = map[object as usize] {
            return id;
        }
        let o = from.get(object).clone();
        let id = match &o {
            Obj::Dict(_) => self.add(Obj::Dict(Vec::new())),
            Obj::Array(_) => self.add(Obj::Array(Vec::new())),
            Obj::Set(_) => self.add(Obj::Set(Vec::new())),
            other => self.add(other.clone()),
        };
        map[object as usize] = Some(id);
        match o {
            Obj::Dict(e) => {
                let v = e.into_iter().map(|(k, v)| (k, self.import_with(from, v, map))).collect();
                *self.get_mut(id) = Obj::Dict(v);
            }
            Obj::Array(e) => {
                let v = e.into_iter().map(|v| self.import_with(from, v, map)).collect();
                *self.get_mut(id) = Obj::Array(v);
            }
            Obj::Set(e) => {
                let v = e.into_iter().map(|v| self.import_with(from, v, map)).collect();
                *self.get_mut(id) = Obj::Set(v);
            }
            _ => {}
        }
        id
    }
}

/// What a buffer `OSUnserializeXML(buffer, size)` is given unserializes to.
#[derive(Debug, PartialEq)]
pub enum Parsed {
    /// The binary form: the object, or none when it does not unserialize.
    Binary(Option<(Graph, Id)>),
    /// XML text (NUL-terminated), which the XML parser takes.
    Xml,
    /// Neither: too short for a signature, or text with no terminator.
    Invalid,
}

/// `OSUnserializeXML(buffer, bufferSize, errorString)` (kernel): the binary
/// form when the buffer starts with either signature, else XML, which must
/// end in a NUL.
pub fn unserialize(buffer: &[u8]) -> Parsed {
    if buffer.len() < SIGNATURE.len() {
        return Parsed::Invalid;
    }
    // strcmp(kOSSerializeBinarySignature, buffer): equal through the NUL.
    if buffer[..4] == SIGNATURE || buffer[0] == INDEXED_SIGNATURE {
        return Parsed::Binary(unserialize_binary(buffer));
    }
    if buffer[buffer.len() - 1] != 0 {
        return Parsed::Invalid;
    }
    Parsed::Xml
}

/// `OSUnserializeBinary(buffer, bufferSize)`: the object the buffer holds,
/// with the arena it is in.
pub fn unserialize_binary(buffer: &[u8]) -> Option<(Graph, Id)> {
    if buffer.len() < SIGNATURE.len() {
        return None;
    }
    let indexed = buffer[0] == INDEXED_SIGNATURE;
    if !indexed && buffer[..4] != SIGNATURE {
        return None;
    }
    let size = buffer.len();
    let word = |at: usize| u32::from_le_bytes(buffer[at..at + 4].try_into().unwrap());
    let mut g = Graph::default();
    // objsArray: the objects read, which a reference names by index.
    let mut objs: Vec<Id> = Vec::new();
    // stackArray: the enclosing collections, index 0 unused.
    let mut stack: Vec<Option<Id>> = vec![None];
    let mut result: Option<Id> = None;
    let mut parent: Option<Id> = None;
    // The collection being filled, by kind.
    let (mut dict, mut array, mut set): (Option<Id>, Option<Id>, Option<Id>) = (None, None, None);
    // A dictionary's key, read and waiting for its value.
    let mut key_obj: Option<Id> = None;
    let mut pos = SIGNATURE.len();
    let mut next = SIGNATURE.len();
    let mut ok;
    loop {
        pos += 4;
        ok = pos <= size;
        if !ok {
            break;
        }
        let key = word(next);
        next += 4;
        let len = key & DATA_MASK;
        let word_len = ((len as usize) + 3) >> 2;
        let mut end = key & END_COLLECTION != 0;
        let (mut new_collect, mut is_ref, mut has_length) = (false, false, false);
        let mut o: Option<Id> = None;
        match key & TYPE_MASK {
            DICTIONARY => {
                o = Some(g.add(Obj::Dict(Vec::new())));
                new_collect = len != 0;
                has_length = indexed;
            }
            ARRAY => {
                o = Some(g.add(Obj::Array(Vec::new())));
                new_collect = len != 0;
                has_length = indexed;
            }
            SET => {
                o = Some(g.add(Obj::Set(Vec::new())));
                new_collect = len != 0;
                has_length = indexed;
            }
            OBJECT => {
                if (len as usize) < objs.len() {
                    o = Some(objs[len as usize]);
                    is_ref = true;
                }
            }
            NUMBER => {
                pos += 8;
                if pos <= size {
                    let value = u64::from(word(next)) | u64::from(word(next + 4)) << 32;
                    o = match len {
                        63 => Some(g.add(Obj::Number { size: 63, value })),
                        // withFloat((float) the double): the double's value
                        // rounded to a float and widened back.
                        31 => Some(g.add(Obj::Number { size: 31, value: f64::from(f64::from_bits(value) as f32).to_bits() })),
                        64 | 32 | 16 | 8 => Some(g.number(value, len)),
                        _ => None,
                    };
                    next += 8;
                }
            }
            SYMBOL => {
                pos += word_len * 4;
                if pos <= size && len >= 1 && buffer[next + len as usize - 1] == 0 {
                    // OSSymbol::withCString: the characters to the first NUL.
                    let s = &buffer[next..next + len as usize];
                    let n = s.iter().position(|&c| c == 0).unwrap_or(s.len());
                    if n < MAX_STRING_LENGTH {
                        o = Some(g.add(Obj::Symbol(s[..n].to_vec())));
                    }
                    next += word_len * 4;
                }
            }
            STRING => {
                pos += word_len * 4;
                if pos <= size {
                    // OSString::withCString(next, len): at most len
                    // characters, to the first NUL.
                    if (len as usize) < MAX_STRING_LENGTH {
                        let s = &buffer[next..next + len as usize];
                        let n = s.iter().position(|&c| c == 0).unwrap_or(s.len());
                        o = Some(g.add(Obj::String(s[..n].to_vec())));
                    }
                    next += word_len * 4;
                }
            }
            DATA => {
                pos += word_len * 4;
                if pos <= size {
                    o = Some(g.add(Obj::Data(buffer[next..next + len as usize].to_vec())));
                    next += word_len * 4;
                }
            }
            BOOLEAN => o = Some(g.add(Obj::Bool(len != 0))),
            _ => {}
        }
        let Some(o) = o else {
            ok = false;
            break;
        };
        if has_length {
            pos += 4;
            ok = pos <= size;
            if !ok {
                break;
            }
            // The collection's length in words, which nothing checks.
            next += 4;
        }
        if !is_ref {
            // setAtIndex(objs, ...): capacity grows by 64 to its maximum.
            ok = (objs.len() as u32) < OBJS_CAPACITY_MAX;
            if !ok {
                break;
            }
            objs.push(o);
        }
        if let Some(d) = dict {
            match key_obj {
                None => key_obj = Some(o),
                Some(k) => {
                    // A symbol, or a string made one; anything else is no key
                    // (setObject of a null key fails).
                    let name = match g.get(k) {
                        Obj::Symbol(s) | Obj::String(s) => Some(s.clone()),
                        _ => None,
                    };
                    key_obj = None;
                    match name {
                        None => ok = false,
                        Some(name) => {
                            if o != d {
                                g.dict_set(d, &name, o);
                            }
                        }
                    }
                }
            }
        } else if let Some(a) = array {
            if let Obj::Array(v) = g.get_mut(a) {
                v.push(o);
            }
        } else if let Some(s) = set {
            let has = matches!(g.get(s), Obj::Set(v) if v.contains(&o));
            if has {
                ok = false;
            } else if let Obj::Set(v) = g.get_mut(s) {
                v.push(o);
            }
        } else if result.is_some() {
            ok = false;
        } else {
            result = Some(o);
        }
        if !ok {
            break;
        }
        if end {
            parent = None;
        }
        if new_collect {
            // setAtIndex(stack, ++stackIdx, parent).
            let idx = stack.len() as u32;
            ok = idx < STACK_CAPACITY_MAX;
            if !ok {
                break;
            }
            stack.push(parent);
            parent = Some(o);
            dict = matches!(g.get(o), Obj::Dict(_)).then_some(o);
            array = matches!(g.get(o), Obj::Array(_)).then_some(o);
            set = matches!(g.get(o), Obj::Set(_)).then_some(o);
            end = false;
        }
        if end {
            while stack.len() > 1 {
                parent = stack.pop().unwrap();
                if parent.is_some() {
                    break;
                }
            }
            let Some(p) = parent else { break };
            dict = matches!(g.get(p), Obj::Dict(_)).then_some(p);
            array = matches!(g.get(p), Obj::Array(_)).then_some(p);
            set = matches!(g.get(p), Obj::Set(_)).then_some(p);
            ok = dict.is_some() || array.is_some() || set.is_some();
            if !ok {
                break;
            }
        }
    }
    if !ok {
        return None;
    }
    result.map(|r| (g, r))
}

/// `OSSerialize::binaryWithCapacity` and `binarySerialize(o)`, no editor
/// and no index: the signature, then each object once, an object met again
/// written as a reference to its first. A symbol is the pool's one object
/// for its characters, whether a dictionary's key or a value.
pub fn serialize_binary(g: &Graph, root: Id) -> Vec<u8> {
    #[derive(PartialEq)]
    enum Tag {
        Obj(Id),
        Sym(Vec<u8>),
    }
    struct W<'a> {
        g: &'a Graph,
        out: Vec<u8>,
        tags: Vec<Tag>,
        end: bool,
    }
    impl W<'_> {
        fn header(&mut self, mut key: u32) {
            if self.end {
                self.end = false;
                key |= END_COLLECTION;
            }
            self.out.extend_from_slice(&key.to_le_bytes());
        }
        /// The reference to an object already written, if it was.
        fn reference(&mut self, t: &Tag) -> bool {
            match self.tags.iter().position(|x| x == t) {
                Some(i) => {
                    self.header(OBJECT | i as u32);
                    true
                }
                None => false,
            }
        }
        /// addBinaryObject: the tag recorded, the header, the bytes padded
        /// to a word.
        fn object(&mut self, t: Tag, key: u32, bits: &[u8]) {
            self.tags.push(t);
            self.header(key);
            self.out.extend_from_slice(bits);
            self.out.resize((self.out.len() + 3) & !3, 0);
        }
        fn symbol(&mut self, s: &[u8]) {
            if self.reference(&Tag::Sym(s.to_vec())) {
                return;
            }
            let mut b = s.to_vec();
            b.push(0);
            self.object(Tag::Sym(s.to_vec()), SYMBOL | b.len() as u32, &b);
        }
        fn write(&mut self, o: Id) {
            let g = self.g;
            if let Obj::Symbol(s) = g.get(o) {
                return self.symbol(s);
            }
            if self.reference(&Tag::Obj(o)) {
                return;
            }
            match g.get(o) {
                Obj::Dict(e) => {
                    self.object(Tag::Obj(o), DICTIONARY | e.len() as u32, &[]);
                    for (i, (k, v)) in e.iter().enumerate() {
                        self.symbol(k);
                        self.end = i + 1 == e.len();
                        self.write(*v);
                    }
                }
                Obj::Array(e) | Obj::Set(e) => {
                    let kind = if matches!(g.get(o), Obj::Array(_)) { ARRAY } else { SET };
                    self.object(Tag::Obj(o), kind | e.len() as u32, &[]);
                    for (i, v) in e.iter().enumerate() {
                        self.end = i + 1 == e.len();
                        self.write(*v);
                    }
                }
                Obj::Number { size, value } => self.object(Tag::Obj(o), NUMBER | size, &value.to_le_bytes()),
                Obj::Bool(b) => self.object(Tag::Obj(o), BOOLEAN | u32::from(*b), &[]),
                Obj::String(s) => self.object(Tag::Obj(o), STRING | s.len() as u32, s),
                Obj::Data(d) => self.object(Tag::Obj(o), DATA | d.len() as u32, d),
                Obj::Symbol(_) => unreachable!(),
            }
        }
    }
    let mut w = W { g, out: SIGNATURE.to_vec(), tags: Vec::new(), end: true };
    w.write(root);
    w.out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(ws: &[u32]) -> Vec<u8> {
        ws.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    #[test]
    fn a_dictionary_round_trips_with_its_references() {
        // { "a" = 5 (32 bits), "b" = "xy", "c" = <reference to 5> }.
        let mut b = SIGNATURE.to_vec();
        b.extend(words(&[END_COLLECTION | DICTIONARY | 3]));
        b.extend(words(&[SYMBOL | 2]));
        b.extend(b"a\0\0\0");
        b.extend(words(&[NUMBER | 32, 5, 0]));
        b.extend(words(&[SYMBOL | 2]));
        b.extend(b"b\0\0\0");
        b.extend(words(&[STRING | 2]));
        b.extend(b"xy\0\0");
        b.extend(words(&[SYMBOL | 2]));
        b.extend(b"c\0\0\0");
        b.extend(words(&[END_COLLECTION | OBJECT | 2]));
        let (g, root) = unserialize_binary(&b).unwrap();
        let a = g.lookup(root, b"a").unwrap();
        assert_eq!(g.u32_value(a), Some(5));
        assert_eq!(g.lookup(root, b"c"), Some(a));
        assert_eq!(g.get(g.lookup(root, b"b").unwrap()), &Obj::String(b"xy".to_vec()));
        // The serializer writes the shared number once and a reference.
        assert_eq!(serialize_binary(&g, root), b);
        assert_eq!(unserialize(&b), Parsed::Binary(Some((g, root))));
    }

    #[test]
    fn what_osunserializebinary_refuses() {
        // Two top-level objects.
        let mut b = SIGNATURE.to_vec();
        b.extend(words(&[BOOLEAN | 1, BOOLEAN]));
        assert_eq!(unserialize_binary(&b), None);
        // A reference past the objects read.
        let mut b = SIGNATURE.to_vec();
        b.extend(words(&[OBJECT]));
        assert_eq!(unserialize_binary(&b), None);
        // A number of 12 bits.
        let mut b = SIGNATURE.to_vec();
        b.extend(words(&[NUMBER | 12, 1, 0]));
        assert_eq!(unserialize_binary(&b), None);
        // A set holding one object twice.
        let mut b = SIGNATURE.to_vec();
        b.extend(words(&[END_COLLECTION | SET | 2, BOOLEAN | 1, END_COLLECTION | BOOLEAN | 1]));
        assert_eq!(unserialize_binary(&b), None);
        // A key that is a number.
        let mut b = SIGNATURE.to_vec();
        b.extend(words(&[END_COLLECTION | DICTIONARY | 1, NUMBER | 8, 1, 0, END_COLLECTION | BOOLEAN]));
        assert_eq!(unserialize_binary(&b), None);
        // A truncated string.
        let mut b = SIGNATURE.to_vec();
        b.extend(words(&[STRING | 9]));
        b.extend(b"abcd");
        assert_eq!(unserialize_binary(&b), None);
        // Text is XML's when it ends in a NUL.
        assert_eq!(unserialize(b"<dict/>\0"), Parsed::Xml);
        assert_eq!(unserialize(b"<dict/>"), Parsed::Invalid);
    }

    #[test]
    fn nesting_stops_at_sixty_three_open_collections() {
        let nest = |n: u32| {
            let mut b = SIGNATURE.to_vec();
            // Each array the last (only) object of the one around it.
            for _ in 0..n {
                b.extend(words(&[END_COLLECTION | ARRAY | 1]));
            }
            b.extend(words(&[END_COLLECTION | BOOLEAN | 1]));
            b
        };
        assert!(unserialize_binary(&nest(63)).is_some());
        assert_eq!(unserialize_binary(&nest(64)), None);
    }

    #[test]
    fn numbers_keep_their_size_and_mask() {
        let mut g = Graph::default();
        let n = g.number(0x1_2345, 16);
        assert_eq!(g.get(n), &Obj::Number { size: 16, value: 0x2345 });
        let d = g.add(Obj::Number { size: 63, value: 2.75f64.to_bits() });
        assert_eq!(g.u64_value(d), Some(2));
        let t = g.add(Obj::Bool(true));
        assert_eq!(g.add(Obj::Bool(true)), t);
    }
}
