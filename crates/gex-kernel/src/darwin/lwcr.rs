//! Lightweight code requirements (LWCRs) as AppleMobileFileIntegrity
//! evaluates them on iOS 17.7.11: the CoreEntitlements objects they are
//! written in, validated as the kext's copy of CoreEntitlements validates
//! them (`0x...ac57e8`, `0x...ac7a28`) and queried with its DER VM
//! (`der_vm_execute`, `0x...ac2c10`); an LWCR's fields (`loadFromCE`,
//! `0x...ac0c94`); and a requirement dictionary built into operations on
//! facts (`0x...abedb4`, `0x...ac0f0c`) and evaluated (`0x...aac08c`).
//!
//! A requirement dictionary is an implicit `$and` of its entries. A key
//! that is a fact's name compares the fact with its value, or applies the
//! one operator its dictionary holds to the fact; a key starting with `$`
//! is an operator. The facts come from an encyclopedia: a process's, the
//! system's and the launch's ([`Facts`]). A fact is read when the
//! operation is built (for its type) and again when it is evaluated.

use super::codesign::{der_element, Ent};

/// DER's tag classes, as `der_element` returns them, and the tags CE uses.
mod tag {
    pub const CONSTRUCTED: u8 = 0x20;
    pub const APPLICATION: u8 = 0x40;
    pub const CONTEXT: u8 = 0x80;
    pub const BOOLEAN: u32 = 1;
    pub const INTEGER: u32 = 2;
    pub const OCTET_STRING: u32 = 4;
    pub const UTF8_STRING: u32 = 12;
    pub const SEQUENCE: u32 = 16;
    pub const SET: u32 = 17;
}

/// `CEType_t`: the types of CoreEntitlements values, which facts share.
pub mod ty {
    pub const UNKNOWN: u32 = 0;
    pub const DICTIONARY: u32 = 1;
    pub const SEQUENCE: u32 = 2;
    pub const INTEGER: u32 = 3;
    pub const STRING: u32 = 4;
    pub const BOOL: u32 = 5;
    pub const DATA: u32 = 6;
}

/// The type of a CE value.
fn ent_type(v: &Ent) -> u32 {
    match v {
        Ent::Dict(_) => ty::DICTIONARY,
        Ent::Array(_) => ty::SEQUENCE,
        Ent::Int(_) => ty::INTEGER,
        Ent::String(_) => ty::STRING,
        Ent::Bool(_) => ty::BOOL,
        Ent::Data(_) => ty::DATA,
    }
}

/// Why a CoreEntitlements object was refused: XML, or DER it does not
/// accept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CeError {
    Xml,
    Invalid,
}

/// The deepest a value may nest (`0x...ac7a28`'s limit of 12).
const CE_MAX_DEPTH: u32 = 12;

/// `CEValidate` of a DER object (`0x...ac57e8`): the version 1 form,
/// `[APPLICATION 16] { INTEGER 1, [CONTEXT 16] dictionary }` with its keys
/// sorted, or the legacy form, a SET of entries in any order. Data values
/// are allowed when `allow_data`. What follows the object, or its
/// dictionary inside the version 1 wrapper, is not looked at.
pub fn ce_validate(b: &[u8], allow_data: bool) -> Result<Vec<(Vec<u8>, Ent)>, CeError> {
    if b.is_empty() {
        return Err(CeError::Invalid);
    }
    if b.len() > 4 && b.starts_with(b"<?xml") {
        return Err(CeError::Xml);
    }
    let (class, t, body, _) = der_element(b).ok_or(CeError::Invalid)?;
    if (class, t) == (tag::APPLICATION | tag::CONSTRUCTED, tag::SEQUENCE) {
        let (vc, vt, version, rest) = der_element(body).ok_or(CeError::Invalid)?;
        if (vc, vt) != (0, tag::INTEGER) || ce_int(version) != Some(1) {
            return Err(CeError::Invalid);
        }
        let dict_tag = (tag::CONTEXT | tag::CONSTRUCTED, tag::SEQUENCE);
        let v = Validator { dict_tag, sorted: true, allow_data, depth: 0 };
        match v.value(rest).ok_or(CeError::Invalid)? {
            Ent::Dict(d) => Ok(d),
            _ => Err(CeError::Invalid),
        }
    } else {
        let v = Validator { dict_tag: (tag::CONSTRUCTED, tag::SET), sorted: false, allow_data, depth: 0 };
        match v.value(b).ok_or(CeError::Invalid)? {
            Ent::Dict(d) => Ok(d),
            _ => Err(CeError::Invalid),
        }
    }
}

/// An INTEGER's contents, sign-extended: at most eight bytes, none being 0.
fn ce_int(c: &[u8]) -> Option<i64> {
    if c.len() > 8 {
        return None;
    }
    let neg = c.first().is_some_and(|&x| x & 0x80 != 0);
    Some(c.iter().fold(if neg { -1i64 } else { 0 }, |a, &x| a << 8 | i64::from(x)))
}

/// `0x...ac7a28`: one value, by its tag.
struct Validator {
    dict_tag: (u8, u32),
    sorted: bool,
    allow_data: bool,
    depth: u32,
}

impl Validator {
    fn value(&self, b: &[u8]) -> Option<Ent> {
        if self.depth > CE_MAX_DEPTH {
            return None;
        }
        let (class, t, c, _) = der_element(b)?;
        let deeper = Validator { depth: self.depth + 1, ..*self };
        if (class, t) == self.dict_tag {
            let mut out: Vec<(Vec<u8>, Ent)> = Vec::new();
            let mut rest = c;
            while !rest.is_empty() {
                let (key, value, r) = kv(rest)?;
                if key.contains(&0) {
                    return None;
                }
                if self.sorted {
                    if let Some((prev, _)) = out.last() {
                        if prev.as_slice() >= key {
                            return None;
                        }
                    }
                }
                out.push((key.to_vec(), deeper.value(value)?));
                rest = r;
            }
            return Some(Ent::Dict(out));
        }
        match (class, t) {
            (0, tag::BOOLEAN) => (c.len() == 1).then(|| Ent::Bool(c[0] != 0)),
            (0, tag::INTEGER) => ce_int(c).map(Ent::Int),
            (0, tag::OCTET_STRING) if self.allow_data => Some(Ent::Data(c.to_vec())),
            (0, tag::UTF8_STRING) => (!c.contains(&0)).then(|| Ent::String(c.to_vec())),
            (tag::CONSTRUCTED, tag::SEQUENCE) => {
                let mut out = Vec::new();
                let mut rest = c;
                while !rest.is_empty() {
                    let (_, _, _, r) = der_element(rest)?;
                    out.push(deeper.value(rest)?);
                    rest = r;
                }
                Some(Ent::Array(out))
            }
            _ => None,
        }
    }
}

/// `0x...ac8870`: a dictionary entry, `SEQUENCE { UTF8String key, value }`
/// with a key of at least one byte and nothing after the value; the key,
/// the value's element and what follows the entry.
fn kv(b: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    let (class, t, c, rest) = der_element(b)?;
    if (class, t) != (tag::CONSTRUCTED, tag::SEQUENCE) {
        return None;
    }
    let (kc, kt, key, after) = der_element(c)?;
    if (kc, kt) != (0, tag::UTF8_STRING) || key.is_empty() {
        return None;
    }
    let (_, _, _, end) = der_element(after)?;
    end.is_empty().then_some((key, after, rest))
}

// The DER VM.

/// `CEQueryOpOpcode_t`'s opcodes an LWCR query may use (`0x...ac2084`
/// refuses `kCEOpNoop`, `kCEOpSelectIndex` and the data operations).
pub mod op {
    pub const SELECT_KEY: i64 = 1;
    pub const MATCH_STRING: i64 = 3;
    pub const MATCH_STRING_PREFIX: i64 = 4;
    pub const MATCH_BOOL: i64 = 5;
    pub const STRING_VALUE_ALLOWED: i64 = 6;
    pub const MATCH_INTEGER: i64 = 7;
    pub const STRING_PREFIX_VALUE_ALLOWED: i64 = 8;
    pub const SELECT_KEY_WITH_PREFIX: i64 = 9;
    pub const INTEGER_VALUE_ALLOWED: i64 = 10;
    pub const MATCH_TYPE: i64 = 11;
    /// `kCEOpDynamic`.
    pub const DYNAMIC: i64 = 1 << 62;
}

/// A query operation's parameter.
#[derive(Clone, Debug)]
enum Param {
    Str(Vec<u8>),
    Num(i64),
}

/// A key and its value.
type Pair<'a> = (&'a [u8], &'a Ent);

/// A dictionary's or a sequence's entries as the VM walks them for a key:
/// a dictionary's pairs, or a sequence's elements that are key and value
/// pairs. `None` where an element is not a pair (the walk stops there).
fn pairs(v: &Ent) -> Option<Vec<Option<Pair<'_>>>> {
    match v {
        Ent::Dict(d) => Some(d.iter().map(|(k, v)| Some((k.as_slice(), v))).collect()),
        Ent::Array(a) => Some(
            a.iter()
                .map(|e| match e {
                    Ent::Array(p) if p.len() == 2 => match &p[0] {
                        Ent::String(k) if !k.is_empty() => Some((k.as_slice(), &p[1])),
                        _ => None,
                    },
                    _ => None,
                })
                .collect(),
        ),
        _ => None,
    }
}

/// `der_vm_execute` of one operation on a context (`None`: invalid).
fn vm_execute<'a>(ctx: Option<&'a Ent>, opcode: i64, p: &Param) -> Option<&'a Ent> {
    let v = ctx?;
    let s = |p: &Param| match p {
        Param::Str(s) => s.clone(),
        Param::Num(_) => Vec::new(),
    };
    let n = |p: &Param| match p {
        Param::Num(n) => *n,
        Param::Str(_) => 0,
    };
    // match_string: equal and both nonempty, or both empty.
    let match_string = |val: &[u8], s: &[u8]| (!s.is_empty() && !val.is_empty() && val == s) || (s.is_empty() && val.is_empty());
    let keep = |ok: bool| ok.then_some(v);
    match opcode {
        op::SELECT_KEY => {
            let key = s(p);
            if key.is_empty() {
                return None;
            }
            for e in pairs(v)? {
                let (k, val) = e?;
                if k == key.as_slice() {
                    return Some(val);
                }
            }
            None
        }
        op::MATCH_STRING => match v {
            Ent::String(val) => keep(match_string(val, &s(p))),
            _ => None,
        },
        op::MATCH_STRING_PREFIX => match v {
            Ent::String(val) => keep(val.starts_with(&s(p))),
            _ => None,
        },
        op::MATCH_BOOL => match v {
            Ent::Bool(b) => keep(n(p) == i64::from(*b)),
            _ => None,
        },
        op::STRING_VALUE_ALLOWED => {
            let want = s(p);
            match v {
                Ent::String(val) => {
                    if match_string(val, &want) {
                        return Some(v);
                    }
                    match val.split_last() {
                        Some((b'*', prefix)) => keep(prefix.is_empty() || (want.len() >= prefix.len() && want[..prefix.len()] == *prefix)),
                        _ => None,
                    }
                }
                Ent::Array(a) => {
                    let ok = a.iter().any(|e| match e {
                        Ent::String(val) => match_string(val, &want) || (val.len() >= 2 && val.ends_with(b"*") && want.len() >= val.len() - 1 && want[..val.len() - 1] == val[..val.len() - 1]),
                        _ => false,
                    });
                    keep(ok)
                }
                _ => None,
            }
        }
        op::MATCH_INTEGER => match v {
            Ent::Int(i) => keep(*i == n(p)),
            _ => None,
        },
        op::STRING_PREFIX_VALUE_ALLOWED => {
            let want = s(p);
            match v {
                Ent::String(val) => keep(val.starts_with(&want)),
                Ent::Array(a) => keep(a.iter().any(|e| matches!(e, Ent::String(val) if val.starts_with(&want)))),
                _ => None,
            }
        }
        op::SELECT_KEY_WITH_PREFIX => {
            let key = s(p);
            if key.is_empty() {
                return None;
            }
            // Every entry is looked at; the last that matches is taken.
            let mut found = None;
            for e in pairs(v)? {
                let Some((k, val)) = e else { break };
                let hit = match k.split_last() {
                    Some((b'*', prefix)) => prefix.is_empty() || (prefix.len() <= key.len() && key[..prefix.len()] == *prefix),
                    _ => k == key.as_slice(),
                };
                if hit {
                    found = Some(val);
                }
            }
            found
        }
        op::INTEGER_VALUE_ALLOWED => match v {
            Ent::Int(i) => keep(*i == n(p)),
            // The elements in order: an equal integer allows it; the first
            // element that is not an integer ends the walk.
            Ent::Array(a) => {
                for e in a {
                    match e {
                        Ent::Int(i) if *i == n(p) => return Some(v),
                        Ent::Int(_) => {}
                        _ => return None,
                    }
                }
                None
            }
            _ => None,
        },
        op::MATCH_TYPE => {
            let t = n(p);
            keep((1..=6).contains(&t) && i64::from(ent_type(v)) == t)
        }
        _ => None,
    }
}

// Facts.

/// A fact's value. `Dict` is the entitlements, `None` when the process's
/// entitlements object has no CoreEntitlements context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Int(i64),
    Str(Vec<u8>),
    Bool(bool),
    Data(Vec<u8>),
    Dict(Option<Vec<(Vec<u8>, Ent)>>),
}

impl Value {
    fn ty(&self) -> u32 {
        match self {
            Value::Int(_) => ty::INTEGER,
            Value::Str(_) => ty::STRING,
            Value::Bool(_) => ty::BOOL,
            Value::Data(_) => ty::DATA,
            Value::Dict(_) => ty::DICTIONARY,
        }
    }
}

/// What an encyclopedia knows of a fact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fact {
    /// No encyclopedia has it.
    Missing,
    Known(Value),
    /// The device has it, of this type, but this kernel cannot say its
    /// value: why, for the report.
    Unknown(u32, String),
    /// This kernel cannot even say whether the device has it.
    Unported(String),
}

/// A process's, the system's and the launch's facts, by name, in the order
/// the meta encyclopedia asks its members (`0x...aaaed4`).
pub trait Facts {
    fn fact(&self, name: &[u8]) -> Fact;
}

// Operations.

/// An error building or evaluating an operation: its code and message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fail {
    pub code: u32,
    pub msg: String,
}

fn fail(code: u32, msg: &str) -> Fail {
    Fail { code, msg: msg.into() }
}

/// What stops a build or an evaluation that this kernel cannot finish as
/// the device would.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stop {
    Fail(Fail),
    Unported(String),
}

impl From<Fail> for Stop {
    fn from(f: Fail) -> Stop {
        Stop::Fail(f)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cmp {
    Lt,
    Le,
    Gt,
    Ge,
    FlagCheck,
}

/// A built operation.
#[derive(Clone, Debug)]
enum Op {
    And(Vec<Op>),
    Or(Vec<Op>),
    Optional(Box<Op>),
    /// A fact equal to a value of its own type.
    Eq(Vec<u8>, Value),
    Cmp(Vec<u8>, Cmp, i64),
    In(Vec<u8>, Vec<Ent>),
    Query(Vec<u8>, Ent),
    /// An operation that always fails so: an operator or a fact the
    /// encyclopedia does not know.
    Error(Fail),
}

/// The operators (`0x...e0c0`, in this order).
const OPERATORS: [&str; 12] = ["$and", "$or", "$in", "$lt", "$lte", "$gt", "$gte", "$flag-check", "$optional", "$query", "$and-array", "$or-array"];

/// How deep requirement dictionaries may nest before the build refuses
/// (the depth counter reaching 6).
const MAX_NESTING: u32 = 5;

/// The fact an operator dictionary applies to: its type and name (type 0
/// for none).
#[derive(Clone, Copy)]
struct Active<'a> {
    ty: u32,
    name: &'a [u8],
}

const NO_FACT: Active<'static> = Active { ty: 0, name: b"" };

struct Builder<'f> {
    facts: &'f dyn Facts,
    depth: u32,
}

impl Builder<'_> {
    /// `0x...abedb4`: a dictionary's entries, each an operation, in order;
    /// `facts` whether fact names may be keys here, `excluded` the keys
    /// that may not.
    fn dict(&mut self, v: &Ent, active: Active<'_>, facts: bool, excluded: &[&str]) -> Result<Vec<Op>, Stop> {
        if self.depth + 1 > MAX_NESTING {
            return Err(fail(8, "Constraint is too deeply nested. Failing to avoid recursion overflow").into());
        }
        let Ent::Dict(entries) = v else {
            return Err(fail(3, "Got an unexpected type (not a dictionary) when trying to generate dependent operations for evaluation.").into());
        };
        if entries.is_empty() {
            return Err(fail(4, "The dictionary of dependent operations is empty.").into());
        }
        self.depth += 1;
        let out = entries.iter().map(|(k, v)| self.entry(k, v, active, facts, excluded)).collect();
        self.depth -= 1;
        out
    }

    /// `0x...abf120`: one entry.
    fn entry(&mut self, key: &[u8], v: &Ent, active: Active<'_>, facts: bool, excluded: &[&str]) -> Result<Op, Stop> {
        if excluded.iter().any(|e| e.as_bytes() == key) {
            return Err(fail(6, "Unexpected key for parsing context").into());
        }
        if key.first() == Some(&b'$') {
            let Some(i) = OPERATORS.iter().position(|o| o.as_bytes() == key) else {
                return Ok(Op::Error(Fail { code: 1, msg: String::from_utf8_lossy(key).into_owned() }));
            };
            return self.operator(i, v, active);
        }
        if !facts {
            return Err(fail(6, "Fact not allowed in context").into());
        }
        let t = match self.facts.fact(key) {
            Fact::Missing => return Ok(Op::Error(Fail { code: 5, msg: String::from_utf8_lossy(key).into_owned() })),
            Fact::Known(val) => val.ty(),
            Fact::Unknown(t, _) => t,
            Fact::Unported(why) => return Err(Stop::Unported(why)),
        };
        if let Ent::Dict(_) = v {
            // 0x...abfc18: the one operator applied to the fact.
            let ops = self.dict(v, Active { ty: t, name: key }, false, &[])?;
            return match <[Op; 1]>::try_from(ops) {
                Ok([op]) => Ok(op),
                Err(_) => Err(fail(6, "There should only be one operation to match a fact").into()),
            };
        }
        if ent_type(v) != t {
            return Err(fail(3, "Unexpected type of an operation declaration.").into());
        }
        // 0x...abfebc: an equality for an integer, string, bool or data.
        let val = match v {
            Ent::Int(i) => Value::Int(*i),
            Ent::String(s) => Value::Str(s.clone()),
            Ent::Bool(b) => Value::Bool(*b),
            Ent::Data(d) => Value::Data(d.clone()),
            _ => return Err(fail(3, "Unexpected type of an fact declaration.").into()),
        };
        Ok(Op::Eq(key.to_vec(), val))
    }

    /// The operators' builders (`0x...abd184` on).
    fn operator(&mut self, i: usize, v: &Ent, active: Active<'_>) -> Result<Op, Stop> {
        let one_or = |ops: Vec<Op>, f: fn(Vec<Op>) -> Op| if ops.len() == 1 { ops.into_iter().next().unwrap() } else { f(ops) };
        let int_op = |c: Cmp| match v {
            Ent::Int(n) if active.ty == ty::INTEGER => Ok(Op::Cmp(active.name.to_vec(), c, *n)),
            _ => Err(fail(3, "Got an unexpected type (not an integer) when trying to generate an integer operation.").into()),
        };
        match OPERATORS[i] {
            "$and" | "$or" => {
                if active.ty != 0 {
                    return Err(fail(6, if i == 0 { "$and operator disallowed for active fact" } else { "$or operator disallowed for active fact" }).into());
                }
                let ops = self.dict(v, NO_FACT, true, &[])?;
                Ok(one_or(ops, if i == 0 { Op::And } else { Op::Or }))
            }
            "$in" => {
                if ![ty::INTEGER, ty::STRING, ty::DATA].contains(&active.ty) {
                    return Err(fail(3, "Got an unexpected type (not an integer, string or data) when trying to generate an In operation.").into());
                }
                match v {
                    Ent::Array(items) => Ok(Op::In(active.name.to_vec(), items.clone())),
                    _ => Err(fail(3, "Got an unexpected type (not a sequence) when trying to read the array of matches.").into()),
                }
            }
            "$lt" => int_op(Cmp::Lt),
            "$lte" => int_op(Cmp::Le),
            "$gt" => int_op(Cmp::Gt),
            "$gte" => int_op(Cmp::Ge),
            "$flag-check" => int_op(Cmp::FlagCheck),
            "$optional" => {
                let ops = self.dict(v, active, active.ty == 0, &["$and", "$or", "$optional"])?;
                match <[Op; 1]>::try_from(ops) {
                    Ok([op]) => Ok(Op::Optional(Box::new(op))),
                    Err(_) => Err(fail(6, "$optional only supports a single dependent operation").into()),
                }
            }
            "$query" => {
                if active.ty != ty::DICTIONARY {
                    return Err(fail(3, "Got an unexpected type (not a dictionary) when trying to generate a query operation.").into());
                }
                // Each element a sequence of two (0x...abed64).
                let ok = match v {
                    Ent::Array(a) => a.iter().all(|e| matches!(e, Ent::Array(p) if p.len() == 2)),
                    // A dictionary's elements are its entries, each a
                    // sequence of two.
                    Ent::Dict(_) => true,
                    _ => true,
                };
                if !ok {
                    return Err(fail(6, "$query deserialization failed since it has an invalid query definition").into());
                }
                Ok(Op::Query(active.name.to_vec(), v.clone()))
            }
            // $and-array and $or-array (0x...abe2cc).
            _ => {
                if active.ty != 0 {
                    return Err(fail(6, "factless operator disallowed for active fact").into());
                }
                let Ent::Array(items) = v else {
                    return Err(fail(3, "Got an unexpected type (not a sequence) when trying to read the array of matches.").into());
                };
                if items.is_empty() {
                    return Err(fail(4, "The array of dependent operations is empty.").into());
                }
                let mut ops = Vec::new();
                for item in items {
                    // 0x...abe6b8: [operator, dictionary].
                    let Ent::Array(pair) = item else {
                        return Err(fail(6, "Non array element found in operator Array").into());
                    };
                    if pair.len() != 2 {
                        return Err(fail(6, "Incorrect number of elements in operator Array tuple").into());
                    }
                    let Ent::String(name) = &pair[0] else {
                        return Err(fail(3, "Expected operator string in Array tuple").into());
                    };
                    if !matches!(pair[1], Ent::Dict(_)) {
                        return Err(fail(3, "Expected operator dictionary in Array tuple").into());
                    }
                    let k = match name.as_slice() {
                        b"$and" => 0,
                        b"$or" => 1,
                        b"$optional" => 8,
                        _ => return Err(fail(9, "Unexpected operator in Array tuple").into()),
                    };
                    ops.push(self.operator(k, &pair[1], NO_FACT)?);
                }
                Ok(one_or(ops, if OPERATORS[i] == "$and-array" { Op::And } else { Op::Or }))
            }
        }
    }
}

/// An evaluation's outcome: its error or whether it matched.
pub type Outcome = Result<bool, Fail>;

/// The choices an evaluation makes for facts the kernel cannot supply: the
/// ones made so far and those still to make, and what made each.
struct Choices {
    script: Vec<bool>,
    at: usize,
    why: Vec<String>,
}

impl Choices {
    fn next(&mut self, why: &str) -> bool {
        if !self.why.iter().any(|w| w == why) {
            self.why.push(why.into());
        }
        if self.at == self.script.len() {
            self.script.push(false);
        }
        self.at += 1;
        self.script[self.at - 1]
    }
}

struct Eval<'f, 'c> {
    facts: &'f dyn Facts,
    choices: &'c mut Choices,
}

/// A leaf's reading of its fact: the value, a type error's outcome, or a
/// value this kernel cannot supply (`None`).
enum Read {
    Val(Value),
    Unknown(String),
}

impl Eval<'_, '_> {
    /// `0x...aaaf78`: the fact again, as the leaf evaluates.
    fn read(&self, name: &[u8]) -> Result<(u32, Read), Stop> {
        match self.facts.fact(name) {
            Fact::Missing => Ok((0, Read::Unknown(String::new()))),
            Fact::Known(v) => Ok((v.ty(), Read::Val(v))),
            Fact::Unknown(t, why) => Ok((t, Read::Unknown(why))),
            Fact::Unported(why) => Err(Stop::Unported(why)),
        }
    }

    /// A leaf whose result rests on a value this kernel cannot supply:
    /// either, as the choices say.
    fn guess(&mut self, why: &str) -> Outcome {
        Ok(self.choices.next(why))
    }

    /// An operation's `evaluate`, and whether it is an `$optional` whose
    /// fact or operator was unknown (what `$or` skips).
    fn op(&mut self, o: &Op) -> Result<(Outcome, bool), Stop> {
        let int_or_bool = "Invalid fact type for this operation (expected an integer or bool)";
        Ok((
            match o {
                // 0x...ac12e4: an error or a mismatch ends it.
                Op::And(ops) => {
                    for c in ops {
                        match self.op(c)?.0 {
                            Err(e) => return Ok((Err(e), false)),
                            Ok(false) => return Ok((Ok(false), false)),
                            Ok(true) => {}
                        }
                    }
                    Ok(true)
                }
                // 0x...ac16f8: an error ends it; a match that is not a
                // skipped $optional does.
                Op::Or(ops) => {
                    for c in ops {
                        let (r, skipped) = self.op(c)?;
                        match r {
                            Err(e) => return Ok((Err(e), false)),
                            Ok(true) if !skipped => return Ok((Ok(true), false)),
                            _ => {}
                        }
                    }
                    Ok(false)
                }
                // 0x...ac2448: an unknown fact or operator inside counts as
                // a match, and marks it skipped.
                Op::Optional(inner) => {
                    return Ok(match self.op(inner)?.0 {
                        Err(e) if e.code == 5 || e.code == 1 => (Ok(true), true),
                        r => (r, false),
                    });
                }
                Op::Error(f) => Err(f.clone()),
                Op::Eq(name, want) => {
                    let (t, r) = self.read(name)?;
                    match want {
                        // 0x...ac04ec, 0x...ac05f8: integers and bools compare
                        // as integers.
                        Value::Int(_) | Value::Bool(_) => {
                            if t != ty::INTEGER && t != ty::BOOL {
                                Err(fail(3, int_or_bool))
                            } else {
                                match r {
                                    Read::Unknown(why) => self.guess(&why),
                                    Read::Val(v) => {
                                        let have = match v {
                                            Value::Int(i) => i,
                                            Value::Bool(b) => i64::from(b),
                                            _ => 0,
                                        };
                                        Ok(match want {
                                            Value::Int(i) => have == *i,
                                            Value::Bool(b) => (have != 0) == *b,
                                            _ => false,
                                        })
                                    }
                                }
                            }
                        }
                        // 0x...ac039c, 0x...ac01d8: both nonempty and equal.
                        Value::Str(w) | Value::Data(w) => {
                            let (want_t, msg) = if matches!(want, Value::Str(_)) { (ty::STRING, "Invalid fact type for this operation (expected a string)") } else { (ty::DATA, "Invalid fact type for this operation (expected data)") };
                            if t != want_t {
                                Err(fail(3, msg))
                            } else {
                                match r {
                                    Read::Unknown(why) => self.guess(&why),
                                    Read::Val(Value::Str(h) | Value::Data(h)) => Ok(!h.is_empty() && h == *w),
                                    Read::Val(_) => Ok(false),
                                }
                            }
                        }
                        Value::Dict(_) => Ok(false),
                    }
                }
                // 0x...ac0bc4 and its kin: signed comparisons, or every bit
                // of the value set in the fact.
                Op::Cmp(name, c, n) => {
                    let (t, r) = self.read(name)?;
                    if t != ty::INTEGER && t != ty::BOOL {
                        Err(fail(3, int_or_bool))
                    } else {
                        match r {
                            Read::Unknown(why) => self.guess(&why),
                            Read::Val(v) => {
                                let f = match v {
                                    Value::Int(i) => i,
                                    Value::Bool(b) => i64::from(b),
                                    _ => 0,
                                };
                                Ok(match c {
                                    Cmp::Lt => f < *n,
                                    Cmp::Le => f <= *n,
                                    Cmp::Gt => *n < f,
                                    Cmp::Ge => *n <= f,
                                    Cmp::FlagCheck => *n & !f == 0,
                                })
                            }
                        }
                    }
                }
                // 0x...ac1934: the fact among the sequence's elements of its
                // type.
                Op::In(name, items) => {
                    let (t, r) = self.read(name)?;
                    if ![ty::INTEGER, ty::STRING, ty::DATA].contains(&t) {
                        Err(fail(3, "In Operation expected the Fact to be an integer, string or data"))
                    } else {
                        match r {
                            Read::Unknown(why) => self.guess(&why),
                            Read::Val(v) => Ok(items.iter().any(|e| match (&v, e) {
                                (Value::Int(f), Ent::Int(i)) => f == i,
                                (Value::Str(f), Ent::String(s)) => !f.is_empty() && f == s,
                                (Value::Data(f), Ent::Data(s)) => !f.is_empty() && f == s,
                                _ => false,
                            })),
                        }
                    }
                }
                // 0x...ac1e1c: the query's operations on the entitlements,
                // in order; it matches when the context stays valid.
                Op::Query(name, q) => {
                    let (t, r) = self.read(name)?;
                    if t != ty::DICTIONARY {
                        Err(fail(3, "Query Operation expected the Fact to be a CoreEntitlements dictionary"))
                    } else {
                        let ents = match r {
                            Read::Val(Value::Dict(d)) => d,
                            Read::Val(_) => None,
                            Read::Unknown(why) => return Ok((self.guess(&why), false)),
                        };
                        let root = ents.map(Ent::Dict);
                        query(root.as_ref(), q)?
                    }
                }
            },
            false,
        ))
    }
}

/// A query's tuples run on the entitlements (`0x...ac2084` for each).
fn query(root: Option<&Ent>, q: &Ent) -> Result<Outcome, Stop> {
    let tuples: Vec<Ent> = match q {
        Ent::Array(a) => a.clone(),
        Ent::Dict(d) => d.iter().map(|(k, v)| Ent::Array(vec![Ent::String(k.clone()), v.clone()])).collect(),
        _ => return Ok(Err(fail(6, "Attempted to execute a non-iterable query"))),
    };
    let mut ctx = root;
    for t in &tuples {
        let Ent::Array(p) = t else { return Err(Stop::Unported("AMFI: an LWCR query element that is not a pair".into())) };
        let Ent::Int(opcode) = p.first().ok_or_else(|| Stop::Unported("AMFI: an LWCR query pair with no opcode".into()))? else {
            return Err(Stop::Unported("AMFI: an LWCR query opcode that is not an integer (CoreEntitlements aborts)".into()));
        };
        let opcode = opcode & !op::DYNAMIC;
        let unknown = || Ok(Err(fail(1, "Attempted to execute unknown CoreEntitlements operation")));
        if !(0..=11).contains(&opcode) {
            return unknown();
        }
        let arg = p.get(1);
        let param = match opcode {
            op::SELECT_KEY | op::MATCH_STRING | op::MATCH_STRING_PREFIX | op::STRING_VALUE_ALLOWED | op::STRING_PREFIX_VALUE_ALLOWED | op::SELECT_KEY_WITH_PREFIX => match arg {
                Some(Ent::String(s)) => Param::Str(s.clone()),
                _ => return Err(Stop::Unported("AMFI: an LWCR query string parameter that is not a string (CoreEntitlements aborts)".into())),
            },
            op::MATCH_INTEGER | op::INTEGER_VALUE_ALLOWED | op::MATCH_TYPE => match arg {
                Some(Ent::Int(n)) => Param::Num(*n),
                _ => return Err(Stop::Unported("AMFI: an LWCR query integer parameter that is not an integer (CoreEntitlements aborts)".into())),
            },
            op::MATCH_BOOL => match arg {
                Some(Ent::Bool(b)) => Param::Num(i64::from(*b)),
                _ => return Err(Stop::Unported("AMFI: an LWCR query bool parameter that is not a bool (CoreEntitlements aborts)".into())),
            },
            _ => return unknown(),
        };
        ctx = vm_execute(ctx, opcode, &param);
    }
    Ok(Ok(ctx.is_some()))
}

/// How evaluating a requirement dictionary ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Built and evaluated: matched or not.
    Matched(bool),
    /// The build failed (`m` 2).
    Build(Fail),
    /// The evaluation failed (`m` 5).
    Eval(Fail),
    /// The device's answer depends on what this kernel cannot supply.
    Unported(String),
}

/// `0x...aac08c`: build the requirements `reqs` (a dictionary) on `facts`
/// and evaluate them. Where the outcome turns on facts this kernel cannot
/// supply, every way they could fall is tried: one outcome for all is the
/// device's; more than one is unported.
pub fn evaluate(reqs: &Ent, facts: &dyn Facts) -> Verdict {
    let mut b = Builder { facts, depth: 0 };
    let ops = match b.dict(reqs, NO_FACT, true, &[]) {
        Ok(ops) => ops,
        Err(Stop::Fail(f)) => return Verdict::Build(f),
        Err(Stop::Unported(why)) => return Verdict::Unported(why),
    };
    let root = if ops.len() == 1 { ops.into_iter().next().unwrap() } else { Op::And(ops) };
    let mut outcomes: Vec<Outcome> = Vec::new();
    let mut script: Vec<bool> = Vec::new();
    let mut why = Vec::new();
    loop {
        let mut ch = Choices { script: script.clone(), at: 0, why: std::mem::take(&mut why) };
        let r = match (Eval { facts, choices: &mut ch }).op(&root) {
            Ok((r, _)) => r,
            Err(Stop::Unported(w)) => return Verdict::Unported(w),
            Err(Stop::Fail(f)) => Err(f),
        };
        if !outcomes.contains(&r) {
            outcomes.push(r);
        }
        why = ch.why;
        // The next script: the last false choice made true, the rest gone.
        script = ch.script[..ch.at].to_vec();
        while script.last() == Some(&true) {
            script.pop();
        }
        match script.last_mut() {
            Some(last) => *last = true,
            None => break,
        }
    }
    match <[Outcome; 1]>::try_from(outcomes) {
        Ok([Ok(m)]) => Verdict::Matched(m),
        Ok([Err(f)]) => Verdict::Eval(f),
        Err(_) => Verdict::Unported(format!("AMFI launch constraints: a requirement whose outcome turns on {}", why.join(", "))),
    }
}

/// An integer field (`0x...ac482c`: the key selected, then an integer
/// matched).
fn int_field(d: &[(Vec<u8>, Ent)], key: &[u8]) -> Option<i64> {
    match d.iter().find(|(k, _)| k == key) {
        Some((_, Ent::Int(i))) => Some(*i),
        _ => None,
    }
}

/// `loadFromCE` (`0x...ac0c94`) of a light weight code requirement: its
/// constraint category (`ccat`, 0 for none) and its requirements
/// (`reqs`), and the error that stopped the load. `vers` and `comp` are
/// required integers, `comp` below 2; `ccat`, when present, is not
/// negative; `reqs`, when present, is a dictionary; and there is a
/// category or requirements. A category read before the load failed is
/// kept, as the kext keeps it; requirements are kept only by a load that
/// succeeds.
pub fn load(d: &[(Vec<u8>, Ent)]) -> (i64, Option<Ent>, Option<Fail>) {
    let bad = |c: i64, code: u32, m: &str| (c, None, Some(fail(code, m)));
    if int_field(d, b"vers").is_none() {
        return bad(0, 7, "LWCRs are not encoded correctly");
    }
    let Some(comp) = int_field(d, b"comp") else {
        return bad(0, 7, "LWCRs are not encoded correctly");
    };
    if comp >= 2 {
        return bad(0, 6, "This LWCR is not compatible with this runtime");
    }
    let ccat = int_field(d, b"ccat");
    let c = ccat.unwrap_or(0);
    if ccat.is_some_and(|c| c < 0) {
        return bad(c, 7, "LWCRs constraint category cannot be less that zero");
    }
    let reqs = match d.iter().find(|(k, _)| k == b"reqs") {
        None => None,
        Some((_, v @ Ent::Dict(_))) => Some(v.clone()),
        Some(_) => return bad(c, 7, "LWCRs 'requirements' field is not a dictionary"),
    };
    if c == 0 && reqs.is_none() {
        return bad(c, 7, "LWCRs do not specify a constraint category or explicit requirements");
    }
    (c, reqs, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct F(Vec<(&'static str, Fact)>);
    impl Facts for F {
        fn fact(&self, name: &[u8]) -> Fact {
            self.0.iter().find(|(n, _)| n.as_bytes() == name).map_or(Fact::Missing, |(_, f)| f.clone())
        }
    }

    fn s(x: &str) -> Ent {
        Ent::String(x.as_bytes().to_vec())
    }
    fn d(kv: Vec<(&str, Ent)>) -> Ent {
        Ent::Dict(kv.into_iter().map(|(k, v)| (k.as_bytes().to_vec(), v)).collect())
    }

    #[test]
    fn version_one_objects_validate_as_coreentitlements_does() {
        // {"a": true, "b": 1} in the version 1 form.
        let b = [0x70, 0x15, 0x02, 0x01, 0x01, 0xb0, 0x10, 0x30, 0x06, 0x0c, 0x01, b'a', 0x01, 0x01, 0xff, 0x30, 0x06, 0x0c, 0x01, b'b', 0x02, 0x01, 0x01];
        assert_eq!(ce_validate(&b, true), Ok(vec![(b"a".to_vec(), Ent::Bool(true)), (b"b".to_vec(), Ent::Int(1))]));
        // Keys out of order, or a key repeated, are refused.
        let mut swapped = b;
        swapped[11] = b'c';
        assert_eq!(ce_validate(&swapped, true), Err(CeError::Invalid));
        assert_eq!(ce_validate(b"<?xml version", true), Err(CeError::Xml));
    }

    #[test]
    fn optional_skips_an_unknown_fact_and_or_ignores_it() {
        let facts = F(vec![("launch-type", Fact::Known(Value::Int(0)))]);
        // $or {$optional {nope: 1}, launch-type: 1}: the optional is skipped,
        // and launch-type does not match.
        let r = d(vec![("$or", d(vec![("$optional", d(vec![("nope", Ent::Int(1))])), ("launch-type", Ent::Int(1))]))]);
        assert_eq!(evaluate(&r, &facts), Verdict::Matched(false));
        // In an $and, the skipped optional counts as a match.
        let r = d(vec![("$optional", d(vec![("nope", Ent::Int(1))])), ("launch-type", Ent::Int(0))]);
        assert_eq!(evaluate(&r, &facts), Verdict::Matched(true));
        // Bare, an unknown fact is an evaluation error (5).
        let r = d(vec![("nope", Ent::Int(1))]);
        assert_eq!(evaluate(&r, &facts), Verdict::Eval(Fail { code: 5, msg: "nope".into() }));
    }

    #[test]
    fn an_unknown_fact_that_cannot_change_the_outcome_is_not_a_stop() {
        let facts = F(vec![("on-authorized-authapfs-volume", Fact::Unknown(ty::BOOL, "on-authorized-authapfs-volume".into())), ("on-system-volume", Fact::Known(Value::Bool(true)))]);
        let r = d(vec![("$or", d(vec![("on-authorized-authapfs-volume", Ent::Bool(true)), ("on-system-volume", Ent::Bool(true))]))]);
        assert_eq!(evaluate(&r, &facts), Verdict::Matched(true));
        let facts = F(vec![("on-authorized-authapfs-volume", Fact::Unknown(ty::BOOL, "on-authorized-authapfs-volume".into())), ("on-system-volume", Fact::Known(Value::Bool(false)))]);
        assert!(matches!(evaluate(&r, &facts), Verdict::Unported(_)));
    }

    #[test]
    fn queries_run_on_the_entitlements() {
        let ents = vec![(b"com.apple.private.x".to_vec(), Ent::Int(1))];
        let facts = F(vec![("entitlements", Fact::Known(Value::Dict(Some(ents))))]);
        let q = |op: i64, p: Ent| d(vec![("entitlements", d(vec![("$query", Ent::Array(vec![Ent::Array(vec![Ent::Int(1), s("com.apple.private.x")]), Ent::Array(vec![Ent::Int(op), p])]))]))]);
        assert_eq!(evaluate(&q(10, Ent::Int(1)), &facts), Verdict::Matched(true));
        assert_eq!(evaluate(&q(5, Ent::Bool(true)), &facts), Verdict::Matched(false));
        assert_eq!(evaluate(&q(12, Ent::Int(1)), &facts), Verdict::Eval(Fail { code: 1, msg: "Attempted to execute unknown CoreEntitlements operation".into() }));
    }

    #[test]
    fn nesting_is_limited_to_five_dictionaries() {
        let facts = F(vec![("x", Fact::Known(Value::Int(1)))]);
        let mut r = d(vec![("x", Ent::Int(1))]);
        for _ in 0..4 {
            r = d(vec![("$and", r)]);
        }
        assert_eq!(evaluate(&r, &facts), Verdict::Matched(true));
        let r = d(vec![("$and", r)]);
        assert_eq!(evaluate(&r, &facts), Verdict::Build(Fail { code: 8, msg: "Constraint is too deeply nested. Failing to avoid recursion overflow".into() }));
    }
}
