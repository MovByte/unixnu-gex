//! Darwin's `sysctl` tree, as much of it as libsystem and dyld read.
//!
//! Names resolve to OIDs through the `{0, 3}` (`name2oid`) node, which is
//! how `sysctlbyname` works; nodes with a standard number (`CTL_KERN`,
//! `CTL_HW`) keep it, and the rest get one under [`PRIVATE`]. The values
//! describe the iPad7,1 the UniXNU iPadOS 17.7 profile runs.

/// What a node holds, in the representation `sysctl` copies out.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Str(&'static str),
    I32(i32),
    I64(i64),
    /// `struct timeval`: seconds, microseconds.
    Timeval(i64, i32),
}

impl Value {
    pub fn bytes(&self) -> Vec<u8> {
        match self {
            Value::Str(s) => {
                let mut b = s.as_bytes().to_vec();
                b.push(0);
                b
            }
            Value::I32(v) => v.to_le_bytes().to_vec(),
            Value::I64(v) => v.to_le_bytes().to_vec(),
            Value::Timeval(s, us) => {
                let mut b = s.to_le_bytes().to_vec();
                b.extend_from_slice(&us.to_le_bytes());
                b.extend_from_slice(&[0; 4]);
                b
            }
        }
    }
}

/// The top-level node numbers.
pub const CTL_KERN: i32 = 1;
pub const CTL_VM: i32 = 2;
pub const CTL_HW: i32 = 6;
/// Where nodes without a standard number go.
pub const PRIVATE: i32 = 0x7f00;

/// `bootsessionuuid_string`.
pub const BOOTSESSIONUUID: &str = "00000000-0000-0000-0000-000000000000";

/// `(name, oid, value)`.
pub fn table() -> Vec<(&'static str, Vec<i32>, Value)> {
    use Value::*;
    use super::mig::machine::NCPUS;
    let mut t = vec![
        ("kern.ostype", vec![CTL_KERN, 1], Str("Darwin")),
        ("kern.osrelease", vec![CTL_KERN, 2], Str("23.6.0")),
        ("kern.osrevision", vec![CTL_KERN, 3], I32(199_506)),
        ("kern.version", vec![CTL_KERN, 4], Str("Darwin Kernel Version 23.6.0: gex; root:xnu-10063.141.1/RELEASE_ARM64_T8011")),
        ("kern.maxproc", vec![CTL_KERN, 6], I32(super::rlimit::MAXPROC as i32)),
        ("kern.maxfiles", vec![CTL_KERN, 7], I32(super::rlimit::MAXFILES as i32)),
        ("kern.argmax", vec![CTL_KERN, 8], I32(super::rlimit::ARG_MAX as i32)),
        ("kern.securelevel", vec![CTL_KERN, 9], I32(0)),
        ("kern.hostname", vec![CTL_KERN, 10], Str("iPad")),
        ("kern.hostid", vec![CTL_KERN, 11], I32(0)),
        ("kern.posix1version", vec![CTL_KERN, 17], I32(200_112)),
        ("kern.ngroups", vec![CTL_KERN, 18], I32(16)),
        ("kern.boottime", vec![CTL_KERN, 21], Timeval(1_730_000_000, 0)),
        ("kern.maxfilesperproc", vec![CTL_KERN, 29], I32(super::rlimit::MAXFILESPERPROC as i32)),
        ("kern.maxprocperuid", vec![CTL_KERN, 30], I32(super::rlimit::MAXPROCPERUID as i32)),
        ("kern.usrstack64", vec![CTL_KERN, 59], I64(gex_abi::STACK_TOP as i64)),
        ("kern.osversion", vec![CTL_KERN, 65], Str("21H461")),
        ("hw.machine", vec![CTL_HW, 1], Str("iPad7,1")),
        ("hw.model", vec![CTL_HW, 2], Str("J120AP")),
        ("hw.ncpu", vec![CTL_HW, 3], I32(NCPUS as i32)),
        ("hw.byteorder", vec![CTL_HW, 4], I32(1234)),
        ("hw.pagesize", vec![CTL_HW, 7], I32(16384)),
        ("hw.memsize", vec![CTL_HW, 24], I64(4 << 30)),
        ("hw.availcpu", vec![CTL_HW, 25], I32(NCPUS as i32)),
    ];
    let private = [
        ("kern.bootargs", Str("")),
        ("kern.osproductversion", Str("17.7.11")),
        ("kern.osbuildversion", Str("21H461")),
        ("kern.osvariant_status", I64(0)),
        ("kern.secure_kernel", I32(0)),
        ("kern.hv_vmm_present", I32(0)),
        ("kern.dyld_system_flags", I64(0)),
        ("kern.bootsessionuuid", Str(BOOTSESSIONUUID)),
        ("kern.uuid", Str("00000000-0000-0000-0000-000000000000")),
        ("kern.willshutdown", I32(0)),
        ("kern.memorystatus_level", I32(100)),
        ("hw.activecpu", I32(NCPUS as i32)),
        ("hw.physicalcpu", I32(NCPUS as i32)),
        ("hw.physicalcpu_max", I32(NCPUS as i32)),
        ("hw.logicalcpu", I32(NCPUS as i32)),
        ("hw.logicalcpu_max", I32(NCPUS as i32)),
        ("hw.cputype", I32(0x0100_000c)),
        ("hw.cpusubtype", I32(super::mig::machine::CPU_SUBTYPE as i32)),
        ("hw.cpufamily", I32(0x67ce_ee93u32 as i32)),
        ("hw.cachelinesize", I32(64)),
        ("hw.l1icachesize", I32(65_536)),
        ("hw.l1dcachesize", I32(65_536)),
        ("hw.l2cachesize", I32(8 << 20)),
        ("hw.optional.neon", I32(1)),
        ("hw.optional.floatingpoint", I32(1)),
        ("hw.optional.armv8_crc32", I32(1)),
        ("hw.optional.armv8_1_atomics", I32(1)),
        ("hw.optional.arm.FEAT_LSE", I32(1)),
        ("hw.optional.arm.FEAT_CRC32", I32(1)),
        ("hw.targettype", Str("J120")),
        ("vm.footprint_suspend", I32(0)),
        ("security.mac.amfi.developer_mode_status", I32(1)),
    ];
    for (i, (name, v)) in private.into_iter().enumerate() {
        t.push((name, vec![PRIVATE, i as i32], v));
    }
    t
}

/// The OID `name` resolves to.
pub fn oid(name: &str) -> Option<Vec<i32>> {
    table().into_iter().find(|(n, _, _)| *n == name).map(|(_, o, _)| o)
}

/// The value at `oid`.
pub fn get(oid: &[i32]) -> Option<Value> {
    table().into_iter().find(|(_, o, _)| o.as_slice() == oid).map(|(_, _, v)| v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_numbers_resolve() {
        assert_eq!(oid("kern.osrelease"), Some(vec![CTL_KERN, 2]));
        assert_eq!(get(&oid("kern.bootargs").unwrap()), Some(Value::Str("")));
        assert_eq!(get(&[CTL_HW, 1]), Some(Value::Str("iPad7,1")));
        assert_eq!(oid("no.such.node"), None);
        let names: std::collections::BTreeSet<_> = table().into_iter().map(|(n, _, _)| n).collect();
        assert_eq!(names.len(), table().len(), "names are unique");
    }
}
