//! The program's embedded code signature (`LC_CODE_SIGNATURE`,
//! `osfmk/kern/cs_blobs.h`): what the kernel asks of it about the task,
//! whether it is a platform binary and which entitlements it holds.
//!
//! The signature is a big-endian superblob of indexed blobs: the
//! CodeDirectory, whose `platform` byte is nonzero only for a platform
//! binary, and the entitlements (an XML property list).

use crate::syscalls::Kernel;

/// `CSMAGIC_*`, `CSSLOT_*`.
const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade_0cc0;
const CSMAGIC_CODEDIRECTORY: u32 = 0xfade_0c02;
const CSMAGIC_EMBEDDED_ENTITLEMENTS: u32 = 0xfade_7171;
const CSSLOT_CODEDIRECTORY: u32 = 0;
const CSSLOT_ENTITLEMENTS: u32 = 5;

/// The parts of a signature the kernel reads.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CodeSign {
    /// The CodeDirectory's `platform`: zero for a program that is not a
    /// platform binary.
    pub platform: u8,
    pub cd_flags: u32,
    /// The entitlements' XML property list.
    pub entitlements: Option<String>,
}

fn be32(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o + 4).map(|s| u32::from_be_bytes(s.try_into().unwrap()))
}

impl CodeSign {
    /// Read an `LC_CODE_SIGNATURE` superblob; what is malformed or absent
    /// reads as no CodeDirectory and no entitlements.
    pub fn parse(blob: &[u8]) -> CodeSign {
        let mut cs = CodeSign::default();
        if be32(blob, 0) != Some(CSMAGIC_EMBEDDED_SIGNATURE) {
            return cs;
        }
        let count = be32(blob, 8).unwrap_or(0) as usize;
        for i in 0..count {
            let (Some(ty), Some(off)) = (be32(blob, 12 + 8 * i), be32(blob, 16 + 8 * i)) else { break };
            let off = off as usize;
            let (Some(magic), Some(len)) = (be32(blob, off), be32(blob, off + 4)) else { continue };
            let Some(b) = blob.get(off..off + len as usize) else { continue };
            match (ty, magic) {
                (CSSLOT_CODEDIRECTORY, CSMAGIC_CODEDIRECTORY) => {
                    cs.cd_flags = be32(b, 12).unwrap_or(0);
                    cs.platform = b.get(38).copied().unwrap_or(0);
                }
                (CSSLOT_ENTITLEMENTS, CSMAGIC_EMBEDDED_ENTITLEMENTS) => {
                    cs.entitlements = Some(String::from_utf8_lossy(&b[8..]).into_owned());
                }
                _ => {}
            }
        }
        cs
    }

    /// Whether the top-level entitlement `name` is the boolean true
    /// (`IOTaskHasEntitlement`).
    pub fn entitled(&self, name: &str) -> bool {
        let Some(xml) = &self.entitlements else { return false };
        // Walk the property list's tags, keeping the depth of dicts and
        // arrays: a key at the top-level dict's depth names an entitlement,
        // its value the next element.
        let mut depth = 0i32;
        let mut rest = xml.as_str();
        let mut pending: Option<String> = None;
        while let Some(lt) = rest.find('<') {
            rest = &rest[lt..];
            let Some(gt) = rest.find('>') else { break };
            let tag = &rest[1..gt];
            rest = &rest[gt + 1..];
            if tag.starts_with('?') || tag.starts_with('!') {
                continue;
            }
            match tag.trim_end_matches('/').trim() {
                "dict" | "array" if !tag.ends_with('/') => {
                    if depth == 1 {
                        pending = None;
                    }
                    depth += 1;
                }
                "/dict" | "/array" => depth -= 1,
                "key" if depth == 1 => {
                    let end = rest.find("</key>").unwrap_or(rest.len());
                    pending = Some(rest[..end].to_string());
                    rest = &rest[end..];
                }
                "/key" | "plist" | "/plist" => {}
                t if depth == 1 && pending.is_some() && !t.starts_with('/') => {
                    if pending.take().as_deref() == Some(name) {
                        return t == "true" && tag.ends_with('/');
                    }
                }
                _ => {}
            }
        }
        false
    }
}

impl Kernel {
    /// `task_get_platform_binary`: the CodeDirectory names a platform. (AMFI
    /// takes it from the trust cache the binary is in; Apple's signing sets
    /// the field for exactly those binaries.)
    pub(crate) fn darwin_task_platform_binary(&self) -> bool {
        self.dtask.codesign.as_ref().is_some_and(|c| c.platform != 0)
    }

    /// `IOTaskHasEntitlement`.
    pub(crate) fn darwin_task_entitled(&self, name: &str) -> bool {
        self.dtask.codesign.as_ref().is_some_and(|c| c.entitled(name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_top_level_true_key_is_an_entitlement() {
        let cs = CodeSign {
            entitlements: Some(
                "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>a</key><true/><key>b</key><false/><key>c</key><dict><key>d</key><true/></dict><key>e</key><string>x</string></dict></plist>".into(),
            ),
            ..CodeSign::default()
        };
        assert!(cs.entitled("a"));
        assert!(!cs.entitled("b"));
        assert!(!cs.entitled("d"));
        assert!(!cs.entitled("e"));
        assert!(!cs.entitled("z"));
    }

    #[test]
    fn a_signature_gives_its_platform_byte() {
        // A superblob with one CodeDirectory whose platform byte is 13.
        let mut cd = vec![0u8; 44];
        cd[0..4].copy_from_slice(&CSMAGIC_CODEDIRECTORY.to_be_bytes());
        cd[4..8].copy_from_slice(&44u32.to_be_bytes());
        cd[38] = 13;
        let mut sb = Vec::new();
        sb.extend_from_slice(&CSMAGIC_EMBEDDED_SIGNATURE.to_be_bytes());
        sb.extend_from_slice(&(20 + 44u32).to_be_bytes());
        sb.extend_from_slice(&1u32.to_be_bytes());
        sb.extend_from_slice(&0u32.to_be_bytes());
        sb.extend_from_slice(&20u32.to_be_bytes());
        sb.extend_from_slice(&cd);
        assert_eq!(CodeSign::parse(&sb).platform, 13);
    }
}
