//! The native actor loads the pinned glibc libseccomp ABI after dropping
//! privileges. A static musl actor cannot provide that runtime capability.
use crate::{EvidenceError, Result};

const INVALID: EvidenceError = EvidenceError::Invalid(
    "native actor requires a bounded Linux ARM64 ELF with the glibc dynamic loader",
);
const INTERPRETER: &[u8] = b"/lib/ld-linux-aarch64.so.1\0";

/// Inspect inert ELF metadata before reserving an artifact slot. Outside
/// source/hash custody is still required; this is no execution admission.
pub fn verify_native_actor_elf(raw: &[u8]) -> Result<()> {
    if !(64..=2 * 1024 * 1024).contains(&raw.len())
        || raw[..7] != [0x7f, b'E', b'L', b'F', 2, 1, 1]
        || !matches!(u16::from_le_bytes(raw[16..18].try_into().unwrap()), 2 | 3)
        || u16::from_le_bytes(raw[18..20].try_into().unwrap()) != 183
        || u32::from_le_bytes(raw[20..24].try_into().unwrap()) != 1
        || u16::from_le_bytes(raw[52..54].try_into().unwrap()) != 64
        || u16::from_le_bytes(raw[54..56].try_into().unwrap()) != 56
    {
        return Err(INVALID);
    }
    let offset = usize::try_from(u64::from_le_bytes(raw[32..40].try_into().unwrap()))
        .map_err(|_| INVALID)?;
    let count = u16::from_le_bytes(raw[56..58].try_into().unwrap()) as usize;
    if !(1..=128).contains(&count)
        || offset < 64
        || offset
            .checked_add(count * 56)
            .is_none_or(|end| end > raw.len())
    {
        return Err(INVALID);
    }
    let mut interpreters = 0;
    for index in 0..count {
        let header = offset + index * 56;
        if u32::from_le_bytes(raw[header..header + 4].try_into().unwrap()) != 3 {
            continue;
        }
        interpreters += 1;
        let start = usize::try_from(u64::from_le_bytes(
            raw[header + 8..header + 16].try_into().unwrap(),
        ))
        .map_err(|_| INVALID)?;
        let bytes = usize::try_from(u64::from_le_bytes(
            raw[header + 32..header + 40].try_into().unwrap(),
        ))
        .map_err(|_| INVALID)?;
        let end = start.checked_add(bytes).ok_or(INVALID)?;
        if bytes != INTERPRETER.len() || raw.get(start..end) != Some(INTERPRETER) {
            return Err(INVALID);
        }
    }
    if interpreters != 1 {
        return Err(INVALID);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn elf() -> Vec<u8> {
        let mut raw = vec![0; 256];
        raw[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
        raw[16..18].copy_from_slice(&3u16.to_le_bytes());
        raw[18..20].copy_from_slice(&183u16.to_le_bytes());
        raw[20..24].copy_from_slice(&1u32.to_le_bytes());
        raw[32..40].copy_from_slice(&64u64.to_le_bytes());
        raw[52..54].copy_from_slice(&64u16.to_le_bytes());
        raw[54..56].copy_from_slice(&56u16.to_le_bytes());
        raw[56..58].copy_from_slice(&1u16.to_le_bytes());
        raw[64..68].copy_from_slice(&3u32.to_le_bytes());
        raw[72..80].copy_from_slice(&192u64.to_le_bytes());
        raw[96..104].copy_from_slice(&(INTERPRETER.len() as u64).to_le_bytes());
        raw[192..192 + INTERPRETER.len()].copy_from_slice(INTERPRETER);
        raw
    }
    #[test]
    fn glibc_actor_metadata_is_distinct_from_static_and_other_abis() {
        verify_native_actor_elf(&elf()).unwrap();
        let mut static_actor = elf();
        static_actor[64..68].copy_from_slice(&1u32.to_le_bytes());
        assert!(verify_native_actor_elf(&static_actor).is_err());
        for (offset, byte) in [(4, 1), (5, 2), (18, 62), (192, b'X')] {
            let mut wrong = elf();
            wrong[offset] = byte;
            assert!(verify_native_actor_elf(&wrong).is_err());
        }
    }
    #[test]
    fn duplicate_interpreters_and_overflowing_or_truncated_tables_refuse() {
        let mut duplicate = elf();
        duplicate[56..58].copy_from_slice(&2u16.to_le_bytes());
        let header = duplicate[64..120].to_vec();
        duplicate[120..176].copy_from_slice(&header);
        assert!(verify_native_actor_elf(&duplicate).is_err());
        let mut overflow = elf();
        overflow[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(verify_native_actor_elf(&overflow).is_err());
        let mut truncated = elf();
        truncated.truncate(120);
        assert!(verify_native_actor_elf(&truncated).is_err());
        let mut overflow = elf();
        overflow[72..80].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(verify_native_actor_elf(&overflow).is_err());
    }
}
