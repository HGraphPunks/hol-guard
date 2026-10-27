use super::*;
use std::os::unix::fs::PermissionsExt;

fn archive(entries: &[(&str, &[u8], tar::EntryType)]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (name, raw, kind) in entries {
        let mut h = tar::Header::new_ustar();
        h.set_size(raw.len() as u64);
        h.set_mode(0o600);
        h.set_uid(0);
        h.set_gid(0);
        h.set_mtime(0);
        h.set_entry_type(*kind);
        h.set_cksum();
        builder.append_data(&mut h, name, *raw).unwrap();
    }
    builder.into_inner().unwrap()
}
#[test]
fn public_archive_refuses_duplicates_links_extensions_and_nonzero_tail() {
    let valid = archive(&[("public.json", b"{}", tar::EntryType::Regular)]);
    assert_eq!(members(&valid).unwrap()["public.json"], b"{}");
    let duplicate = archive(&[
        ("x", b"1", tar::EntryType::Regular),
        ("x", b"2", tar::EntryType::Regular),
    ]);
    assert!(members(&duplicate).is_err());
    for kind in [
        tar::EntryType::Symlink,
        tar::EntryType::Link,
        tar::EntryType::Directory,
        tar::EntryType::XHeader,
        tar::EntryType::GNULongName,
    ] {
        assert!(members(&archive(&[("x", b"", kind)])).is_err());
    }
    let mut trailing = valid.clone();
    trailing.extend_from_slice(&[1; 512]);
    assert!(members(&trailing).is_err());
    assert!(members(&valid[..1024]).is_err());
    let mut outside = valid;
    outside[..100].fill(0);
    outside[..6].copy_from_slice(b"../bad");
    let mut h = tar::Header::new_ustar();
    h.as_mut_bytes().copy_from_slice(&outside[..512]);
    h.set_cksum();
    outside[..512].copy_from_slice(h.as_bytes());
    assert!(members(&outside).is_err());
}
#[test]
fn descriptor_reader_requires_exact_pin_and_safe_file_and_ancestry() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let raw = archive(&[("public.json", b"{}", tar::EntryType::Regular)]);
    let path = root.join("public.tar");
    std::fs::write(&path, &raw).unwrap();
    assert_eq!(read_stable(&path, &sha(&raw)).unwrap(), raw);
    assert!(read_stable(&path, &"0".repeat(64)).is_err());
    let symlink = root.join("link.tar");
    std::os::unix::fs::symlink(&path, &symlink).unwrap();
    assert!(read_stable(&symlink, &sha(&raw)).is_err());
    let directory_link = root.join("alias");
    std::os::unix::fs::symlink(&root, &directory_link).unwrap();
    assert!(read_stable(&directory_link.join("public.tar"), &sha(&raw)).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert!(read_stable(&path, &sha(&raw)).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let hard = root.join("hard.tar");
    std::fs::hard_link(&path, &hard).unwrap();
    assert!(read_stable(&path, &sha(&raw)).is_err());
}
