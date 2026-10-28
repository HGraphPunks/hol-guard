use super::*;
use std::io::{Read, Write};

fn root() -> Option<tempfile::TempDir> {
    if unsafe { libc::geteuid() } != 0 {
        assert!(NativeMcpSockets::prepare("aabbccddeeff0011").is_err());
        return None;
    }
    let root = tempfile::Builder::new()
        .prefix("gmcp-")
        .tempdir_in("/var/lib")
        .unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    Some(root)
}

#[test]
fn all_fixed_families_accept_bytes_and_only_owned_socket_names_retire() {
    let Some(root) = root() else {
        return;
    };
    let mut sockets = NativeMcpSockets::at(root.path()).unwrap();
    assert!(
        !root.path().join("mcp-u").exists(),
        "prepare is mutation free"
    );
    sockets.initialize().unwrap();
    for directory in [sockets.upstream_directory(), sockets.resource_directory()] {
        for family in FAMILIES {
            let path = directory.join(format!("{}.sock", family.name()));
            let mut client = UnixStream::connect(&path).unwrap();
            client.write_all(b"frame\x00\xff").unwrap();
            let mut server = if directory == sockets.upstream_directory() {
                sockets.accept_upstream(family)
            } else {
                sockets.accept_resource(family)
            }
            .unwrap()
            .unwrap();
            let mut raw = [0; 7];
            server.read_exact(&mut raw).unwrap();
            assert_eq!(&raw, b"frame\x00\xff");
        }
    }
    let gate = UnixStream::connect(sockets.gate_directory().join("ready.sock")).unwrap();
    let accepted = sockets.accept_gate().unwrap().unwrap();
    std::fs::write(root.path().join("keep-evidence"), b"retained").unwrap();
    sockets.close().unwrap();
    sockets.close().unwrap();
    sockets.verify().unwrap();
    let v = sockets.observation();
    assert_eq!(v["socket_namespace_retired"], true);
    assert_eq!(v["accepted_streams_drained"], false);
    assert_eq!(v["peer_authenticated"], false);
    assert_eq!(
        std::fs::read(root.path().join("keep-evidence")).unwrap(),
        b"retained"
    );
    assert!(sockets.accept_gate().is_err());
    drop((gate, accepted));
}

#[test]
fn replacements_are_retained_and_restoring_modes_never_unpoisons_custody() {
    let Some(root) = root() else {
        return;
    };
    let mut sockets = NativeMcpSockets::at(root.path()).unwrap();
    sockets.initialize().unwrap();
    let path = sockets.upstream_directory().join("docs.sock");
    std::fs::rename(&path, root.path().join("original.sock")).unwrap();
    let substitute = UnixListener::bind(&path).unwrap();
    assert!(sockets.accept_upstream(Family::Docs).is_err());
    assert!(sockets.close().is_err());
    assert!(path.exists(), "cleanup must never unlink a substitute");
    assert!(root.path().join("original.sock").exists());
    assert_eq!(sockets.observation()["cleanup_uncertain"], true);
    drop(substitute);
    let Some(root) = self::root() else {
        return;
    };
    let mut sockets = NativeMcpSockets::at(root.path()).unwrap();
    sockets.initialize().unwrap();
    let path = sockets.resource_directory();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o770)).unwrap();
    assert!(sockets.verify().is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o710)).unwrap();
    assert!(sockets.accept_resource(Family::Mail).is_err());
    sockets.close().unwrap();
    assert_eq!(sockets.observation()["poisoned"], true);
}

#[test]
fn partial_initialization_keeps_its_owner_and_cannot_adopt_previous_namespaces() {
    let Some(root) = root() else {
        return;
    };
    let mut sockets = NativeMcpSockets::at(root.path()).unwrap();
    std::fs::create_dir(root.path().join("sdk-r")).unwrap();
    std::fs::write(root.path().join("sdk-r/previous"), b"old evidence").unwrap();
    assert!(sockets.initialize().is_err());
    assert!(sockets.initialize().is_err());
    assert!(sockets.close().is_err());
    assert_eq!(
        std::fs::read(root.path().join("sdk-r/previous")).unwrap(),
        b"old evidence"
    );
    assert!(sockets.upstream_directory().exists());
    assert!(
        !sockets.upstream_directory().join("docs.sock").exists(),
        "known own leaves can retire"
    );
    assert_eq!(sockets.observation()["socket_namespace_retired"], false);
    assert_eq!(sockets.observation()["cleanup_uncertain"], true);
}
