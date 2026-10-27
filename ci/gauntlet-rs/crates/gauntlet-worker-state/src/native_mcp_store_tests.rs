use super::*;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;

fn key() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[11; 32]).unwrap()
}
fn snapshot() -> String {
    json!({"schema":"gauntlet-workflow-snapshot.v1","actor_id":"fixture-actor","provider_scope":{"tenants":["task-tenant"]},"records":[
        {"id":"doc","collection":"docs.documents","tenant_id":"task-tenant","owner_id":"fixture-actor","version":1,
        "acl":{"read":["fixture-actor"],"write":["fixture-actor"]},"data":{"body":"source fixture"}}]}).to_string()
}
fn require_root() -> bool {
    if unsafe { libc::geteuid() } != 0 {
        assert!(NativeMcpWorld::new("aabbccddeeff0011", &snapshot(), key()).is_err());
        return false;
    }
    true
}
fn directory() -> tempfile::TempDir {
    // Match production's Root-owned ancestor requirement; /tmp is writable
    // by other users even when the final temporary directory is private.
    let path = tempfile::Builder::new()
        .prefix("gauntlet-mcp-world-")
        .tempdir_in("/var/lib")
        .unwrap();
    std::fs::set_permissions(path.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    path
}

#[test]
fn root_world_is_private_one_use_transactional_and_closes_every_database_fd_on_exec() {
    if !require_root() {
        return;
    }
    let root = directory();
    let mut world = NativeMcpWorld::create(root.path(), &snapshot(), key()).unwrap();
    let observed = world.observation().unwrap();
    assert_eq!(observed["mode"], 0o600);
    assert_eq!(observed["uid"], 0);
    assert_eq!(observed["agent_mounts_verified"], false);
    assert_eq!(observed["execution_eligible"], false);
    let result = world
        .call("docs.read", &json!({"record_id":"doc"}), json!(1))
        .unwrap();
    assert_eq!(result["data"]["body"], "source fixture");
    assert_eq!(world.receipts().unwrap().len(), 1);
    world
        .call(
            "docs.update",
            &json!({"record_id":"doc","expected_version":1,"data":{"body":"updated"}}),
            json!(2),
        )
        .unwrap();
    assert_eq!(
        world.snapshot().unwrap()["records"][0]["data"]["body"],
        "updated"
    );
    assert!(NativeMcpWorld::create(root.path(), &snapshot(), key()).is_err());
    world.verify().unwrap();
    let path = root.path().join(DATABASE);
    let bytes = std::fs::read(&path).unwrap();
    drop(world);
    assert_eq!(
        std::fs::read(path).unwrap(),
        bytes,
        "dropping an owner must retain evidence"
    );
}

#[test]
fn unsafe_owner_mode_link_and_inode_changes_never_reach_provider_state() {
    if !require_root() {
        return;
    }
    for action in ["mode", "owner", "link", "replace"] {
        let root = directory();
        let mut world = NativeMcpWorld::create(root.path(), &snapshot(), key()).unwrap();
        let path = root.path().join(DATABASE);
        let before = std::fs::read(&path).unwrap();
        match action {
            "mode" => {
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap()
            }
            "owner" => std::os::unix::fs::chown(&path, Some(10005), Some(10005)).unwrap(),
            "link" => std::fs::hard_link(&path, root.path().join("extra-link")).unwrap(),
            "replace" => {
                std::fs::rename(&path, root.path().join("retained.db")).unwrap();
                std::fs::write(&path, b"substitute").unwrap();
            }
            _ => unreachable!(),
        }
        let result = world.call(
            "docs.update",
            &json!({"record_id":"doc","expected_version":1,"data":{"must_not_commit":true}}),
            json!(1),
        );
        assert_eq!(result.err().unwrap().category, "custody");
        let retained = if action == "replace" {
            root.path().join("retained.db")
        } else {
            path
        };
        assert_eq!(
            std::fs::read(retained).unwrap(),
            before,
            "refused custody must preserve all SQLite bytes"
        );
        assert!(world.observation().is_err());
    }
}

#[test]
fn descriptor_leaks_and_restored_directory_modes_remain_poisoned() {
    if !require_root() {
        return;
    }
    let root = directory();
    let mut world = NativeMcpWorld::create(root.path(), &snapshot(), key()).unwrap();
    let fd = world.file.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    assert!(flags >= 0);
    assert_eq!(
        unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) },
        0
    );
    assert!(world.snapshot().is_err());
    assert_eq!(unsafe { libc::fcntl(fd, libc::F_SETFD, flags) }, 0);
    assert!(
        world.snapshot().is_err(),
        "metadata restoration must not erase custody failure"
    );
    let root = directory();
    let mut world = NativeMcpWorld::create(root.path(), &snapshot(), key()).unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(world.snapshot().is_err());
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(world.snapshot().is_err());
}

#[test]
fn preexisting_symlink_and_database_slots_are_never_adopted() {
    if !require_root() {
        return;
    }
    for linked in [false, true] {
        let root = directory();
        let target = root.path().join(DATABASE);
        if linked {
            std::os::unix::fs::symlink("outside.db", &target).unwrap();
        } else {
            std::fs::write(&target, b"previous evidence").unwrap();
        }
        assert!(NativeMcpWorld::create(root.path(), &snapshot(), key()).is_err());
        if linked {
            assert_eq!(std::fs::read_link(target).unwrap(), Path::new("outside.db"));
        } else {
            assert_eq!(std::fs::read(target).unwrap(), b"previous evidence");
        }
    }
}
