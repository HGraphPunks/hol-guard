//! One-use Rust-owned SDK tap socket directory, detached from the active
//! Python controller. Binding a listener is not a conformance observation.

use crate::{ActiveLease, RunReservationJournal};
use rustix::fs::{
    chmodat, chownat, fchmod, fchown, fstat, fsync, mkdirat, openat, statat, AtFlags, FileType,
    Mode, OFlags, Stat,
};
use rustix::process::{geteuid, Gid};
use serde_json::{json, Value};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixListener;

const TAP_GID: u32 = 10001;
const DIRECTORY_MODE: u32 = 0o710;
const SOCKET_MODE: u32 = 0o660;
const FAMILY_NAMES: [&str; 2] = ["docs.sock", "mail.sock"];

pub struct SdkTapListeners {
    directory: OwnedFd,
    directory_name: String,
    directory_stat: Stat,
    socket_stats: [Stat; 2],
    listeners: [UnixListener; 2],
}

impl SdkTapListeners {
    pub fn directory_name(&self) -> &str {
        &self.directory_name
    }

    pub fn docs(&self) -> &UnixListener {
        &self.listeners[0]
    }

    pub fn mail(&self) -> &UnixListener {
        &self.listeners[1]
    }

    pub fn to_json(&self) -> Value {
        json!({
            "schema":"hol-gauntlet-sdk-tap-listeners.v1",
            "directory_name":self.directory_name,
            "families":["docs","mail"],
            "peer_identity_verified":false,
            "journal_durable":false,
            "execution_eligible":false,
        })
    }

    /// Verify the held directory against the visible one-use name and both
    /// fixed socket inodes while the worker still holds its active lease.
    pub fn recheck(
        &self,
        journal: &RunReservationJournal,
        lease: &ActiveLease,
    ) -> Result<(), String> {
        lease
            .verify(&journal.root)
            .map_err(|error| error.to_string())?;
        let held = fstat(&self.directory).map_err(|error| error.to_string())?;
        let visible = statat(
            &journal.root,
            self.directory_name.as_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|error| error.to_string())?;
        if !same_inode(&held, &self.directory_stat)
            || !same_inode(&visible, &self.directory_stat)
            || !exact_directory(&held)
            || !exact_directory(&visible)
        {
            return Err("SDK tap directory identity or permissions changed".to_owned());
        }
        for (name, original) in FAMILY_NAMES.iter().zip(self.socket_stats.iter()) {
            let visible = statat(&self.directory, *name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|error| error.to_string())?;
            if !same_inode(&visible, original) || !exact_socket(&visible) {
                return Err(format!("SDK tap socket identity changed: {name}"));
            }
        }
        Ok(())
    }
}

fn same_inode(left: &Stat, right: &Stat) -> bool {
    left.st_dev == right.st_dev
        && left.st_ino == right.st_ino
        && left.st_uid == right.st_uid
        && left.st_gid == right.st_gid
        && left.st_mode == right.st_mode
        && left.st_nlink == right.st_nlink
}

fn exact_directory(stat: &Stat) -> bool {
    FileType::from_raw_mode(stat.st_mode) == FileType::Directory
        && stat.st_uid == 0
        && stat.st_gid == TAP_GID
        && stat.st_mode & 0o7777 == DIRECTORY_MODE
        && stat.st_nlink >= 2
}

fn exact_socket(stat: &Stat) -> bool {
    FileType::from_raw_mode(stat.st_mode) == FileType::Socket
        && stat.st_uid == 0
        && stat.st_gid == TAP_GID
        && stat.st_mode & 0o7777 == SOCKET_MODE
        && stat.st_nlink == 1
}

fn bind_one(directory: &OwnedFd, name: &str) -> Result<(UnixListener, Stat), String> {
    let relative = format!("/proc/self/fd/{}/{name}", directory.as_raw_fd());
    let listener = UnixListener::bind(&relative)
        .map_err(|error| format!("one-use SDK {name} listener bind failed: {error}"))?;
    chownat(
        directory,
        name,
        None,
        Some(Gid::from_raw(TAP_GID)),
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(|error| format!("SDK {name} group assignment failed: {error}"))?;
    chmodat(
        directory,
        name,
        Mode::from_bits_truncate(SOCKET_MODE),
        AtFlags::empty(),
    )
    .map_err(|error| format!("SDK {name} socket mode failed: {error}"))?;
    let visible = statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|error| format!("SDK {name} socket inspection failed: {error}"))?;
    if !exact_socket(&visible) {
        return Err(format!("SDK {name} socket has unsafe metadata"));
    }
    fsync(directory).map_err(|error| error.to_string())?;
    Ok((listener, visible))
}

/// Bind exactly docs/mail under an exclusive one-use hex run namespace in a
/// Root-owned private journal. An error leaves that namespace consumed for
/// later review; it must never trigger a direct-socket fallback.
pub fn bind_sdk_tap_listeners_ineligible(
    journal: &RunReservationJournal,
    lease: &ActiveLease,
    run_id: &str,
) -> Result<SdkTapListeners, String> {
    if geteuid().as_raw() != 0 || !journal.root_owned {
        return Err("Linux Root-owned tap journal required".to_owned());
    }
    if run_id.len() != 16
        || !run_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("fixed 16-hex one-use SDK tap run ID required".to_owned());
    }
    lease
        .verify(&journal.root)
        .map_err(|error| error.to_string())?;
    let directory_name = format!("{run_id}.sdk-tap");
    mkdirat(
        &journal.root,
        directory_name.as_str(),
        Mode::from_bits_truncate(0o700),
    )
    .map_err(|error| format!("one-use SDK tap namespace unavailable: {error}"))?;
    let directory = openat(
        &journal.root,
        directory_name.as_str(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| format!("SDK tap namespace open failed: {error}"))?;
    fchown(&directory, None, Some(Gid::from_raw(TAP_GID)))
        .map_err(|error| format!("SDK tap directory group failed: {error}"))?;
    fchmod(&directory, Mode::from_bits_truncate(DIRECTORY_MODE))
        .map_err(|error| format!("SDK tap directory mode failed: {error}"))?;
    let directory_stat = fstat(&directory).map_err(|error| error.to_string())?;
    if !exact_directory(&directory_stat) {
        return Err("SDK tap directory has unsafe metadata".to_owned());
    }
    fsync(&directory).map_err(|error| error.to_string())?;
    fsync(&journal.root).map_err(|error| error.to_string())?;
    let (docs, docs_stat) = bind_one(&directory, FAMILY_NAMES[0])?;
    let (mail, mail_stat) = bind_one(&directory, FAMILY_NAMES[1])?;
    let listeners = SdkTapListeners {
        directory,
        directory_name,
        directory_stat,
        socket_stats: [docs_stat, mail_stat],
        listeners: [docs, mail],
    };
    listeners.recheck(journal, lease)?;
    Ok(listeners)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::{Read, Write};
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream;
    use std::path::Path;

    #[test]
    #[ignore = "requires Linux Root for the private worker journal"]
    fn binds_exact_root_sockets_and_refuses_replay_or_changed_mode() {
        let temporary = tempfile::Builder::new()
            .prefix("gauntlet-sdk-tap-")
            .tempdir_in("/root")
            .unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let metadata = fs::metadata(temporary.path()).unwrap();
        assert_eq!(geteuid().as_raw(), 0);
        assert_eq!(metadata.uid(), 0);
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o700);
        let journal = RunReservationJournal::open_root_owned(temporary.path()).unwrap();
        let lease = journal.acquire_active_lease().unwrap();
        let listeners =
            bind_sdk_tap_listeners_ineligible(&journal, &lease, "0123456789abcdef").unwrap();
        listeners.recheck(&journal, &lease).unwrap();
        assert_eq!(listeners.to_json()["execution_eligible"], false);
        assert!(bind_sdk_tap_listeners_ineligible(&journal, &lease, "0123456789abcdef").is_err());
        let path = Path::new("/proc/self/fd")
            .join(listeners.directory.as_raw_fd().to_string())
            .join("docs.sock");
        let mut client = UnixStream::connect(&path).unwrap();
        let (mut server, _) = listeners.docs().accept().unwrap();
        client.write_all(b"x").unwrap();
        let mut byte = [0_u8; 1];
        server.read_exact(&mut byte).unwrap();
        assert_eq!(byte, [b'x']);
        fs::set_permissions(
            temporary
                .path()
                .join(listeners.directory_name())
                .join("mail.sock"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(listeners.recheck(&journal, &lease).is_err());
    }
}
