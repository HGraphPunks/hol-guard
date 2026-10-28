use super::*;
use rustix::fs::{open, Mode, OFlags};
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

fn input(mode: u32) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(b"one").unwrap();
    file.as_file().sync_all().unwrap();
    std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(mode)).unwrap();
    file
}

fn descriptor(path: &Path) -> OwnedFd {
    open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .unwrap()
}

#[test]
fn metadata_reuse_requires_bounded_single_link_root_regular_image() {
    let file = input(0o555);
    let mut info = fstat(file.as_file()).unwrap();
    info.st_uid = 0;
    assert!(reusable(&info));
    let baseline = info;
    for changed in [
        {
            info.st_uid = 10004;
            info
        },
        {
            info = baseline;
            info.st_mode |= 0o020;
            info
        },
        {
            info = baseline;
            info.st_mode |= 0o002;
            info
        },
        {
            info = baseline;
            info.st_nlink = 2;
            info
        },
        {
            info = baseline;
            info.st_nlink = 0;
            info
        },
        {
            info = baseline;
            info.st_size = 0;
            info
        },
        {
            info = baseline;
            info.st_size = MAX_BYTES as i64 + 1;
            info
        },
        {
            info = baseline;
            info.st_mode = libc::S_IFDIR | 0o555;
            info
        },
    ] {
        assert!(!reusable(&changed));
    }
}

#[test]
fn writable_images_are_rehashed_instead_of_retained() {
    let mut file = input(0o666);
    let mut images = Images::default();
    let first = images.measure(descriptor(file.path())).unwrap();
    assert_eq!(first.bytes, 3);
    assert_eq!(first.metadata.st_mode & 0o7777, 0o666);
    file.seek(SeekFrom::Start(0)).unwrap();
    file.write_all(b"two").unwrap();
    file.as_file().sync_all().unwrap();
    let next = images.measure(descriptor(file.path())).unwrap();
    assert_eq!(first.sha256, crate::hash(b"one"));
    assert_eq!(next.sha256, crate::hash(b"two"));
    assert_eq!(images.reads, 2);
    assert!(images.held.is_empty());
}

#[test]
fn public_or_unprivileged_images_never_gain_root_reuse() {
    let file = input(0o555);
    let mut images = Images::default();
    if unsafe { libc::geteuid() } == 0 {
        return; // The explicit Root ownership-change proof below covers Root.
    }
    for _ in 0..2 {
        assert_eq!(
            images.measure(descriptor(file.path())).unwrap().sha256,
            crate::hash(b"one")
        );
    }
    assert!(images.held.is_empty());
    assert_eq!(images.reads, 2);
}

#[test]
fn empty_and_oversized_images_refuse_without_reading_or_retaining() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let mut images = Images::default();
    assert!(images.measure(descriptor(file.path())).is_err());
    file.as_file().set_len(MAX_BYTES + 1).unwrap();
    assert!(images.measure(descriptor(file.path())).is_err());
    assert_eq!(images.reads, 0);
    assert!(images.held.is_empty());
}

#[cfg(all(
    target_os = "linux",
    target_arch = "aarch64",
    feature = "owned-process-trace-fixture"
))]
mod root {
    use super::*;

    fn root_input() -> tempfile::NamedTempFile {
        assert_eq!(
            unsafe { libc::geteuid() },
            0,
            "owned VM Root proof required"
        );
        input(0o555)
    }

    #[test]
    fn unchanged_root_image_reuses_a_held_read_only_cloexec_generation() {
        let file = root_input();
        let mut images = Images::default();
        let first = images.measure(descriptor(file.path())).unwrap();
        let next = images.measure(descriptor(file.path())).unwrap();
        assert_eq!(first.sha256, next.sha256);
        assert_eq!(images.reads, 1);
        assert_eq!(images.held.len(), 1);
        let held = &images.held[0].file;
        assert!(rustix::io::fcntl_getfd(held)
            .unwrap()
            .contains(rustix::io::FdFlags::CLOEXEC));
        use std::os::fd::AsRawFd;
        assert_eq!(
            unsafe { libc::fcntl(held.as_raw_fd(), libc::F_GETFL) } & libc::O_ACCMODE,
            libc::O_RDONLY
        );
        assert!(fs_input::same(&first.metadata, &fstat(held).unwrap()));
    }

    #[test]
    fn root_content_and_metadata_changes_force_full_reads() {
        let mut file = root_input();
        let mut images = Images::default();
        let first = images.measure(descriptor(file.path())).unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_all(b"two").unwrap();
        file.as_file().sync_all().unwrap();
        let changed = images.measure(descriptor(file.path())).unwrap();
        assert_eq!(changed.sha256, crate::hash(b"two"));
        assert_ne!(first.sha256, changed.sha256);
        assert_eq!(images.reads, 2);
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let changed_mode = images.measure(descriptor(file.path())).unwrap();
        assert_eq!(changed_mode.sha256, changed.sha256);
        assert_eq!(changed_mode.metadata.st_mode & 0o7777, 0o755);
        assert_eq!(images.reads, 3);
        assert_eq!(images.held.len(), 1);
    }

    #[test]
    fn replaced_inode_does_not_reuse_the_retained_old_generation() {
        let file = root_input();
        let replacement = root_input();
        let mut images = Images::default();
        let first = images.measure(descriptor(file.path())).unwrap();
        std::fs::rename(replacement.path(), file.path()).unwrap();
        let next = images.measure(descriptor(file.path())).unwrap();
        assert_ne!(first.metadata.st_ino, next.metadata.st_ino);
        assert_eq!(first.sha256, next.sha256);
        assert_eq!(images.reads, 2);
        assert_eq!(fstat(&images.held[0].file).unwrap().st_nlink, 0);
    }

    #[test]
    fn ownership_and_write_permission_changes_invalidate_reuse() {
        use std::os::fd::AsRawFd;
        let file = root_input();
        let mut images = Images::default();
        images.measure(descriptor(file.path())).unwrap();
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o575)).unwrap();
        images.measure(descriptor(file.path())).unwrap();
        assert!(images.held.is_empty());
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o555)).unwrap();
        assert_eq!(
            unsafe { libc::fchown(file.as_file().as_raw_fd(), 10004, 10004) },
            0
        );
        for _ in 0..2 {
            let image = images.measure(descriptor(file.path())).unwrap();
            assert_eq!(image.metadata.st_uid, 10004);
            assert_eq!(image.sha256, crate::hash(b"one"));
        }
        assert_eq!(images.reads, 4);
        assert!(images.held.is_empty());
    }

    #[test]
    fn a_full_cache_keeps_the_descriptor_bound_and_hashes_new_images() {
        let files = (0..MAX_HELD + 1).map(|_| root_input()).collect::<Vec<_>>();
        let mut images = Images::default();
        for file in &files {
            images.measure(descriptor(file.path())).unwrap();
        }
        assert_eq!(images.held.len(), MAX_HELD);
        assert_eq!(images.reads, MAX_HELD + 1);
        images.measure(descriptor(files[MAX_HELD].path())).unwrap();
        assert_eq!(images.held.len(), MAX_HELD);
        assert_eq!(images.reads, MAX_HELD + 2);
        images.measure(descriptor(files[0].path())).unwrap();
        assert_eq!(images.reads, MAX_HELD + 2);
    }
}
