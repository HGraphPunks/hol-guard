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

fn check(file: &tempfile::NamedTempFile, expected: &[u8]) -> Image {
    let image = measure(descriptor(file.path())).unwrap();
    assert_eq!(image.sha256, crate::hash(expected));
    assert_eq!(image.bytes, expected.len() as u64);
    image
}

#[test]
fn rapid_same_size_writes_are_measured_without_timestamp_cache_reuse() {
    let mut file = input(0o666);
    let first = check(&file, b"one");
    file.seek(SeekFrom::Start(0)).unwrap();
    file.write_all(b"two").unwrap();
    file.as_file().sync_all().unwrap();
    let next = check(&file, b"two");
    assert_ne!(first.sha256, next.sha256);
    assert_eq!(first.metadata.st_size, next.metadata.st_size);
}

#[test]
fn unprivileged_or_writable_images_are_collected_without_admitting_them() {
    for mode in [0o555, 0o755, 0o666] {
        let file = input(mode);
        let image = check(&file, b"one");
        assert_eq!(image.metadata.st_uid, unsafe { libc::geteuid() });
        assert_eq!(u64::from(image.metadata.st_mode & 0o7777), u64::from(mode));
    }
}

#[test]
fn empty_and_oversized_images_refuse_before_the_read() {
    let file = tempfile::NamedTempFile::new().unwrap();
    assert!(measure(descriptor(file.path())).is_err());
    file.as_file().set_len(MAX_BYTES + 1).unwrap();
    assert!(measure(descriptor(file.path())).is_err());
}

#[test]
fn accelerated_digest_matches_the_existing_engine_across_read_boundaries() {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    let raw = (0..131073).map(|i| (i % 251) as u8).collect::<Vec<_>>();
    file.write_all(&raw).unwrap();
    file.as_file().sync_all().unwrap();
    check(&file, &raw);
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
    fn root_same_size_content_changes_are_rehashed_even_with_coarse_timestamps() {
        let mut file = root_input();
        let first = check(&file, b"one");
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_all(b"two").unwrap();
        file.as_file().sync_all().unwrap();
        let changed = check(&file, b"two");
        assert_eq!(first.metadata.st_ino, changed.metadata.st_ino);
        assert_eq!(first.metadata.st_size, changed.metadata.st_size);
        assert_ne!(first.sha256, changed.sha256);
    }

    #[test]
    fn replaced_inode_is_measured_from_the_current_descriptor() {
        let file = root_input();
        let mut replacement = root_input();
        let first = check(&file, b"one");
        replacement.seek(SeekFrom::Start(0)).unwrap();
        replacement.write_all(b"two").unwrap();
        replacement.as_file().sync_all().unwrap();
        std::fs::rename(replacement.path(), file.path()).unwrap();
        let next = check(&file, b"two");
        assert_ne!(first.metadata.st_ino, next.metadata.st_ino);
        assert_ne!(first.sha256, next.sha256);
    }

    #[test]
    fn ownership_and_permission_changes_do_not_substitute_old_measurements() {
        use std::os::fd::AsRawFd;
        let file = root_input();
        check(&file, b"one");
        for mode in [0o755, 0o575] {
            std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(
                u64::from(check(&file, b"one").metadata.st_mode & 0o7777),
                u64::from(mode)
            );
        }
        assert_eq!(
            unsafe { libc::fchown(file.as_file().as_raw_fd(), 10004, 10004) },
            0
        );
        assert_eq!(check(&file, b"one").metadata.st_uid, 10004);
    }

    #[test]
    fn measured_kernel_inputs_are_read_only_and_close_on_exec() {
        use std::os::fd::AsRawFd;
        let file = root_input();
        let fd = descriptor(file.path());
        assert!(rustix::io::fcntl_getfd(&fd)
            .unwrap()
            .contains(rustix::io::FdFlags::CLOEXEC));
        assert_eq!(
            unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) } & libc::O_ACCMODE,
            libc::O_RDONLY
        );
        let image = measure(fd).unwrap();
        assert_eq!(image.sha256, crate::hash(b"one"));
        assert_eq!(image.metadata.st_uid, 0);
    }

    #[test]
    fn repeated_measurements_do_not_retain_executable_descriptors() {
        // This opt-in owned Root suite runs with --test-threads=1.
        let file = root_input();
        let count = || std::fs::read_dir("/proc/self/fd").unwrap().count();
        let before = count();
        for _ in 0..256 {
            check(&file, b"one");
        }
        assert_eq!(count(), before);
    }
}
