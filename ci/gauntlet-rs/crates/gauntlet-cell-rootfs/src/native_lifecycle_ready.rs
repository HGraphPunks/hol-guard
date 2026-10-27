//! Keep the child's actual overlay view and ready inode across teardown.
use crate::native_lifecycle_spec::NativeLifecycleSpec;
use crate::{hash, Result};
use rustix::fs::{fstat, openat, statat, AtFlags, FileType, Mode, OFlags, Stat};
use serde_json::{json, Value};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    os::fd::OwnedFd,
};

pub(crate) struct HeldLifecycleReady {
    directory: OwnedFd,
    file: File,
    original: Stat,
    raw: Vec<u8>,
    pub ready: Value,
}

fn content_inode(a: &Stat, b: &Stat) -> bool {
    a.st_dev == b.st_dev
        && a.st_ino == b.st_ino
        && a.st_mode == b.st_mode
        && a.st_uid == b.st_uid
        && a.st_gid == b.st_gid
        && a.st_size == b.st_size
        && a.st_mtime == b.st_mtime
        && a.st_mtime_nsec == b.st_mtime_nsec
}
fn metadata(s: &Stat) -> Value {
    json!({"device":s.st_dev,"inode":s.st_ino,"mode":s.st_mode,"links":s.st_nlink,
        "uid":s.st_uid,"gid":s.st_gid,"bytes":s.st_size,"mtime":s.st_mtime,"mtime_nsec":s.st_mtime_nsec,
        "ctime":s.st_ctime,"ctime_nsec":s.st_ctime_nsec})
}
fn retired(dead: bool, original: &Stat, held: &Stat, visible: Option<&Stat>) -> bool {
    dead && held.st_nlink == 0
        && content_inode(original, held)
        && visible.is_none_or(|s| crate::fs_input::same(held, s))
}

impl HeldLifecycleReady {
    pub fn read(directory: &OwnedFd, spec: &NativeLifecycleSpec) -> Result<Option<Self>> {
        Self::read_owned(directory, spec, 10004, 10004)
    }
    fn read_owned(
        directory: &OwnedFd,
        spec: &NativeLifecycleSpec,
        uid: u32,
        gid: u32,
    ) -> Result<Option<Self>> {
        let fd = match openat(
            directory,
            "detached-ready.json",
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(e) => return Err(e.to_string()),
        };
        let mut file = File::from(fd);
        let s = fstat(&file).map_err(|e| e.to_string())?;
        // Publication is complete only after the exclusive pending name is retired.
        if s.st_nlink == 2 {
            return Ok(None);
        }
        if FileType::from_raw_mode(s.st_mode) != FileType::RegularFile
            || s.st_uid != uid
            || s.st_gid != gid
            || s.st_mode & 0o7777 != 0o600
            || s.st_nlink != 1
            || !(1..=4096).contains(&s.st_size)
        {
            return Err("private lifecycle ready-file custody differs".into());
        }
        let mut raw = Vec::new();
        Read::by_ref(&mut file)
            .take(4097)
            .read_to_end(&mut raw)
            .map_err(|e| e.to_string())?;
        let ready = spec.ready(&raw)?;
        let visible = statat(directory, "detached-ready.json", AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|e| e.to_string())?;
        if !crate::fs_input::same(&s, &visible)
            || !crate::fs_input::same(&s, &fstat(&file).map_err(|e| e.to_string())?)
            || raw.len() as i64 != s.st_size
        {
            return Err("lifecycle ready generation changed while being read".into());
        }
        Ok(Some(Self {
            directory: rustix::io::dup(directory).map_err(|e| e.to_string())?,
            file,
            original: s,
            raw,
            ready,
        }))
    }
    pub fn recheck_with_liveness(
        &mut self,
        child_dead: impl Fn() -> Result<bool>,
    ) -> Result<Value> {
        let dead = child_dead()?;
        match self.recheck(dead) {
            // Timeout may kill the child and retire the overlay between the
            // pidfd check and file stat. Reobserve death before allowing unlink.
            Err(_) if !dead && child_dead()? => self.recheck(true),
            result => result,
        }
    }
    pub fn recheck(&mut self, child_dead: bool) -> Result<Value> {
        let before = fstat(&self.file).map_err(|e| e.to_string())?;
        let visible = statat(
            &self.directory,
            "detached-ready.json",
            AtFlags::SYMLINK_NOFOLLOW,
        );
        let visible_metadata = match &visible {
            Ok(s) => metadata(s),
            Err(e) => json!({"error":e.to_string()}),
        };
        let unlinked = match visible {
            Ok(visible)
                if crate::fs_input::same(&self.original, &visible)
                    && crate::fs_input::same(&self.original, &before) =>
            {
                false
            }
            // A held overlay mount can still resolve the retired dentry.
            // It must name the same zero-link inode as the held descriptor.
            Ok(visible) if retired(child_dead, &self.original, &before, Some(&visible)) => true,
            Err(rustix::io::Errno::NOENT) if retired(child_dead, &self.original, &before, None) => {
                true
            }
            _ => {
                return Err(format!(
                    "held lifecycle readiness replaced or changed after control: {}",
                    json!({"original":metadata(&self.original),"held":metadata(&before),"visible":visible_metadata,"child_dead":child_dead})
                ))
            }
        };
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|e| e.to_string())?;
        let mut after = Vec::new();
        Read::by_ref(&mut self.file)
            .take(4097)
            .read_to_end(&mut after)
            .map_err(|e| e.to_string())?;
        if after != self.raw
            || !crate::fs_input::same(&before, &fstat(&self.file).map_err(|e| e.to_string())?)
        {
            return Err("held lifecycle readiness bytes changed".into());
        }
        if !matches!(
            statat(
                &self.directory,
                "late-detached-effect.txt",
                AtFlags::SYMLINK_NOFOLLOW
            ),
            Err(rustix::io::Errno::NOENT)
        ) {
            return Err(
                "late lifecycle effect is present or unavailable in held child view".into(),
            );
        }
        Ok(
            json!({"view":"kernel-held-process-cwd.v1","file":"detached-ready.json",
            "sha256":hash(&self.raw),"bytes":self.raw.len(),"utf8":std::str::from_utf8(&self.raw).map_err(|e|e.to_string())?,
            "device":self.original.st_dev,"inode":self.original.st_ino,"uid":self.original.st_uid,"gid":self.original.st_gid,
            "mode":self.original.st_mode & 0o7777,"original_links":self.original.st_nlink,"final_links":before.st_nlink,
            "overlay_cleanup_unlinked":unlinked,"held_bytes_unchanged":true,"late_effect_absent":true}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn setup() -> (tempfile::TempDir, OwnedFd, NativeLifecycleSpec) {
        let dir = tempfile::tempdir().unwrap();
        let fd = rustix::fs::open(
            dir.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let spec = NativeLifecycleSpec::new(
            std::path::Path::new("/var/lib/hol-gauntlet-rust/native-jobs/0123456789abcdef/cell"),
            crate::NativeControlRole::Timeout,
        )
        .unwrap();
        let raw = json!({"schema":"hol-gauntlet-native-detached-ready.v1","role":"timeout","token":spec.token,"pid":17,"sid":17,"pgrp":17}).to_string();
        std::fs::write(dir.path().join("detached-ready.json"), raw).unwrap();
        std::fs::set_permissions(
            dir.path().join("detached-ready.json"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        (dir, fd, spec)
    }
    fn hold(fd: &OwnedFd, spec: &NativeLifecycleSpec) -> HeldLifecycleReady {
        let s = fstat(fd).unwrap();
        if s.st_uid != 10004 || s.st_gid != 10004 {
            assert!(HeldLifecycleReady::read(fd, spec).is_err());
        }
        let held = HeldLifecycleReady::read_owned(fd, spec, s.st_uid, s.st_gid)
            .unwrap()
            .unwrap();
        assert_eq!(held.ready["token"], spec.token);
        held
    }
    #[test]
    fn overlay_unlink_is_allowed_only_after_held_child_death_and_preserves_bytes() {
        let (dir, fd, spec) = setup();
        let mut held = hold(&fd, &spec);
        held.recheck(false).unwrap();
        std::fs::remove_file(dir.path().join("detached-ready.json")).unwrap();
        assert!(held.recheck(false).is_err());
        let retired = held.recheck(true).unwrap();
        assert_eq!(retired["final_links"], 0);
        assert_eq!(retired["overlay_cleanup_unlinked"], true);
    }
    #[test]
    fn same_bytes_replacement_or_late_effect_cannot_pass_held_readback() {
        let (dir, fd, spec) = setup();
        let mut held = hold(&fd, &spec);
        let original = dir.path().join("detached-ready.json");
        let raw = std::fs::read(&original).unwrap();
        std::fs::remove_file(&original).unwrap();
        std::fs::write(&original, raw).unwrap();
        std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(held.recheck(true).is_err());
        let mut held = hold(&fd, &spec);
        std::fs::write(dir.path().join("late-detached-effect.txt"), "late").unwrap();
        assert!(held.recheck(true).is_err());
    }
    #[test]
    fn death_during_readback_requires_a_fresh_liveness_observation() {
        let (dir, fd, spec) = setup();
        let mut held = hold(&fd, &spec);
        std::fs::remove_file(dir.path().join("detached-ready.json")).unwrap();
        assert!(held.recheck_with_liveness(|| Ok(false)).is_err());
        let checks = std::cell::Cell::new(0);
        held.recheck_with_liveness(|| {
            let n = checks.get();
            checks.set(n + 1);
            Ok(n > 0)
        })
        .unwrap();
        assert_eq!(checks.get(), 2);
    }
    #[test]
    fn lookupable_retired_overlay_dentry_requires_dead_child_and_exact_held_inode() {
        let (dir, fd, spec) = setup();
        let held = hold(&fd, &spec);
        std::fs::remove_file(dir.path().join("detached-ready.json")).unwrap();
        let current = fstat(&held.file).unwrap();
        assert!(retired(true, &held.original, &current, Some(&current)));
        assert!(!retired(false, &held.original, &current, Some(&current)));
        let mut substituted = fstat(&held.file).unwrap();
        substituted.st_ino += 1;
        assert!(!retired(true, &held.original, &current, Some(&substituted)));
        assert!(!retired(
            true,
            &held.original,
            &substituted,
            Some(&substituted)
        ));
    }
}
