//! The fixed unprivileged dependency adapter. Only the outer Root owner may
//! grant custody to its output after independent capture and cleanup checks.

use crate::native_dependency_archive::archive_dependencies;
use crate::process_reap::reap_probe_child_bounded;
use rustix::fs::{fstat, open, statat, AtFlags, FileType, Mode, OFlags};
use rustix::process::{getegid, geteuid, getgid, getuid};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn input(name: &str, expected: &str) -> Result<Vec<u8>, String> {
    let path = format!("/input/{name}");
    let fd = open(
        path.as_str(),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| "fixed dependency input unavailable")?;
    let before = fstat(&fd).map_err(|_| "dependency input metadata unavailable")?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != 0
        || before.st_nlink != 1
        || before.st_mode & 0o777 != 0o444
        || before.st_size <= 0
        || before.st_size > 4 * 1024 * 1024
    {
        return Err("immutable Root dependency input required".to_owned());
    }
    let mut file = File::from(fd);
    let mut bytes = Vec::new();
    (&mut file)
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "dependency input read failed")?;
    let after = fstat(&file).map_err(|_| "dependency input readback failed")?;
    let visible = statat(rustix::fs::CWD, path.as_str(), AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| "dependency input disappeared")?;
    let key = |s: &rustix::fs::Stat| {
        (
            s.st_dev,
            s.st_ino,
            s.st_uid,
            s.st_gid,
            s.st_mode,
            s.st_nlink,
            s.st_size,
            s.st_mtime,
            s.st_mtime_nsec,
            s.st_ctime,
            s.st_ctime_nsec,
        )
    };
    if key(&before) != key(&after)
        || key(&before) != key(&visible)
        || bytes.len() as i64 != before.st_size
        || format!("{:x}", Sha256::digest(&bytes)) != expected
    {
        return Err("dependency input changed or differs from outside hash".to_owned());
    }
    Ok(bytes)
}

pub fn export_native_dependencies(
    job: &str,
    source: &str,
    project_sha256: &str,
    lock_sha256: &str,
) -> Result<Value, String> {
    if !crate::hex(job, 16)
        || !crate::hex(source, 40)
        || !crate::hex(project_sha256, 64)
        || !crate::hex(lock_sha256, 64)
    {
        return Err("exact dependency job/source/input hashes required".to_owned());
    }
    if [
        geteuid().as_raw(),
        getuid().as_raw(),
        getegid().as_raw(),
        getgid().as_raw(),
    ] != [65532; 4]
    {
        return Err("dedicated unprivileged dependency identity required".to_owned());
    }
    let status = std::fs::read_to_string("/proc/self/status")
        .map_err(|_| "dependency process identity unavailable")?;
    let field = |key: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(key))
            .map(str::trim)
    };
    if field("CapEff:") != Some("0000000000000000")
        || field("CapPrm:") != Some("0000000000000000")
        || field("NoNewPrivs:") != Some("1")
        || field("Seccomp:") != Some("2")
    {
        return Err("dependency process containment differs".to_owned());
    }
    let label = std::fs::read_to_string("/proc/self/attr/current")
        .map_err(|_| "dependency AppArmor label unavailable")?;
    let profile = format!("hol-gauntlet-build-{job}");
    if ![
        format!("{profile} (enforce)"),
        format!("crun//&{profile} (mixed)"),
        format!("{profile}//&crun (mixed)"),
    ]
    .contains(&label.trim().to_owned())
    {
        return Err("dependency job AppArmor attachment differs".to_owned());
    }
    let project = input("pyproject.toml", project_sha256)?;
    let lock = input("uv.lock", lock_sha256)?;
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create("/work/home")
        .map_err(|_| "one-use dependency home exists or cannot be created")?;
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create("/work/project")
        .map_err(|_| "one-use dependency workspace exists or cannot be created")?;
    for (name, bytes) in [("pyproject.toml", project), ("uv.lock", lock)] {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(format!("/work/project/{name}"))
            .map_err(|_| "dependency input copy unavailable")?;
        file.write_all(&bytes)
            .map_err(|_| "dependency input copy failed")?;
        file.sync_all()
            .map_err(|_| "dependency input copy fsync failed")?;
    }
    let mut child = Command::new("/usr/local/bin/uv")
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("HOME", "/work/home")
        .env("UV_CACHE_DIR", "/work/uv-cache")
        .env("UV_LINK_MODE", "copy")
        .env("UV_PYTHON_DOWNLOADS", "never")
        .current_dir("/work/project")
        .args([
            "sync",
            "--frozen",
            "--no-dev",
            "--no-install-project",
            "--no-build",
            "--python",
            "/usr/local/bin/gauntlet-python",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|_| "fixed dependency installer unavailable")?;
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break,
            Ok(Some(_)) => {
                return Err("locked wheel-only dependency installation failed".to_owned())
            }
            Ok(None) if started.elapsed() < Duration::from_secs(300) => {
                std::thread::sleep(Duration::from_millis(100))
            }
            _ => {
                let _ = child.kill();
                reap_probe_child_bounded(&mut child)
                    .map_err(|_| "dependency installer reap uncertain")?;
                return Err("dependency installer timeout or status unavailable".to_owned());
            }
        }
    }
    archive_dependencies(
        Path::new("/work/project/.venv/lib/python3.12/site-packages"),
        Path::new("/output/dependencies.zip"),
        &json!({"job_id":job,"source_sha":source,"pyproject_sha256":project_sha256,"uv_lock_sha256":lock_sha256,"wheel_only_install":true}),
    )
}
