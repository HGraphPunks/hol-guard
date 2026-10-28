//! No host mount is changed: failures terminate this private PID1 namespace.
use crate::fs_input;
use crate::inputs::{task_metadata, Inputs};
use crate::mounts::{bind, fd_path, idmap, mount, raise_loopback, tmpfs, verify_idmap_runtime, RO};
use crate::{NetworkProfile, Result, StateProfile};
use std::fs::{DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn directory(path: &Path) -> Result<()> {
    DirBuilder::new()
        .mode(0o755)
        .create(path)
        .map_err(|e| e.to_string())?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| e.to_string())
}
fn target(root: &Path, destination: &Path) -> Result<PathBuf> {
    Ok(root.join(
        destination
            .strip_prefix("/")
            .map_err(|_| "absolute destination required")?,
    ))
}
fn scaffolding(root: &Path, path: &Path) -> Result<()> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| "scaffolding escaped private root")?;
    let mut current = root.to_owned();
    for part in relative.components() {
        current.push(part);
        match std::fs::symlink_metadata(&current) {
            Ok(info) if info.is_dir() && info.uid() == 0 && info.mode() & 0o022 == 0 => {}
            Ok(_) => return Err("unsafe private scaffolding".into()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => directory(&current)?,
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(())
}
fn write(root: &Path, name: &str, raw: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o444)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root.join(name))
        .map_err(|e| e.to_string())?;
    file.write_all(raw).map_err(|e| e.to_string())?;
    file.set_permissions(std::fs::Permissions::from_mode(0o444))
        .map_err(|e| e.to_string())
}
fn allocator(system: &Path) -> Result<Option<Vec<u8>>> {
    let path = system.join("etc/ld.so.preload");
    match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
        Ok(_) => {
            let raw = fs_input::read(&path, 4096)?;
            if raw != b"/usr/lib/hol-gauntlet/libmalloc-policy.so\n" {
                return Err("fixed image allocator preload required".into());
            }
            fs_input::read(
                &system.join("usr/lib/hol-gauntlet/libmalloc-policy.so"),
                2 * 1024 * 1024,
            )?;
            Ok(Some(raw))
        }
    }
}
fn devices(new: &Path) -> Result<()> {
    tmpfs(&new.join("dev"), libc::MS_NOSUID, "size=64k,mode=0755")?;
    for (name, major, minor) in [
        ("null", 1, 3),
        ("zero", 1, 5),
        ("full", 1, 7),
        ("random", 1, 8),
        ("urandom", 1, 9),
        ("tty", 5, 0),
    ] {
        let source = Path::new("/dev").join(name);
        let info = std::fs::symlink_metadata(&source).map_err(|e| e.to_string())?;
        if !info.file_type().is_char_device()
            || info.uid() != 0
            || libc::major(info.rdev()) != major
            || libc::minor(info.rdev()) != minor
        {
            return Err("fixed safe character device required".into());
        }
        let destination = new.join("dev").join(name);
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&destination)
            .map_err(|e| e.to_string())?;
        mount(Some(&source), &destination, None, libc::MS_BIND, None)?;
    }
    std::os::unix::fs::symlink("/proc/self/fd", new.join("dev/fd")).map_err(|e| e.to_string())?;
    mount(
        None,
        &new.join("dev"),
        None,
        libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID,
        None,
    )
}

pub(crate) fn run(inputs: Inputs) -> Result<()> {
    verify_idmap_runtime(&inputs.spec.idmap_runtime)?;
    let preload = allocator(&inputs.system.root)?;
    if matches!(inputs.spec.network, NetworkProfile::PrivateLoopback { .. }) {
        raise_loopback()?;
    }
    let new = inputs.spec.stage.join("rootfs");
    // Exclusive creation refuses an interrupted or reused stage, even if empty.
    directory(&new)?;
    mount(
        None,
        Path::new("/"),
        None,
        libc::MS_REC | libc::MS_PRIVATE,
        None,
    )?;
    // util-linux's idmap helper needs proc to name this PID namespace.
    mount(
        Some(Path::new("proc")),
        Path::new("/proc"),
        Some("proc"),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        None,
    )?;
    tmpfs(&new, libc::MS_NOSUID | libc::MS_NODEV, "size=8m,mode=0755")?;
    for name in [
        "usr", "etc", "dev", "proc", "tmp", "public", "oldroot", "run", "product", "opt",
    ] {
        directory(&new.join(name))?;
    }
    let image = fd_path(&inputs.image);
    bind(&image.join("usr"), &new.join("usr"))?;
    directory(&new.join("opt/node"))?;
    bind(&image.join("opt/node"), &new.join("opt/node"))?;
    for (name, to) in [("bin", "usr/bin"), ("sbin", "usr/sbin"), ("lib", "usr/lib")] {
        std::os::unix::fs::symlink(to, new.join(name)).map_err(|e| e.to_string())?;
    }
    let runtime = target(&new, &inputs.runtime.mountpoint)?;
    scaffolding(&new, &runtime)?;
    bind(&fd_path(&inputs.prefix), &runtime)?;
    for name in [
        "group",
        "hosts",
        "ld.so.cache",
        "nsswitch.conf",
        "passwd",
        "protocols",
        "services",
    ] {
        write(
            &new,
            &format!("etc/{name}"),
            &fs_input::read(&inputs.system.root.join("etc").join(name), 2 * 1024 * 1024)?,
        )?;
    }
    if let Some(raw) = preload {
        write(&new, "etc/ld.so.preload", &raw)?;
    }
    let layout = serde_json::json!({"schema":"product-cell-layout.v1","workspace":inputs.system.workspace,"path":"/usr/local/bin:/usr/bin:/bin"});
    let mut layout = gauntlet_contracts::canonicalize(layout.to_string().as_bytes())
        .map_err(|e| e.to_string())?;
    layout.push(b'\n');
    write(&new, "etc/hol-cell-layout.json", &layout)?;
    if matches!(inputs.spec.network, NetworkProfile::PrivateLoopback { .. }) {
        write(
            &new,
            "etc/hol-cell-network-profile",
            b"private-loopback-v1\n",
        )?;
    }
    directory(&new.join("etc/alternatives"))?;
    bind(
        &image.join("etc/alternatives"),
        &new.join("etc/alternatives"),
    )?;
    bind(&fd_path(&inputs.public), &new.join("public"))?;
    devices(&new)?;
    tmpfs(
        &new.join("tmp"),
        libc::MS_NOSUID | libc::MS_NODEV,
        "size=128m,mode=0700,uid=10004,gid=10004",
    )?;
    match inputs.spec.state {
        StateProfile::Memory => tmpfs(
            &new.join("product"),
            libc::MS_NOSUID | libc::MS_NODEV,
            "size=128m,mode=0700,uid=10004,gid=10004",
        )?,
        StateProfile::Persistent => {
            let source = inputs.spec.stage.join("state");
            let info = std::fs::symlink_metadata(&source).map_err(|e| e.to_string())?;
            if !info.is_dir()
                || info.uid() != 10004
                || info.gid() != 10004
                || info.mode() & 0o7777 != 0o700
            {
                return Err("persistent state changed before bind".into());
            }
            mount(
                Some(&source),
                &new.join("product"),
                None,
                libc::MS_BIND,
                None,
            )?;
            mount(
                None,
                &new.join("product"),
                None,
                libc::MS_REMOUNT | libc::MS_BIND | libc::MS_NOSUID | libc::MS_NODEV,
                None,
            )?;
        }
    }
    for row in &inputs.tasks {
        task_metadata(row)?;
        let destination = target(&new, &row.destination)?;
        scaffolding(
            &new,
            destination.parent().ok_or("task target parent required")?,
        )?;
        DirBuilder::new()
            .mode(0o700)
            .create(&destination)
            .map_err(|e| e.to_string())?;
        idmap(&row.source, &destination)?;
        mount(
            None,
            &destination,
            None,
            libc::MS_REMOUNT | libc::MS_BIND | libc::MS_NOSUID | libc::MS_NODEV,
            None,
        )?;
        task_metadata(row)?;
        let mapped = std::fs::symlink_metadata(&destination).map_err(|e| e.to_string())?;
        if mapped.uid() != 10004
            || mapped.gid() != 10004
            || mapped.dev() != row.device
            || mapped.ino() != row.inode
            || mapped.mode() & 0o7777 != row.mode
        {
            return Err("kernel idmap differs from pinned physical custody".into());
        }
    }
    mount(
        Some(Path::new("proc")),
        &new.join("proc"),
        Some("proc"),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        None,
    )?;
    // Keep the stage descriptor live until all construction has finished.
    rustix::fs::fstat(&inputs.stage).map_err(|e| e.to_string())?;
    std::env::set_current_dir(&new).map_err(|e| e.to_string())?;
    // SAFETY: fixed AArch64 pivot_root arguments name this newly created mount
    // and its empty child; all namespace checks preceded the first mutation.
    if unsafe { libc::syscall(libc::SYS_pivot_root, c".".as_ptr(), c"oldroot".as_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    std::env::set_current_dir("/").map_err(|e| e.to_string())?;
    // SAFETY: the fixed path is solely the detached old root in this namespace.
    if unsafe { libc::umount2(c"/oldroot".as_ptr(), libc::MNT_DETACH) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    std::fs::remove_dir("/oldroot").map_err(|e| e.to_string())?;
    mount(None, Path::new("/"), None, libc::MS_REMOUNT | RO, None)?;
    let error = Command::new("/public/initializer")
        .args(["/public/gauntlet-product-cell", "actor"])
        .env_clear()
        .exec();
    Err(format!(
        "fixed privilege-dropping initializer exec failed: {error}"
    ))
}
