//! Inert Rust staging. Only the pinned, unprivileged product executes later.
use crate::declarations::{parse_tasks, Runtime, System};
use crate::{fs_input, hash, CellPreparation, NativeCell, Result, RootfsSpec};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::{atomic::AtomicBool, Arc};

fn write_new(path: &Path, raw: &[u8], mode: u32) -> Result<String> {
    fs_input::directory(path.parent().ok_or("staged file parent required")?)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| e.to_string())?;
    file.write_all(raw)
        .and_then(|_| file.set_permissions(std::fs::Permissions::from_mode(mode)))
        .and_then(|_| file.sync_all())
        .map_err(|_| "cell staging write uncertain")?;
    File::open(path.parent().unwrap())
        .and_then(|f| f.sync_all())
        .map_err(|_| "cell staging directory commit uncertain")?;
    Ok(hash(raw))
}

fn declaration(path: &Path, value: &Value) -> Result<String> {
    let mut raw = gauntlet_contracts::canonicalize(value.to_string().as_bytes())
        .map_err(|e| e.to_string())?;
    raw.push(b'\n');
    write_new(path, &raw, 0o444)
}

fn make_directory(path: &Path, mode: u32) -> Result<()> {
    fs_input::directory(path.parent().ok_or("staged directory parent required")?)?;
    std::fs::DirBuilder::new()
        .mode(mode)
        .create(path)
        .map_err(|e| e.to_string())?;
    let descriptor = fs_input::directory(path)?;
    rustix::fs::fchmod(&descriptor, rustix::fs::Mode::from_bits_truncate(mode))
        .map_err(|e| e.to_string())?;
    File::from(descriptor)
        .sync_all()
        .map_err(|_| "staged directory mode commit uncertain")?;
    File::open(path.parent().unwrap())
        .and_then(|f| f.sync_all())
        .map_err(|_| "cell directory creation commit uncertain".to_owned())
}

fn state(stage: &Path) -> Result<()> {
    // Keep all paths Root-owned until fixed state has been written and synced.
    let root = stage.join("state");
    make_directory(&root, 0o700)?;
    for name in ["home", "guard"] {
        make_directory(&root.join(name), 0o700)?;
    }
    let context = root.join("home/omp.json");
    write_new(&context, b"{}\n", 0o600)?;
    rustix::fs::chown(
        &context,
        Some(rustix::process::Uid::from_raw(10004)),
        Some(rustix::process::Gid::from_raw(10004)),
    )
    .map_err(|e| e.to_string())?;
    let path = root.join("guard/config.toml");
    write_new(&path,b"mode=\"enforce\"\nsync=false\ntelemetry=false\ndesktop_notifications=false\napproval_wait_timeout_seconds=1\n",0o600)?;
    rustix::fs::chown(
        &path,
        Some(rustix::process::Uid::from_raw(10004)),
        Some(rustix::process::Gid::from_raw(10004)),
    )
    .map_err(|e| e.to_string())?;
    for path in [root.join("guard"), root.join("home"), root] {
        rustix::fs::chown(
            &path,
            Some(rustix::process::Uid::from_raw(10004)),
            Some(rustix::process::Gid::from_raw(10004)),
        )
        .map_err(|e| e.to_string())?;
    }
    Ok(())
}

pub fn prepare_and_start(
    declaration_path: &Path,
    expected_sha256: &str,
    cancelled: Arc<AtomicBool>,
) -> Result<NativeCell> {
    crate::kernel_process::root_proc()?;
    let raw = fs_input::pinned(declaration_path, 49152, expected_sha256)?;
    let spec = CellPreparation::parse(&raw, expected_sha256)?;
    if cancelled.load(std::sync::atomic::Ordering::Acquire) {
        return Err("cell preparation cancelled".into());
    }
    let manifest_raw = fs_input::pinned(
        &spec.artifacts.join("manifest.json"),
        1024 * 1024,
        &spec.artifact_manifest_sha256,
    )?;
    let manifest = gauntlet_evidence::verify_native_private_cell_manifest(
        &manifest_raw,
        &spec.artifact_manifest_sha256,
        &spec.initializer_sha256,
    )
    .map_err(|e| e.to_string())?;
    let mut public = BTreeMap::new();
    let mut total = 0usize;
    for (name, pin) in &manifest.files {
        let raw = fs_input::pinned(&spec.artifacts.join(name), 2 * 1024 * 1024, pin)?;
        total += raw.len();
        if total > 16 * 1024 * 1024 {
            return Err("cell artifact byte budget".into());
        }
        if let Some(basename) = name.strip_prefix("public/") {
            if basename.contains('/') {
                return Err("fixed flat native public artifacts required".into());
            }
            if basename == "gauntlet-product-cell" {
                gauntlet_evidence::verify_native_actor_elf(&raw).map_err(|e| e.to_string())?;
            }
            public.insert(basename.to_owned(), raw);
        }
    }
    fs_input::directory(&spec.runtime_prefix)?;
    let runtime = gauntlet_evidence::inventory_tree(
        &spec.runtime_prefix,
        gauntlet_evidence::TreeKind::InstalledPrefix,
    )
    .map_err(|e| e.to_string())?;
    if runtime.digest != spec.runtime_tree_digest {
        return Err("installed runtime prefix differs before cell staging".into());
    }
    let launch = spec.supervisor(&"0".repeat(64))?;
    let launch_raw = launch.to_string();
    let launch = crate::SupervisorSpec::parse(launch_raw.as_bytes(), &hash(launch_raw.as_bytes()))?;
    for (name, pin) in &launch.host_helpers {
        fs_input::pinned(Path::new(name), 16 * 1024 * 1024, pin)?;
    }
    fs_input::pinned(
        &launch.constructor,
        16 * 1024 * 1024,
        &launch.constructor_sha256,
    )?;
    fs_input::pinned(
        Path::new("/usr/bin/podman"),
        128 * 1024 * 1024,
        &spec.podman_sha256,
    )?;
    make_directory(&spec.stage, 0o700)?;
    write_new(
        &spec.stage.join("cell-artifact-manifest.json"),
        &manifest_raw,
        0o444,
    )?;
    make_directory(&spec.stage.join("public"), 0o755)?;
    if public.values().map(Vec::len).sum::<usize>() > 8 * 1024 * 1024 {
        return Err("public cell bootstrap byte budget".into());
    }
    for (name, raw) in public {
        write_new(
            &spec.stage.join("public").join(&name),
            &raw,
            if matches!(name.as_str(), "initializer" | "gauntlet-product-cell") {
                0o555
            } else {
                0o444
            },
        )?;
    }
    state(&spec.stage)?;
    let runtime_sha256 = declaration(&spec.stage.join("runtime.json"), &spec.runtime())?;
    let task_sha256 = declaration(&spec.stage.join("task-mounts.json"), &spec.task_mounts)?;
    let image =
        crate::image_lease::ImageLease::acquire(&spec.stage, &spec.image_id, &spec.podman_sha256)?;
    let system = image.declaration()?;
    let parsed_system = System::parse(system.to_string().as_bytes())?;
    let parsed_runtime = Runtime::parse(spec.runtime().to_string().as_bytes())?;
    for task in parse_tasks(
        spec.task_mounts.to_string().as_bytes(),
        &spec.stage,
        &parsed_system,
        &parsed_runtime,
    )? {
        crate::inputs::task_metadata(&task)?;
    }
    let system_sha256 = declaration(&spec.stage.join("system.json"), &system)?;
    let parent_network = std::fs::read_link("/proc/self/ns/net").map_err(|e| e.to_string())?;
    let rootfs = json!({"schema":"hol-gauntlet-product-rootfs.v1","stage":spec.stage,
        "initializer_sha256":spec.initializer_sha256,"artifact_manifest_sha256":spec.artifact_manifest_sha256,
        "system_spec_sha256":system_sha256,"task_spec_sha256":task_sha256,"runtime_spec_sha256":runtime_sha256,
        "idmap_runtime":"ubuntu2404-controller-v1","state":"persistent-v1","network_profile":"private-loopback-v1","parent_network_namespace":parent_network});
    let rootfs_sha256 = declaration(&spec.stage.join("native-rootfs.v1.json"), &rootfs)?;
    RootfsSpec::parse(
        &fs_input::pinned(
            &spec.stage.join("native-rootfs.v1.json"),
            8192,
            &rootfs_sha256,
        )?,
        &rootfs_sha256,
    )?;
    let supervisor = spec.supervisor(&rootfs_sha256)?;
    let path = spec.stage.join("native-supervisor.v1.json");
    let digest = declaration(&path, &supervisor)?;
    let mut cell = NativeCell::start_with_image(&path, &digest, cancelled, Some(image))?;
    cell.journal.append("rust-preparation-bound",json!({"preparation_sha256":expected_sha256,"rust_image_lease_owned":true,
        "image_id":spec.image_id,"runtime_tree_digest":spec.runtime_tree_digest,"artifact_manifest_sha256":spec.artifact_manifest_sha256}))?;
    Ok(cell)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::CommandExt;

    #[test]
    fn private_worker_umask_preserves_explicit_public_and_private_modes() {
        const CHILD: &str = "HOL_GAUNTLET_UMASK_REGRESSION_CHILD";
        if let Some(root) = std::env::var_os(CHILD) {
            let root = std::path::PathBuf::from(root);
            let public = root.join("public");
            make_directory(&public, 0o755).unwrap();
            for (name, mode) in [("actor", 0o555), ("manifest", 0o444), ("private", 0o600)] {
                let file = public.join(name);
                write_new(&file, b"retained", mode).unwrap();
                assert_eq!(file.metadata().unwrap().permissions().mode() & 0o7777, mode);
                assert!(write_new(&file, b"replacement", mode).is_err());
                assert_eq!(std::fs::read(file).unwrap(), b"retained");
            }
            assert_eq!(
                public.metadata().unwrap().permissions().mode() & 0o7777,
                0o755
            );
            return;
        }
        if rustix::process::geteuid().as_raw() != 0 {
            assert!(
                make_directory(Path::new("/var/lib/hol-gauntlet-rust/non-root-test"), 0o755)
                    .is_err()
            );
            return;
        }
        // A separate process prevents changing the parallel test runner's umask.
        let root = tempfile::Builder::new()
            .prefix("umask-regression-")
            .tempdir_in("/var/lib/hol-gauntlet-rust")
            .unwrap();
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command.args(["--exact", "preparation::tests::private_worker_umask_preserves_explicit_public_and_private_modes", "--nocapture"])
            .env(CHILD, root.path());
        unsafe {
            command.pre_exec(|| {
                libc::umask(0o077);
                Ok(())
            });
        }
        assert!(command.status().unwrap().success());
    }
}
