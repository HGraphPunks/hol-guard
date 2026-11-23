//! Exact source/wheel setup inside the disposable unprivileged feature box.
use super::feature_executor_files as files;
use super::feature_executor_process::{environment, execute};
use super::feature_executor_scope::FeatureBox;
use gauntlet_contracts::{canonicalize, FeatureExecutorSpec};
use serde_json::Value;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

pub(super) const SOURCE: &str = "/work/source";
pub(super) const RUNTIME: &str = "/work/source/.venv/lib/python3.12/site-packages/codex_plugin_scanner/_native/hol-guard-runtime";
pub(super) const SOURCE_RUNTIME: &str = "/work/verified-native-runtime";
pub(super) const COMPILER: &str = "/work/source/rust/target/release/guard-command-source";

pub(super) struct Prepared {
    pub(super) wheel: String,
    pub(super) compiler_sha256: String,
}

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|s| (*s).into()).collect()
}

fn checked(
    owner: &FeatureBox,
    program: &str,
    argv: &[&str],
    cwd: &str,
    label: &str,
    seconds: u64,
    capture: bool,
) -> Result<Vec<u8>, String> {
    let result = execute(
        owner,
        program,
        &args(argv),
        cwd,
        &environment(),
        label,
        seconds,
        capture,
    )?;
    if result.code != 0 {
        return Err(format!(
            "fixed feature preparation failed: {label}, exit {}",
            result.code
        ));
    }
    Ok(result.stdout)
}

pub(super) fn native_pin(spec: &FeatureExecutorSpec, path: &str) -> Result<(), String> {
    if files::hash(Path::new(path), 64 * 1024 * 1024)? != spec.text("native_sha256") {
        return Err("feature Native bytes differ from outside build pin".into());
    }
    Ok(())
}

pub(super) fn install(
    owner: &FeatureBox,
    spec: &FeatureExecutorSpec,
    wheel: &str,
    label: &str,
) -> Result<(), String> {
    if files::hash(Path::new(wheel), 256 * 1024 * 1024)? != spec.text("wheel_sha256") {
        return Err("feature wheel changed before installation".into());
    }
    checked(
        owner,
        "/usr/local/bin/uv",
        &[
            "pip",
            "install",
            "--python",
            ".venv/bin/python",
            "--no-deps",
            wheel,
        ],
        SOURCE,
        label,
        120,
        false,
    )?;
    native_pin(spec, RUNTIME)
}

fn extract_wheel(spec: &FeatureExecutorSpec) -> Result<String, String> {
    let mut input = files::root_input(
        Path::new("/input/candidate.zip"),
        257 * 1024 * 1024,
        spec.text("candidate_archive_sha256"),
    )?;
    let declared =
        crate::inspect_candidate_archive(&mut input, spec.text("source_sha"), spec.text("version"))
            .map_err(|e| e.to_string())?;
    if declared.wheel_sha256 != spec.text("wheel_sha256")
        || declared.native_sha256_claim != spec.text("native_sha256")
    {
        return Err("feature artifact differs from outside wheel/Native pins".into());
    }
    let wheel = format!("/work/{}", declared.wheel);
    let mut archive = zip::ZipArchive::new(input).map_err(|e| e.to_string())?;
    let entry = archive
        .by_name(&declared.wheel)
        .map_err(|e| e.to_string())?;
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&wheel)
        .map_err(|e| e.to_string())?;
    let count = std::io::copy(&mut entry.take(256 * 1024 * 1024 + 1), &mut output)
        .map_err(|e| e.to_string())?;
    if count != declared.wheel_bytes {
        return Err("feature wheel extraction length differs".into());
    }
    output.flush().map_err(|e| e.to_string())?;
    output.sync_all().map_err(|e| e.to_string())?;
    if files::hash(Path::new(&wheel), 256 * 1024 * 1024)? != spec.text("wheel_sha256") {
        return Err("extracted feature wheel differs".into());
    }
    Ok(wheel)
}

pub(super) fn prepare(owner: &FeatureBox, spec: &FeatureExecutorSpec) -> Result<Prepared, String> {
    // Exercise the same-UID kernel boundary before any candidate instruction.
    // This fixed image-Python adapter probes only this container's PID 1; it
    // does not read another process's data or inherit the owner stdout FD.
    let isolation = "import os; assert os.getpid() != 1\nfor name,flags in [('/proc/1/fd/1',os.O_WRONLY),('/proc/1/mem',os.O_RDWR)]:\n try:\n  fd=os.open(name,flags|os.O_CLOEXEC)\n except PermissionError:\n  continue\n else:\n  os.close(fd); raise AssertionError('feature controller channel is accessible')\nprint('feature-controller-fd-and-memory-denied')";
    let probe = checked(
        owner,
        "/usr/local/bin/gauntlet-python",
        &["-I", "-B", "-c", isolation],
        "/work",
        "controller-isolation",
        20,
        true,
    )?;
    if probe != b"feature-controller-fd-and-memory-denied\n" {
        return Err("feature controller isolation probe differs".into());
    }
    // These fixed mounts are admitted and pinned by the outside Root owner.
    // Unpacking, installation and every candidate instruction stay UID 65532.
    let source = files::root_input(
        Path::new("/input/source.tar.gz"),
        512 * 1024 * 1024,
        spec.text("source_archive_sha256"),
    )?;
    drop(source);
    let node = Path::new("/usr/local/bin/node");
    let meta = node.symlink_metadata().map_err(|e| e.to_string())?;
    if !meta.is_file()
        || meta.uid() != 0
        || meta.gid() != 0
        || meta.nlink() != 1
        || meta.mode() & 0o6022 != 0
        || files::hash(node, 256 * 1024 * 1024)? != spec.text("node_sha256")
    {
        return Err("immutable pinned feature Node required".into());
    }
    std::fs::create_dir("/work/home").map_err(|e| e.to_string())?;
    checked(
        owner,
        "/usr/bin/tar",
        &[
            "--extract",
            "--gzip",
            "--file=/input/source.tar.gz",
            "--directory=/work",
            "--no-same-owner",
            "--no-same-permissions",
        ],
        "/work",
        "source-unpack",
        120,
        false,
    )?;
    checked(
        owner,
        "/usr/bin/git",
        &[
            "clone",
            "--no-hardlinks",
            "--no-checkout",
            "/work/repository.git",
            SOURCE,
        ],
        "/work",
        "source-clone",
        120,
        false,
    )?;
    checked(
        owner,
        "/usr/bin/git",
        &["checkout", "--detach", spec.text("source_sha")],
        SOURCE,
        "source-checkout",
        120,
        false,
    )?;
    let head = checked(
        owner,
        "/usr/bin/git",
        &["rev-parse", "HEAD"],
        SOURCE,
        "source-head",
        10,
        true,
    )?;
    if std::str::from_utf8(&head)
        .map_err(|e| e.to_string())?
        .trim()
        != spec.text("source_sha")
    {
        return Err("feature checkout differs from built source".into());
    }
    let wheel = extract_wheel(spec)?;
    checked(
        owner,
        "/usr/local/bin/uv",
        &[
            "sync",
            "--frozen",
            "--no-dev",
            "--group",
            "ci-test",
            "--no-install-project",
            "--python",
            "3.12",
        ],
        SOURCE,
        "dependencies",
        600,
        false,
    )?;
    install(owner, spec, &wheel, "initial-install")?;
    let raw = checked(
        owner,
        RUNTIME,
        &["capabilities", "--json"],
        SOURCE,
        "native-capabilities",
        20,
        true,
    )?;
    let canonical = canonicalize(&raw).map_err(|e| e.to_string())?;
    let cap: Value = serde_json::from_slice(&canonical).map_err(|e| e.to_string())?;
    if cap["build_sha"] != spec.text("source_sha") || cap["runtime_version"] != spec.text("version")
    {
        return Err("feature Native capability provenance differs".into());
    }
    let node_version = checked(
        owner,
        "/usr/local/bin/node",
        &["--version"],
        SOURCE,
        "node-version",
        10,
        true,
    )?;
    if node_version != b"v22.22.2\n" {
        return Err("feature Node version differs".into());
    }
    let installed = Path::new(
        "/work/source/.venv/lib/python3.12/site-packages/codex_plugin_scanner/guard/contracts/data",
    );
    let overlay = Path::new("/work/source/src/codex_plugin_scanner/guard/contracts/data");
    files::copy_tree(installed, overlay)?;
    for name in [
        "extensions/command-catalog.v1.json",
        "extensions/native-command-program.v1.json",
    ] {
        files::hash(&overlay.join(name), 16 * 1024 * 1024)?;
    }
    files::copy(
        Path::new(RUNTIME),
        Path::new(SOURCE_RUNTIME),
        64 * 1024 * 1024,
        0o555,
    )?;
    native_pin(spec, SOURCE_RUNTIME)?;
    checked(
        owner,
        "/usr/local/bin/uv",
        &[
            "pip",
            "uninstall",
            "--python",
            ".venv/bin/python",
            "hol-guard",
        ],
        SOURCE,
        "source-uninstall",
        120,
        false,
    )?;
    let absent = "import importlib.metadata as m; assert not any(d.metadata[\"Name\"].lower().replace(\"_\", \"-\") == \"hol-guard\" for d in m.distributions())";
    checked(
        owner,
        "/work/source/.venv/bin/python",
        &["-I", "-B", "-c", absent],
        SOURCE,
        "source-distribution-absent",
        20,
        false,
    )?;
    checked(
        owner,
        "/usr/local/cargo/bin/cargo",
        &[
            "build",
            "--locked",
            "--release",
            "--manifest-path",
            "rust/Cargo.toml",
            "-p",
            "guard-command",
            "--bin",
            "guard-command-source",
        ],
        SOURCE,
        "source-compiler",
        1800,
        false,
    )?;
    let compiler_sha256 = files::hash(Path::new(COMPILER), 64 * 1024 * 1024)?;
    let meta = Path::new(COMPILER)
        .symlink_metadata()
        .map_err(|e| e.to_string())?;
    if meta.mode() & 0o111 == 0 {
        return Err("feature source compiler is not executable".into());
    }
    Ok(Prepared {
        wheel,
        compiler_sha256,
    })
}
