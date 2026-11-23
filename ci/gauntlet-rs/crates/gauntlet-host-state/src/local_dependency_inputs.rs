//! One-use dependency capsule from an exact, already verified Git source graph.
//! No checkout, package import, installer, VM or provider starts on the host.

use crate::private_jobs::{child_directory, same_file, state_root};
use crate::verify_retained_source_archive_commit;
use rustix::fs::{
    fchmod, fstat, fsync, mkdirat, open, openat, statat, AtFlags, FileType, Mode, OFlags,
};
use rustix::process::geteuid;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::os::fd::OwnedFd;
use std::path::Path;
use std::time::Duration;

fn write_verified(directory: &OwnedFd, name: &str, bytes: &[u8]) -> Result<(), String> {
    let fd = openat(
        directory,
        name,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|e| e.to_string())?;
    let mut file = File::from(fd);
    file.write_all(bytes).map_err(|e| e.to_string())?;
    fchmod(&file, Mode::RUSR | Mode::WUSR).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    let before = fstat(&file).map_err(|e| e.to_string())?;
    if before.st_uid != geteuid().as_raw()
        || before.st_nlink != 1
        || before.st_mode & 0o7777 != 0o600
        || before.st_size as usize != bytes.len()
    {
        return Err("host capsule write custody differs".into());
    }
    file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    let mut hash = Sha256::new();
    std::io::copy(&mut file, &mut hash).map_err(|e| e.to_string())?;
    let after = fstat(&file).map_err(|e| e.to_string())?;
    let visible = statat(directory, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|e| e.to_string())?;
    if !same_file(&before, &after)
        || !same_file(&before, &visible)
        || hash.finalize()[..] != Sha256::digest(bytes)[..]
    {
        return Err("host capsule readback differs".into());
    }
    Ok(())
}

fn static_arm64(raw: &[u8]) -> bool {
    if raw.len() < 64
        || &raw[..4] != b"\x7fELF"
        || raw[4] != 2
        || raw[5] != 1
        || raw[6] != 1
        || raw[18..20] != [183, 0]
        || !matches!(u16::from_le_bytes(raw[16..18].try_into().unwrap()), 2 | 3)
        || u32::from_le_bytes(raw[20..24].try_into().unwrap()) != 1
        || u16::from_le_bytes(raw[52..54].try_into().unwrap()) != 64
    {
        return false;
    }
    let offset = u64::from_le_bytes(raw[32..40].try_into().unwrap());
    let size = u16::from_le_bytes(raw[54..56].try_into().unwrap()) as u64;
    let count = u16::from_le_bytes(raw[56..58].try_into().unwrap()) as u64;
    if offset < 64
        || size != 56
        || count == 0
        || count > 1024
        || offset
            .checked_add(size * count)
            .is_none_or(|end| end > raw.len() as u64)
    {
        return false;
    }
    let kinds = (0..count)
        .map(|index| {
            let begin = (offset + index * size) as usize;
            u32::from_le_bytes(raw[begin..begin + 4].try_into().unwrap())
        })
        .collect::<Vec<_>>();
    kinds.contains(&1) && !kinds.contains(&3)
}

fn exporter(path: &Path, expected: &str) -> Result<Vec<u8>, String> {
    if !path.is_absolute()
        || path.canonicalize().ok().as_deref() != Some(path)
        || expected.len() != 64
        || !expected
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("canonical exporter and exact SHA-256 required".into());
    }
    let fd = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| "exporter input unavailable")?;
    let before = fstat(&fd).map_err(|e| e.to_string())?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != geteuid().as_raw()
        || before.st_nlink != 1
        || before.st_mode & 0o7022 != 0
        || !(64..=16 * 1024 * 1024).contains(&before.st_size)
    {
        return Err("owned ordinary exporter required".into());
    }
    let mut file = File::from(fd);
    let mut raw = Vec::new();
    (&mut file)
        .take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut raw)
        .map_err(|e| e.to_string())?;
    let after = fstat(&file).map_err(|e| e.to_string())?;
    let visible =
        statat(rustix::fs::CWD, path, AtFlags::SYMLINK_NOFOLLOW).map_err(|e| e.to_string())?;
    if !same_file(&before, &after)
        || !same_file(&before, &visible)
        || raw.len() as i64 != before.st_size
        || format!("{:x}", Sha256::digest(&raw)) != expected
        || !static_arm64(&raw)
    {
        return Err("exporter changed, is not static ARM64 ELF, or differs from pin".into());
    }
    Ok(raw)
}

/// Add a distinct one-use capsule under an existing source slot. The source
/// archive/ref/graph is independently reverified before any capsule mutation.
pub fn prepare_local_dependency_inputs(
    state: &Path,
    job: &str,
    source_archive: &str,
    repository: &Path,
    source: &str,
    exporter_path: &Path,
    exporter_sha256: &str,
) -> Result<Value, String> {
    verify_retained_source_archive_commit(
        state,
        job,
        source_archive,
        source,
        &format!("refs/heads/local-{source}"),
    )
    .map_err(|e| e.to_string())?;
    let owner = geteuid().as_raw();
    let root = state_root(state, owner).map_err(|e| e.to_string())?;
    let private = child_directory(&root, "private", owner).map_err(|e| e.to_string())?;
    let builds = child_directory(&private, "local-builds", owner).map_err(|e| e.to_string())?;
    let slot = child_directory(&builds, job, owner).map_err(|e| e.to_string())?;
    match statat(&slot, "dependency-inputs", AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => {}
        _ => return Err("host dependency input slot already consumed".into()),
    }
    let [project, lock] =
        crate::local_source_prepare::dependency_project_inputs(repository, source)?;
    let binary = exporter(exporter_path, exporter_sha256)?;
    let hashes = [&project, &lock, &binary].map(|bytes| format!("{:x}", Sha256::digest(bytes)));
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, bytes) in ["pyproject.toml", "uv.lock", "gauntlet-dependency-exporter"]
        .into_iter()
        .zip([project, lock, binary])
    {
        zip.start_file(
            name,
            zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated)
                .unix_permissions(0o644),
        )
        .map_err(|e| e.to_string())?;
        zip.write_all(&bytes).map_err(|e| e.to_string())?;
    }
    let raw = zip.finish().map_err(|e| e.to_string())?.into_inner();
    if raw.is_empty() || raw.len() > 32 * 1024 * 1024 {
        return Err("bounded dependency capsule required".into());
    }
    let report = json!({"schema":"hol-gauntlet-host-dependency-inputs.v1","job_id":job,"source_sha":source,"source_archive_sha256":source_archive,
        "payload_sha256":format!("{:x}",Sha256::digest(&raw)),"payload_bytes":raw.len(),"pyproject_sha256":hashes[0],"uv_lock_sha256":hashes[1],"exporter_sha256":hashes[2],"git_graph_verified":true,"execution_eligible":false,"model_requests":0});
    mkdirat(
        &slot,
        "dependency-inputs",
        Mode::RUSR | Mode::WUSR | Mode::XUSR,
    )
    .map_err(|_| "host dependency input slot consumed or creation failed")?;
    fsync(&slot).map_err(|e| e.to_string())?;
    let output = child_directory(&slot, "dependency-inputs", owner).map_err(|e| e.to_string())?;
    fchmod(&output, Mode::RUSR | Mode::WUSR | Mode::XUSR).map_err(|e| e.to_string())?;
    write_verified(&output, "inputs.zip", &raw)?;
    verify_retained_source_archive_commit(
        state,
        job,
        source_archive,
        source,
        &format!("refs/heads/local-{source}"),
    )
    .map_err(|e| e.to_string())?;
    write_verified(
        &output,
        "preparation.v1.json",
        &gauntlet_contracts::canonicalize(report.to_string().as_bytes())
            .map_err(|e| e.to_string())?,
    )?;
    fsync(&output).map_err(|e| e.to_string())?;
    fsync(&slot).map_err(|e| e.to_string())?;
    Ok(report)
}

fn capsule(args: &[String]) -> Result<(Value, Vec<u8>), String> {
    use crate::private_jobs::{read_dependency_capsule, read_regular_bytes};
    let owner = geteuid().as_raw();
    let root = state_root(Path::new(&args[1]), owner).map_err(|e| e.to_string())?;
    let private = child_directory(&root, "private", owner).map_err(|e| e.to_string())?;
    let builds = child_directory(&private, "local-builds", owner).map_err(|e| e.to_string())?;
    let slot = child_directory(&builds, &args[5], owner).map_err(|e| e.to_string())?;
    let inputs = child_directory(&slot, "dependency-inputs", owner).map_err(|e| e.to_string())?;
    let raw =
        read_regular_bytes(&inputs, "preparation.v1.json", owner).map_err(|e| e.to_string())?;
    let proof: Value =
        serde_json::from_slice(&raw).map_err(|_| "dependency preparation invalid")?;
    let payload = read_dependency_capsule(&inputs, owner).map_err(|e| e.to_string())?;
    let hex = |s: &str| s.len() == 64 && s.bytes().all(|b| b"0123456789abcdef".contains(&b));
    if ["pyproject_sha256", "uv_lock_sha256", "exporter_sha256"]
        .iter()
        .any(|k| !proof[k].as_str().is_some_and(hex))
        || gauntlet_contracts::canonicalize(&raw).map_err(|e| e.to_string())? != raw
        || proof
            != json!({"schema":"hol-gauntlet-host-dependency-inputs.v1",
            "job_id":args[5],"source_sha":args[6],"source_archive_sha256":args[7],
            "payload_sha256":args[8],"payload_bytes":payload.len(),
            "pyproject_sha256":proof["pyproject_sha256"],"uv_lock_sha256":proof["uv_lock_sha256"],
            "exporter_sha256":proof["exporter_sha256"],"git_graph_verified":true,
            "execution_eligible":false,"model_requests":0})
        || payload.is_empty()
        || format!("{:x}", Sha256::digest(&payload)) != args[8]
    {
        return Err("dependency capsule differs from outside source or payload pins".into());
    }
    Ok((proof, payload))
}

/// Stream one inert capsule through the pinned original Lima instance. An
/// uncertain return consumes this dispatch; it never authorizes a second send.
pub(crate) fn transfer(args: &[String]) -> Result<Value, String> {
    use crate::native_operation::context::{Lima, TransportContext};
    use crate::private_jobs::{read_regular_bytes, write_private_once};
    use gauntlet_contracts::canonicalize;
    let read = args.first().is_some_and(|s| s == "transfer-read");
    let hex = |s: &str, n| s.len() == n && s.bytes().all(|b| b"0123456789abcdef".contains(&b));
    if !matches!(args.len(), 12 | 13)
        || !matches!(args[0].as_str(), "transfer" | "transfer-read")
        || (read && args.len() != 13)
        || !hex(&args[5], 16)
        || !hex(&args[6], 40)
        || [4, 7, 8, 9].iter().any(|i| !hex(&args[*i], 64))
        || (args.len() == 13 && !hex(&args[12], 64))
    {
        return Err("complete dependency transfer identity required".into());
    }
    verify_retained_source_archive_commit(
        Path::new(&args[1]),
        &args[5],
        &args[7],
        &args[6],
        &format!("refs/heads/local-{}", args[6]),
    )
    .map_err(|e| e.to_string())?;
    let (proof, payload) = capsule(args)?;
    let context =
        TransportContext::from_paths(Path::new(&args[10]), Path::new(&args[11]), &args[3])?;
    let mut lima = Lima::open_pinned("/opt/homebrew/bin/limactl", &args[4], context.value())?;
    let journal = crate::HostCandidateBuildPinJournal::open(Path::new(&args[2]))
        .map_err(|e| e.to_string())?;
    let dispatch_name = format!("{}.dependency-input-dispatch.json", args[5]);
    let result_name = format!("{}.dependency-input-result.json", args[5]);
    let absent = || -> Result<(), String> {
        match statat(
            journal.directory().map_err(|e| e.to_string())?,
            &result_name,
            AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Err(rustix::io::Errno::NOENT) => Ok(()),
            _ => Err("dependency transfer result exists or is uncertain".into()),
        }
    };
    if !read {
        absent()?;
    }
    let bounded = args.len() == 13;
    let mut dispatch_value = json!({"schema":"hol-gauntlet-host-dependency-input-dispatch.v1",
        "job_id":args[5],"source_sha":args[6],"source_archive_sha256":args[7],
        "payload_sha256":args[8],"payload_bytes":payload.len(),"worker_generation":args[9],
        "preparation_sha256":format!("{:x}",Sha256::digest(canonicalize(proof.to_string().as_bytes()).map_err(|e| e.to_string())?)),
        "lima_sha256":args[4],"transport_context":context.value(),"retry_allowed":false,
        "execution_eligible":false});
    if bounded {
        dispatch_value["schema"] = json!("hol-gauntlet-host-dependency-input-dispatch.v2");
        dispatch_value["storage_receipt_sha256"] = json!(args[12]);
    }
    let dispatch =
        canonicalize(dispatch_value.to_string().as_bytes()).map_err(|e| e.to_string())?;
    if !read {
        write_private_once(
            journal.directory().map_err(|e| e.to_string())?,
            &dispatch_name,
            &dispatch,
        )?;
    }
    let stable = || -> Result<(), String> {
        if read_regular_bytes(
            journal.directory().map_err(|e| e.to_string())?,
            &dispatch_name,
            geteuid().as_raw(),
        )
        .map_err(|e| e.to_string())?
            != dispatch
            || capsule(args)? != (proof.clone(), payload.clone())
        {
            return Err(
                "dependency dispatch or input custody changed; preserve consumed job".into(),
            );
        }
        TransportContext::parse(context.value())?;
        Ok(())
    };
    stable()?;
    if !read {
        absent()?;
    }
    let mut command = lima.command(&args[3])?;
    command
        .arg(format!(
            "/opt/hol-gauntlet/rust-native-dependency-worker-{}",
            args[9]
        ))
        .args([
            if read {
                "--read-captured-dependency-inputs-v2"
            } else if bounded {
                "--capture-dependency-inputs-v2"
            } else {
                "--capture-dependency-inputs"
            },
            &args[5],
            &args[6],
            &args[7],
            &args[8],
            &payload.len().to_string(),
            proof["pyproject_sha256"].as_str().unwrap(),
            proof["uv_lock_sha256"].as_str().unwrap(),
            proof["exporter_sha256"].as_str().unwrap(),
            &args[9],
        ]);
    if bounded {
        command.arg(&args[12]);
    }
    let raw = crate::stream_process::run_streamed_command(
        command,
        if read { &[] } else { &payload },
        Duration::from_secs(180),
        4096,
    )
    .map_err(|_| {
        if read {
            "dependency capture read unavailable; preserve dispatch and never resend the capsule"
        } else {
            "dependency transfer uncertain; dispatch consumed, reconcile without retry"
        }
    })?;
    lima.recheck()?;
    stable()?;
    let frame = raw
        .strip_suffix(b"\n")
        .filter(|v| !v.is_empty() && !v.contains(&b'\n'))
        .ok_or("one dependency capture frame required; dispatch consumed")?;
    let response: Value =
        serde_json::from_slice(frame).map_err(|_| "dependency capture JSON invalid")?;
    let mut expected = json!({"schema":"hol-gauntlet-native-dependency-inputs.v1",
        "job_id":args[5],"source_sha":args[6],"source_archive_sha256":args[7],
        "payload_sha256":args[8],"payload_bytes":payload.len(),"pyproject_sha256":proof["pyproject_sha256"],
        "uv_lock_sha256":proof["uv_lock_sha256"],"exporter_sha256":proof["exporter_sha256"],
        "worker_generation":args[9],"builder_executed":false,"execution_eligible":false,"model_requests":0});
    if bounded {
        expected["schema"] = json!("hol-gauntlet-native-dependency-inputs.v2");
        expected["storage_receipt_sha256"] = json!(args[12]);
    }
    if canonicalize(frame).map_err(|e| e.to_string())? != frame || response != expected {
        return Err("dependency capture differs from outside pins; dispatch consumed".into());
    }
    let result = json!({"schema":"hol-gauntlet-host-dependency-input-transfer.v1",
        "capture":response,"dispatch_sha256":format!("{:x}",Sha256::digest(&dispatch)),
        "source_graph_verified":true,"candidate_executed":false,"execution_eligible":false});
    let result_bytes = canonicalize(result.to_string().as_bytes()).map_err(|e| e.to_string())?;
    let directory = journal.directory().map_err(|e| e.to_string())?;
    match statat(directory, &result_name, AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => {
            write_private_once(directory, &result_name, &result_bytes)?
        }
        Ok(_)
            if read
                && read_regular_bytes(directory, &result_name, geteuid().as_raw())
                    .map_err(|e| e.to_string())?
                    == result_bytes => {}
        _ => return Err("dependency transfer result exists, differs, or is uncertain".into()),
    }
    stable()?;
    Ok(result)
}
