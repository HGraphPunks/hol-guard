//! Fixed failure archive, original file custody and historical cleanup observations.
use super::super::{artifact, bytes, receipt, sha, Intent, Journal, Value, EXPORT, LIMIT, RECEIPT};
use super::{base, exact, parse, require, stable, text};
use serde_json::json;
pub(in crate::native_operation::failure) const MEMBERS: [&str; 21] = [
    "worker/started.json",
    "worker/controller-key.json",
    "worker/running.json",
    "worker/terminal.json",
    "worker/report.json",
    "native.stdout",
    "native.stderr",
    "preparation.json",
    "initialization.json",
    "declaration.json",
    "cell/native-rootfs.v1.json",
    "cell/native-supervisor.v1.json",
    "cell/system.json",
    "cell/runtime.json",
    "cell/task-mounts.json",
    "cell/native-image-events.v1.jsonl",
    "cell/native-supervisor-events.v1.jsonl",
    "cell/native-cell.apparmor",
    "cell/cell-artifact-manifest.json",
    "cell/native-wire.v1.json",
    "results.sha256.json",
];
pub(in crate::native_operation::failure) fn archive(
    j: &Journal,
    i: &Intent,
    f: &Value,
    e: &Value,
    raw: &[u8],
) -> Result<(), String> {
    require(
        raw.len() <= LIMIT
            && e["receipt"]["archive_bytes"] == raw.len()
            && e["receipt"]["archive_sha256"] == sha(raw),
    )?;
    let files = crate::native_diagnostic_archive::members(raw)?;
    require(files.len() == MEMBERS.len() && MEMBERS.iter().all(|n| files.contains_key(*n)))?;
    let manifest = &files["results.sha256.json"];
    require(e["receipt"]["manifest_sha256"] == sha(manifest))?;
    let v = parse(manifest)?;
    let frame = parse(&j.read(i.job(), "return")?)?;
    let r = &frame["report"];
    let mut expected = base(f, "hol-gauntlet-native-readonly-failure-evidence.v1");
    for (k, value) in [
        ("status", json!("controller-failed-before-report")),
        ("exit_code", r["exit_code"].clone()),
        ("controller", r["controller"].clone()),
        ("prelaunch", f["prelaunch"].clone()),
        ("host_pin_sha256", f["host_pin_sha256"].clone()),
        ("quiescent", v["quiescent"].clone()),
        ("files", v["files"].clone()),
        ("filesystem", v["filesystem"].clone()),
        ("execution_eligible", json!(false)),
        ("guard_causality_verified", json!(false)),
        ("model_requests", Value::Null),
        ("qualification_eligible", json!(false)),
    ] {
        expected[k] = value;
    }
    require(
        v == expected
            && bytes(&v)? == *manifest
            && v["files"].as_object().is_some_and(|o| o.len() == 20)
            && v["filesystem"].as_object().is_some_and(|o| o.len() == 20),
    )?;
    for (name, raw) in files
        .iter()
        .filter(|(n, _)| n.as_str() != "results.sha256.json")
    {
        let mode = if name == "cell/native-cell.apparmor" {
            0o400
        } else if name.starts_with("cell/") && !name.ends_with(".jsonl") {
            0o444
        } else {
            0o600
        };
        let meta = &v["filesystem"][name];
        require(
            v["files"][name] == json!({"bytes":raw.len(),"sha256":sha(raw)})
                && meta.as_object().is_some_and(|o| o.len() == 11)
                && meta["bytes"] == raw.len()
                && meta["links"] == 1
                && meta["uid"] == 0
                && meta["gid"] == 0
                && meta["mode"] == mode
                && ["device", "inode"]
                    .iter()
                    .all(|k| meta[*k].as_u64().is_some())
                && ["mtime", "mtime_nsec", "ctime", "ctime_nsec"]
                    .iter()
                    .all(|k| meta[*k].as_i64().is_some()),
        )?;
    }
    for (member, key) in [
        ("worker/started.json", "started"),
        ("worker/controller-key.json", "controller_key_pin"),
        ("worker/terminal.json", "terminal"),
        ("worker/report.json", "report"),
    ] {
        require(files[member] == bytes(&frame[key])?)?;
    }
    for (member, pin) in [
        ("preparation.json", "preparation_sha256"),
        ("declaration.json", "deployment_digest"),
        ("initialization.json", "initialization_sha256"),
    ] {
        require(sha(&files[member]) == text(f, pin)?)?;
    }
    require(
        files["native.stdout"].is_empty()
            && files["native.stderr"].len() <= 1024 * 1024
            && sha(&files["native.stderr"]) == r["controller_stderr_sha256"],
    )?;
    let running = parse(&files["worker/running.json"])?;
    require(
        running["schema"] == "hol-gauntlet-worker-running.v1"
            && running["source_sha"] == f["source_sha"]
            && running["job_id"] == f["job_id"]
            && running["deployment_digest"] == f["deployment_digest"]
            && running["worker_generation"] == f["original_worker_generation"]
            && running["started_marker_sha256"] == f["prelaunch"]["started_marker_sha256"]
            && running["pid"] == r["controller"]["pid"]
            && running["process_start_ticks"] == r["controller"]["start_ticks"],
    )?;
    quiescent(&v["quiescent"], &files)?;
    stable(j, i, f)
}
fn quiescent(q: &Value, files: &std::collections::BTreeMap<String, Vec<u8>>) -> Result<(), String> {
    require(exact(
        q,
        &[
            "image_events_sha256",
            "supervisor_events_sha256",
            "rootfs_declaration_sha256",
            "supervisor_declaration_sha256",
            "profile",
            "product_cgroup_absent",
            "product_slice_absent",
            "rootfs_mount_absent",
            "apparmor_profile_absent",
            "runtime_tree_digest",
            "image_id",
            "startup_error",
            "recorded_cleanup_failures",
            "idmap_runtime",
            "product_unit_absent",
        ],
    ))?;
    for k in [
        "product_cgroup_absent",
        "product_slice_absent",
        "rootfs_mount_absent",
        "apparmor_profile_absent",
        "product_unit_absent",
    ] {
        require(q[k] == true)?;
    }
    for (k, n) in [
        ("image_events_sha256", "cell/native-image-events.v1.jsonl"),
        (
            "supervisor_events_sha256",
            "cell/native-supervisor-events.v1.jsonl",
        ),
        ("rootfs_declaration_sha256", "cell/native-rootfs.v1.json"),
        (
            "supervisor_declaration_sha256",
            "cell/native-supervisor.v1.json",
        ),
    ] {
        require(q[k] == sha(&files[n]))?;
    }
    let prep = parse(&files["preparation.json"])?;
    let rootfs = parse(&files["cell/native-rootfs.v1.json"])?;
    require(
        q["runtime_tree_digest"] == prep["runtime_tree_digest"]
            && q["image_id"] == prep["image_id"]
            && q["idmap_runtime"] == rootfs["idmap_runtime"]
            && matches!(
                q["idmap_runtime"].as_str(),
                Some("ubuntu2404-product-v1" | "ubuntu2404-controller-v1")
            )
            && q["startup_error"] == "product management pipe exited before ready marker",
    )?;
    let raw = &files["cell/native-supervisor-events.v1.jsonl"];
    require(raw.ends_with(b"\n"))?;
    let mut previous = "0".repeat(64);
    let mut failures = Vec::new();
    let mut prepared = 0;
    let mut startup = 0;
    let mut recorder = 0;
    let mut pipe = 0;
    let mut image = 0;
    for (sequence, line) in raw[..raw.len() - 1].split(|b| *b == b'\n').enumerate() {
        require(sequence < 4096 && line.len() <= 256 * 1024)?;
        let event = parse(line)?;
        require(
            bytes(&event)? == line
                && exact(
                    &event,
                    &["schema", "sequence", "previous_sha256", "kind", "data"],
                )
                && event["schema"] == "hol-gauntlet-cell-event.v1"
                && event["sequence"] == sequence
                && event["previous_sha256"] == previous,
        )?;
        previous = sha(line);
        match event["kind"].as_str() {
            Some("prepared") if sequence == 0 => {
                prepared += 1;
                require(event["data"]["profile"] == q["profile"])?;
            }
            Some("image-interpreter-pinned" | "private-parent-mount-namespace") if startup == 0 => {
            }
            Some("startup-failure") if startup == 0 => {
                require(
                    event["data"]
                        == json!({"error":"product management pipe exited before ready marker"}),
                )?;
                startup += 1;
            }
            Some("cell-stderr") if startup == 1 => {}
            Some("process-events-closed")
                if startup == 1 && recorder == 0 && failures.is_empty() =>
            {
                require(
                    event["data"]
                        == json!({"available":false,"error":"required process recorder was not established","schema":"hol-gauntlet-native-process-recorder.v1"}),
                )?;
                recorder += 1;
            }
            Some("native-pipe-owner-terminal")
                if recorder == 1 && pipe == 0 && failures.is_empty() =>
            {
                require(
                    event["data"]
                        == json!({"available":false,"error":"Native pipe owner was not established","execution_eligible":false}),
                )?;
                pipe += 1;
            }
            Some("terminal-cleanup") if startup == 1 && recorder == 1 && pipe == 1 => {
                let d = &event["data"];
                let v = &d["failures"];
                require(
                    exact(d, &["cgroup_absent", "rootfs_mount_absent", "failures"])
                        && d["cgroup_absent"] == true
                        && d["rootfs_mount_absent"] == true
                        && v.as_array().is_some_and(|a| {
                            a.iter().all(|s| s.as_str().is_some_and(|s| !s.is_empty()))
                        }),
                )?;
                failures.push(v.clone());
            }
            Some("rust-image-cleanup") if !failures.is_empty() => {
                require(
                    event["data"] == json!({"image_mount_absent":true,"active_lease_removed":true}),
                )?;
                image += 1;
            }
            _ => return Err("readonly failure reached a gate or has unknown observations".into()),
        }
    }
    require(
        prepared == 1
            && startup == 1
            && recorder == 1
            && pipe == 1
            && image > 0
            && !failures.is_empty()
            && q["recorded_cleanup_failures"] == Value::Array(failures),
    )
}

pub(in crate::native_operation::failure) fn recover(
    j: &Journal,
    i: &Intent,
    f: &Value,
    e: &Value,
) -> Result<bool, String> {
    for n in 1..=4 {
        let suffix = format!("readonly-failure-download-attempt-{n:04}");
        if j.absent(i.job(), &suffix)? {
            continue;
        }
        let raw = j.read(i.job(), &suffix)?;
        let a = parse(&raw)?;
        let operation = text(&a, "operation")?;
        require(
            matches!(
                operation,
                "failure-download" | "failure-download-read" | "failure-download-resume"
            ) && a
                == json!({"schema":"hol-gauntlet-host-native-readonly-failure-attempt.v1","failure_intent_sha256":sha(&bytes(f)?),"attempt":n,"operation":operation})
                && bytes(&a)? == raw,
        )?;
        let name = super::archive_name(i.job(), n);
        match rustix::fs::statat(
            &j.root,
            name.as_str(),
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Err(rustix::io::Errno::NOENT) => continue,
            Err(e) => return Err(e.to_string()),
            Ok(_) => {}
        }
        let mut h = artifact::open_private_archive(j, name)?;
        let actual = h.facts["bytes"]
            .as_u64()
            .ok_or("failure file bytes absent")?;
        let expected = e["receipt"]["archive_bytes"]
            .as_u64()
            .ok_or("failure export bytes absent")?;
        if actual < expected {
            continue;
        }
        require(actual == expected)?;
        h.verify(j, text(&e["receipt"], "archive_sha256")?)?;
        let raw = crate::native_diagnostic_archive::read_stable(
            &j.path.join(&h.name),
            text(&e["receipt"], "archive_sha256")?,
        )?;
        archive(j, i, f, e, &raw)?;
        h.finish(j, text(&e["receipt"], "archive_sha256")?)?;
        let r = receipt(f, e, &h)?;
        j.retain(i.job(), EXPORT, &bytes(e)?)?;
        j.write(i.job(), RECEIPT, &bytes(&r)?)?;
        return Ok(true);
    }
    Ok(false)
}
