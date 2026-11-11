use super::*;

fn inputs(f: &Fixture) -> (Value, Value) {
    let root = f.journal.path.parent().unwrap();
    let site = root.join("site-packages");
    let model = root.join("model");
    let socket = root.join("socket");
    for dir in [site.join("mlx_lm/models"), model.clone(), socket.clone()] {
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let python = root.join("mock-runtime/bin/python3.11");
    let stdlib = root.join("mock-runtime/lib/python3.11");
    for dir in [python.parent().unwrap().to_path_buf(), stdlib.clone()] {
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut paths = vec![python.clone()];
    for leaf in [
        "server.py",
        "generate.py",
        "utils.py",
        "tokenizer_utils.py",
        "sample_utils.py",
        "models/cache.py",
    ] {
        paths.push(site.join("mlx_lm").join(leaf));
    }
    for leaf in [
        "config.json",
        "tokenizer_config.json",
        "weights.safetensors",
    ] {
        paths.push(model.join(leaf));
    }
    let mut assets = serde_json::Map::new();
    for path in paths {
        std::fs::write(&path, b"mock").unwrap();
        std::fs::set_permissions(
            &path,
            std::fs::Permissions::from_mode(if path == python { 0o700 } else { 0o600 }),
        )
        .unwrap();
        assets.insert(
            path.to_str().unwrap().into(),
            json!({"sha256":sha(b"mock"),"bytes":4}),
        );
    }
    let producer = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
    let raw = std::fs::read(&producer).unwrap();
    let producer_sha = sha(&raw);
    assets.insert(
        producer.to_str().unwrap().into(),
        json!({"sha256":producer_sha,"bytes":raw.len()}),
    );
    let mut spec = f.intent.spec().clone();
    spec["schema"] = json!("hol-gauntlet-rust-provider-spec.v1");
    spec["python"] = json!(python);
    spec["site_packages"] = json!(site);
    spec["model_directory"] = json!(model);
    spec["socket_directory"] = json!(socket);
    spec["server_sha256"] = json!(sha(b"mock"));
    spec["producer_sha256"] = json!(producer_sha);
    spec["assets"] = Value::Object(assets);
    let auth = json!({"schema":"hol-gauntlet-rust-provider-source-authorization.v1","authority":"operator-approved-source-binding-preserve-retained-quota","source_sha":spec["source_sha"],"provider_job_id":spec["provider_job_id"],"profile":"feature-ai","provider_spec_sha256":sha(&bytes(&spec).unwrap()),"quota_root":spec["quota_root"],"quota_config_digest":spec["quota_config_digest"],"quota_allowance_digest":spec["quota_allowance_digest"],"model_identity_digest":spec["model_identity_digest"],"token_cap":spec["token_cap"],"retained_quota":f.intent.0["quota_at_prepare"],"job_tokens":200_000,"allowance_reset":false,"token_cap_increase":false});
    (spec, auth)
}
#[test]
fn normal_prepare_binds_history_progress_private_channel_and_one_use_dispatch() {
    let mut f = fixture();
    let (spec, auth) = inputs(&f);
    let lease = f.writer.reserve(4, 8, &"d".repeat(64), None).unwrap();
    f.writer.settle(&lease, 4, 1).unwrap();
    let before = f.intent.snapshot().unwrap();
    let prepared = prepare(
        &mut f.journal,
        &bytes(&spec).unwrap(),
        &bytes(&auth).unwrap(),
    )
    .unwrap();
    let digest = prepared["binding_sha256"].as_str().unwrap();
    assert_eq!(prepared["maximum_accounted_tokens"], 200_005);
    assert_eq!(prepared["inference_started"], false);
    assert_eq!(f.intent.snapshot().unwrap(), before);
    let binding = read_live_provider_binding(&f.journal.path, digest).unwrap();
    assert_eq!(binding["cells"], spec["cells"]);
    assert_eq!(binding["known_tokens_before"], 5);
    assert_eq!(
        binding["status_pins"]["profile"],
        "owned-mlx-rust-serial.v2"
    );
    assert!(binding.get("key").is_none());
    let args = vec![
        "read".into(),
        f.journal.path.to_str().unwrap().into(),
        digest.into(),
    ];
    assert_eq!(
        run_live_provider_command(&args).unwrap()["state"],
        "prepared"
    );
    assert!(read_live_provider_binding(&f.journal.path, &"0".repeat(64)).is_err());
    f.journal.put("provider-dispatch.json",&json!({"schema":"hol-gauntlet-rust-provider-dispatch.v1","binding_sha256":digest,"one_use":true,"owner_pid":1})).unwrap();
    let path = f.journal.path.clone();
    drop(f.journal);
    assert!(run_live_provider_command(&[
        "start".into(),
        path.to_str().unwrap().into(),
        digest.into()
    ])
    .is_err());
    assert_eq!(
        read_provider_quota_snapshot(
            Path::new(spec["quota_root"].as_str().unwrap()),
            f.writer.config_digest(),
            f.writer.allowance_digest()
        )
        .unwrap(),
        before
    );
}
#[test]
fn outside_authorization_substitution_refuses_before_private_quota_or_assets() {
    let mut f = fixture();
    let (spec, mut auth) = inputs(&f);
    auth["source_sha"] = json!("0".repeat(40));
    let before = f.intent.snapshot().unwrap();
    assert!(prepare(
        &mut f.journal,
        &bytes(&spec).unwrap(),
        &bytes(&auth).unwrap()
    )
    .is_err());
    assert!(!f.journal.exists("provider-intent.json").unwrap());
    assert_eq!(f.intent.snapshot().unwrap(), before);
}
#[test]
fn global_lifetime_blocks_alternate_journals_and_survives_owner_crash() {
    let mut f = fixture();
    let (spec, auth) = inputs(&f);
    let before = f.intent.snapshot().unwrap();
    let prepared = prepare(
        &mut f.journal,
        &bytes(&spec).unwrap(),
        &bytes(&auth).unwrap(),
    )
    .unwrap();
    let digest = prepared["binding_sha256"].as_str().unwrap();
    let mut opened = Journal::open(&f.journal.path).unwrap();
    let intent = Intent::load(&mut opened, digest).unwrap();
    let owner = lifetime::Lifetime::claim(&opened, &intent).unwrap();
    assert!(lifetime::available(&spec).is_err());
    drop(owner); // A crash releases flock, but never clears durable active state.
    let mut other = spec.clone();
    other["provider_job_id"] = json!("3".repeat(16));
    assert!(lifetime::available(&other).is_err());
    assert!(lifetime::Lifetime::claim(&opened, &intent).is_err());
    assert_eq!(relay::read(&opened, &intent).unwrap()["state"], "uncertain");
    assert_eq!(f.intent.snapshot().unwrap(), before);
}
#[test]
fn mock_verified_cleanup_releases_resource_but_never_rearms_approved_job() {
    let mut f = fixture();
    let (spec, auth) = inputs(&f);
    let prepared = prepare(
        &mut f.journal,
        &bytes(&spec).unwrap(),
        &bytes(&auth).unwrap(),
    )
    .unwrap();
    let digest = prepared["binding_sha256"].as_str().unwrap();
    let mut opened = Journal::open(&f.journal.path).unwrap();
    let intent = Intent::load(&mut opened, digest).unwrap();
    let owner = lifetime::Lifetime::claim(&opened, &intent).unwrap();
    opened.put("provider-terminal.json",&json!({"schema":"hol-gauntlet-rust-provider-terminal.v1","binding_sha256":digest,"state":"stopped","cleanup":{"owned_process_group_stopped":true,"child_reaped":true,"private_socket_removed":true},"qualification_eligible":false})).unwrap();
    owner.finish(&opened, &intent).unwrap();
    drop(owner);
    assert!(lifetime::available(&spec).is_err());
    let mut next = spec.clone();
    next["provider_job_id"] = json!("3".repeat(16));
    lifetime::available(&next).unwrap();
    let another = f
        .journal
        .path
        .parent()
        .unwrap()
        .join("another-private-journal");
    std::fs::create_dir(&another).unwrap();
    std::fs::set_permissions(&another, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(prepare(
        &mut Journal::open(&another).unwrap(),
        &bytes(&spec).unwrap(),
        &bytes(&auth).unwrap()
    )
    .is_err());
}
#[test]
fn private_channel_replacement_and_operational_asset_smuggling_fail_before_transport() {
    let mut f = fixture();
    let (mut spec, auth) = inputs(&f);
    let operational = f.journal.path.join("unrelated-worker-record.json");
    spec["assets"][operational.to_str().unwrap()] = json!({"sha256":"0".repeat(64),"bytes":1});
    assert!(assets::validate_scope(&spec).is_err());
    spec["assets"]
        .as_object_mut()
        .unwrap()
        .remove(operational.to_str().unwrap());
    let prepared = prepare(
        &mut f.journal,
        &bytes(&spec).unwrap(),
        &bytes(&auth).unwrap(),
    )
    .unwrap();
    let digest = prepared["binding_sha256"].as_str().unwrap();
    let mut opened = Journal::open(&f.journal.path).unwrap();
    let intent = Intent::load(&mut opened, digest).unwrap();
    let mut changed = opened.json("provider-channel.json").unwrap();
    changed["key"] = json!("0".repeat(64));
    std::fs::write(
        opened.path.join("provider-channel.json"),
        bytes(&changed).unwrap(),
    )
    .unwrap();
    assert!(http::client(&opened, &intent, "GET", "/v1/hol-gauntlet/status", None).is_err());
}
#[test]
fn numerical_inventory_covers_added_code_and_retains_directory_membership() {
    let f = fixture();
    let (spec, _auth) = inputs(&f);
    let captured = Assets::capture_spec(&spec).unwrap();
    let added = Path::new(spec["site_packages"].as_str().unwrap()).join("unreviewed.py");
    std::fs::write(&added, b"not executed").unwrap();
    std::fs::set_permissions(&added, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(captured.stable().is_err());
    assert!(Assets::capture_spec(&spec).is_err());
}
