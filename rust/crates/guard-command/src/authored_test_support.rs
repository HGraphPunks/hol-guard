//! Full authored-library fixtures, compiled only by tests; never resident inputs.
use crate::native_command_program::{source, NativeCommandProgram};
use serde_json::{json, Value};
use std::{
    fs,
    path::PathBuf,
    sync::{Arc, OnceLock},
};

pub(crate) fn sources() -> Vec<(Value, Vec<u8>)> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let mut result = Vec::new();
    for (directory, kind) in [("command-sources", "command"), ("mcp-servers", "mcp")] {
        let mut paths: Vec<_> = fs::read_dir(root.join("contributions").join(directory))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.extension().is_some_and(|value| value == "json")
                    && path.file_name().unwrap() != "migration-manifest.json"
            })
            .collect();
        paths.sort();
        for path in paths {
            let bytes = fs::read(&path).unwrap();
            let value: Value = serde_json::from_slice(&bytes).unwrap();
            let id = if kind == "command" {
                value["extension"]["extension_id"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            } else {
                format!(
                    "command.mcp-{}",
                    value["id"].as_str().unwrap().strip_prefix("mcp.").unwrap()
                )
            };
            let binding: Value = serde_json::from_slice(
                &fs::read(root.join(format!("contracts/extensions/trust/{id}.v1.json"))).unwrap(),
            )
            .unwrap();
            let mut trust = trust_map();
            trust["classes"][binding["trustClass"].as_str().unwrap()] = json!([id]);
            result.push((json!({"kind":kind, "trust":trust}), bytes));
        }
    }
    result
}

pub(crate) fn trust_map() -> Value {
    json!({"schemaVersion":"guard.extension-trust-class-map.v1", "publishers":{
        "hol":{"id":"hol", "displayName":"Hashgraph Online"},
        "hol-curated":{"id":"hol-curated", "displayName":"HOL curated library"}},
        "classes":{"first-party":[], "trusted-library":[], "external":[]}})
}

pub(crate) fn stream(sources: &[(Value, Vec<u8>)]) -> Vec<u8> {
    fn frame(stream: &mut Vec<u8>, bytes: &[u8]) {
        stream.extend((bytes.len() as u32).to_be_bytes());
        stream.extend(bytes);
    }
    let mut stream = b"HGPS\x01".to_vec();
    frame(
        &mut stream,
        &serde_json::to_vec(
            &json!({"schema":"guard.command-pack-source-stream.v1", "count":sources.len()}),
        )
        .unwrap(),
    );
    for (metadata, bytes) in sources {
        frame(&mut stream, &serde_json::to_vec(metadata).unwrap());
        frame(&mut stream, bytes);
    }
    stream
}

pub(crate) fn full_catalog() -> &'static source::CompiledSourceCatalog {
    static COMPILED: OnceLock<source::CompiledSourceCatalog> = OnceLock::new();
    COMPILED.get_or_init(|| {
        let sources = sources();
        let mut trust = trust_map();
        let mut commands = Vec::new();
        let mut servers = Vec::new();
        for (metadata, bytes) in &sources {
            if metadata["kind"] == "command" {
                commands.push(bytes.as_slice());
            } else {
                servers.push(bytes.as_slice());
            }
            for (class, ids) in metadata["trust"]["classes"].as_object().unwrap() {
                trust["classes"][class]
                    .as_array_mut()
                    .unwrap()
                    .extend(ids.as_array().unwrap().iter().cloned());
            }
        }
        source::compile_catalog_with_mcp(&commands, &servers, &serde_json::to_vec(&trust).unwrap())
            .unwrap()
    })
}

pub(crate) fn full_program() -> Arc<NativeCommandProgram> {
    static PROGRAM: OnceLock<Arc<NativeCommandProgram>> = OnceLock::new();
    Arc::clone(PROGRAM.get_or_init(|| {
        Arc::new(
            NativeCommandProgram::from_packaged_bytes(
                &serde_json::to_vec(&full_catalog().program).unwrap(),
            )
            .unwrap(),
        )
    }))
}

pub(crate) fn catalog_bytes() -> Vec<u8> {
    let compiled = full_catalog();
    serde_json::to_vec(&json!({"catalog":compiled.catalog,
        "catalog_digest":compiled.program["catalog_digest"],
        "program_digest":compiled.program["program_digest"]}))
    .unwrap()
}
