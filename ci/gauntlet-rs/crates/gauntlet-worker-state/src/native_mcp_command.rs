//! The normal OMP CLI binding, including Python's stable server identifier.
use gauntlet_mcp_service::Family;
use sha2::{Digest, Sha256};
use std::path::Path;

pub(crate) fn proxy_argv(prefix: &Path, family: Family) -> Vec<String> {
    // stable_mcp_server_identifier uses sorted JSON with Python's default
    // separators and replaces the two absolute argument paths with <path>.
    let name = family.name();
    let payload=format!("{{\"args\": [\"<path>\", \"--socket\", \"<path>\"], \"command\": \"python3\", \"harness\": \"omp\", \"name\": \"{name}\", \"source_scope\": \"project\", \"transport\": \"stdio\"}}");
    let hash = format!("{:x}", Sha256::digest(payload.as_bytes()));
    let id = format!("mcp_server:omp:project:{name}:{}", &hash[..20]);
    let mut args = vec![
        prefix.join("bin/python").to_string_lossy().into_owned(),
        "-I".into(),
    ];
    args.extend(
        [
            "-m",
            "codex_plugin_scanner.cli",
            "guard",
            "omp-mcp-proxy",
            "--guard-home",
            "/product/guard",
            "--server-name",
            name,
            "--server-id",
            &id,
            "--source-scope",
            "project",
            "--config-path",
            "/product/public/mcp.json",
            "--transport",
            "stdio",
            "--command",
            "/usr/bin/python3",
            "--home",
            "/product/home",
            "--workspace",
            "/product/home/project",
            "--arg=/product/public/service_relay.py",
            "--arg=--socket",
        ]
        .map(String::from),
    );
    args.push(format!("--arg=/upstream/{name}.sock"));
    args
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn normal_cli_bindings_match_the_actual_python_adapter_for_all_families() {
        for (family, suffix) in [
            (Family::Mail, "0fc8525e4f702fd82399"),
            (Family::Crm, "2ef4e1b169b2b112e135"),
            (Family::Calendar, "a9725f46965f7ff481ca"),
            (Family::Docs, "ab3a6f8e60021e87e4c2"),
            (Family::Tables, "8258a608f8e8065a427e"),
            (Family::Chat, "5350df83ba32d287269b"),
            (Family::Tickets, "244ceb03c7e0e2afc228"),
        ] {
            let args = proxy_argv(Path::new("/opt/frozen/prefix"), family);
            assert_eq!(args.len(), 27);
            assert_eq!(args[0], "/opt/frozen/prefix/bin/python");
            assert_eq!(args[5], "omp-mcp-proxy");
            assert_eq!(
                args[11],
                format!("mcp_server:omp:project:{}:{suffix}", family.name())
            );
            assert_eq!(
                args.last().unwrap(),
                &format!("--arg=/upstream/{}.sock", family.name())
            );
        }
    }
}
