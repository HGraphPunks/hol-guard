//! Fixed readonly MCP entrypoints. Root writes bytes only; product imports
//! execute exclusively inside the UID10005 agent container.
use gauntlet_contracts::canonicalize;
use rustix::fs::{
    fchmod, fchown, fstat, fsync, mkdirat, openat, statat, AtFlags, Mode, OFlags, Stat,
};
use rustix::process::{Gid, Uid};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

const RELAY: &str = include_str!("../../../../gauntlet/benchmark/service_relay.py");
const PROXY: &str = include_str!("../../../adapters/native_mcp_proxy_v1.py.txt");
const PROBE: &str = include_str!("../../../adapters/native_mcp_identity_v1.py.txt");
pub(crate) const CONFIG: &str = "mode=\"enforce\"\nsync=false\ntelemetry=false\ndesktop_notifications=false\napproval_wait_timeout_seconds=30\n";
struct PublicFile {
    name: &'static str,
    file: File,
    stat: Stat,
    sha256: String,
}
pub(crate) struct NativeMcpPublic {
    root: PathBuf,
    directory: OwnedFd,
    stat: Stat,
    files: Vec<PublicFile>,
}
fn digest(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}
fn directory(root: &OwnedFd, name: &str, mode: u32, agent: bool) -> Result<OwnedFd, String> {
    mkdirat(root, name, Mode::from_bits_truncate(0o700)).map_err(|e| e.to_string())?;
    let fd = openat(
        root,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    if agent {
        fchown(&fd, Some(Uid::from_raw(10005)), Some(Gid::from_raw(10005)))
            .map_err(|e| e.to_string())?;
    }
    fchmod(&fd, Mode::from_bits_truncate(mode))
        .and_then(|_| fsync(&fd))
        .and_then(|_| fsync(root))
        .map_err(|e| e.to_string())?;
    Ok(fd)
}
pub(crate) fn write_file(
    root: &OwnedFd,
    name: &str,
    raw: &[u8],
    mode: u32,
) -> Result<File, String> {
    if raw.is_empty() || raw.len() > 1024 * 1024 {
        return Err("bounded public MCP file required".into());
    }
    let fd = openat(
        root,
        name,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(|e| e.to_string())?;
    let mut file = File::from(fd);
    file.write_all(raw)
        .and_then(|_| file.sync_all())
        .map_err(|e| e.to_string())?;
    fchmod(&file, Mode::from_bits_truncate(mode))
        .and_then(|_| fsync(root))
        .map_err(|e| e.to_string())?;
    Ok(file)
}
impl NativeMcpPublic {
    pub(crate) fn prepare(job: &Path, prefix: &Path) -> Result<Self, String> {
        Self::prepare_profile(job, prefix, None)
    }
    pub(crate) fn prepare_live(
        job: &Path,
        prefix: &Path,
        job_id: &str,
        spec: &Value,
    ) -> Result<Self, String> {
        if !crate::hex(job_id, 16)
            || spec["task_prompt"]
                .as_str()
                .is_none_or(|s| s.is_empty() || s.len() > 65536)
        {
            return Err("source-selected live MCP prompt required".into());
        }
        let authorization = canonicalize(spec["workflow"]["authorization"].to_string().as_bytes())
            .map_err(|e| e.to_string())?;
        let prompt = format!(
            "{}\n\nSource-selected user delegation:\n{}",
            spec["task_prompt"].as_str().unwrap(),
            std::str::from_utf8(&authorization).map_err(|_| "public delegation UTF8")?
        );
        let payload = json!({"hook_event_name":"UserPromptSubmit","config_path":"/product/public/mcp.json",
            "session_id":format!("gauntlet-live-{job_id}"),"prompt":prompt});
        Self::prepare_profile(job, prefix, Some(payload))
    }
    fn prepare_profile(job: &Path, prefix: &Path, live: Option<Value>) -> Result<Self, String> {
        gauntlet_cell_rootfs::require_outside_root()?;
        if !prefix.is_absolute()
            || prefix
                .components()
                .any(|p| matches!(p, std::path::Component::ParentDir))
            || prefix
                .to_str()
                .is_none_or(|s| s.contains([':', '\n', '\0']))
        {
            return Err("literal installed MCP prefix required".into());
        }
        let root = crate::open_root_owned_public_directory(job).map_err(|e| e.to_string())?;
        let stat = fstat(&root).map_err(|e| e.to_string())?;
        if stat.st_uid != 0 || stat.st_gid != 0 || stat.st_mode & 0o7777 != 0o700 {
            return Err("private MCP job required".into());
        }
        let home = directory(&root, "mcp-home", 0o700, true)?;
        directory(&home, "project", 0o700, true)?;
        let guard = directory(&root, "mcp-guard", 0o700, true)?;
        let config_file = write_file(&guard, "config.toml", CONFIG.as_bytes(), 0o600)?;
        fchown(
            &config_file,
            Some(Uid::from_raw(10005)),
            Some(Gid::from_raw(10005)),
        )
        .map_err(|e| e.to_string())?;
        fsync(&config_file)
            .and_then(|_| fsync(&guard))
            .map_err(|e| e.to_string())?;
        let directory = directory(&root, "mcp-public", 0o755, false)?;
        let config = canonicalize(json!({"prefix":prefix}).to_string().as_bytes())
            .map_err(|e| e.to_string())?;
        let mcp = if live.is_some() {
            let servers=["crm","docs","mail","tickets"].into_iter().map(|family|(family.to_owned(),json!({"command":"/usr/bin/python3",
                "args":["/product/public/service_relay.py","--socket",format!("/upstream/{family}.sock")],"env":{},"transport":"stdio"}))).collect::<serde_json::Map<_,_>>();
            canonicalize(json!({"mcpServers":servers}).to_string().as_bytes())
                .map_err(|e| e.to_string())?
        } else {
            b"{}\n".to_vec()
        };
        let mut files = Vec::new();
        let live_raw = live
            .map(|v| canonicalize(v.to_string().as_bytes()).map_err(|e| e.to_string()))
            .transpose()?;
        let mut sources = vec![
            ("service_relay.py", RELAY.as_bytes()),
            ("native_mcp_proxy_v1.py", PROXY.as_bytes()),
            ("native_mcp_identity_v1.py", PROBE.as_bytes()),
            ("mcp.json", mcp.as_slice()),
            ("prefix.json", config.as_slice()),
        ];
        if let Some(raw) = live_raw.as_ref() {
            sources.push(("live-prompt.json", raw.as_slice()));
        }
        for (name, bytes) in sources {
            let file = write_file(&directory, name, bytes, 0o444)?;
            files.push(PublicFile {
                name,
                stat: fstat(&file).map_err(|e| e.to_string())?,
                file,
                sha256: digest(bytes),
            });
        }
        let public = Self {
            root: job.join("mcp-public"),
            stat: fstat(&directory).map_err(|e| e.to_string())?,
            directory,
            files,
        };
        public.verify()?;
        Ok(public)
    }
    pub(crate) fn verify(&self) -> Result<(), String> {
        let visible =
            crate::open_root_owned_public_directory(&self.root).map_err(|e| e.to_string())?;
        for stat in [fstat(&self.directory), fstat(&visible)] {
            let stat = stat.map_err(|e| e.to_string())?;
            if stat.st_dev != self.stat.st_dev
                || stat.st_ino != self.stat.st_ino
                || stat.st_uid != 0
                || stat.st_gid != 0
                || stat.st_mode & 0o7777 != 0o755
            {
                return Err("readonly MCP helper directory changed".into());
            }
        }
        let mut count = 0;
        for entry in rustix::fs::Dir::read_from(&self.directory).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            if !matches!(entry.file_name().to_bytes(), b"." | b"..") {
                count += 1
            }
        }
        if count != self.files.len() {
            return Err("MCP helper entries changed".into());
        }
        for file in &self.files {
            let visible = statat(&self.directory, file.name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|e| e.to_string())?;
            let held = fstat(&file.file).map_err(|e| e.to_string())?;
            if !crate::dependency_prefix_meta::same(&file.stat, &visible)
                || !crate::dependency_prefix_meta::same(&file.stat, &held)
            {
                return Err("MCP helper held/visible custody changed".into());
            }
            let fd = openat(
                &self.directory,
                file.name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| e.to_string())?;
            let mut raw = Vec::new();
            File::from(fd)
                .take(1024 * 1024 + 1)
                .read_to_end(&mut raw)
                .map_err(|e| e.to_string())?;
            if digest(&raw) != file.sha256 || raw.len() as i64 != file.stat.st_size {
                return Err("actual readonly MCP helper bytes changed".into());
            }
        }
        Ok(())
    }
    pub(crate) fn path(&self) -> &Path {
        &self.root
    }
    pub(crate) fn observation(&self) -> Value {
        json!({"schema":"hol-gauntlet-native-mcp-public-helpers.v1","directory":self.root,
            "files":self.files.iter().map(|f|json!({"name":f.name,"sha256":f.sha256,"bytes":f.stat.st_size,
                "device":f.stat.st_dev,"inode":f.stat.st_ino,"uid":0,"gid":0,"mode":0o444})).collect::<Vec<_>>(),
            "entrypoint_bytes_verified":true,"product_imported_by_root":false,"execution_eligible":false})
    }
}
