//! Bounded numerical asset manifests exclude private operational records.
use super::text;
use crate::private_jobs::same_file;
use rustix::fs::{fstat, open, openat, FileType, Mode, OFlags};
use serde_json::{json, Value};
use std::{
    fs::File,
    io::Read,
    path::{Component, Path, PathBuf},
};

fn open_file(path: &Path) -> Result<File, String> {
    if !path.is_absolute() || path.as_os_str().len() > 4096 {
        return Err("absolute bounded provider asset required".into());
    }
    let mut normalized = PathBuf::from("/");
    let mut parts = Vec::new();
    for c in path.components() {
        match c {
            Component::RootDir => {}
            Component::Normal(p) => {
                normalized.push(p);
                parts.push(p);
            }
            _ => return Err("ordinary provider asset ancestry required".into()),
        }
    }
    if normalized != path || parts.is_empty() || parts.len() > 64 {
        return Err("canonical provider asset required".into());
    }
    let mut dir = open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| "provider asset root unavailable")?;
    let owner = rustix::process::geteuid().as_raw();
    for p in &parts[..parts.len() - 1] {
        dir = openat(
            &dir,
            *p,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| "provider asset ancestry unsafe")?;
        let s = fstat(&dir).map_err(|_| "provider asset ancestry unavailable")?;
        if ![0, owner].contains(&s.st_uid)
            || (s.st_mode & 0o022 != 0 && !(s.st_uid == 0 && s.st_mode & 0o1000 != 0))
        {
            return Err("provider asset ancestry writable outside owner".into());
        }
    }
    let fd = openat(
        &dir,
        *parts.last().ok_or("provider asset absent")?,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| "provider asset unavailable")?;
    let s = fstat(&fd).map_err(|_| "provider asset metadata unavailable")?;
    if FileType::from_raw_mode(s.st_mode) != FileType::RegularFile
        || ![0, owner].contains(&s.st_uid)
        || s.st_nlink < 1
        || (s.st_uid != 0 && s.st_nlink != 1)
        || s.st_mode & 0o6022 != 0
        || s.st_size < 0
    {
        return Err("provider asset custody unsafe".into());
    }
    Ok(File::from(fd))
}
pub(super) struct Assets {
    files: Vec<(PathBuf, rustix::fs::Stat)>,
    pub facts: Value,
    pub directories: Value,
}
impl Assets {
    pub fn capture_spec(spec: &Value) -> Result<Self, String> {
        validate_scope(spec)?;
        let directories = inventory(spec)?;
        let mut captured = Self::capture(&spec["assets"])?;
        captured.directories = directories;
        captured.stable()?;
        Ok(captured)
    }
    pub fn capture(pins: &Value) -> Result<Self, String> {
        use sha2::{Digest, Sha256};
        let pins = pins
            .as_object()
            .filter(|p| !p.is_empty() && p.len() <= 20_000)
            .ok_or("bounded numerical asset inventory required")?;
        let mut files = Vec::new();
        let mut facts = serde_json::Map::new();
        let mut total = 0_u64;
        for (path, pin) in pins {
            let expected = pin["sha256"]
                .as_str()
                .filter(|v| super::hex(v, 64))
                .ok_or("asset SHA256 required")?;
            let size = pin["bytes"]
                .as_u64()
                .filter(|v| *v <= 16 * 1024 * 1024 * 1024)
                .ok_or("bounded asset size required")?;
            if pin.as_object().is_none_or(|p| p.len() != 2) {
                return Err("exact asset pins required".into());
            }
            total = total
                .checked_add(size)
                .filter(|n| *n <= 128 * 1024 * 1024 * 1024)
                .ok_or("numerical inventory exceeds bound")?;
            let path = PathBuf::from(path);
            let mut file = open_file(&path)?;
            let before = fstat(&file).map_err(|_| "asset metadata unavailable")?;
            if before.st_size as u64 != size {
                return Err("numerical asset size changed".into());
            }
            let mut digest = Sha256::new();
            let mut chunk = [0_u8; 65536];
            let mut count = 0_u64;
            loop {
                let n = file
                    .read(&mut chunk)
                    .map_err(|_| "numerical asset read failed")?;
                if n == 0 {
                    break;
                }
                count += n as u64;
                if count > size {
                    return Err("numerical asset grew".into());
                }
                digest.update(&chunk[..n]);
            }
            if count != size
                || format!("{:x}", digest.finalize()) != expected
                || !same_file(&before, &fstat(&file).map_err(|_| "asset unavailable")?)
            {
                return Err("numerical asset changed or differs from pin".into());
            }
            facts.insert(path.to_string_lossy().into_owned(),json!({"device":before.st_dev,"inode":before.st_ino,"uid":before.st_uid,"gid":before.st_gid,"mode":before.st_mode&0o7777,"links":before.st_nlink,"bytes":size,"sha256":expected,"mtime":before.st_mtime,"mtime_nsec":before.st_mtime_nsec,"ctime":before.st_ctime,"ctime_nsec":before.st_ctime_nsec}));
            files.push((path, before));
        }
        let result = Self {
            files,
            facts: Value::Object(facts),
            directories: json!({"roots":{},"entries":{}}),
        };
        result.stable()?;
        Ok(result)
    }
    pub fn stable(&self) -> Result<(), String> {
        for (path, context) in self.directories["roots"]
            .as_object()
            .ok_or("numerical root custody absent")?
        {
            if crate::native_operation::context::snapshot(Path::new(path))? != *context {
                return Err("numerical inventory ancestry changed".into());
            }
        }
        for (path, facts) in self.directories["entries"]
            .as_object()
            .ok_or("numerical directory custody absent")?
        {
            if directory(Path::new(path))? != *facts {
                return Err("numerical inventory membership changed".into());
            }
        }
        for (path, original) in &self.files {
            let named = open_file(path)?;
            if !same_file(
                original,
                &fstat(&named).map_err(|_| "named numerical asset unavailable")?,
            ) {
                return Err("retained numerical asset replaced or changed".into());
            }
        }
        Ok(())
    }
    pub fn executable_file(&self, path: &str) -> Result<File, String> {
        self.files
            .iter()
            .find(|(p, _)| p == Path::new(path))
            .map(|(p, s)| {
                if s.st_mode & 0o111 != 0 {
                    let file = open_file(p)?;
                    if !same_file(
                        s,
                        &fstat(&file).map_err(|_| "interpreter metadata unavailable")?,
                    ) {
                        return Err("pinned interpreter changed".into());
                    }
                    Ok(file)
                } else {
                    Err("numerical interpreter is not executable".into())
                }
            })
            .ok_or("interpreter absent from pinned inventory")?
    }
}

/// Validate roles before any manifest-selected bytes are opened. In particular,
/// operational JSON records, keys, homes and arbitrary private captures cannot
/// be smuggled into the numerical inventory as additional assets.
pub(super) fn validate_scope(spec: &Value) -> Result<(), String> {
    let python = Path::new(text(spec, "python")?);
    let runtime = python
        .parent()
        .and_then(Path::parent)
        .ok_or("numerical interpreter runtime root absent")?;
    let site = Path::new(text(spec, "site_packages")?);
    let model = Path::new(text(spec, "model_directory")?);
    let producer =
        std::fs::canonicalize(std::env::current_exe().map_err(|_| "Rust producer unavailable")?)
            .map_err(|_| "Rust producer unavailable")?;
    let pins = spec["assets"]
        .as_object()
        .ok_or("numerical manifest absent")?;
    if pins
        .get(producer.to_str().ok_or("producer path invalid")?)
        .is_none_or(|p| p["sha256"] != spec["producer_sha256"])
    {
        return Err("current Rust producer absent from outside-pinned inventory".into());
    }
    for name in pins.keys() {
        let path = Path::new(name);
        if !path.is_absolute()
            || path
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
        {
            return Err("canonical numerical manifest paths required".into());
        }
        let code = matches!(
            path.extension().and_then(|s| s.to_str()),
            Some("py" | "pyi" | "so" | "dylib" | "zip")
        );
        let leaf = path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or("numerical asset leaf absent")?;
        let model_data = leaf.ends_with(".safetensors")
            || leaf.ends_with(".json")
            || leaf.ends_with(".safetensors.index.json")
            || matches!(
                leaf,
                "config.json"
                    | "tokenizer.json"
                    | "tokenizer_config.json"
                    | "special_tokens_map.json"
                    | "generation_config.json"
                    | "vocab.json"
                    | "merges.txt"
                    | "vocab.txt"
                    | "tokenizer.model"
                    | "chat_template.jinja"
                    | "added_tokens.json"
            );
        if path != python
            && path != producer
            && !((path.starts_with(site) || path.starts_with(runtime)) && code)
            && !(path.starts_with(model) && model_data)
        {
            return Err("manifest entry is outside fixed numerical code or model roles".into());
        }
    }
    Ok(())
}

fn directory(path: &Path) -> Result<Value, String> {
    use std::os::unix::fs::MetadataExt;
    let m =
        std::fs::symlink_metadata(path).map_err(|_| "numerical inventory directory unavailable")?;
    if !m.is_dir() {
        return Err("ordinary numerical inventory directory required".into());
    }
    Ok(
        json!({"device":m.dev(),"inode":m.ino(),"uid":m.uid(),"gid":m.gid(),"mode":m.mode(),"links":m.nlink(),"mtime":m.mtime(),"mtime_nsec":m.mtime_nsec(),"ctime":m.ctime(),"ctime_nsec":m.ctime_nsec()}),
    )
}
fn inventory(spec: &Value) -> Result<Value, String> {
    let python = Path::new(text(spec, "python")?);
    if python
        .parent()
        .and_then(Path::file_name)
        .and_then(|s| s.to_str())
        != Some("bin")
        || !python
            .file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|s| s.starts_with("python3.11"))
    {
        return Err("pinned physical CPython3.11 distribution interpreter required".into());
    }
    let runtime = python
        .parent()
        .and_then(Path::parent)
        .ok_or("CPython distribution absent")?;
    let site = Path::new(text(spec, "site_packages")?);
    let model = Path::new(text(spec, "model_directory")?);
    let stdlib = runtime.join("lib/python3.11");
    let mut roots = serde_json::Map::new();
    let mut entries = serde_json::Map::new();
    let mut seen = 0_usize;
    for root in [site, stdlib.as_path(), model] {
        roots.insert(
            root.to_string_lossy().into_owned(),
            crate::native_operation::context::snapshot(root)?,
        );
        let mut pending = vec![(root.to_path_buf(), 0_usize)];
        while let Some((path, depth)) = pending.pop() {
            if depth > 64 {
                return Err("numerical directory depth exceeds bound".into());
            }
            entries.insert(path.to_string_lossy().into_owned(), directory(&path)?);
            for child in
                std::fs::read_dir(&path).map_err(|_| "numerical directory inventory unavailable")?
            {
                seen += 1;
                if seen > 100_000 {
                    return Err("numerical directory entry bound exceeded".into());
                }
                let child = child.map_err(|_| "numerical directory inventory incomplete")?;
                let path = child.path();
                let kind = child
                    .file_type()
                    .map_err(|_| "numerical inventory metadata unavailable")?;
                if kind.is_symlink() {
                    return Err(
                        "numerical inventory links require a separately reviewed publication"
                            .into(),
                    );
                }
                if kind.is_dir() {
                    if child.file_name() != "__pycache__" {
                        pending.push((path, depth + 1));
                    }
                    continue;
                }
                let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
                if ext == "pyc" {
                    return Err("source-less numerical bytecode is unsupported".into());
                }
                let loaded = matches!(ext, "py" | "pyi" | "so" | "dylib" | "zip")
                    || (root == model
                        && matches!(ext, "json" | "safetensors" | "model" | "txt" | "jinja"));
                if loaded
                    && (!kind.is_file()
                        || spec["assets"]
                            .get(path.to_str().ok_or("numerical path invalid")?)
                            .is_none())
                {
                    return Err(
                        "complete outside-pinned numerical code and model inventory required"
                            .into(),
                    );
                }
            }
        }
    }
    let zip = runtime.join("lib/python311.zip");
    if zip.exists()
        && spec["assets"]
            .get(zip.to_str().ok_or("CPython zip path invalid")?)
            .is_none()
    {
        return Err("pinned CPython standard-library archive required".into());
    }
    Ok(json!({"roots":roots,"entries":entries}))
}
