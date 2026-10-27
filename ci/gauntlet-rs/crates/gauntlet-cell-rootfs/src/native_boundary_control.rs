//! Fixed synthetic canaries: descriptor custody precedes any agent or product
//! probe, and physical preservation is checked after both cells drain.
use crate::{fs_input, hash, NativeCell, Result};
use rustix::fs::{
    fchmod, fchown, fstat, fsync, openat, statat, AtFlags, FileType, Mode, OFlags, Stat,
};
use rustix::process::{Gid, Uid};
use serde_json::{json, Value};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    os::fd::OwnedFd,
    path::PathBuf,
    time::Duration,
};

const DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const AGENT: &[u8] = b"gauntlet-sdk-agent-canary-v1";
const GUARD: &[u8] = b"gauntlet-product-guard-canary-v1";

struct Canary {
    root: PathBuf,
    components: Vec<(&'static str, u32)>,
    parent: OwnedFd,
    parent_stat: Stat,
    file: File,
    stat: Stat,
    name: &'static str,
    bytes: &'static [u8],
    inside: String,
}
fn directory(root: &std::path::Path, components: &[(&str, u32)]) -> Result<OwnedFd> {
    let mut held = fs_input::directory(root)?;
    for (name, owner) in components {
        held = openat(&held, *name, DIRECTORY, Mode::empty()).map_err(|e| e.to_string())?;
        let s = fstat(&held).map_err(|e| e.to_string())?;
        if FileType::from_raw_mode(s.st_mode) != FileType::Directory
            || s.st_uid != *owner
            || s.st_gid != *owner
            || s.st_mode & 0o7777 != 0o700
        {
            return Err("boundary canary parent custody differs".into());
        }
    }
    Ok(held)
}
fn same_directory(a: &Stat, b: &Stat) -> bool {
    a.st_dev == b.st_dev
        && a.st_ino == b.st_ino
        && a.st_uid == b.st_uid
        && a.st_gid == b.st_gid
        && a.st_mode == b.st_mode
}
impl Canary {
    fn create(
        root: PathBuf,
        components: Vec<(&'static str, u32)>,
        name: &'static str,
        owner: u32,
        bytes: &'static [u8],
        inside: String,
    ) -> Result<Self> {
        let parent = directory(&root, &components)?;
        let parent_stat = fstat(&parent).map_err(|e| e.to_string())?;
        let fd = openat(
            &parent,
            name,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|e| e.to_string())?;
        let mut file = File::from(fd);
        file.write_all(bytes).map_err(|e| e.to_string())?;
        fchmod(&file, Mode::RUSR | Mode::WUSR).map_err(|e| e.to_string())?;
        fchown(
            &file,
            Some(Uid::from_raw(owner)),
            Some(Gid::from_raw(owner)),
        )
        .map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        fsync(&parent).map_err(|e| e.to_string())?;
        let stat = fstat(&file).map_err(|e| e.to_string())?;
        if stat.st_uid != owner
            || stat.st_gid != owner
            || stat.st_mode & 0o7777 != 0o600
            || stat.st_nlink != 1
            || stat.st_size != bytes.len() as i64
        {
            return Err("fresh boundary canary metadata differs".into());
        }
        let mut result = Self {
            root,
            components,
            parent,
            parent_stat,
            file,
            stat,
            name,
            bytes,
            inside,
        };
        result.verify()?;
        Ok(result)
    }
    fn verify(&mut self) -> Result<()> {
        let visible_parent = directory(&self.root, &self.components)?;
        for parent in [&self.parent, &visible_parent] {
            if !same_directory(
                &fstat(parent).map_err(|e| e.to_string())?,
                &self.parent_stat,
            ) {
                return Err("boundary canary parent replaced".into());
            }
        }
        let visible = statat(&visible_parent, self.name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|e| e.to_string())?;
        if !fs_input::same(&visible, &self.stat)
            || !fs_input::same(&fstat(&self.file).map_err(|e| e.to_string())?, &self.stat)
        {
            return Err("boundary canary replaced or changed".into());
        }
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|e| e.to_string())?;
        let mut raw = Vec::new();
        Read::by_ref(&mut self.file)
            .take(1025)
            .read_to_end(&mut raw)
            .map_err(|e| e.to_string())?;
        if raw != self.bytes {
            return Err("boundary canary bytes changed".into());
        }
        Ok(())
    }
    fn observation(&self) -> Value {
        let mut path = self.root.clone();
        for (name, _) in &self.components {
            path.push(name);
        }
        path.push(self.name);
        json!({"path":path,"inside":self.inside,"sha256":hash(self.bytes),"bytes":self.bytes.len(),
            "device":self.stat.st_dev,"inode":self.stat.st_ino,"uid":self.stat.st_uid,"gid":self.stat.st_gid,"mode":0o600})
    }
}

pub struct NativeBoundaryControl {
    canaries: Vec<Canary>,
    product_positive: Value,
    task: crate::declarations::TaskMount,
}
impl NativeBoundaryControl {
    pub fn prepare(cell: &mut NativeCell) -> Result<Self> {
        crate::require_outside_root()?;
        let job = cell.inputs.tasks[0].custody_root.clone();
        if cell.inputs.spec.stage.parent() != Some(job.as_path()) {
            return Err("boundary job/stage binding differs".into());
        }
        let controller_path = job
            .join("controller-canary.txt")
            .to_string_lossy()
            .into_owned();
        let canaries = vec![
            Canary::create(
                job.clone(),
                vec![],
                "controller-canary.txt",
                0,
                b"gauntlet-controller-canary-v1",
                controller_path,
            )?,
            Canary::create(
                job,
                vec![("sdk-agent", 10001)],
                "agent-canary.txt",
                10001,
                AGENT,
                "/runtime/agent/agent-canary.txt".into(),
            )?,
            Canary::create(
                cell.inputs.spec.stage.clone(),
                vec![("state", 10004), ("guard", 10004)],
                "native-boundary-canary.txt",
                10004,
                GUARD,
                "/product/guard/native-boundary-canary.txt".into(),
            )?,
        ];
        let argv = ["/usr/bin/python3", "-I", "-B", "-c", "import os,hashlib;from pathlib import Path;assert os.geteuid()==10004;print(hashlib.sha256(Path('/product/guard/native-boundary-canary.txt').read_bytes()).hexdigest())"].map(String::from);
        let positive = cell.capture(&argv, b"", Duration::from_secs(5))?;
        if positive.returncode != 0
            || positive.stdout != format!("{}\n", hash(GUARD)).as_bytes()
            || !positive.stderr.is_empty()
        {
            return Err("product boundary canary positive visibility failed".into());
        }
        let product_positive = json!({"native_command":argv,"exit_code":positive.returncode,"stdout_sha256":hash(&positive.stdout),"stderr_sha256":hash(&positive.stderr)});
        Ok(Self {
            canaries,
            product_positive,
            task: cell.inputs.tasks[0].clone(),
        })
    }
    pub fn sdk_canary_sha256(&self) -> String {
        hash(AGENT)
    }
    pub fn verify(&mut self) -> Result<Value> {
        for canary in &mut self.canaries {
            canary.verify()?;
        }
        Ok(self.observation())
    }
    pub fn readback(&mut self) -> Result<Value> {
        let custody = self.verify()?;
        let workspace = crate::native_binding_fixture::workspace(&self.task)?;
        let descriptor = openat(
            &workspace,
            "boundary-negatives.json",
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())?;
        let mut file = File::from(descriptor);
        let before = fstat(&file).map_err(|e| e.to_string())?;
        if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
            || before.st_uid != 10001
            || before.st_gid != 10001
            || before.st_nlink != 1
            || before.st_mode & 0o022 != 0
            || !(1..=65536).contains(&before.st_size)
        {
            return Err("physical boundary result custody differs".into());
        }
        let mut raw = Vec::new();
        Read::by_ref(&mut file)
            .take(65537)
            .read_to_end(&mut raw)
            .map_err(|e| e.to_string())?;
        let visible = statat(
            &workspace,
            "boundary-negatives.json",
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|e| e.to_string())?;
        crate::native_binding_fixture::workspace(&self.task)?;
        if !fs_input::same(&before, &visible)
            || !fs_input::same(&before, &fstat(&file).map_err(|e| e.to_string())?)
            || raw.len() as i64 != before.st_size
        {
            return Err("physical boundary result changed during readback".into());
        }
        let canonical = gauntlet_contracts::canonicalize(&raw).map_err(|e| e.to_string())?;
        let reported: Value = serde_json::from_slice(&canonical).map_err(|e| e.to_string())?;
        let paths = self
            .canaries
            .iter()
            .map(|c| c.inside.clone())
            .collect::<Vec<_>>();
        crate::native_boundary_result::verify(&reported, &paths)?;
        Ok(
            json!({"schema":"hol-gauntlet-native-boundary-control.v1","status":"passed","canary_custody":custody,
            "reported":reported,"physical_report":{"file":"boundary-negatives.json","sha256":hash(&raw),"bytes":raw.len(),
                "device":before.st_dev,"inode":before.st_ino,"uid":before.st_uid,"gid":before.st_gid,"mode":before.st_mode & 0o7777},
            "canaries_unchanged":true,"kernel_claims_authenticated":false,"execution_eligible":false,"guard_causality_verified":false,"model_requests":0}),
        )
    }
    pub fn observation(&self) -> Value {
        json!({"schema":"hol-gauntlet-native-boundary-canaries.v1","canaries":self.canaries.iter().map(Canary::observation).collect::<Vec<_>>(),
            "product_positive":self.product_positive,"execution_eligible":false,"guard_causality_verified":false,"model_requests":0})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn replacement_with_identical_bytes_cannot_preserve_boundary_canary_custody() {
        assert_eq!(
            rustix::process::geteuid().as_raw(),
            0,
            "native canary test requires Root"
        );
        let root = tempfile::tempdir_in("/var/lib").unwrap();
        let path = root.path().join("controller-canary.txt");
        let mut held = Canary::create(
            root.path().into(),
            vec![],
            "controller-canary.txt",
            0,
            b"synthetic",
            path.to_string_lossy().into(),
        )
        .unwrap();
        held.verify().unwrap();
        std::fs::rename(&path, root.path().join("retained-original")).unwrap();
        std::fs::write(&path, b"synthetic").unwrap();
        assert!(held.verify().is_err());
    }
}
