//! Exclusive private append journal. A partial/uncertain write is never reused.
use crate::{hash, Result};
use serde_json::{json, Value};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::PathBuf;

pub(crate) struct Journal {
    path: PathBuf,
    file: File,
    device: u64,
    inode: u64,
    bytes: u64,
    count: u64,
    previous: String,
    poisoned: bool,
    maximum_events: u64,
}

impl Journal {
    pub(crate) fn create(stage: &std::path::Path) -> Result<Self> {
        Self::create_file(stage, "native-supervisor-events.v1.jsonl")
    }

    pub(crate) fn create_image(stage: &std::path::Path) -> Result<Self> {
        Self::create_file(stage, "native-image-events.v1.jsonl")
    }

    pub(crate) fn create_process_events(stage: &std::path::Path) -> Result<Self> {
        let mut journal = Self::create_file(stage, "native-process-events.v1.jsonl")?;
        journal.maximum_events = 65536;
        Ok(journal)
    }

    pub(crate) fn create_recovery(stage: &std::path::Path) -> Result<Self> {
        Self::create_file(
            stage,
            &format!("native-recovery-{}.v1.jsonl", crate::nonce()?),
        )
    }

    fn create_file(stage: &std::path::Path, name: &str) -> Result<Self> {
        crate::fs_input::directory(stage)?;
        let path = stage.join(name);
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|e| e.to_string())?;
        let info = file.metadata().map_err(|e| e.to_string())?;
        if info.uid() != 0 || info.gid() != 0 || info.nlink() != 1 || info.mode() & 0o7777 != 0o600
        {
            return Err("private Root supervisor journal required".into());
        }
        file.sync_all().map_err(|e| e.to_string())?;
        File::open(stage)
            .and_then(|f| f.sync_all())
            .map_err(|e| e.to_string())?;
        Ok(Self {
            path,
            file,
            device: info.dev(),
            inode: info.ino(),
            bytes: 0,
            count: 0,
            previous: "0".repeat(64),
            poisoned: false,
            maximum_events: 10000,
        })
    }

    fn stable(&self) -> Result<()> {
        for info in [self.file.metadata(), std::fs::symlink_metadata(&self.path)] {
            let info = info.map_err(|e| e.to_string())?;
            if !info.is_file()
                || info.uid() != 0
                || info.gid() != 0
                || info.mode() & 0o7777 != 0o600
                || info.nlink() != 1
                || info.dev() != self.device
                || info.ino() != self.inode
                || info.len() != self.bytes
            {
                return Err("supervisor journal custody changed; retain uncertainty".into());
            }
        }
        Ok(())
    }

    pub(crate) fn binding(&self) -> Result<Value> {
        if self.poisoned {
            return Err("supervisor journal commit remains uncertain".into());
        }
        self.stable()?;
        Ok(
            json!({"schema":"hol-gauntlet-cell-journal-binding.v1","available":true,
            "events":self.count,"bytes":self.bytes,"tail_sha256":self.previous,
            "device":self.device,"inode":self.inode,"uid":0,"gid":0,"mode":0o600,"links":1}),
        )
    }

    pub(crate) fn append(&mut self, kind: &str, data: Value) -> Result<()> {
        if self.poisoned || self.count >= self.maximum_events {
            return Err("supervisor journal unavailable or exhausted".into());
        }
        self.stable()?;
        let record = json!({"schema":"hol-gauntlet-cell-event.v1","sequence":self.count,
            "previous_sha256":self.previous,"kind":kind,"data":data});
        let mut raw = gauntlet_contracts::canonicalize(record.to_string().as_bytes())
            .map_err(|e| e.to_string())?;
        if raw.len() > 256 * 1024 || self.bytes + raw.len() as u64 + 1 > 64 * 1024 * 1024 {
            return Err("supervisor journal byte bound".into());
        }
        let digest = hash(&raw);
        raw.push(b'\n');
        // Any failure after this point may have persisted bytes.
        self.poisoned = true;
        self.file
            .write_all(&raw)
            .and_then(|_| self.file.sync_all())
            .map_err(|_| "supervisor journal commit uncertain")?;
        self.bytes += raw.len() as u64;
        self.count += 1;
        self.previous = digest;
        self.stable()?;
        self.poisoned = false;
        Ok(())
    }

    pub(crate) fn capture(
        &mut self,
        argv: &[String],
        stdout: &[u8],
        stderr: &[u8],
        returncode: Option<i64>,
        error: Option<&str>,
    ) -> Result<()> {
        if stdout.len().saturating_add(stderr.len()) > 8 * 1024 * 1024 + 128 * 1024 {
            return Err("capture evidence byte bound".into());
        }
        let parent = self
            .path
            .parent()
            .ok_or("capture evidence parent missing")?;
        crate::fs_input::directory(parent)?;
        let id = crate::nonce()?;
        let mut files = serde_json::Map::new();
        for (name, raw) in [("stdout", stdout), ("stderr", stderr)] {
            let filename = format!("capture-{id}.{name}");
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(parent.join(&filename))
                .map_err(|e| e.to_string())?;
            file.write_all(raw)
                .and_then(|_| file.sync_all())
                .map_err(|_| "capture evidence commit uncertain")?;
            files.insert(
                name.into(),
                json!({"file":filename,"bytes":raw.len(),"sha256":hash(raw)}),
            );
        }
        File::open(parent)
            .and_then(|f| f.sync_all())
            .map_err(|_| "capture evidence directory commit uncertain")?;
        self.append("capture-terminal",json!({"argv_sha256":hash(argv.join("\0").as_bytes()),"files":files,"returncode":returncode,"error":error}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn root_journal_binding_tracks_committed_events_and_refuses_changed_visible_inode() {
        assert_eq!(
            rustix::process::geteuid().as_raw(),
            0,
            "Root journal tests require the owned Root VM"
        );
        let temp = tempfile::tempdir_in("/run").unwrap();
        let mut journal = Journal::create(temp.path()).unwrap();
        journal.append("test", json!({"value":1})).unwrap();
        let binding = journal.binding().unwrap();
        assert_eq!(binding["events"], 1);
        assert_eq!(binding["available"], true);
        let raw = std::fs::read(&journal.path).unwrap();
        assert_eq!(binding["bytes"], raw.len());
        assert_eq!(binding["tail_sha256"], hash(&raw[..raw.len() - 1]));
        std::fs::rename(&journal.path, temp.path().join("original-events.jsonl")).unwrap();
        let mut replacement = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&journal.path)
            .unwrap();
        replacement.write_all(&raw).unwrap();
        replacement.sync_all().unwrap();
        assert!(journal.binding().is_err());
    }
    #[test]
    fn root_journal_partial_append_and_poison_cannot_receive_a_binding() {
        assert_eq!(
            rustix::process::geteuid().as_raw(),
            0,
            "Root journal tests require the owned Root VM"
        );
        let temp = tempfile::tempdir_in("/run").unwrap();
        let mut journal = Journal::create(temp.path()).unwrap();
        journal.append("committed", json!({})).unwrap();
        journal.poisoned = true;
        assert!(journal.binding().is_err());
        journal.poisoned = false;
        let mut external = OpenOptions::new().append(true).open(&journal.path).unwrap();
        external.write_all(b"partial").unwrap();
        external.sync_all().unwrap();
        assert!(journal.binding().is_err());
    }
}
