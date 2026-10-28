//! Root-owned inert image mount, exclusively journaled before helper mutation.
use crate::image_process::{run, Operation};
use crate::supervisor_journal::Journal;
use crate::{fs_input, Result};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub(crate) struct ImageLease {
    image: String,
    podman_sha256: String,
    root: Option<PathBuf>,
    lock: crate::image_lock::ImageLock,
    journal: Journal,
    owned: bool,
    cell_may_exist: bool,
    closed: bool,
}

impl ImageLease {
    pub(crate) fn acquire(stage: &Path, image: &str, podman_sha256: &str) -> Result<Self> {
        crate::kernel_process::root_proc()?;
        fs_input::directory(stage)?;
        crate::image_protocol::image_id(image)?;
        fs_input::pinned(
            Path::new("/usr/bin/podman"),
            128 * 1024 * 1024,
            podman_sha256,
        )?;
        let lock = crate::image_lock::ImageLock::reserve(image, stage)?;
        let journal = Journal::create_image(stage)?;
        let mut lease = Self {
            image: image.into(),
            podman_sha256: podman_sha256.into(),
            root: None,
            lock,
            journal,
            owned: false,
            cell_may_exist: false,
            closed: false,
        };
        lease.journal.append(
            "image-reserved",
            json!({"image_id":image,"podman_sha256":podman_sha256,"stage":stage}),
        )?;
        crate::image_protocol::inspect(&run(podman_sha256, Operation::Inspect, image)?, image)?;
        if lease.mounted()?.is_some() {
            return Err(
                "image already mounted; refusing to borrow or unmount another lease".into(),
            );
        }
        lease
            .journal
            .append("image-acquiring", json!({"image_id":image}))?;
        // A helper may fail after mutation. This owner must retain responsibility.
        lease.owned = true;
        let raw = run(podman_sha256, Operation::Mount, image)?;
        let text = std::str::from_utf8(&raw)
            .map_err(|_| "image mount root UTF-8")?
            .trim();
        let root = crate::spec::literal_path(text)?;
        if root == Path::new("/") || lease.mounted()?.as_ref() != Some(&root) {
            return Err("mounted image provenance mismatch".into());
        }
        let directory = fs_input::directory(&root)?;
        let info = rustix::fs::fstat(&directory).map_err(|e| e.to_string())?;
        lease.journal.append(
            "image-mounted",
            json!({"image_id":image,"root":root,"device":info.st_dev,"inode":info.st_ino}),
        )?;
        lease.root = Some(root);
        Ok(lease)
    }

    fn mounted(&self) -> Result<Option<PathBuf>> {
        self.lock.verify()?;
        crate::image_protocol::mounted(
            &run(&self.podman_sha256, Operation::Inventory, &self.image)?,
            &self.image,
        )
    }

    pub(crate) fn declaration(&self) -> Result<Value> {
        let root = self
            .root
            .as_ref()
            .filter(|_| self.owned && !self.closed)
            .ok_or("active image lease required")?;
        if self.mounted()?.as_ref() != Some(root) {
            return Err("owned image mount changed".into());
        }
        let descriptor = fs_input::directory(root)?;
        let info = rustix::fs::fstat(&descriptor).map_err(|e| e.to_string())?;
        Ok(
            json!({"schema":"product-cell-image-system.v1","root":root,"device":info.st_dev,
            "inode":info.st_ino,"image_id":self.image,"workspace":"/runtime/home/project"}),
        )
    }

    pub(crate) fn before_cell_launch(&mut self) -> Result<()> {
        self.lock.verify()?;
        self.journal
            .append("image-cell-launch-pending", json!({"image_id":self.image}))?;
        self.cell_may_exist = true;
        Ok(())
    }

    pub(crate) fn after_cell_absent(&mut self) {
        self.cell_may_exist = false;
    }

    pub(crate) fn close(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        self.lock.verify()?;
        if self.cell_may_exist {
            return Err("cell cleanup uncertain; retain owned image mount and active lease".into());
        }
        if self.owned {
            self.journal
                .append("image-releasing", json!({"image_id":self.image}))?;
            if self.mounted()?.is_some() {
                run(&self.podman_sha256, Operation::Unmount, &self.image)?;
            }
            if self.mounted()?.is_some() {
                return Err("owned image mount survived cleanup".into());
            }
        }
        self.journal.append("image-cleanup",json!({"image_id":self.image,"owned_mount_absent":self.owned,"borrowed_mount_untouched":!self.owned}))?;
        self.lock.complete()?;
        self.owned = false;
        self.closed = true;
        Ok(())
    }
}

impl Drop for ImageLease {
    fn drop(&mut self) {
        if !self.closed {
            if let Err(error) = self.close() {
                eprintln!("native image lease cleanup uncertain: {error}");
            }
        }
    }
}
