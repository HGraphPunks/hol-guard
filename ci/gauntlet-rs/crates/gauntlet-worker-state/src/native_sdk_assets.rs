//! Actual immutable SDK/Bun custody for the Root launcher. Receipt bytes alone
//! do not establish an SDK import, call, model request or Guard verdict.
use crate::{NativeSdkAssetPins, NativeSdkPins};
use gauntlet_evidence::{inventory_tree, TreeInventory, TreeKind};
use rustix::fs::{fstat, openat, Mode, OFlags, Stat};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

pub struct VerifiedNativeSdkAssets {
    pins: NativeSdkPins,
    input: NativeSdkAssetPins,
    directory: OwnedFd,
    directory_stat: Stat,
    bun: File,
    bun_stat: Stat,
    tree: TreeInventory,
    receipt: Value,
}
impl VerifiedNativeSdkAssets {
    pub fn load(pins: &NativeSdkPins) -> Result<Self, String> {
        gauntlet_cell_rootfs::require_outside_root()?;
        NativeSdkPins::parse(&pins.to_json())?;
        let path = pins.directory();
        let directory =
            crate::open_root_owned_public_directory(&path).map_err(|e| e.to_string())?;
        let directory_stat = fstat(&directory).map_err(|e| e.to_string())?;
        if directory_stat.st_uid != 0
            || directory_stat.st_gid != 0
            || directory_stat.st_mode & 0o7777 != 0o755
        {
            return Err("SDK publication directory custody differs".into());
        }
        let raw = crate::read_bounded_regular(&directory, "sdk-publication.v1.json", 8192)
            .map_err(|e| e.to_string())?
            .ok_or("SDK publication receipt missing")?;
        if format!("{:x}", Sha256::digest(&raw)) != pins.publication_sha256 {
            return Err("SDK publication receipt differs from outside pin".into());
        }
        let canonical = gauntlet_contracts::canonicalize(&raw)
            .map_err(|_| "ambiguous SDK publication receipt")?;
        let receipt: Value =
            serde_json::from_slice(&canonical).map_err(|_| "SDK publication receipt JSON")?;
        if raw != canonical
            || receipt["schema"] != "hol-gauntlet-native-sdk-publication.v1"
            || receipt["directory"] != path.to_string_lossy().as_ref()
            || receipt["sdk_version"] != "18.4.12"
            || [
                "sdk_imported",
                "bun_executed",
                "artifact_admitted",
                "execution_eligible",
            ]
            .iter()
            .any(|k| receipt[*k] != false)
            || receipt["model_requests"] != 0
        {
            return Err("SDK publication identity/shape differs".into());
        }
        let input_raw = gauntlet_contracts::canonicalize(receipt["inputs"].to_string().as_bytes())
            .map_err(|e| e.to_string())?;
        let input =
            NativeSdkAssetPins::parse(&input_raw, &format!("{:x}", Sha256::digest(&input_raw)))?;
        if input.sdk_tree_sha256 != pins.sdk_tree_sha256 || input.bun_sha256 != pins.bun_sha256 {
            return Err("SDK publication pins differ from job inputs".into());
        }
        let job = receipt["job_id"]
            .as_str()
            .filter(|s| crate::hex(s, 16))
            .ok_or("SDK publication job missing")?;
        let job = crate::open_root_owned_public_directory(
            &Path::new(crate::native_job_spec::NATIVE_JOBS).join(job),
        )
        .map_err(|e| e.to_string())?;
        let original = crate::read_bounded_regular(&job, "sdk-publication.v1.json", 8192)
            .map_err(|e| e.to_string())?
            .ok_or("SDK job receipt missing")?;
        if original != raw {
            return Err("SDK dual publication receipt changed".into());
        }
        let source = crate::read_bounded_regular(&job, "sdk-source.v1.json", 8192)
            .map_err(|e| e.to_string())?
            .ok_or("SDK source declaration missing")?;
        let source_pin = receipt["source_declaration_sha256"]
            .as_str()
            .ok_or("SDK source pin missing")?;
        if NativeSdkAssetPins::parse(&source, source_pin)? != input {
            return Err("SDK source declaration and receipt differ".into());
        }
        let tree =
            inventory_tree(&path.join("node_modules"), TreeKind::Sdk).map_err(|e| e.to_string())?;
        if tree.digest != pins.sdk_tree_sha256
            || tree.entries as u64 != input.sdk_entries
            || tree.bytes != input.sdk_bytes
        {
            return Err("actual SDK tree differs from outside publication".into());
        }
        crate::native_sdk_asset_publish::verify_bun(&path.join("bun"), &input)?;
        crate::native_sdk_asset_publish::sdk_version(&path)?;
        let bun = File::from(
            openat(
                &directory,
                "bun",
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| e.to_string())?,
        );
        let bun_stat = fstat(&bun).map_err(|e| e.to_string())?;
        let verified = Self {
            pins: pins.clone(),
            input,
            directory,
            directory_stat,
            bun,
            bun_stat,
            tree,
            receipt,
        };
        verified.recheck_custody()?;
        Ok(verified)
    }
    pub fn recheck_custody(&self) -> Result<(), String> {
        let visible = crate::open_root_owned_public_directory(&self.pins.directory())
            .map_err(|e| e.to_string())?;
        for fd in [&self.directory, &visible] {
            let stat = fstat(fd).map_err(|e| e.to_string())?;
            if stat.st_dev != self.directory_stat.st_dev
                || stat.st_ino != self.directory_stat.st_ino
                || stat.st_uid != 0
                || stat.st_gid != 0
                || stat.st_mode != self.directory_stat.st_mode
            {
                return Err("SDK publication directory was replaced".into());
            }
        }
        let visible = openat(
            &self.directory,
            "bun",
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())?;
        for stat in [fstat(&self.bun), fstat(&visible)] {
            if !crate::dependency_prefix_meta::same(
                &self.bun_stat,
                &stat.map_err(|e| e.to_string())?,
            ) {
                return Err("SDK held/visible Bun custody changed".into());
            }
        }
        let raw = crate::read_bounded_regular(&self.directory, "sdk-publication.v1.json", 8192)
            .map_err(|e| e.to_string())?
            .ok_or("SDK receipt disappeared")?;
        if format!("{:x}", Sha256::digest(raw)) != self.pins.publication_sha256 {
            return Err("SDK publication receipt changed".into());
        }
        Ok(())
    }
    pub fn verify_after_cleanup(&self) -> Result<(), String> {
        self.recheck_custody()?;
        let current =
            inventory_tree(&self.sdk_directory(), TreeKind::Sdk).map_err(|e| e.to_string())?;
        if current != self.tree {
            return Err("SDK source tree changed during execution".into());
        }
        crate::native_sdk_asset_publish::verify_bun(&self.bun_path(), &self.input)
    }
    pub fn sdk_directory(&self) -> PathBuf {
        self.pins.directory().join("node_modules")
    }
    pub fn bun_path(&self) -> PathBuf {
        self.pins.directory().join("bun")
    }
    pub fn bun(&self) -> &File {
        &self.bun
    }
    pub fn pins(&self) -> &NativeSdkPins {
        &self.pins
    }
    pub fn observation(&self) -> Value {
        json!({"schema":"hol-gauntlet-verified-native-sdk-assets.v1","pins":self.pins.to_json(),
            "directory":self.pins.directory(),"sdk_entries":self.tree.entries,"sdk_bytes":self.tree.bytes,
            "sdk_version":self.receipt["sdk_version"],"actual_tree_and_bun_verified":true,
            "sdk_imported":false,"execution_eligible":false})
    }
}
