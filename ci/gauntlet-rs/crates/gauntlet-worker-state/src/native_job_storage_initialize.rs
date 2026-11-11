//! Exclusive bounded initialization. Readback never creates or remounts.
use super::{lifecycle::JobVolume, JobStoragePins, JobStorageProfile};
use crate::{native_initialize, RunReservationJournal};
use rustix::fs::{fchown, fsync};
use std::path::Path;

pub fn initialize_native_job_v2(p: &JobStoragePins<'_>, publish: bool) -> Result<Vec<u8>, String> {
    gauntlet_cell_rootfs::require_outside_root()?;
    super::linux::pins_valid(p)?;
    crate::verify_running_binary(p.worker_generation).map_err(|e| e.to_string())?;
    if publish {
        native_initialize::initialize_native_worker(p.worker_generation)?;
    }
    let journal =
        RunReservationJournal::open_root_owned(Path::new(crate::builder_image_context::RUST_STATE))
            .map_err(|e| e.to_string())?;
    let active = journal.acquire_active_lease().map_err(|e| e.to_string())?;
    let python = crate::builder_image_context::python_worker_lock().map_err(|e| e.to_string())?;
    native_initialize::require_unstarted_job(&journal, p.job_id)?;
    if publish {
        let volume = JobVolume::create(p, JobStorageProfile::Native, &journal, &active, &python)?;
        let workspace = crate::feature_files::directory(&volume.root, "workspace", (0, 0), true)?;
        fchown(
            &workspace,
            Some(rustix::process::Uid::from_raw(10001)),
            Some(rustix::process::Gid::from_raw(10001)),
        )
        .and_then(|_| fsync(&workspace))
        .and_then(|_| fsync(&volume.root))
        .map_err(|e| e.to_string())?;
        let body = native_initialize::job_receipt(
            p.source_sha,
            p.job_id,
            p.worker_generation,
            &volume.root,
            &workspace,
            Some(volume.binding()),
        )?;
        volume.verify(p)?;
        let receipts = crate::open_root_owned_public_directory(Path::new(
            "/var/lib/hol-gauntlet-rust/native-initialization",
        ))
        .map_err(|e| e.to_string())?;
        let raw = super::linux::canonical(&body)?;
        crate::feature_files::write(
            &receipts,
            &format!("{}.job.json", p.job_id),
            &raw,
            (0, 0),
            0o600,
        )?;
        super::admission::admit(&volume, &raw)?;
    }
    let (raw, body) =
        native_initialize::job_initialization(p.source_sha, p.job_id, p.worker_generation)?;
    if body["schema"] != "hol-gauntlet-native-job-initialization.v2"
        || body["storage"]["receipt"]["mke2fs_sha256"] != p.mke2fs_sha256
    {
        return Err(
            "bounded initialization differs from original outside formatter/version pin".into(),
        );
    }
    active.verify(&journal.root).map_err(|e| e.to_string())?;
    crate::builder_image_context::verify_python_lock(&python).map_err(|e| e.to_string())?;
    crate::verify_running_binary(p.worker_generation).map_err(|e| e.to_string())?;
    native_initialize::initialization_result(
        &raw,
        "hol-gauntlet-native-job-initialization-result.v2",
    )
}

#[cfg(test)]
#[path = "native_job_storage_fixture.rs"]
mod fixture;

#[cfg(test)]
mod tests {
    use super::fixture::{capacity, file_name, fill, inventory, Runtime};
    use super::*;
    use ring::rand::{SecureRandom, SystemRandom};
    use rustix::fs::{statat, unlinkat, AtFlags};
    impl Runtime {
        pub(super) fn retire(mut self) -> Result<(), String> {
            if !self.closed {
                return Err("fixture runtime teardown not observed".into());
            }
            self.commands.take();
            let logs = crate::feature_files::open_directory(&self.root, "sdk-processes", (0, 0))?;
            for n in 1..=5 {
                for suffix in ["stdout", "stderr"] {
                    rustix::fs::unlinkat(
                        &logs,
                        format!("{n:03}.{suffix}"),
                        rustix::fs::AtFlags::empty(),
                    )
                    .map_err(|e| e.to_string())?;
                }
            }
            super::super::admission::closed_inventory(&logs, &[])?;
            drop(logs);
            rustix::fs::unlinkat(&self.root, "sdk-processes", rustix::fs::AtFlags::REMOVEDIR)
                .map_err(|e| e.to_string())?;
            rustix::fs::unlinkat(
                &self.root,
                "storage-fixture.apparmor",
                rustix::fs::AtFlags::empty(),
            )
            .and_then(|_| rustix::fs::fsync(&self.root))
            .map_err(|e| e.to_string())
        }
    }
    #[test]
    #[ignore = "requires outside Root, both worker leases, pinned mke2fs and2GiB real space plus12GiB reserve"]
    fn bounded_ext4_enforces_bytes_and_inodes_then_restarts_pinned_abort() {
        run_fixture(false).unwrap();
    }
    #[test]
    #[ignore = "requires Root, original2GiB Native volume and pinned frozen VM worker; no candidate/model"]
    fn lost_owner_with_running_runtime_retains_policy_and_cleans_original_resources() {
        run_fixture(true).unwrap();
    }
    fn run_fixture(owner_loss: bool) -> Result<(), String> {
        gauntlet_cell_rootfs::require_outside_root()?;
        let source = std::env::var("GAUNTLET_STORAGE_TEST_SOURCE_SHA")
            .map_err(|_| "outside fixture Source SHA required")?;
        let generation = std::env::var("GAUNTLET_STORAGE_TEST_WORKER_SHA")
            .map_err(|_| "outside fixture executable SHA required")?;
        let formatter = std::env::var("GAUNTLET_STORAGE_TEST_MKE2FS_SHA")
            .map_err(|_| "outside fixture formatter SHA required")?;
        let mut random = [0u8; 8];
        SystemRandom::new()
            .fill(&mut random)
            .map_err(|_| "fresh fixture ID unavailable")?;
        let job = random
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let p = JobStoragePins {
            source_sha: &source,
            job_id: &job,
            worker_generation: &generation,
            mke2fs_sha256: &formatter,
        };
        println!(
            "{}",
            serde_json::json!({"schema":"hol-gauntlet-storage-fixture-start.v1","source_sha":source,"job_id":job,"worker_generation":generation,"mke2fs_sha256":formatter})
        );
        let journal = RunReservationJournal::open_root_owned(Path::new(
            crate::builder_image_context::RUST_STATE,
        ))
        .map_err(|e| e.to_string())?;
        let before_records = inventory(&journal.root)?;
        let active = journal.acquire_active_lease().map_err(|e| e.to_string())?;
        let python =
            crate::builder_image_context::python_worker_lock().map_err(|e| e.to_string())?;
        let volume = JobVolume::create(&p, JobStorageProfile::Native, &journal, &active, &python)?;
        let root = volume.root.try_clone().map_err(|e| e.to_string())?;
        let work = crate::feature_files::directory(&root, "workspace", (0, 0), true)?;
        fchown(
            &work,
            Some(rustix::process::Uid::from_raw(10001)),
            Some(rustix::process::Gid::from_raw(10001)),
        )
        .map_err(|e| e.to_string())?;
        let identities = volume.binding();
        let kernel_options = super::super::linux::kernel_options(&volume.device.file)?;
        let active_stat = statat(&journal.root, "active.lock", AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|e| e.to_string())?;
        let python_stat =
            std::fs::metadata("/opt/hol-gauntlet/worker.lock").map_err(|e| e.to_string())?;
        use std::os::unix::fs::MetadataExt;
        let locks = serde_json::json!({"active":{"device":active_stat.st_dev,"inode":active_stat.st_ino},"python":{"device":python_stat.dev(),"inode":python_stat.ino()}});
        let measurements = (|| -> Result<serde_json::Value, String> {
            let mut temporary = Vec::new();
            let mut loss = serde_json::Value::Null;
            for (scope, inodes) in [
                (super::super::temporary::Scope::Sdk, false),
                (super::super::temporary::Scope::Mcp, true),
            ] {
                let mut runtime =
                    Runtime::new_scoped(&JobStorageProfile::Native.root(&job)?, &job, Some(scope))?;
                let path = Path::new(super::super::lifecycle::BASE)
                    .join(&job)
                    .join("temporary")
                    .join(scope.name());
                let metadata =
                    crate::open_root_owned_public_directory(&path).map_err(|e| e.to_string())?;
                let tmp = rustix::fs::openat(
                    &metadata,
                    "tmp",
                    rustix::fs::OFlags::RDONLY
                        | rustix::fs::OFlags::DIRECTORY
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                )
                .map_err(|e| e.to_string())?;
                let filled = fill(&tmp, inodes)?;
                let cap = capacity(&tmp)?;
                if filled["errno"] != libc::ENOSPC
                    || filled["uid"] != 10001
                    || filled["gid"] != 10001
                    || if inodes {
                        cap["free_inodes"] != 0 || cap["free_blocks"].as_u64() == Some(0)
                    } else {
                        cap["free_inodes"].as_u64() == Some(0)
                    }
                {
                    return Err(
                        "actual finite temporary bind did not independently enforce bytes/inodes"
                            .into(),
                    );
                }
                drop(tmp);
                if owner_loss && scope == super::super::temporary::Scope::Mcp {
                    loss = runtime.lose_owner(&job, &p)?;
                }
                let teardown = runtime.close()?;
                super::super::temporary::require_absent(&job, scope)?;
                let read = |name| -> Result<serde_json::Value, String> {
                    serde_json::from_slice(&crate::feature_files::required(
                        &metadata,
                        name,
                        (0, 0),
                        0o600,
                        24576,
                    )?)
                    .map_err(|e| e.to_string())
                };
                temporary.push(serde_json::json!({"scope":scope.name(),"filled":filled,"capacity":cap,
                    "inside":read("inside.json")?,"closed":read("closed.json")?,"teardown":teardown}));
                runtime.retire()?;
            }
            if owner_loss {
                return Ok(
                    serde_json::json!({"mode":"owner-loss-runtime","temporary":temporary,"owner_loss":loss}),
                );
            }
            let mut runtime = Runtime::new(&JobStorageProfile::Native.root(&job)?, &job)?;
            let bytes = fill(&work, false)?;
            let byte_capacity = capacity(&work)?;
            if bytes["errno"] != libc::ENOSPC
                || bytes["uid"] != 10001
                || bytes["gid"] != 10001
                || !bytes["written_bytes"]
                    .as_u64()
                    .is_some_and(|n| n > 0 && n <= JobStorageProfile::Native.bytes())
                || byte_capacity["free_inodes"].as_u64() == Some(0)
            {
                return Err("byte ceiling did not produce independent actual ENOSPC".into());
            }
            let byte_teardown = runtime.close()?;
            unlinkat(&work, "byte-enospc", AtFlags::empty())
                .and_then(|_| fsync(&work))
                .map_err(|e| e.to_string())?;
            runtime.retire()?;
            let mut runtime = Runtime::new(&JobStorageProfile::Native.root(&job)?, &job)?;
            let inodes = fill(&work, true)?;
            let inode_capacity = capacity(&work)?;
            if inodes["errno"] != libc::ENOSPC
                || inodes["uid"] != 10001
                || inodes["gid"] != 10001
                || !inodes["created_files"]
                    .as_u64()
                    .is_some_and(|n| n > 0 && n <= 65536)
                || inode_capacity["free_inodes"] != 0
                || inode_capacity["free_blocks"].as_u64() == Some(0)
            {
                return Err("inode ceiling did not produce independent actual ENOSPC".into());
            }
            let inode_teardown = runtime.close()?;
            for n in 0..inodes["created_files"]
                .as_u64()
                .ok_or("fixture inode count absent")?
            {
                unlinkat(&work, file_name(n).as_str(), AtFlags::empty())
                    .map_err(|e| e.to_string())?;
            }
            fsync(&work).map_err(|e| e.to_string())?;
            runtime.retire()?;
            volume.verify(&p)?;
            active.verify(&journal.root).map_err(|e| e.to_string())?;
            crate::builder_image_context::verify_python_lock(&python).map_err(|e| e.to_string())?;
            Ok(
                serde_json::json!({"kernel_options":kernel_options,"temporary":temporary,"bytes":bytes,"byte_capacity":byte_capacity,"byte_teardown":byte_teardown,"inodes":inodes,"inode_capacity":inode_capacity,"inode_teardown":inode_teardown}),
            )
        })();
        // Only exact files made by this fresh fixture can be removed.
        for name in std::iter::once("byte-enospc".to_owned()).chain((0..=65536).map(file_name)) {
            match unlinkat(&work, name.as_str(), AtFlags::empty()) {
                Ok(()) | Err(rustix::io::Errno::NOENT) => {}
                Err(e) => return Err(e.to_string()),
            }
        }
        fsync(&work).map_err(|e| e.to_string())?;
        super::super::admission::closed_inventory(&work, &[])?;
        // Reproduce a crash between the initial Root mkdir and UID transfer.
        fchown(
            &work,
            Some(rustix::process::Uid::ROOT),
            Some(rustix::process::Gid::ROOT),
        )
        .and_then(|_| fsync(&work))
        .map_err(|e| e.to_string())?;
        if owner_loss {
            JobVolume::read_for_cleanup(&p, JobStorageProfile::Native)?;
        } else {
            volume.verify(&p)?;
        }
        drop(work);
        drop(root);
        drop(volume);
        drop(python);
        drop(active);
        // Reopen after dropping every mount/loop/lease FD, as a restarted owner.
        let retired = super::super::retire::abort_native_job_storage(
            &p,
            JobStorageProfile::Native,
            &generation,
            true,
        )?;
        if super::super::retire::abort_native_job_storage(
            &p,
            JobStorageProfile::Native,
            &generation,
            false,
        )? != retired
        {
            return Err("read-only restarted retirement differs".into());
        }
        super::super::admission::require_complete()?;
        if inventory(&journal.root)? != before_records {
            return Err("fixture changed historical worker record inventory".into());
        }
        let measurements = measurements?;
        let receipts = crate::open_root_owned_public_directory(Path::new(
            "/var/lib/hol-gauntlet-rust/native-initialization",
        ))
        .map_err(|e| e.to_string())?;
        let evidence = serde_json::json!({"schema":"hol-gauntlet-job-storage-fixture.v1","job_id":job,"source_sha":source,"worker_generation":generation,"storage":identities,"leases":locks,"measurements":measurements,"retirement":serde_json::from_slice::<serde_json::Value>(&retired).map_err(|e|e.to_string())?,"worker_records_unchanged":true,"candidate_executed":false,"model_requests":0});
        crate::feature_files::write(
            &receipts,
            &format!("{job}.storage-fixture.json"),
            &super::super::linux::canonical(&evidence)?,
            (0, 0),
            0o600,
        )?;
        println!(
            "{}",
            serde_json::json!({"job_id":job,"storage_fixture":"passed","model_requests":0})
        );
        Ok(())
    }

    #[test]
    #[ignore = "requires Root and an outside-pinned frozen VM worker; creates one real private namespace owner"]
    fn lost_namespace_owner_blocks_reentry_and_empty_abort_restores_original_namespace() {
        owner_loss().unwrap();
    }
    fn owner_loss() -> Result<(), String> {
        use super::super::{admission, linux, owner};
        gauntlet_cell_rootfs::require_outside_root()?;
        let source = std::env::var("GAUNTLET_STORAGE_TEST_SOURCE_SHA")
            .map_err(|_| "outside fixture Source SHA required")?;
        let generation = std::env::var("GAUNTLET_STORAGE_TEST_WORKER_SHA")
            .map_err(|_| "outside fixture executable SHA required")?;
        let formatter = std::env::var("GAUNTLET_STORAGE_TEST_MKE2FS_SHA")
            .map_err(|_| "outside fixture formatter SHA required")?;
        let mut random = [0; 8];
        SystemRandom::new()
            .fill(&mut random)
            .map_err(|_| "fresh fixture ID unavailable")?;
        let job = random
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let p = JobStoragePins {
            source_sha: &source,
            job_id: &job,
            worker_generation: &generation,
            mke2fs_sha256: &formatter,
        };
        println!(
            "{}",
            serde_json::json!({"schema":"hol-gauntlet-storage-owner-loss-fixture-start.v1","source_sha":source,"job_id":job,"worker_generation":generation,"mke2fs_sha256":formatter})
        );
        let _restore = owner::scope()?;
        let original = owner::descriptor(&owner::current()?)?;
        let journal = RunReservationJournal::open_root_owned(Path::new(
            crate::builder_image_context::RUST_STATE,
        ))
        .map_err(|e| e.to_string())?;
        let before_records = inventory(&journal.root)?;
        let active = journal.acquire_active_lease().map_err(|e| e.to_string())?;
        let python =
            crate::builder_image_context::python_worker_lock().map_err(|e| e.to_string())?;
        native_initialize::require_unstarted_job(&journal, &job)?;
        admission::require_complete()?;
        let receipt = owner::create(&p, JobStorageProfile::Native)?;
        if receipt["original_namespace"] != original || receipt["namespace"] == original {
            return Err("fixture owner did not isolate original namespace".into());
        }
        let held = owner::lose_fixture_owner(&job)?;
        if owner::health().is_ok() || owner::enter_pinned(&source, &job, &generation).is_ok() {
            return Err("lost owner permitted runtime reentry".into());
        }
        owner::restore_original(&job, &held)?;
        if owner::descriptor(&owner::current()?)? != original {
            return Err("fixture did not restore caller namespace".into());
        }
        drop(held);
        drop(python);
        drop(active);
        let retired = super::super::retire::abort_native_job_storage(
            &p,
            JobStorageProfile::Native,
            &generation,
            true,
        )?;
        if super::super::retire::abort_native_job_storage(
            &p,
            JobStorageProfile::Native,
            &generation,
            false,
        )? != retired
        {
            return Err("owner-only abort readback changed".into());
        }
        owner::verify_finished(&job)?;
        if owner::enter(&job).is_ok() || inventory(&journal.root)? != before_records {
            return Err("fixture owner replay or historical inventory changed".into());
        }
        admission::require_complete()?;
        let receipts = crate::open_root_owned_public_directory(Path::new(
            "/var/lib/hol-gauntlet-rust/native-initialization",
        ))
        .map_err(|e| e.to_string())?;
        let evidence = serde_json::json!({"schema":"hol-gauntlet-storage-owner-loss-fixture.v1","source_sha":source,"job_id":job,"worker_generation":generation,"owner":receipt,"retirement":serde_json::from_slice::<serde_json::Value>(&retired).map_err(|e|e.to_string())?,"original_namespace_restored":true,"replay_refused":true,"worker_records_unchanged":true,"candidate_executed":false,"model_requests":0});
        crate::feature_files::write(
            &receipts,
            &format!("{job}.storage-owner-fixture.json"),
            &linux::canonical(&evidence)?,
            (0, 0),
            0o600,
        )?;
        println!(
            "{}",
            serde_json::json!({"job_id":job,"owner_loss_fixture":"passed","model_requests":0})
        );
        Ok(())
    }
}
