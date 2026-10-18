//! Bounded batches avoid restarting the complete closure per missing object.
use super::*;
#[derive(Default)]
pub(super) struct Transfers {
    requests: Vec<Value>,
    seen: BTreeSet<String>,
}
impl Transfers {
    pub(super) fn push(&mut self, error: Failure) -> Result<()> {
        let value = match error {
            Failure::Need(reference) => json!({"need":reference}),
            Failure::Archives(archives) => json!({"need_archives":archives}),
            error => return Err(error),
        };
        if self.requests.len() < 32 && self.seen.insert(hash(&encoded(&value)?)) {
            self.requests.push(value);
        }
        Ok(())
    }
    pub(super) fn finish(self) -> Result<()> {
        if self.requests.is_empty() {
            Ok(())
        } else {
            Err(Failure::Batch(self.requests))
        }
    }
}
pub(super) fn prefetch(
    preparation: &mut Preparation<'_>,
    selected: &BTreeSet<String>,
) -> Result<()> {
    let mut transfers = Transfers::default();
    for id in selected {
        if preparation.input["profile"] == "committed-subset"
            && !preparation.committed_selected.contains(id)
        {
            return Err("offline subset cannot activate uncommitted policy".into());
        }
        if let Err(error) = preparation.metadata(id) {
            transfers.push(error)?;
        }
    }
    transfers.finish()?;
    let mut transfers = Transfers::default();
    for id in selected {
        let (record, _) = preparation.details.get(id).ok_or_else(invalid)?;
        if let Err(error) = metadata::revocation(
            preparation.directory,
            &preparation.root,
            id,
            &record["manifest"],
        ) {
            transfers.push(error)?;
            continue;
        }
        let manifest = match proofs::policy_object(
            preparation.directory,
            &record["manifest"],
            &record["archives"],
        ) {
            Ok(value) => value,
            Err(error) => {
                transfers.push(error)?;
                continue;
            }
        };
        for field in ["program", "catalog", "descriptors"] {
            let value = match proofs::policy_object(
                preparation.directory,
                &manifest[field],
                &record["archives"],
            ) {
                Ok(value) => value,
                Err(error) => {
                    transfers.push(error)?;
                    continue;
                }
            };
            if field == "program" {
                for reference in value["nodes"].as_object().ok_or_else(invalid)?.values() {
                    if let Err(error) =
                        proofs::policy_object(preparation.directory, reference, &record["archives"])
                    {
                        transfers.push(error)?;
                        break;
                    }
                }
            }
        }
    }
    transfers.finish()
}
