//! Read-only projection of durable journal state into the fixed worker wire
//! response. It never infers a live process from a started marker alone.

use crate::{hex, ReservationError, RunReservationJournal, TerminalOutcome, TerminalReceipt};
use gauntlet_contracts::{canonicalize, WorkerAction, WorkerRequest, WorkerResponse};
use serde_json::{json, Value};

fn terminal_value(receipt: TerminalReceipt) -> Value {
    let status = match receipt.status {
        TerminalOutcome::Passed => "passed",
        TerminalOutcome::Failed => "failed",
        TerminalOutcome::InvalidEvidence => "invalid-evidence",
    };
    json!({
        "state": "terminal",
        "deployment_digest": receipt.deployment_digest,
        "started_marker_sha256": receipt.started_marker_sha256,
        "report_sha256": receipt.report_sha256,
        "exit_code": receipt.exit_code,
        "status": status,
    })
}

impl RunReservationJournal {
    /// Return an exact v1 response for a passive shadow worker. `inspect` is
    /// unavailable, and an unstarted `run` is unavailable until a trusted
    /// deployment reader and dispatcher exist. A started job without a verified
    /// terminal remains unknown; the host must never retry it.
    pub fn project_read_only(
        &self,
        request: &WorkerRequest,
        expected_source_sha: &str,
        expected_deployment_digest: Option<&str>,
        expected_worker_generation: &str,
    ) -> Result<Vec<u8>, ReservationError> {
        if request.source_sha() != expected_source_sha
            || !hex(expected_worker_generation, 64)
            || expected_deployment_digest.is_some_and(|pin| !hex(pin, 64))
        {
            return Err(ReservationError::InvalidPins);
        }
        if request.action() == WorkerAction::Run
            && !expected_deployment_digest
                .is_some_and(|pin| request.matches_deployment(expected_source_sha, pin))
        {
            return Err(ReservationError::WrongRequest);
        }
        let state = match request.action() {
            WorkerAction::Inspect => json!({"state":"unavailable"}),
            WorkerAction::Progress | WorkerAction::Reconcile | WorkerAction::Run => {
                if let Some(deployment) = expected_deployment_digest {
                    match self.terminal(
                        request.job_id(),
                        expected_source_sha,
                        deployment,
                        expected_worker_generation,
                    ) {
                        Ok(Some(receipt)) => terminal_value(receipt),
                        Ok(None)
                            if matches!(
                                request.action(),
                                WorkerAction::Progress | WorkerAction::Run
                            ) =>
                        {
                            match self.started(
                                request.job_id(),
                                expected_source_sha,
                                deployment,
                                expected_worker_generation,
                            ) {
                                Ok(None) if request.action() == WorkerAction::Progress => {
                                    json!({"state":"not-started"})
                                }
                                Ok(None) => json!({"state":"unavailable"}),
                                Ok(Some(_)) | Err(ReservationError::InvalidMarker) => {
                                    json!({"state":"unknown"})
                                }
                                Err(_) => json!({"state":"unavailable"}),
                            }
                        }
                        Ok(None) | Err(ReservationError::InvalidMarker) => {
                            json!({"state":"unknown"})
                        }
                        Err(_) => json!({"state":"unavailable"}),
                    }
                } else {
                    json!({"state":"unavailable"})
                }
            }
        };
        let mut response = json!({
            "schema": "hol-gauntlet-worker-response.v1",
            "action": request.action().as_str(),
            "source_sha": request.source_sha(),
            "job_id": request.job_id(),
            "worker_generation": expected_worker_generation,
        });
        response
            .as_object_mut()
            .expect("response has fixed object shape")
            .extend(
                state
                    .as_object()
                    .expect("state has fixed object shape")
                    .clone(),
            );
        let bytes = canonicalize(response.to_string().as_bytes())
            .map_err(|_| ReservationError::InvalidMarker)?;
        WorkerResponse::parse(&bytes)
            .map_err(|_| ReservationError::InvalidMarker)?
            .bind_request(
                request,
                expected_worker_generation,
                expected_deployment_digest,
            )
            .map_err(|_| ReservationError::InvalidMarker)?;
        Ok(bytes)
    }
}
