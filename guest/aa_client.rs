use anyhow::{Context, Result};
use protocols::attestation_agent::{GetEvidenceRequest, GetEvidenceResponse};
use protocols::attestation_agent_ttrpc_async::AttestationAgentServiceClient;

/// Ask the in-guest Confidential Containers Attestation Agent for fresh
/// evidence whose runtime-data field is the workload commitment.
pub async fn get_bound_evidence(
    aa_socket_uri: &str,
    commitment: [u8; 32],
) -> Result<Vec<u8>> {
    let client = ttrpc::asynchronous::Client::connect(aa_socket_uri)
        .await
        .context("connect to Attestation Agent")?;
    let aa = AttestationAgentServiceClient::new(client);

    let req = GetEvidenceRequest {
        RuntimeData: commitment.to_vec(),
        ..Default::default()
    };

    let GetEvidenceResponse { Evidence, .. } = aa
        .get_evidence(ttrpc::context::with_timeout(10_000_000_000), &req)
        .await
        .context("Attestation Agent GetEvidence failed")?;

    if Evidence.is_empty() {
        anyhow::bail!("Attestation Agent returned empty evidence");
    }
    Ok(Evidence)
}
