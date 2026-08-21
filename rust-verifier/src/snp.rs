use crate::{
    ErrorCategory, ExpectedWorkloadCommitment, VerificationError, VerificationRequest,
    VerificationSuccess,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde_json::json;
use sev::firmware::guest::AttestationReport;
use sev::parser::ByteParser;
use verifier::{snp::Snp, InitDataHash, ReportData, Verifier};

pub async fn verify_request(
    request: &VerificationRequest,
) -> Result<VerificationSuccess, VerificationError> {
    let commitment = ExpectedWorkloadCommitment::parse(&request.expected_workload_commitment_hex)?;
    let raw_report = B64
        .decode(request.evidence.report_b64.as_bytes())
        .map_err(|_| {
            VerificationError::new(
                ErrorCategory::MalformedEvidence,
                "SEV-SNP report is not valid base64",
            )
        })?;
    let report = AttestationReport::from_bytes(&raw_report).map_err(|_| {
        VerificationError::new(
            ErrorCategory::InvalidReport,
            "SEV-SNP report could not be parsed",
        )
    })?;

    // The Akash envelope currently does not provide Trustee's typed certificate
    // table. Trustee therefore uses its configured VCEK source and performs the
    // complete chain, signature, TCB, VMPL, and REPORT_DATA verification.
    let evidence = json!({
        "attestation_report": report,
        "cert_chain": null
    });
    let snp = Snp::new(None).await.map_err(|_| {
        VerificationError::new(
            ErrorCategory::VerifierUnavailable,
            "Trustee SEV-SNP verifier could not be initialized",
        )
    })?;

    let init_data_storage = request
        .expected_init_data_hash_hex
        .as_deref()
        .map(ExpectedWorkloadCommitment::parse)
        .transpose()?;
    let init_data = match init_data_storage.as_ref() {
        Some(value) => InitDataHash::Value(value.as_bytes()),
        None => InitDataHash::NotProvided,
    };

    // Trustee's pinned API exposes anyhow errors rather than stable typed
    // signature/policy/binding variants. All evaluate failures are therefore
    // conservatively source-classified as VerificationFailed.
    snp.evaluate(
        evidence,
        &ReportData::Value(commitment.as_bytes()),
        &init_data,
    )
    .await
    .map_err(|_| {
        VerificationError::new(
            ErrorCategory::VerificationFailed,
            "Trustee rejected the SEV-SNP evidence",
        )
    })?;

    Ok(VerificationSuccess::new())
}
