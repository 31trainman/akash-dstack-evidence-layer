use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::Deserialize;
use serde_json::{json, Value};
use sev::firmware::guest::AttestationReport;
use verifier::{
    snp::Snp,
    InitDataHash,
    ReportData,
    Verifier,
};

#[derive(Debug, Deserialize)]
pub struct AkashSnpEnvelope {
    /// Base64-encoded raw AMD SEV-SNP attestation report.
    pub report: String,

    /// Akash may provide an empty string when no certificate chain is bundled.
    /// Trustee can fetch VCEK from AMD KDS when cert_chain is absent.
    #[serde(default)]
    pub cert_chain: String,

    #[serde(default)]
    pub tee_platform: Option<String>,
}

#[derive(Debug)]
pub struct VerifiedSnp {
    pub claims: Vec<(Value, String)>,
}

/// Convert an Akash sidecar envelope into the JSON structure expected by
/// Trustee's SNP verifier.
///
/// We intentionally set cert_chain = null here. Trustee's verifier then uses
/// its configured AMD VCEK source (KDS by default) and validates the chain,
/// report signature, TCB, VMPL and expected REPORT_DATA.
pub fn akash_envelope_to_trustee_evidence(input: &AkashSnpEnvelope) -> Result<Value> {
    let raw = B64
        .decode(input.report.as_bytes())
        .context("decode Akash base64 SNP report")?;

    let report = AttestationReport::from_bytes(&raw)
        .context("parse AMD SEV-SNP attestation report")?;

    Ok(json!({
        "attestation_report": report,
        "cert_chain": null
    }))
}

/// Verify real SEV-SNP evidence using Trustee's production verifier.
///
/// `expected_report_data` should be the 32-byte workload commitment from v0.7.
/// Trustee regularizes it to the SNP 64-byte REPORT_DATA field and checks it
/// against the signed report.
///
/// `expected_init_data_hash` is optional because the current binding prototype
/// may verify Init-Data elsewhere in the Trustee pipeline. When available,
/// pass the actual expected digest rather than None.
pub async fn verify_akash_snp(
    envelope: &AkashSnpEnvelope,
    expected_report_data: &[u8],
    expected_init_data_hash: Option<&[u8]>,
) -> Result<VerifiedSnp> {
    if expected_report_data.len() > 64 {
        bail!("expected REPORT_DATA must be <=64 bytes for SNP");
    }

    let evidence = akash_envelope_to_trustee_evidence(envelope)?;
    let snp = Snp::new(None).await.context("initialize Trustee SNP verifier")?;

    let init = match expected_init_data_hash {
        Some(v) => InitDataHash::Value(v),
        None => InitDataHash::NotProvided,
    };

    let claims = snp
        .evaluate(
            evidence,
            &ReportData::Value(expected_report_data),
            &init,
        )
        .await
        .context("Trustee SEV-SNP verification failed")?;

    Ok(VerifiedSnp { claims })
}
