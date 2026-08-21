use akash_coco_snp_verifier::ExpectedWorkloadCommitment;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde_json::json;
use sev::firmware::guest::AttestationReport;
use sev::parser::ByteParser;
use verifier::{snp::Snp, InitDataHash, ReportData, Verifier};

const COMMITMENT_HEX: &str = "ec6c52d7533cc2c4f45be7849cf112ab82b2009fe7bd43e71ed08c14400ad7e2";

fn fixture_evidence() -> serde_json::Value {
    let report = B64
        .decode(include_str!("fixtures/trustee-test-report.b64").trim())
        .expect("fixture report must be base64");
    let report = AttestationReport::from_bytes(&report).expect("fixture report must parse");
    let vcek = B64
        .decode(include_str!("fixtures/trustee-test-vcek.b64").trim())
        .expect("fixture VCEK must be base64");
    json!({
        "attestation_report": report,
        "cert_chain": [{"cert_type": "VCEK", "data": vcek}]
    })
}

#[tokio::test]
async fn trustee_proves_exact_32_byte_report_data_semantics() {
    let commitment = ExpectedWorkloadCommitment::parse(COMMITMENT_HEX).unwrap();
    let snp = Snp::new(None)
        .await
        .expect("Trustee SNP verifier must initialize");

    snp.evaluate(
        fixture_evidence(),
        &ReportData::Value(commitment.as_bytes()),
        &InitDataHash::NotProvided,
    )
    .await
    .expect("valid signed fixture and exact 32-byte commitment must verify");

    let mut wrong = *commitment.as_bytes();
    wrong[0] ^= 1;
    snp.evaluate(
        fixture_evidence(),
        &ReportData::Value(&wrong),
        &InitDataHash::NotProvided,
    )
    .await
    .expect_err("one-bit commitment mismatch must fail Trustee verification");
}
