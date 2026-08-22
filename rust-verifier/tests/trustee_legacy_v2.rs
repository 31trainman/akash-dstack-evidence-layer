use akash_coco_snp_verifier::ExpectedWorkloadCommitment;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde_json::json;
use sev::{
    certs::snp::{Certificate, Verifiable},
    firmware::guest::AttestationReport,
    parser::ByteParser,
};
use verifier::{snp::Snp, InitDataHash, ReportData, Verifier};

const COMMITMENT_HEX: &str = "ec6c52d7533cc2c4f45be7849cf112ab82b2009fe7bd43e71ed08c14400ad7e2";

fn legacy_report_bytes() -> Vec<u8> {
    B64.decode(include_str!("fixtures/trustee-test-report.b64").trim())
        .expect("legacy Trustee report must be base64")
}

fn legacy_vcek_bytes() -> Vec<u8> {
    B64.decode(include_str!("fixtures/trustee-test-vcek.b64").trim())
        .expect("legacy Trustee VCEK must be base64")
}

fn legacy_evidence() -> serde_json::Value {
    let report = AttestationReport::from_bytes(&legacy_report_bytes())
        .expect("legacy Trustee report must parse");
    json!({
        "attestation_report": report,
        "cert_chain": [{"cert_type": "VCEK", "data": legacy_vcek_bytes()}]
    })
}

#[test]
fn legacy_v2_report_and_vcek_are_a_matching_signed_pair() {
    let report = AttestationReport::from_bytes(&legacy_report_bytes())
        .expect("legacy Trustee report must parse");
    let vcek =
        Certificate::from_bytes(&legacy_vcek_bytes()).expect("legacy Trustee VCEK must parse");

    assert_eq!(
        report.version, 2,
        "fixture classification must remain explicit"
    );
    (&vcek, &report)
        .verify()
        .expect("unchanged legacy VCEK must verify the unchanged signed report");
}

#[tokio::test]
async fn pinned_trustee_full_evaluator_rejects_legacy_report_version_2() {
    let report = AttestationReport::from_bytes(&legacy_report_bytes())
        .expect("legacy Trustee report must parse");
    assert_eq!(report.version, 2);

    let commitment = ExpectedWorkloadCommitment::parse(COMMITMENT_HEX).unwrap();
    let snp = Snp::new(None)
        .await
        .expect("Trustee SNP verifier must initialize");
    let error = snp
        .evaluate(
            legacy_evidence(),
            &ReportData::Value(commitment.as_bytes()),
            &InitDataHash::NotProvided,
        )
        .await
        .expect_err("pinned Trustee must reject legacy report version 2");

    assert!(
        error
            .to_string()
            .contains("Attestation Report version is too old"),
        "unexpected pinned Trustee rejection: {error:#}"
    );
}
