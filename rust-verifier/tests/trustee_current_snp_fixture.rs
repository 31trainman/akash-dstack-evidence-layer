use serde_json::json;
use sev::{firmware::guest::AttestationReport, parser::ByteParser};
use sha2::{Digest, Sha256};
use std::{env, fs, path::PathBuf};
use verifier::{snp::Snp, InitDataHash, ReportData, Verifier};

const COMMITMENT_HEX: &str = "a9101838fe1e450778a358747803d6ea9b3ff4563f77a79727d42923eeb3cf5a";

#[test]
fn public_fixture_commitment_is_reproducible() {
    assert_eq!(
        hex::encode(Sha256::digest(b"akash-dstack-trustee-snp-fixture-v1")),
        COMMITMENT_HEX
    );
}

#[tokio::test]
#[ignore = "requires a genuine current hardware fixture; run scripts/validate-snp-fixture.sh"]
async fn trustee_current_fixture_exact_commitment_and_mutation() {
    let fixture = env::var_os("SNP_FIXTURE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("tests/fixtures/snp-v3-current"));
    let raw_report = fs::read(fixture.join("report.bin")).expect("missing captured report.bin");
    assert_eq!(raw_report.len(), 1184, "raw SNP report must be 1,184 bytes");
    let report = AttestationReport::from_bytes(&raw_report).expect("captured report must parse");
    let vcek = fs::read(fixture.join("vcek.der")).expect("missing captured vcek.der");
    let commitment: [u8; 32] = hex::decode(COMMITMENT_HEX).unwrap().try_into().unwrap();
    let snp = Snp::new(None)
        .await
        .expect("Trustee SNP verifier must initialize");

    let evidence = || {
        json!({
            "attestation_report": report,
            "cert_chain": [{"cert_type": "VCEK", "data": vcek}]
        })
    };
    snp.evaluate(
        evidence(),
        &ReportData::Value(&commitment),
        &InitDataHash::NotProvided,
    )
    .await
    .expect("exact public 32-byte commitment must pass pinned Trustee");

    let mut wrong = commitment;
    wrong[0] ^= 1;
    snp.evaluate(
        evidence(),
        &ReportData::Value(&wrong),
        &InitDataHash::NotProvided,
    )
    .await
    .expect_err("one-bit expected-commitment mutation must fail pinned Trustee");
}
