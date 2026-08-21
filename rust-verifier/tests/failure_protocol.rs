use akash_coco_snp_verifier::{parse_request, ErrorCategory};

#[test]
fn missing_report_is_malformed_evidence() {
    let request = format!(
        r#"{{"protocol_version":1,"evidence_type":"sev-snp","evidence":{{"report_b64":"","cert_chain":""}},"expected_workload_commitment_hex":"{}","expected_init_data_hash_hex":null}}"#,
        "11".repeat(32)
    );
    let error = parse_request(request.as_bytes()).unwrap_err();
    assert_eq!(error.category, ErrorCategory::MalformedEvidence);
}

#[test]
fn unsupported_evidence_is_source_classified() {
    let request = format!(
        r#"{{"protocol_version":1,"evidence_type":"tdx","evidence":{{"report_b64":"AA==","cert_chain":""}},"expected_workload_commitment_hex":"{}","expected_init_data_hash_hex":null}}"#,
        "11".repeat(32)
    );
    let error = parse_request(request.as_bytes()).unwrap_err();
    assert_eq!(error.category, ErrorCategory::UnsupportedEvidence);
}
