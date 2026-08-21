use crate::error::{ErrorCategory, VerificationError};
use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u8 = 1;
pub const MAX_REQUEST_BYTES: usize = 1024 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 4096;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationRequest {
    pub protocol_version: u8,
    pub evidence_type: String,
    pub evidence: SnpEvidenceInput,
    pub expected_workload_commitment_hex: String,
    #[serde(default)]
    pub expected_init_data_hash_hex: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnpEvidenceInput {
    pub report_b64: String,
    #[serde(default)]
    pub cert_chain: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedWorkloadCommitment([u8; 32]);

impl ExpectedWorkloadCommitment {
    pub fn parse(value: &str) -> Result<Self, VerificationError> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(VerificationError::new(
                ErrorCategory::InvalidInput,
                "expected workload commitment must be exactly 32 lowercase hexadecimal bytes",
            ));
        }
        let decoded = hex::decode(value).map_err(|_| {
            VerificationError::new(
                ErrorCategory::InvalidInput,
                "expected workload commitment is not valid hexadecimal",
            )
        })?;
        let bytes: [u8; 32] = decoded.try_into().map_err(|_| {
            VerificationError::new(
                ErrorCategory::InvalidInput,
                "expected workload commitment must decode to exactly 32 bytes",
            )
        })?;
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Debug, Serialize)]
pub struct VerificationSuccess {
    pub protocol_version: u8,
    pub outcome: &'static str,
    pub security: SecurityClaims,
    pub metadata: InformationalMetadata,
}

impl VerificationSuccess {
    pub const fn new() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            outcome: "verified",
            security: SecurityClaims {
                tee: "sev-snp",
                verification_profile: "trustee-sev-snp-v1",
                report_data_binding: "verified",
            },
            metadata: InformationalMetadata {
                verifier: "confidential-containers-trustee",
                protocol: "akash-dstack-rust-verifier-v1",
            },
        }
    }
}

impl Default for VerificationSuccess {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Serialize)]
pub struct SecurityClaims {
    pub tee: &'static str,
    pub verification_profile: &'static str,
    pub report_data_binding: &'static str,
}

#[derive(Debug, Serialize)]
pub struct InformationalMetadata {
    pub verifier: &'static str,
    pub protocol: &'static str,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub protocol_version: u8,
    pub outcome: &'static str,
    pub error: ErrorBody,
}

impl From<&VerificationError> for ErrorResponse {
    fn from(error: &VerificationError) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            outcome: "error",
            error: ErrorBody {
                category: error.category,
                code: error.category.code(),
                message: error.message,
            },
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub category: ErrorCategory,
    pub code: &'static str,
    pub message: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum ProtocolResponse {
    Verified(VerificationSuccess),
    Error(ErrorResponse),
}

pub fn parse_request(input: &[u8]) -> Result<VerificationRequest, VerificationError> {
    if input.is_empty() || input.len() > MAX_REQUEST_BYTES {
        return Err(VerificationError::new(
            ErrorCategory::InvalidInput,
            "verification request is empty or exceeds the maximum size",
        ));
    }
    let request: VerificationRequest = serde_json::from_slice(input).map_err(|_| {
        VerificationError::new(
            ErrorCategory::InvalidInput,
            "verification request is not valid protocol JSON",
        )
    })?;
    if request.protocol_version != PROTOCOL_VERSION {
        return Err(VerificationError::new(
            ErrorCategory::InvalidInput,
            "unsupported verification protocol version",
        ));
    }
    if request.evidence_type != "sev-snp" {
        return Err(VerificationError::new(
            ErrorCategory::UnsupportedEvidence,
            "unsupported evidence type",
        ));
    }
    if request.evidence.report_b64.is_empty() {
        return Err(VerificationError::new(
            ErrorCategory::MalformedEvidence,
            "SEV-SNP report is missing",
        ));
    }
    ExpectedWorkloadCommitment::parse(&request.expected_workload_commitment_hex)?;
    if let Some(init_data) = &request.expected_init_data_hash_hex {
        ExpectedWorkloadCommitment::parse(init_data).map_err(|_| {
            VerificationError::new(
                ErrorCategory::InvalidInput,
                "expected Init-Data hash must be exactly 32 lowercase hexadecimal bytes",
            )
        })?;
    }
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(commitment: &str) -> Vec<u8> {
        format!(
            r#"{{"protocol_version":1,"evidence_type":"sev-snp","evidence":{{"report_b64":"AA==","cert_chain":""}},"expected_workload_commitment_hex":"{commitment}","expected_init_data_hash_hex":null}}"#
        )
        .into_bytes()
    }

    #[test]
    fn accepts_exact_32_byte_commitment() {
        let parsed = parse_request(&request(&"ab".repeat(32))).unwrap();
        assert_eq!(
            ExpectedWorkloadCommitment::parse(&parsed.expected_workload_commitment_hex)
                .unwrap()
                .as_bytes(),
            &[0xab; 32]
        );
    }

    #[test]
    fn rejects_non_exact_or_non_lowercase_commitment() {
        for invalid in [
            "ab".repeat(31),
            "ab".repeat(33),
            "AB".repeat(32),
            format!("0x{}", "ab".repeat(32)),
        ] {
            let error = parse_request(&request(&invalid)).unwrap_err();
            assert_eq!(error.category, ErrorCategory::InvalidInput);
        }
    }

    #[test]
    fn rejects_unknown_and_duplicate_fields() {
        let unknown = request(&"ab".repeat(32));
        let unknown = String::from_utf8(unknown).unwrap().replace(
            "\"protocol_version\":1",
            "\"protocol_version\":1,\"extra\":true",
        );
        assert!(parse_request(unknown.as_bytes()).is_err());

        let duplicate = request(&"ab".repeat(32));
        let duplicate = String::from_utf8(duplicate).unwrap().replace(
            "\"protocol_version\":1",
            "\"protocol_version\":1,\"protocol_version\":1",
        );
        assert!(parse_request(duplicate.as_bytes()).is_err());
    }

    #[test]
    fn success_response_is_small_and_contains_no_raw_claims() {
        let encoded = serde_json::to_vec(&VerificationSuccess::new()).unwrap();
        assert!(encoded.len() < 512);
        let text = String::from_utf8(encoded).unwrap();
        assert!(!text.contains("claims"));
        assert!(!text.contains("report_b64"));
        assert!(!text.contains("report_data\""));
    }
}
