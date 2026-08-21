use serde::Serialize;
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum ErrorCategory {
    InvalidInput,
    MalformedEvidence,
    UnsupportedEvidence,
    InvalidReport,
    ReportDataMismatch,
    InvalidSignature,
    InvalidPolicy,
    VerifierUnavailable,
    VerificationFailed,
    InternalError,
}

impl ErrorCategory {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidInput => "E_INVALID_INPUT",
            Self::MalformedEvidence => "E_MALFORMED_EVIDENCE",
            Self::UnsupportedEvidence => "E_UNSUPPORTED_EVIDENCE",
            Self::InvalidReport => "E_INVALID_REPORT",
            Self::ReportDataMismatch => "E_REPORT_DATA_MISMATCH",
            Self::InvalidSignature => "E_INVALID_SIGNATURE",
            Self::InvalidPolicy => "E_INVALID_POLICY",
            Self::VerifierUnavailable => "E_VERIFIER_UNAVAILABLE",
            Self::VerificationFailed => "E_VERIFICATION_FAILED",
            Self::InternalError => "E_INTERNAL",
        }
    }
}

#[derive(Debug)]
pub struct VerificationError {
    pub category: ErrorCategory,
    pub message: &'static str,
}

impl VerificationError {
    pub const fn new(category: ErrorCategory, message: &'static str) -> Self {
        Self { category, message }
    }
}

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message)
    }
}

impl std::error::Error for VerificationError {}
