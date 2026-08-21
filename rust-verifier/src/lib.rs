pub mod error;
pub mod protocol;
pub mod snp;

pub use error::{ErrorCategory, VerificationError};
pub use protocol::{
    parse_request, ErrorResponse, ExpectedWorkloadCommitment, ProtocolResponse,
    VerificationRequest, VerificationSuccess, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES,
};
pub use snp::verify_request;
