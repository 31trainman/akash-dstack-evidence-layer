use akash_coco_snp_verifier::{
    parse_request, verify_request, ErrorCategory, ErrorResponse, ProtocolResponse,
    VerificationError, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES,
};
use std::io::{self, Read, Write};

fn bounded_response(response: ProtocolResponse) -> Vec<u8> {
    match serde_json::to_vec(&response) {
        Ok(encoded) if encoded.len() <= MAX_RESPONSE_BYTES => encoded,
        _ => serde_json::to_vec(&ProtocolResponse::Error(ErrorResponse::from(
            &VerificationError::new(
                ErrorCategory::InternalError,
                "verification response could not be serialized safely",
            ),
        )))
        .expect("static fallback response must serialize"),
    }
}

#[tokio::main]
async fn main() {
    let mut input = Vec::new();
    let read_result = io::stdin()
        .take((MAX_REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut input);

    let result = match read_result {
        Ok(_) if input.len() <= MAX_REQUEST_BYTES => match parse_request(&input) {
            Ok(request) => verify_request(&request).await,
            Err(error) => Err(error),
        },
        _ => Err(VerificationError::new(
            ErrorCategory::InvalidInput,
            "verification request exceeds the maximum size",
        )),
    };

    let (response, exit_code) = match result {
        Ok(success) => (ProtocolResponse::Verified(success), 0),
        Err(error) => (ProtocolResponse::Error(ErrorResponse::from(&error)), 1),
    };
    let encoded = bounded_response(response);
    let _ = io::stdout().write_all(&encoded);
    let _ = io::stdout().flush();
    std::process::exit(exit_code);
}
