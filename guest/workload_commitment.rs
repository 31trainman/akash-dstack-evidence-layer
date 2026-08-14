use anyhow::{bail, Result};
use sha2::{Digest, Sha256};

const DOMAIN: &[u8] = b"akash-dstack-workload-identity/v0.1\0";

fn add_len_prefixed(h: &mut Sha256, bytes: &[u8]) {
    h.update((bytes.len() as u64).to_be_bytes());
    h.update(bytes);
}

/// Construct exactly 32 bytes of runtime data for fresh SEV-SNP evidence.
///
/// Current CoCo SNP attester accepts <=64 bytes and copies them into SNP
/// REPORT_DATA (zero-padded to 64 bytes). We intentionally use SHA-256 so the
/// verifier has a fixed 32-byte commitment and can recompute it exactly.
pub fn workload_commitment(
    workload_pubkey: &[u8],
    image_manifest_digest: &str,
    config_digest: &str,
    verifier_nonce: &[u8],
) -> Result<[u8; 32]> {
    if workload_pubkey.is_empty() {
        bail!("workload public key must not be empty");
    }
    if verifier_nonce.len() < 16 {
        bail!("verifier nonce must be at least 16 bytes");
    }
    for (name, d) in [
        ("image manifest digest", image_manifest_digest),
        ("config digest", config_digest),
    ] {
        if !d.starts_with("sha256:") || d.len() != 71 || !d[7..].bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("{name} must be sha256:<64 hex>");
        }
    }

    let mut h = Sha256::new();
    h.update(DOMAIN);
    add_len_prefixed(&mut h, workload_pubkey);
    add_len_prefixed(&mut h, image_manifest_digest.as_bytes());
    add_len_prefixed(&mut h, config_digest.as_bytes());
    add_len_prefixed(&mut h, verifier_nonce);
    Ok(h.finalize().into())
}
