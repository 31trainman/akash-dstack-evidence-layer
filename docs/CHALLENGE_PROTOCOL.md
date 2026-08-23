# Challenge protocol v0.1

This is the next implementation target.

## Issue challenge

Verifier creates:
```json
{
  "challenge_id": "opaque-random-id",
  "nonce_b64": "32-random-bytes",
  "expires_at": 0,
  "policy_id": "akash-dstack-poc-v1"
}
```

Requirements:
- nonce generated with a CSPRNG;
- one use only;
- short expiry;
- challenge ID and nonce stored server-side;
- challenge response accepted only over an authenticated verifier endpoint.

## Guest response

Measured guest returns:
```json
{
  "challenge_id": "...",
  "nonce_b64": "...",
  "workload_pubkey": "...",
  "image_manifest_digest": "sha256:...",
  "config_digest": "sha256:...",
  "tee_evidence": "...",
  "gpu_evidence": null
}
```

The guest MUST source image/config facts from the measured guest-side paths, not from tenant-provided environment variables.

The protocol-v1 `cert_chain` input is a retained legacy field. It is
caller-controlled and non-authoritative: the production Rust SNP verifier does
not forward it to Trustee and instead uses Trustee's AMD KDS certificate path.

## Verification

Verifier recomputes the workload commitment and verifies:
- challenge fresh and unused;
- SNP hardware evidence valid;
- REPORT_DATA matches commitment;
- policy accepts the image; `config_digest` remains attestation-bound
  audit/telemetry and is not a live configuration allowlist;
- required GPU evidence verifies and binds to the same challenge;
- optional ZK proof validates when policy requires it.

Only then produce `VerifiedWorkload`.

Measured Init-Data/Kata policy is intended to become the authoritative runtime
configuration control. `expected_init_data_hash_hex` is currently unset, so
that enforcement is not implemented in protocol v1.
