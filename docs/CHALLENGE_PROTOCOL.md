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

## Verification

Verifier recomputes the workload commitment and verifies:
- challenge fresh and unused;
- SNP hardware evidence valid;
- REPORT_DATA matches commitment;
- policy accepts image/config;
- required GPU evidence verifies and binds to the same challenge;
- optional ZK proof validates when policy requires it.

Only then produce `VerifiedWorkload`.
