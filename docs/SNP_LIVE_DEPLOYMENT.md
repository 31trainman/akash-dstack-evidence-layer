# SNP-first live deployment

This is the next experiment.

## 1. Publish the images

GitHub Actions builds the bridge and guest images. Record the immutable digest for the guest image.

## 2. Run the verifier bridge outside Akash

The bridge must be reachable by the confidential guest over HTTPS.

Configure:

```text
BRIDGE_API_TOKEN=<random test token>
SNP_VERIFIER_BINARY=/path/to/akash-coco-snp-adapter
```

Do not enable test evidence.

## 3. Pin the guest image

Replace the guest-image placeholder in the SDL with the immutable GHCR digest.

For this first hardware-binding experiment, `IMAGE_MANIFEST_DIGEST` can be set to that immutable digest.

`RESOLVED_CONFIG_DIGEST` is syntax-validated, bound into REPORT_DATA through the
workload commitment, and returned for audit/telemetry. It is not authorized by
a live configuration allowlist. Measured Init-Data/Kata policy is the intended
authoritative runtime-configuration control, but
`expected_init_data_hash_hex` is currently unset and that control is not yet
implemented.

The protocol-v1 caller `cert_chain` field is legacy and non-authoritative. The
production Rust verifier discards it when constructing Trustee evidence;
Trustee retrieves the report-specific VCEK from AMD KDS and validates the AMD
certificate path.

## 4. Deploy to the AES SNP+GPU provider

The guest sends:

```text
POST http://127.0.0.1:8790/quote
```

with a 64-byte challenge:

```text
workload_commitment || 32 zero bytes
```

The sidecar returns the real SNP quote and GPU reports.

v1.4 validates CPU/SNP first. GPU evidence remains fail-closed until the real NVIDIA adapter is wired.

## 5. Success criterion

Trustee accepts the real SNP report and the exact fresh workload commitment.

Replay, pubkey swap, digest modification, or stale nonce must fail.

Passing this proves fresh CPU evidence is bound to our commitment. It does not yet prove that image/config facts came from the measured Kata path.
