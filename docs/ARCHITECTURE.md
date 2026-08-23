# Architecture

## Security boundary

Hardware validity and workload identity are separate questions.

A valid SNP quote does not prove which workload ran.
A valid GPU attestation does not prove workload identity.
A self-reported image/config digest is not trusted.

The verifier only produces `VerifiedWorkload` when all required inputs bind to the same fresh challenge.

## Workload commitment

```text
SHA256(
  domain_separator ||
  len(workload_pubkey) || workload_pubkey ||
  len(image_manifest_digest) || image_manifest_digest ||
  len(config_digest) || config_digest ||
  len(verifier_nonce) || verifier_nonce
)
```

For SEV-SNP this commitment is supplied as runtime data and verified against REPORT_DATA.

`config_digest` is syntax-validated, included in this attested commitment, and
returned as audit/telemetry data. It is not a live configuration-authorization
allowlist. Measured Init-Data/Kata policy is the intended authoritative runtime
configuration control. The live Python adapter currently sets
`expected_init_data_hash_hex` to `null`, so that control is not implemented yet.

## SNP certificate trust path

The protocol-v1 `cert_chain` field is retained for compatibility but is legacy,
caller-controlled, and non-authoritative. The Rust production verifier always
converts the evidence passed to Trustee to `cert_chain: null` and initializes
the pinned Trustee SNP verifier with its default certificate source. Trustee
derives the report-specific VCEK request from signed report fields, retrieves
the VCEK from AMD KDS, and validates it against Trustee's generation-specific
embedded AMD certificate authorities before validating the report signature.

Production readiness has two certificate tests. A deterministic offline test
uses a genuine captured report and its committed public VCEK to prove the exact
32-byte commitment succeeds and a one-bit mutation fails without network
access. A separate readiness-only parity test sends the same report through
the production `verify_request()` path with hostile caller certificate text;
it must retrieve and validate the VCEK through AMD KDS. Both tests must pass.

## Fail closed

Any mismatch in nonce, key, image, config, CPU evidence, required GPU evidence, or policy results in no verified workload and therefore no secret release.
