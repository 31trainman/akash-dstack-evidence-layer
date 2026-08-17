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

## Fail closed

Any mismatch in nonce, key, image, config, CPU evidence, required GPU evidence, or policy results in no verified workload and therefore no secret release.
