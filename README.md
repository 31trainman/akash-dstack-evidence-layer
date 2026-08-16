# Akash → dstack Evidence Layer

Experimental, fail-closed evidence-layer PoC for comparing confidential-workload identity and attestation across Akash Confidential Compute and Phala/dstack.

## Current status

Completed:
- Akash `tee: cpu-gpu` deployment matched a live AMD SEV-SNP provider.
- CPU attestation validated.
- NVIDIA confidential-GPU attestation validated.
- Initial offline verifier built.
- This containerized evidence agent exposes `/health` and `/identity`.

Not yet completed:
- Independent AMD/NVIDIA signature verification.
- Cryptographic workload identity binding to the attested measurement.
- dstack KMS authorization.
- Secret release.

The workload intentionally starts in a **LOCKED / DENY** state and contains no KMS master secret.

## Endpoints

- `/health`
- `/identity`
- `/`

## GHCR publishing

A GitHub Actions workflow in `.github/workflows/publish-ghcr.yml` builds and pushes this repository to:

`ghcr.io/31trainman/akash-dstack-evidence-layer`

After the first successful workflow run, make the GHCR package public if GitHub created it as private.

Then copy the immutable `sha256:...` digest and update `deploy.yaml`:

```yaml
image: ghcr.io/31trainman/akash-dstack-evidence-layer@sha256:...
```

Also set:

```yaml
- IMAGE_ID=ghcr.io/31trainman/akash-dstack-evidence-layer@sha256:...
```

## Security note

Do not commit real attestation evidence, private keys, seed phrases, API keys, KMS secrets, or `.env` files.

## License

Apache-2.0.
