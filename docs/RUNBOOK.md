# v1.2 Runbook

1. Local test: `docker compose -f docker-compose.local.yml up --build`.
2. Set `BRIDGE_API_TOKEN=local-dev-token-change-me`.
3. Run `guest/challenge_client.py` with image/config digests and `--test-mode`.
4. Upload to GitHub; workflow builds GHCR image.
5. Replace the SDL digest placeholder with the immutable GHCR digest.
6. Before a real Akash claim, replace test evidence generation with the measured-guest CoCo `GetEvidence(workload_commitment)` call from `guest/aa_client.rs`.
7. Configure `SNP_VERIFIER_BINARY` and remove `ALLOW_TEST_EVIDENCE`.
8. Real `snp-gpu` remains fail-closed until the NVIDIA adapter is wired.
