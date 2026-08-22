# Capturing a current SEV-SNP fixture

This tool captures public test evidence; it does not create or modify an SNP
report. Run it only inside a genuine, non-production SEV-SNP confidential guest
with Linux `/dev/sev-guest` access and outbound HTTPS access to AMD KDS.

An SNP report exposes a persistent hardware chip ID. Obtain permission from the
machine operator/provider before capture and publication. Never capture from
production hardware without explicit approval to publish the resulting report,
chip ID, VCEK, and certificate-chain material.

Create a consent file containing exactly:

```text
I authorize publication of this non-production SEV-SNP report, chip ID, and public certificate material.
```

From the repository root, capture into a new or empty directory:

```sh
cargo run --locked \
  --manifest-path rust-verifier/Cargo.toml \
  --bin capture_snp_fixture -- \
  --output rust-verifier/tests/fixtures/snp-v3-current \
  --operator-consent-file /secure/path/operator-publication-consent.txt \
  --source-revision "$(git rev-parse HEAD)"
```

The consent file is checked but not copied into the repository because it may
contain operational records. Preserve the approval separately according to the
operator's governance process.

The fixed public commitment is:

```text
SHA-256("akash-dstack-trustee-snp-fixture-v1")
= a9101838fe1e450778a358747803d6ea9b3ff4563f77a79727d42923eeb3cf5a
```

The tool requests VMPL 0 and a 64-byte report-data request consisting of that
32-byte value followed by 32 zero bytes. It saves the raw response without
rewriting it, retrieves the report-specific public VCEK and AMD's complete
public ASK/ARK certificate-chain response, and requires pinned Trustee
`Snp::evaluate()` to accept the result before writing fixture artifacts.

Pinned Trustee accepts report versions 3 through 5. The tool checks that range
only as capture sanity; Trustee remains authoritative for acceptance.

After capture, run:

```sh
rust-verifier/scripts/validate-snp-fixture.sh
```

The fixture is not acceptable for production-readiness claims unless exact
commitment verification succeeds and a one-bit expected-commitment mutation
fails through the pinned Trustee evaluator.
