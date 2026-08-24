# Capturing a current SEV-SNP fixture

This tool captures public test evidence; it does not create or modify an SNP
report. Its default `direct` mode runs inside a genuine, non-production SEV-SNP
confidential guest with Linux `/dev/sev-guest` access. The additional
`akash-sidecar` mode obtains the same raw report from Akash's injected local
attestation sidecar. Both modes require outbound HTTPS access to AMD KDS.

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

The command above remains the direct `/dev/sev-guest` capture path. Inside an
Akash confidential workload, use the additional sidecar mode:

```sh
cargo run --locked \
  --manifest-path rust-verifier/Cargo.toml \
  --bin capture_snp_fixture -- \
  --capture-mode akash-sidecar \
  --sidecar-url https://127.0.0.1:8790 \
  --output rust-verifier/tests/fixtures/snp-v3-current \
  --operator-consent-file /secure/path/operator-publication-consent.txt \
  --source-revision "$(git rev-parse HEAD)"
```

Akash mode accepts only HTTPS with the literal loopback hosts `127.0.0.1` or
`::1`; redirects, remote hosts, DNS names, credentials, and URL paths are
rejected. It calls `/info` first and requires protocol version 4 and an SNP or
SNP-GPU platform. It then calls `/quote` with `bind_tls: false` and the exact
64-byte `commitment32 || zero32` value. The returned report must be an exact
1,184-byte parseable SNP report. Any returned sidecar `cert_chain` is ignored;
the trusted VCEK and AMD chain continue to come from independently derived AMD
KDS URLs.

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

The committed public VCEK makes the fixture's exact-commitment and one-bit
mutation checks deterministic and offline. The explicit production-readiness
workflow additionally sends the same report through production
`verify_request()` with hostile caller certificate text and requires Trustee to
retrieve and validate the report-specific VCEK through AMD KDS. The protocol-v1
caller `cert_chain` field is legacy/non-authoritative and is converted to
`cert_chain: null` before Trustee evaluation. Both the offline and live-KDS
layers must pass before production readiness can be claimed.

The normal `Build evidence images` workflow validates all non-hardware gates.
When this fixture is absent, its `SNP production fixture` job is visibly
skipped and the workflow summary says production readiness is not satisfied.
A normal green workflow therefore does not establish SNP production readiness.

The separate manually dispatched `SNP production readiness` workflow fails
closed unless every fixture/provenance file exists, hashes validate, the exact
commitment succeeds offline, the one-bit mutation fails offline, the production
AMD KDS parity test passes, and normal CI also passes.
