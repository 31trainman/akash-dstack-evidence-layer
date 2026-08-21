# Rust/Python SEV-SNP trust boundary

The production bridge delegates raw SEV-SNP evidence parsing, certificate and
signature verification, TCB/VMPL evaluation, and expected REPORT_DATA binding
to the packaged Rust/Trustee verifier at:

`/usr/local/bin/akash-coco-snp-verifier`

Production does not accept an arbitrary verifier executable. A custom command
is available only when both `APP_ENV=local` and
`ALLOW_LOCAL_VERIFIER_OVERRIDE=1` are set.

The verifier reads one bounded protocol-v1 JSON request from stdin and writes
one bounded compact JSON response to stdout. A success response exists only
after Trustee completes SEV-SNP verification using the exact 32-byte expected
workload commitment as its `ReportData::Value` input. Python validates the
protocol shape but does not parse raw SNP claims or repeat the REPORT_DATA
comparison.

Trustee's pinned API exposes evaluation failures through `anyhow`, not stable
typed signature, policy, or report-data mismatch variants. Those failures are
therefore classified conservatively as `VerificationFailed`; diagnostic text
does not affect authorization.

## Production-readiness gate

The crate and protocol tests do not substitute for a cryptographically valid
SEV-SNP fixture. Before this path is described as production-ready, a
deterministic test must prove that the pinned Trustee SNP verifier accepts a
valid signed report for the supplied 32-byte commitment and rejects the same
report after a one-bit commitment change. The test must use Trustee itself and
must not mock a successful verification.
