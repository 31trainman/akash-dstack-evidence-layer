#!/usr/bin/env bash
set -euo pipefail

fixture_dir="${1:-rust-verifier/tests/fixtures/snp-v3-current}"
manifest="rust-verifier/Cargo.toml"

for file in report.bin vcek.der amd-cert-chain.pem metadata.json SHA256SUMS README.md; do
  test -f "${fixture_dir}/${file}" || { echo "missing ${fixture_dir}/${file}" >&2; exit 1; }
done

test "$(wc -c < "${fixture_dir}/report.bin")" -eq 1184 || {
  echo "report.bin must be exactly 1,184 bytes" >&2
  exit 1
}

(cd "${fixture_dir}" && sha256sum --check SHA256SUMS)

SNP_FIXTURE_DIR="${fixture_dir}" cargo test --locked \
  --manifest-path "${manifest}" \
  --test trustee_current_snp_fixture \
  trustee_current_fixture_exact_commitment_and_mutation \
  -- --ignored --exact
