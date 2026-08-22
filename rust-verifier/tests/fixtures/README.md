# Trustee SEV-SNP fixtures

`trustee-test-report.b64` and `trustee-test-vcek.b64` are base64 encodings of
`deps/verifier/test_data/snp/test-report.bin` and `test-vcek.der` from
Confidential Containers Trustee commit
`f8761b823952f71db40dd6b53050f3fd008c9758`.

They are Apache-2.0 test material and contain no production evidence or private
key. This is a legacy version-2 report/VCEK pair: the signature remains a useful
cryptographic regression, but pinned Trustee's full evaluator intentionally
rejects report version 2. It is not current-hardware or production-readiness
evidence. The separately captured `snp-v3-current` fixture is required for that
gate and does not exist yet.
