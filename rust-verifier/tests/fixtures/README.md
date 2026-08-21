# Trustee SEV-SNP fixtures

`trustee-test-report.b64` and `trustee-test-vcek.b64` are base64 encodings of
`deps/verifier/test_data/snp/test-report.bin` and `test-vcek.der` from
Confidential Containers Trustee commit
`f8761b823952f71db40dd6b53050f3fd008c9758`.

They are Apache-2.0 test material and contain no production evidence or private
key. They make the REPORT_DATA integration test deterministic and independent
of live AMD KDS availability.
