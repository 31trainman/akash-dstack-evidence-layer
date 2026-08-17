# Akash → dstack Integrated Evidence Layer v1.4

v1.4 freezes the workload-binding contract and makes the live experiment explicitly SNP-first.

Changes:
- platform-neutral `CpuAdapter` contract;
- real `SnpCpuAdapter`;
- TDX adapter placeholder that fails closed;
- verifier refuses non-SNP live evidence instead of guessing;
- SNP-first deployment runbook and environment templates.

The next live milestone is a real AES-provider deployment where Trustee validates a fresh SNP report whose REPORT_DATA is bound to our workload commitment.

TDX support can be added later without changing the workload-binding layer.

## License

License: Apache-2.0
