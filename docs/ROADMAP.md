# Roadmap — execute in this order

## Step 1 — Consolidation
Status: COMPLETE

All useful code from v0.3–v1.0 has been brought into one project tree.

## Step 2 — Live challenge transport
Status: NEXT

Build a small verifier/KBS-facing challenge endpoint that issues:
- challenge_id
- 32-byte cryptographic nonce
- expiry
- expected policy identifiers

Build the measured guest client that fetches/receives that challenge without taking image/config claims from the tenant container.

Success criterion:
A fresh challenge reaches the confidential guest and cannot be replayed.

## Step 3 — Live guest evidence generation

Inside the measured guest:
- obtain trusted manifest digest from guest-pull/CDH path;
- obtain resolved config digest from Kata-side hook;
- generate/use ephemeral workload key;
- compute workload commitment;
- call CoCo Attestation Agent `GetEvidence(commitment)`.

Success criterion:
fresh SNP REPORT_DATA equals the verifier-computed commitment.

## Step 4 — Real CPU verification

Feed the fresh Akash quote to the Trustee-backed SNP adapter.

Success criterion:
Trustee validates AMD chain/signature/TCB/VMPL and exact REPORT_DATA.

## Step 5 — NVIDIA evidence

Add real NVIDIA verification only for `cpu-gpu` workloads.

Success criterion:
CPU and GPU evidence demonstrably belong to the same fresh workload challenge/session.

## Step 6 — Trustee/KBS secret release

Move policy/release into Trustee/KBS RCAR.

Success criterion:
a test secret is released only after `VerifiedWorkload`, and encrypted/wrapped to the attested ephemeral key.

## Step 7 — ZK policy proof

Add the ZK proof as an additional authorization condition for approved build/provenance policy.

Success criterion:
valid TEE evidence without the required ZK policy proof does not release the protected secret.
