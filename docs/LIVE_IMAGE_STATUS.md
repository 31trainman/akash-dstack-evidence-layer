# Live image status

## Now implemented
- fresh verifier nonce
- in-container ephemeral X25519 keypair
- workload commitment
- 64-byte Akash quote challenge (`commitment || zero32`)
- real `POST http://127.0.0.1:8790/quote` call
- return of Akash CPU/GPU quote bundle to external verifier
- one-use challenge state
- Trustee-backed SNP verifier adapter contract

## Still blocked before claiming full workload identity
1. `IMAGE_MANIFEST_DIGEST` must come from a measured guest/Kata path, not SDL env.
2. `RESOLVED_CONFIG_DIGEST` must come from the measured Kata hook, not SDL env.
3. NVIDIA GPU evidence must be cryptographically verified and correlated before GPU-required secret release.
4. KBS/JWE/HPKE secret release to the X25519 key is not wired yet.

## CPU evidence milestone
Even before items 1-4 are complete, the image can now prove that a *fresh arbitrary 64-byte commitment chosen by us* was signed into Akash's CPU TEE report. That is the live mechanism needed for the final workload binding.
