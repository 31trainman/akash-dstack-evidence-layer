# Security rules

1. Never trust `IMAGE_ID`, tags, or tenant self-report as workload identity.
2. Never treat valid CPU + valid GPU evidence as sufficient without common challenge/workload binding.
3. Never reuse a nonce after successful or failed verification.
4. Keep raw hardware evidence parsing outside KMS release logic.
5. KMS receives only normalized verified claims / `VerifiedWorkload`.
6. Historical quotes must fail new challenges.
7. GPU verification is required only when policy requires GPU confidential compute.
8. Do not release plaintext secrets to an unattested channel; wrap/encrypt to the attested workload key.
9. Any missing or mismatched field fails closed.
