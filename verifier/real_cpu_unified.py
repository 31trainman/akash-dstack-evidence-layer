import secrets
from .commitment import workload_commitment
from .models import Challenge, EvidenceBundle, VerifiedWorkload
from .policy import WorkloadPolicy

class RealCpuUnifiedVerifier:
    def __init__(self, snp_verifier, policy: WorkloadPolicy):
        self.snp_verifier=snp_verifier; self.policy=policy
    def verify(self, challenge: Challenge, bundle: EvidenceBundle) -> VerifiedWorkload:
        if bundle.challenge_id != challenge.challenge_id: raise PermissionError("challenge_id mismatch")
        if not secrets.compare_digest(bundle.nonce,challenge.nonce): raise PermissionError("nonce mismatch")
        if challenge.expected_image_digest and bundle.image_digest != challenge.expected_image_digest: raise PermissionError("unexpected image digest")
        if challenge.expected_config_digest and bundle.config_digest != challenge.expected_config_digest: raise PermissionError("unexpected config digest")
        if bundle.snp is None: raise PermissionError("SNP evidence missing")
        c=workload_commitment(bundle.workload_pubkey,bundle.image_digest,bundle.config_digest,bundle.nonce)
        hw=self.snp_verifier.verify(bundle.snp,c)
        if not hw.verified: raise PermissionError("SNP hardware verification did not succeed")
        self.policy.check(bundle.image_digest,bundle.config_digest)
        return VerifiedWorkload(challenge.challenge_id,bundle.nonce,bundle.workload_pubkey,bundle.image_digest,bundle.config_digest,True,False,{"cpu":hw.claims},c)
