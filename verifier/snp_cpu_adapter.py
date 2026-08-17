from .cpu_adapter import CpuAdapter, CpuClaims
from .snp_subprocess_adapter import RealSnpVerifierAdapter
from .models import AkashSnpEvidence

class SnpCpuAdapter(CpuAdapter):
    def __init__(self, verifier_binary: str):
        self.inner = RealSnpVerifierAdapter(verifier_binary)

    def verify(self, evidence: AkashSnpEvidence, expected_commitment: bytes) -> CpuClaims:
        result = self.inner.verify(evidence, expected_commitment)
        return CpuClaims(
            verified=result.verified,
            tee="snp",
            binding_verified=result.verified,
            claims=result.claims,
        )
