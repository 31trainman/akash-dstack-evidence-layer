from .cpu_adapter import CpuAdapter, CpuClaims
from .snp_subprocess_adapter import RealSnpVerifierAdapter
from .models import AkashSnpEvidence

class SnpCpuAdapter(CpuAdapter):
    def __init__(self, verifier_binary: str):
        self.inner = RealSnpVerifierAdapter(verifier_binary)

    def verify(self, evidence: AkashSnpEvidence, expected_commitment: bytes) -> CpuClaims:
        result = self.inner.verify(evidence, expected_commitment)
        return CpuClaims(
            verified=True,
            tee="snp",
            binding_verified=True,
            claims={
                "tee": result.tee.value,
                "verification_profile": result.verification_profile.value,
                "report_data_binding": result.report_data_binding.value,
            },
        )
