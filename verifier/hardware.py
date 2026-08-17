from .models import CpuEvidence, GpuEvidence

class CpuHardwareVerifier:
    def verify(self, evidence: CpuEvidence) -> CpuEvidence:
        raise NotImplementedError

class GpuHardwareVerifier:
    def verify(self, evidence: GpuEvidence) -> GpuEvidence:
        raise NotImplementedError

class StrictMockCpuVerifier(CpuHardwareVerifier):
    """TEST ONLY. Treat exactly 64-byte report_data as already hardware-verified."""
    def verify(self, evidence: CpuEvidence) -> CpuEvidence:
        if len(evidence.report_data) != 64:
            raise PermissionError("invalid CPU report_data length")
        evidence.verified = True
        evidence.claims = {**evidence.claims, "tee": "snp", "mock_cpu": True}
        return evidence

class StrictMockGpuVerifier(GpuHardwareVerifier):
    """TEST ONLY. Verifies presence and shape of challenge binding."""
    def verify(self, evidence: GpuEvidence) -> GpuEvidence:
        if len(evidence.challenge_binding) != 32:
            raise PermissionError("invalid GPU challenge binding length")
        evidence.verified = True
        evidence.claims = {**evidence.claims, "gpu": "nvidia", "mock_gpu": True}
        return evidence
