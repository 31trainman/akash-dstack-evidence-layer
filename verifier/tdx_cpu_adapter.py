from .cpu_adapter import CpuAdapter

class TdxCpuAdapter(CpuAdapter):
    def verify(self, evidence, expected_commitment: bytes):
        raise NotImplementedError(
            "TDX adapter intentionally not implemented in v1.4. "
            "Use SNP path first; add Trustee TDX verification later."
        )
