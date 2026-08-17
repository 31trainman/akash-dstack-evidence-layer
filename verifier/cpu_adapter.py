from dataclasses import dataclass, field
from typing import Any

@dataclass
class CpuClaims:
    verified: bool
    tee: str
    binding_verified: bool
    claims: dict[str, Any] = field(default_factory=dict)

class CpuAdapter:
    def verify(self, evidence, expected_commitment: bytes) -> CpuClaims:
        raise NotImplementedError
