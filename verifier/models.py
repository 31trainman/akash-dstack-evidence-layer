from dataclasses import dataclass, field
from typing import Any, Optional

@dataclass
class Challenge:
    challenge_id: str
    nonce: bytes
    expected_image_digest: Optional[str] = None
    expected_config_digest: Optional[str] = None
    require_gpu: bool = False

@dataclass
class CpuEvidence:
    raw: bytes
    report_data: bytes
    claims: dict[str, Any] = field(default_factory=dict)
    verified: bool = False

@dataclass
class GpuEvidence:
    raw: bytes
    challenge_binding: bytes
    claims: dict[str, Any] = field(default_factory=dict)
    verified: bool = False

@dataclass
class AkashSnpEvidence:
    report_b64: str
    cert_chain: str = ""
    tee_platform: str = "snp-gpu"

@dataclass
class HardwareResult:
    verified: bool
    claims: dict[str, Any] = field(default_factory=dict)

@dataclass
class EvidenceBundle:
    challenge_id: str
    nonce: bytes
    workload_pubkey: bytes
    image_digest: str
    config_digest: str
    cpu: Optional[CpuEvidence] = None
    gpu: Optional[GpuEvidence] = None
    snp: Optional[AkashSnpEvidence] = None

@dataclass
class VerifiedWorkload:
    challenge_id: str
    nonce: bytes
    workload_pubkey: bytes
    image_digest: str
    config_digest: str
    cpu_verified: bool
    gpu_verified: bool
    claims: dict[str, Any]
    commitment: bytes
