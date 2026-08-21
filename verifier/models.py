from dataclasses import dataclass, field
from enum import Enum
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

class SnpTee(str, Enum):
    SEV_SNP = "sev-snp"


class SnpVerificationProfile(str, Enum):
    TRUSTEE_SEV_SNP_V1 = "trustee-sev-snp-v1"


class ReportDataBinding(str, Enum):
    VERIFIED = "verified"


@dataclass(frozen=True)
class SnpVerifierMetadata:
    verifier: str
    protocol: str


@dataclass(frozen=True)
class VerifiedSnpResult:
    """Success-only normalized result from the packaged Rust verifier."""

    tee: SnpTee
    verification_profile: SnpVerificationProfile
    report_data_binding: ReportDataBinding
    metadata: SnpVerifierMetadata

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
