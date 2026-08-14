from pydantic import BaseModel

class ChallengeRequest(BaseModel):
    policy_id: str = 'akash-dstack-cpu-binding-v1'
    require_gpu: bool = False
class ChallengeResponse(BaseModel):
    challenge_id: str
    nonce_b64: str
    expires_at: float
    policy_id: str
    require_gpu: bool
class AttestationSubmission(BaseModel):
    challenge_id: str
    nonce_b64: str
    workload_pubkey_b64: str
    image_manifest_digest: str
    config_digest: str
    snp_report_b64: str
    cert_chain: str = ''
    tee_platform: str = 'snp-gpu'
    gpu_reports: list[dict] = []
class VerifiedWorkloadResponse(BaseModel):
    verified: bool
    challenge_id: str
    image_manifest_digest: str
    config_digest: str
    cpu_verified: bool
    gpu_verified: bool
    commitment_hex: str
