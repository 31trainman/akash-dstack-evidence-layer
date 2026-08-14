import base64, os
from fastapi import FastAPI,Header,HTTPException
from service.auth import verify_bearer
from service.models import ChallengeRequest,ChallengeResponse,AttestationSubmission,VerifiedWorkloadResponse
from service.state import ChallengeStore
from service.verify import validate_sha256,verify_with_real_or_fixture
from verifier.commitment import workload_commitment
app=FastAPI(title='Akash-dstack Evidence Bridge',version='1.3')
store=ChallengeStore(int(os.environ.get('CHALLENGE_TTL_SECONDS','120')))
@app.get('/healthz')
def healthz(): return {'ok':True,'version':'1.3'}
@app.post('/v1/challenge',response_model=ChallengeResponse)
def issue_challenge(req:ChallengeRequest,authorization:str|None=Header(default=None)):
    try: verify_bearer(authorization)
    except Exception as e: raise HTTPException(status_code=401,detail=str(e))
    r=store.issue(req.policy_id,req.require_gpu)
    return ChallengeResponse(challenge_id=r.challenge_id,nonce_b64=base64.b64encode(r.nonce).decode(),expires_at=r.expires_at,policy_id=r.policy_id,require_gpu=r.require_gpu)
@app.post('/v1/attest',response_model=VerifiedWorkloadResponse)
def attest(sub:AttestationSubmission,authorization:str|None=Header(default=None)):
    try:
        verify_bearer(authorization)
        nonce=base64.b64decode(sub.nonce_b64,validate=True); pubkey=base64.b64decode(sub.workload_pubkey_b64,validate=True)
        validate_sha256('image_manifest_digest',sub.image_manifest_digest); validate_sha256('config_digest',sub.config_digest)
        r=store.consume(sub.challenge_id,nonce)
        c=workload_commitment(pubkey,sub.image_manifest_digest,sub.config_digest,nonce)
        if sub.tee_platform not in {'snp','snp-gpu'}:
            raise PermissionError(f'unsupported CPU TEE for v1.4 live path: {sub.tee_platform}')
        cpu_verified,_=verify_with_real_or_fixture(sub.snp_report_b64,sub.cert_chain,sub.tee_platform,c)
        gpu_verified=False
        if r.require_gpu:
            if not sub.gpu_reports: raise PermissionError('GPU evidence required by challenge policy')
            if os.environ.get('ALLOW_TEST_GPU_EVIDENCE')=='1': gpu_verified=True
            else: raise PermissionError('real NVIDIA verifier not configured')
        if not cpu_verified: raise PermissionError('CPU verification failed')
        return VerifiedWorkloadResponse(verified=True,challenge_id=r.challenge_id,image_manifest_digest=sub.image_manifest_digest,config_digest=sub.config_digest,cpu_verified=True,gpu_verified=gpu_verified,commitment_hex=c.hex())
    except PermissionError as e: raise HTTPException(status_code=403,detail=str(e))
    except ValueError as e: raise HTTPException(status_code=400,detail=str(e))
    except Exception as e: raise HTTPException(status_code=500,detail=str(e))
