import argparse,base64,hashlib,json,os
import httpx
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from guest.akash_sidecar import get_quote
DOMAIN=b'akash-dstack-workload-identity/v0.1\0'
def lp(x): return len(x).to_bytes(8,'big')+x
def commitment(pubkey,image_digest,config_digest,nonce): return hashlib.sha256(DOMAIN+lp(pubkey)+lp(image_digest.encode())+lp(config_digest.encode())+lp(nonce)).digest()
def post_json(url,token,payload):
    with httpx.Client(timeout=30.0) as c:
        r=c.post(url,json=payload,headers={'Authorization':f'Bearer {token}'})
        r.raise_for_status(); return r.json()
def main():
    p=argparse.ArgumentParser()
    p.add_argument('--bridge',default=os.environ.get('BRIDGE_URL'))
    p.add_argument('--image-digest',default=os.environ.get('IMAGE_MANIFEST_DIGEST'))
    p.add_argument('--config-digest',default=os.environ.get('RESOLVED_CONFIG_DIGEST'))
    p.add_argument('--sidecar',default=os.environ.get('AKASH_ATTESTATION_SIDECAR','http://127.0.0.1:8790'))
    p.add_argument('--require-gpu',action='store_true')
    a=p.parse_args()
    if not a.bridge or not a.image_digest or not a.config_digest: raise SystemExit('bridge, image digest, and config digest are required')
    token=os.environ['BRIDGE_API_TOKEN']
    ch=post_json(a.bridge.rstrip('/')+'/v1/challenge',token,{'policy_id':'akash-dstack-cpu-binding-v1','require_gpu':a.require_gpu})
    nonce=base64.b64decode(ch['nonce_b64'])
    private_key=X25519PrivateKey.generate()
    pubkey=private_key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    cmt=commitment(pubkey,a.image_digest,a.config_digest,nonce)
    quote=get_quote(cmt,a.sidecar,bind_tls=False)
    tee_platform=quote.get('tee_platform',quote.get('tee_type','snp'))
    if tee_platform not in {'snp','snp-gpu'}:
        raise SystemExit(f'v1.4 live deployment is SNP-first; provider returned {tee_platform}')
    payload={'challenge_id':ch['challenge_id'],'nonce_b64':ch['nonce_b64'],'workload_pubkey_b64':base64.b64encode(pubkey).decode(),'image_manifest_digest':a.image_digest,'config_digest':a.config_digest,'snp_report_b64':quote['report'],'cert_chain':quote.get('cert_chain',''),'tee_platform':tee_platform,'gpu_reports':quote.get('gpu_reports',[])}
    result=post_json(a.bridge.rstrip('/')+'/v1/attest',token,payload)
    print(json.dumps(result,indent=2))
    # Keep private_key alive until result is received. Future KBS release code will use it to unwrap the secret.
if __name__=='__main__': main()
