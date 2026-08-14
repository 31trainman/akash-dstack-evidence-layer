import base64
import httpx

DEFAULT_SIDECAR_URL='http://127.0.0.1:8790'

def get_quote(commitment:bytes,sidecar_url:str=DEFAULT_SIDECAR_URL,bind_tls:bool=False)->dict:
    if len(commitment)!=32: raise ValueError('workload commitment must be 32 bytes')
    report_data=commitment+(b'\x00'*32)
    payload={'nonce':base64.b64encode(report_data).decode(),'bind_tls':bind_tls}
    with httpx.Client(timeout=30.0) as client:
        r=client.post(sidecar_url.rstrip('/')+'/quote',json=payload)
        r.raise_for_status()
        body=r.json()
    if not body.get('report'): raise RuntimeError('attestation sidecar returned no CPU report')
    return body
