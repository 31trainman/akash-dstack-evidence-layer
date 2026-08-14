import hmac, os

def verify_bearer(auth_header):
    expected = os.environ.get('BRIDGE_API_TOKEN')
    if not expected: raise RuntimeError('BRIDGE_API_TOKEN is not configured')
    if not auth_header or not auth_header.startswith('Bearer '): raise PermissionError('missing bearer token')
    supplied = auth_header[7:].strip()
    if not hmac.compare_digest(supplied, expected): raise PermissionError('invalid bearer token')
