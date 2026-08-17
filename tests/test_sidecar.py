import base64,unittest,httpx
from unittest.mock import patch
from guest.akash_sidecar import get_quote
class FakeClient:
    def __init__(self,*a,**k): pass
    def __enter__(self): return self
    def __exit__(self,*a): pass
    def post(self,url,json):
        raw=base64.b64decode(json['nonce']); assert len(raw)==64; assert raw[:32]==b'C'*32; assert raw[32:]==b'\x00'*32
        class R:
            def raise_for_status(self): pass
            def json(self): return {'report':'abc','tee_platform':'snp-gpu','gpu_reports':[]}
        return R()
class T(unittest.TestCase):
    @patch('guest.akash_sidecar.httpx.Client',FakeClient)
    def test_commitment_becomes_exact_64_byte_quote_nonce(self):
        self.assertEqual(get_quote(b'C'*32)['report'],'abc')
