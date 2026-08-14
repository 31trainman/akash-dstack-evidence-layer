import unittest
from verifier.cpu_adapter import CpuClaims
from verifier.tdx_cpu_adapter import TdxCpuAdapter

class T(unittest.TestCase):
    def test_claim_contract(self):
        c=CpuClaims(True,'snp',True,{'x':1})
        self.assertTrue(c.verified and c.binding_verified)

    def test_tdx_fails_closed_until_implemented(self):
        with self.assertRaises(NotImplementedError):
            TdxCpuAdapter().verify(None,b'x'*32)
