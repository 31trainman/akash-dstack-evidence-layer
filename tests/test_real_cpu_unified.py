import unittest
from verifier.models import Challenge, EvidenceBundle, AkashSnpEvidence
from verifier.commitment import workload_commitment
from verifier.snp_subprocess_adapter import FakeSnpVerifierAdapter
from verifier.policy import WorkloadPolicy
from verifier.real_cpu_unified import RealCpuUnifiedVerifier
IMAGE="sha256:"+"11"*32; CONFIG="sha256:"+"22"*32; PUBKEY=bytes(range(32)); NONCE=b"N"*32; CID="c1"
class Tests(unittest.TestCase):
    def make_bundle(self,pubkey=PUBKEY,image=IMAGE,config=CONFIG,nonce=NONCE):
        c=workload_commitment(pubkey,image,config,nonce); ev=AkashSnpEvidence(report_b64=c.hex())
        return EvidenceBundle(CID,nonce,pubkey,image,config,snp=ev)
    def setUp(self):
        self.challenge=Challenge(CID,NONCE,IMAGE,CONFIG); self.v=RealCpuUnifiedVerifier(FakeSnpVerifierAdapter(),WorkloadPolicy({IMAGE},{CONFIG}))
    def test_happy_path(self): self.assertTrue(self.v.verify(self.challenge,self.make_bundle()).cpu_verified)
    def test_swapped_pubkey_fails(self):
        b=self.make_bundle(); b.workload_pubkey=b"X"*32
        with self.assertRaises(PermissionError): self.v.verify(self.challenge,b)
    def test_wrong_nonce_fails(self):
        b=self.make_bundle(nonce=b"O"*32)
        with self.assertRaises(PermissionError): self.v.verify(self.challenge,b)
    def test_unapproved_image_fails(self):
        bad="sha256:"+"33"*32; b=self.make_bundle(image=bad); c=Challenge(CID,NONCE)
        with self.assertRaises(PermissionError): self.v.verify(c,b)
