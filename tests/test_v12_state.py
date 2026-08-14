import unittest
from service.state import ChallengeStore
from verifier.commitment import workload_commitment
class T(unittest.TestCase):
    def test_one_time(self):
        s=ChallengeStore(60); c=s.issue('p'); s.consume(c.challenge_id,c.nonce)
        with self.assertRaises(ValueError): s.consume(c.challenge_id,c.nonce)
    def test_key_changes_commitment(self):
        i='sha256:'+'11'*32; c='sha256:'+'22'*32; n=b'N'*32
        self.assertNotEqual(workload_commitment(b'A'*32,i,c,n),workload_commitment(b'B'*32,i,c,n))
