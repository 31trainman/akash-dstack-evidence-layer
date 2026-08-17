import unittest
from verifier.models import Challenge, CpuEvidence, GpuEvidence, EvidenceBundle
from verifier.hardware import StrictMockCpuVerifier, StrictMockGpuVerifier
from verifier.policy import WorkloadPolicy
from verifier.unified import UnifiedWorkloadVerifier
from verifier.commitment import workload_commitment, gpu_session_binding

IMAGE = "sha256:" + "11"*32
CONFIG = "sha256:" + "22"*32
OTHER_CONFIG = "sha256:" + "33"*32
PUBKEY = bytes(range(32))
OTHER_PUBKEY = bytes(reversed(range(32)))
NONCE = b"N"*32
OLD_NONCE = b"O"*32
CID = "challenge-1"

def build_bundle(pubkey=PUBKEY, image=IMAGE, config=CONFIG, nonce=NONCE, gpu=True):
    c = workload_commitment(pubkey, image, config, nonce)
    cpu = CpuEvidence(raw=b"cpu", report_data=c + b"\x00"*32)
    ge = None
    if gpu:
        ge = GpuEvidence(raw=b"gpu", challenge_binding=gpu_session_binding(c, nonce))
    return EvidenceBundle(CID, nonce, pubkey, image, config, cpu, ge)

class UnifiedVerifierTests(unittest.TestCase):
    def setUp(self):
        self.v = UnifiedWorkloadVerifier(
            StrictMockCpuVerifier(),
            StrictMockGpuVerifier(),
            WorkloadPolicy(approved_images={IMAGE}, approved_configs={CONFIG}),
        )
        self.challenge = Challenge(CID, NONCE, IMAGE, CONFIG, require_gpu=True)

    def test_happy_path(self):
        result = self.v.verify(self.challenge, build_bundle())
        self.assertTrue(result.cpu_verified)
        self.assertTrue(result.gpu_verified)

    def test_old_nonce_rejected(self):
        with self.assertRaises(PermissionError):
            self.v.verify(self.challenge, build_bundle(nonce=OLD_NONCE))

    def test_swapped_pubkey_rejected(self):
        b = build_bundle()
        b.workload_pubkey = OTHER_PUBKEY
        with self.assertRaises(PermissionError):
            self.v.verify(self.challenge, b)

    def test_wrong_config_rejected(self):
        b = build_bundle(config=OTHER_CONFIG)
        with self.assertRaises(PermissionError):
            self.v.verify(self.challenge, b)

    def test_bad_report_data_rejected(self):
        b = build_bundle()
        b.cpu.report_data = b"\x00"*64
        with self.assertRaises(PermissionError):
            self.v.verify(self.challenge, b)

    def test_wrong_gpu_evidence_rejected(self):
        b = build_bundle()
        b.gpu.challenge_binding = b"\xff"*32
        with self.assertRaises(PermissionError):
            self.v.verify(self.challenge, b)

    def test_cpu_from_a_gpu_from_b_rejected(self):
        b = build_bundle()
        other_commitment = workload_commitment(PUBKEY, IMAGE, CONFIG, OLD_NONCE)
        b.gpu.challenge_binding = gpu_session_binding(other_commitment, OLD_NONCE)
        with self.assertRaises(PermissionError):
            self.v.verify(self.challenge, b)

    def test_missing_gpu_rejected_when_required(self):
        with self.assertRaises(PermissionError):
            self.v.verify(self.challenge, build_bundle(gpu=False))

    def test_unapproved_image_rejected_even_with_valid_hardware(self):
        bad_image = "sha256:" + "44"*32
        b = build_bundle(image=bad_image)
        c = Challenge(CID, NONCE, require_gpu=True)
        with self.assertRaises(PermissionError):
            self.v.verify(c, b)

if __name__ == "__main__":
    unittest.main()
