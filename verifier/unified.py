import secrets
from .models import Challenge, EvidenceBundle, VerifiedWorkload
from .commitment import workload_commitment, gpu_session_binding
from .hardware import CpuHardwareVerifier, GpuHardwareVerifier
from .policy import WorkloadPolicy

class UnifiedWorkloadVerifier:
    def __init__(
        self,
        cpu_verifier: CpuHardwareVerifier,
        gpu_verifier: GpuHardwareVerifier | None,
        policy: WorkloadPolicy,
    ):
        self.cpu_verifier = cpu_verifier
        self.gpu_verifier = gpu_verifier
        self.policy = policy

    def verify(self, challenge: Challenge, bundle: EvidenceBundle) -> VerifiedWorkload:
        # 1. Correlate request metadata first.
        if bundle.challenge_id != challenge.challenge_id:
            raise PermissionError("challenge_id mismatch")
        if not secrets.compare_digest(bundle.nonce, challenge.nonce):
            raise PermissionError("nonce mismatch")

        if challenge.expected_image_digest and bundle.image_digest != challenge.expected_image_digest:
            raise PermissionError("unexpected image digest")
        if challenge.expected_config_digest and bundle.config_digest != challenge.expected_config_digest:
            raise PermissionError("unexpected config digest")

        # 2. Recompute workload identity from the exact same challenge.
        commitment = workload_commitment(
            bundle.workload_pubkey,
            bundle.image_digest,
            bundle.config_digest,
            bundle.nonce,
        )

        # 3. Verify CPU evidence independently, then bind it to workload identity.
        cpu = self.cpu_verifier.verify(bundle.cpu)
        if not cpu.verified:
            raise PermissionError("CPU evidence not verified")
        expected_report_data = commitment + (b"\x00" * 32)
        if not secrets.compare_digest(cpu.report_data, expected_report_data):
            raise PermissionError("bad REPORT_DATA workload binding")

        # 4. GPU is optional, but if required it must verify and bind to same session.
        gpu_verified = False
        gpu_claims = {}
        if bundle.gpu is None:
            if challenge.require_gpu:
                raise PermissionError("GPU evidence required")
        else:
            if self.gpu_verifier is None:
                raise PermissionError("no GPU verifier configured")

            gpu = self.gpu_verifier.verify(bundle.gpu)
            if gpu.verified is not True:
                raise PermissionError("GPU evidence not verified")
            if (
                not isinstance(gpu.challenge_binding, bytes)
                or len(gpu.challenge_binding) != 32
            ):
                raise PermissionError("malformed GPU challenge binding")
            if not isinstance(gpu.claims, dict):
                raise PermissionError("malformed GPU claims")

            expected_gpu_binding = gpu_session_binding(commitment, bundle.nonce)
            if not secrets.compare_digest(gpu.challenge_binding, expected_gpu_binding):
                raise PermissionError("GPU evidence belongs to different workload/challenge")

            gpu_verified = True
            gpu_claims = gpu.claims

        # 5. Workload policy is separate from hardware validity.
        self.policy.check(bundle.image_digest, bundle.config_digest)

        claims = {
            "cpu": cpu.claims,
            "gpu": gpu_claims,
            "binding": {
                "challenge_id": challenge.challenge_id,
                "nonce_bound": True,
                "workload_key_bound": True,
                "image_bound": True,
                "config_bound": True,
            },
        }

        return VerifiedWorkload(
            challenge_id=challenge.challenge_id,
            nonce=bundle.nonce,
            workload_pubkey=bundle.workload_pubkey,
            image_digest=bundle.image_digest,
            config_digest=bundle.config_digest,
            cpu_verified=True,
            gpu_verified=gpu_verified,
            claims=claims,
            commitment=commitment,
        )
