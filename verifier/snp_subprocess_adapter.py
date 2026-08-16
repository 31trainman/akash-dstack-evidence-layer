import json
import math
import subprocess
import tempfile
from pathlib import Path
from .models import AkashSnpEvidence, HardwareResult

class RealSnpVerifierAdapter:
    """
    Adapter around the v0.8 Rust/Trustee verifier.

    Security boundary:
      - this class does NOT parse or validate SNP itself;
      - it delegates cryptographic verification to the Trustee-backed Rust binary;
      - success is accepted only on exit code 0.

    The binary is expected to implement:
      akash-coco-snp-adapter <evidence.json> <expected-report-data-hex>
    """

    def __init__(self, verifier_binary: str, timeout_seconds: float = 10):
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0 or timeout_seconds > 60:
            raise ValueError("SNP verifier timeout must be greater than 0 and at most 60 seconds")
        self.verifier_binary = verifier_binary
        self.timeout_seconds = timeout_seconds

    def verify(self, evidence: AkashSnpEvidence, expected_report_data: bytes) -> HardwareResult:
        if len(expected_report_data) > 64:
            raise ValueError("SNP expected report data cannot exceed 64 bytes")

        payload = {
            "report": evidence.report_b64,
            "cert_chain": evidence.cert_chain,
            "tee_platform": evidence.tee_platform,
        }

        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "akash-attestation.json"
            p.write_text(json.dumps(payload), encoding="utf-8")

            try:
                proc = subprocess.run(
                    [
                        self.verifier_binary,
                        str(p),
                        expected_report_data.hex(),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds,
                )
            except subprocess.TimeoutExpired as exc:
                raise PermissionError("real SNP verification timed out") from exc

        if proc.returncode != 0:
            raise PermissionError(
                "real SNP verification failed: "
                + (proc.stderr.strip() or proc.stdout.strip() or "unknown verifier failure")
            )

        claims = {
            "tee": "snp",
            "trustee_verified": True,
            "verifier_output": proc.stdout.strip(),
        }
        return HardwareResult(True, claims)


class FakeSnpVerifierAdapter:
    """TEST ONLY."""
    def verify(self, evidence: AkashSnpEvidence, expected_report_data: bytes) -> HardwareResult:
        if evidence.report_b64 != expected_report_data.hex():
            raise PermissionError("fake SNP evidence mismatch")
        return HardwareResult(True, {"tee": "snp", "fake": True})
