import json
import sys
import time
import unittest
from unittest.mock import patch

from verifier.models import AkashSnpEvidence
from verifier.models import VerifiedSnpResult
from verifier.snp_subprocess_adapter import (
    MAX_STDERR_BYTES,
    MAX_STDOUT_BYTES,
    PACKAGED_SNP_VERIFIER,
    RealSnpVerifierAdapter,
    SnpVerificationError,
    VerificationFailureCategory,
)


SUCCESS = {
    "protocol_version": 1,
    "outcome": "verified",
    "security": {
        "tee": "sev-snp",
        "verification_profile": "trustee-sev-snp-v1",
        "report_data_binding": "verified",
    },
    "metadata": {
        "verifier": "confidential-containers-trustee",
        "protocol": "akash-dstack-rust-verifier-v1",
    },
}


def python_command(source):
    return (sys.executable, "-c", source)


def adapter_for(source, timeout=5):
    return RealSnpVerifierAdapter(
        python_command(source), timeout_seconds=timeout, allow_local_override=True
    )


class SnpProtocolTests(unittest.TestCase):
    def verify(self, adapter):
        return adapter.verify(AkashSnpEvidence("report"), b"C" * 32)

    def assert_fake_response_fails_closed(self, output, exit_code=0):
        source = (
            "import sys;sys.stdin.buffer.read();"
            f"sys.stdout.write({output!r});raise SystemExit({exit_code})"
        )
        with patch(
            "verifier.snp_subprocess_adapter.VerifiedSnpResult",
            wraps=VerifiedSnpResult,
        ) as verified_result:
            with self.assertRaises(SnpVerificationError):
                self.verify(adapter_for(source))
            verified_result.assert_not_called()

    def test_only_strict_normalized_success_is_accepted(self):
        source = f"import sys;sys.stdin.buffer.read();sys.stdout.write({json.dumps(json.dumps(SUCCESS))})"
        result = self.verify(adapter_for(source))
        self.assertEqual(result.tee.value, "sev-snp")
        self.assertFalse(hasattr(result, "verified"))
        self.assertFalse(hasattr(result, "claims"))

    def test_arbitrary_executable_is_rejected_without_local_override(self):
        with self.assertRaisesRegex(ValueError, "packaged executable"):
            RealSnpVerifierAdapter((sys.executable,))
        RealSnpVerifierAdapter((PACKAGED_SNP_VERIFIER,))

    def test_exit_zero_empty_stdout_fails_closed(self):
        self.assert_fake_response_fails_closed("")

    def test_exit_zero_malformed_json_fails_closed(self):
        self.assert_fake_response_fails_closed("{")

    def test_exit_zero_duplicate_json_keys_fail_closed(self):
        output = json.dumps(SUCCESS, separators=(",", ":")).replace(
            '"protocol_version":1',
            '"protocol_version":1,"protocol_version":1',
            1,
        )
        self.assert_fake_response_fails_closed(output)

    def test_exit_zero_multiple_json_documents_fail_closed(self):
        document = json.dumps(SUCCESS, separators=(",", ":"))
        self.assert_fake_response_fails_closed(document + "\n" + document)

    def test_exit_zero_success_plus_trailing_text_fails_closed(self):
        self.assert_fake_response_fails_closed(json.dumps(SUCCESS) + "trailing")

    def test_wrong_protocol_version_fails_closed(self):
        response = {**SUCCESS, "protocol_version": 2}
        self.assert_fake_response_fails_closed(json.dumps(response))

    def test_unknown_security_fields_fail_closed(self):
        response = {
            **SUCCESS,
            "security": {**SUCCESS["security"], "raw_claim": "untrusted"},
        }
        self.assert_fake_response_fails_closed(json.dumps(response))

    def test_missing_required_success_fields_fail_closed(self):
        missing_metadata = {key: value for key, value in SUCCESS.items() if key != "metadata"}
        missing_binding = {
            **SUCCESS,
            "security": {
                key: value
                for key, value in SUCCESS["security"].items()
                if key != "report_data_binding"
            },
        }
        for response in (missing_metadata, missing_binding):
            with self.subTest(response=response):
                self.assert_fake_response_fails_closed(json.dumps(response))

    def test_contradictory_success_and_error_fields_fail_closed(self):
        response = {
            **SUCCESS,
            "error": {
                "category": "VerificationFailed",
                "code": "E_VERIFICATION_FAILED",
                "message": "contradictory",
            },
        }
        self.assert_fake_response_fails_closed(json.dumps(response))

    def test_exit_zero_error_document_fails_closed(self):
        failure = {
            "protocol_version": 1,
            "outcome": "error",
            "error": {
                "category": "VerificationFailed",
                "code": "E_VERIFICATION_FAILED",
                "message": "Trustee rejected the SEV-SNP evidence",
            },
        }
        source = f"import sys;sys.stdin.buffer.read();sys.stdout.write({json.dumps(json.dumps(failure))})"
        with self.assertRaises(SnpVerificationError):
            self.verify(adapter_for(source))

    def test_nonzero_success_document_fails_closed(self):
        self.assert_fake_response_fails_closed(json.dumps(SUCCESS), exit_code=1)

    def test_nonzero_structured_failure_preserves_source_category(self):
        failure = {
            "protocol_version": 1,
            "outcome": "error",
            "error": {
                "category": "InvalidReport",
                "code": "E_INVALID_REPORT",
                "message": "SEV-SNP report could not be parsed",
            },
        }
        source = (
            f"import sys;sys.stdin.buffer.read();sys.stdout.write({json.dumps(json.dumps(failure))});"
            "raise SystemExit(1)"
        )
        with self.assertRaises(SnpVerificationError) as caught:
            self.verify(adapter_for(source))
        self.assertEqual(
            caught.exception.category, VerificationFailureCategory.INVALID_REPORT
        )

    def test_stderr_is_never_interpreted_as_success(self):
        source = (
            f"import sys;sys.stdin.buffer.read();sys.stdout.write({json.dumps(json.dumps(SUCCESS))});"
            "sys.stderr.write('diagnostic-only')"
        )
        result = self.verify(adapter_for(source))
        self.assertEqual(result.tee.value, "sev-snp")

    def test_stdout_overflow_terminates_during_execution(self):
        source = (
            f"import sys,time;sys.stdin.buffer.read();sys.stdout.write('x'*{MAX_STDOUT_BYTES + 1});"
            "sys.stdout.flush();time.sleep(30)"
        )
        started = time.monotonic()
        with self.assertRaisesRegex(SnpVerificationError, "exceeded"):
            self.verify(adapter_for(source, timeout=10))
        self.assertLess(time.monotonic() - started, 5)

    def test_stderr_overflow_terminates_during_execution(self):
        source = (
            f"import sys,time;sys.stdin.buffer.read();sys.stderr.write('x'*{MAX_STDERR_BYTES + 1});"
            "sys.stderr.flush();time.sleep(30)"
        )
        started = time.monotonic()
        with self.assertRaisesRegex(SnpVerificationError, "exceeded"):
            self.verify(adapter_for(source, timeout=10))
        self.assertLess(time.monotonic() - started, 5)

    def test_timeout_fails_closed(self):
        source = "import time;time.sleep(30)"
        with self.assertRaisesRegex(SnpVerificationError, "timed out"):
            self.verify(adapter_for(source, timeout=0.1))

    def test_wrong_commitment_length_never_launches_verifier(self):
        adapter = adapter_for("raise SystemExit(0)")
        with self.assertRaisesRegex(ValueError, "exactly 32 bytes"):
            adapter.verify(AkashSnpEvidence("report"), b"short")


class ProductionVerifierSelectionTests(unittest.TestCase):
    def test_missing_packaged_verifier_fails_closed(self):
        from service.verify import verify_with_real_or_fixture

        with patch.dict("os.environ", {"APP_ENV": "production"}, clear=True), patch(
            "os.path.isfile", return_value=False
        ):
            with self.assertRaisesRegex(RuntimeError, "missing or not executable"):
                verify_with_real_or_fixture("report", "", "snp", b"C" * 32)

    def test_production_rejects_arbitrary_binary_override(self):
        from service.verify import verify_with_real_or_fixture

        with patch.dict(
            "os.environ",
            {"APP_ENV": "production", "SNP_VERIFIER_BINARY": sys.executable},
            clear=True,
        ):
            with self.assertRaisesRegex(RuntimeError, "requires APP_ENV=local"):
                verify_with_real_or_fixture("report", "", "snp", b"C" * 32)

    def test_local_override_requires_dedicated_toggle(self):
        from service.verify import verify_with_real_or_fixture

        with patch.dict(
            "os.environ",
            {"APP_ENV": "local", "SNP_VERIFIER_BINARY": sys.executable},
            clear=True,
        ):
            with self.assertRaisesRegex(RuntimeError, "requires APP_ENV=local"):
                verify_with_real_or_fixture("report", "", "snp", b"C" * 32)

        with patch.dict(
            "os.environ",
            {
                "APP_ENV": "production",
                "ALLOW_LOCAL_VERIFIER_OVERRIDE": "1",
                "SNP_VERIFIER_BINARY": sys.executable,
            },
            clear=True,
        ):
            with self.assertRaisesRegex(RuntimeError, "requires APP_ENV=local"):
                verify_with_real_or_fixture("report", "", "snp", b"C" * 32)

        with patch.dict(
            "os.environ",
            {
                "APP_ENV": "local",
                "ALLOW_LOCAL_VERIFIER_OVERRIDE": "1",
                "SNP_VERIFIER_BINARY": sys.executable,
            },
            clear=True,
        ), patch(
            "verifier.snp_subprocess_adapter.RealSnpVerifierAdapter.verify",
            side_effect=SnpVerificationError(
                VerificationFailureCategory.VERIFICATION_FAILED, "expected test stop"
            ),
        ):
            with self.assertRaisesRegex(SnpVerificationError, "expected test stop"):
                verify_with_real_or_fixture("report", "", "snp", b"C" * 32)


if __name__ == "__main__":
    unittest.main()
