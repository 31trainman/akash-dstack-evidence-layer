import base64
import json
import unittest
from unittest.mock import patch

from fastapi import HTTPException

import service.app as service_app
from service.models import AttestationSubmission
from service.state import ChallengeStore
from service.verify import (
    snp_verifier_timeout_seconds,
    test_evidence_enabled,
    verify_with_real_or_fixture,
)
from verifier.commitment import workload_commitment
from verifier.models import (
    AkashSnpEvidence,
    ReportDataBinding,
    SnpTee,
    SnpVerificationProfile,
)
from verifier.policy import load_workload_policy
from verifier.snp_subprocess_adapter import (
    RealSnpVerifierAdapter,
    SnpVerificationError,
    VerificationFailureCategory,
)


IMAGE = "sha256:" + "11" * 32
CONFIG = "sha256:" + "22" * 32
PUBKEY = b"P" * 32
POLICY_ID = "akash-dstack-cpu-binding-v1"


def policy_json(images=None, configs=None, include_configs=True):
    policy = {"approved_images": images if images is not None else [IMAGE]}
    if include_configs:
        policy["approved_configs"] = configs if configs is not None else [CONFIG]
    return json.dumps({POLICY_ID: policy})


class WorkloadPolicyConfigurationTests(unittest.TestCase):
    def test_valid_policy_is_enforced(self):
        policy = load_workload_policy(POLICY_ID, policy_json())
        policy.check(IMAGE, CONFIG)
        with self.assertRaises(PermissionError):
            policy.check("sha256:" + "33" * 32, CONFIG)

    def test_config_allowlist_is_optional_and_not_an_authorization_gate(self):
        other_config = "sha256:" + "33" * 32
        without_configs = load_workload_policy(
            POLICY_ID, policy_json(include_configs=False)
        )
        with_nonmatching_configs = load_workload_policy(
            POLICY_ID, policy_json(configs=[CONFIG])
        )
        without_configs.check(IMAGE, other_config)
        with_nonmatching_configs.check(IMAGE, other_config)
        self.assertEqual(without_configs.approved_configs, set())
        self.assertEqual(with_nonmatching_configs.approved_configs, set())

    def test_missing_malformed_unknown_and_empty_configuration_fail_closed(self):
        cases = [
            None,
            "not-json",
            "{}",
            json.dumps({"other-policy": {"approved_images": [IMAGE], "approved_configs": [CONFIG]}}),
            policy_json(images=[]),
            json.dumps({POLICY_ID: {"approved_images": [IMAGE], "approved_configs": "bad"}}),
            policy_json(images=[None]),
            '{"duplicate":{"approved_images":[],"approved_configs":[]},"duplicate":{}}',
        ]
        for raw in cases:
            with self.subTest(raw=raw):
                if raw is None:
                    with patch.dict("os.environ", {}, clear=True):
                        with self.assertRaises(PermissionError):
                            load_workload_policy(POLICY_ID)
                else:
                    with self.assertRaises(PermissionError):
                        load_workload_policy(POLICY_ID, raw)

    def test_policy_failure_after_consumption_burns_challenge(self):
        service_app.store = ChallengeStore(60)
        record = service_app.store.issue(POLICY_ID)
        commitment = workload_commitment(PUBKEY, IMAGE, CONFIG, record.nonce)
        submission = AttestationSubmission(
            challenge_id=record.challenge_id,
            nonce_b64=base64.b64encode(record.nonce).decode(),
            workload_pubkey_b64=base64.b64encode(PUBKEY).decode(),
            image_manifest_digest=IMAGE,
            config_digest=CONFIG,
            snp_report_b64=base64.b64encode(commitment + b"\x00" * 32).decode(),
            tee_platform="snp",
        )
        with patch.dict(
            "os.environ",
            {"BRIDGE_API_TOKEN": "test-token", "APP_ENV": "local", "ALLOW_TEST_EVIDENCE": "1"},
            clear=True,
        ):
            with self.assertRaises(HTTPException) as caught:
                service_app.attest(submission, authorization="Bearer test-token")
        self.assertEqual(caught.exception.status_code, 403)
        with self.assertRaisesRegex(ValueError, "already used"):
            service_app.store.consume(record.challenge_id, record.nonce)


class TestEvidenceModeTests(unittest.TestCase):
    def test_cpu_fixture_requires_local_mode_and_toggle(self):
        commitment = b"C" * 32
        report = base64.b64encode(commitment + b"\x00" * 32).decode()
        rejected = [
            {},
            {"APP_ENV": "local"},
            {"ALLOW_TEST_EVIDENCE": "1"},
            {"APP_ENV": "production", "ALLOW_TEST_EVIDENCE": "1"},
        ]
        for env in rejected:
            with self.subTest(env=env), patch.dict("os.environ", env, clear=True):
                with self.assertRaises(RuntimeError):
                    verify_with_real_or_fixture(report, "", "snp", commitment)
        with patch.dict(
            "os.environ", {"APP_ENV": "local", "ALLOW_TEST_EVIDENCE": "1"}, clear=True
        ):
            result = verify_with_real_or_fixture(report, "", "snp", commitment)
        self.assertIsNone(result)

    def test_gpu_fixture_requires_local_mode_and_its_own_toggle(self):
        cases = [
            ({}, False),
            ({"APP_ENV": "local"}, False),
            ({"ALLOW_TEST_GPU_EVIDENCE": "1"}, False),
            ({"APP_ENV": "production", "ALLOW_TEST_GPU_EVIDENCE": "1"}, False),
            ({"APP_ENV": "local", "ALLOW_TEST_EVIDENCE": "1"}, False),
            ({"APP_ENV": "local", "ALLOW_TEST_GPU_EVIDENCE": "1"}, True),
        ]
        for env, expected in cases:
            with self.subTest(env=env), patch.dict("os.environ", env, clear=True):
                self.assertEqual(test_evidence_enabled("ALLOW_TEST_GPU_EVIDENCE"), expected)


class SnpVerifierTimeoutTests(unittest.TestCase):
    def test_timeout_default_and_valid_override(self):
        with patch.dict("os.environ", {}, clear=True):
            self.assertEqual(snp_verifier_timeout_seconds(), 10)
        with patch.dict("os.environ", {"SNP_VERIFIER_TIMEOUT_SECONDS": "60"}, clear=True):
            self.assertEqual(snp_verifier_timeout_seconds(), 60)

    def test_invalid_timeout_configuration_fails_closed(self):
        for value in ["invalid", "nan", "0", "-1", "60.1"]:
            with self.subTest(value=value), patch.dict(
                "os.environ", {"SNP_VERIFIER_TIMEOUT_SECONDS": value}, clear=True
            ):
                with self.assertRaises(RuntimeError):
                    snp_verifier_timeout_seconds()

    @patch("verifier.snp_subprocess_adapter._run_bounded")
    def test_real_verifier_receives_timeout(self, run):
        run.return_value = (
            0,
            b'{"protocol_version":1,"outcome":"verified","security":{"tee":"sev-snp","verification_profile":"trustee-sev-snp-v1","report_data_binding":"verified"},"metadata":{"verifier":"confidential-containers-trustee","protocol":"akash-dstack-rust-verifier-v1"}}',
            b"",
        )
        adapter = RealSnpVerifierAdapter(
            ("verifier",), timeout_seconds=7, allow_local_override=True
        )
        result = adapter.verify(AkashSnpEvidence("report"), b"C" * 32)
        self.assertEqual(result.tee, SnpTee.SEV_SNP)
        self.assertEqual(
            result.verification_profile, SnpVerificationProfile.TRUSTEE_SEV_SNP_V1
        )
        self.assertEqual(result.report_data_binding, ReportDataBinding.VERIFIED)
        self.assertEqual(run.call_args.args[2], 7)

    @patch("verifier.snp_subprocess_adapter._run_bounded")
    def test_real_verifier_timeout_fails_closed(self, run):
        run.side_effect = SnpVerificationError(
            VerificationFailureCategory.VERIFICATION_FAILED,
            "real SNP verification timed out",
        )
        adapter = RealSnpVerifierAdapter(("verifier",), allow_local_override=True)
        with self.assertRaisesRegex(PermissionError, "timed out"):
            adapter.verify(AkashSnpEvidence("report"), b"C" * 32)


if __name__ == "__main__":
    unittest.main()
