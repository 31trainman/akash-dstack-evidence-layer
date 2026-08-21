import json
import math
import os
import subprocess
import threading
from enum import Enum
from typing import Sequence

from .models import (
    AkashSnpEvidence,
    ReportDataBinding,
    SnpTee,
    SnpVerificationProfile,
    SnpVerifierMetadata,
    VerifiedSnpResult,
)


PACKAGED_SNP_VERIFIER = "/usr/local/bin/akash-coco-snp-verifier"
PROTOCOL_VERSION = 1
MAX_REQUEST_BYTES = 1024 * 1024
MAX_STDOUT_BYTES = 4096
MAX_STDERR_BYTES = 4096


class VerificationFailureCategory(str, Enum):
    INVALID_INPUT = "InvalidInput"
    MALFORMED_EVIDENCE = "MalformedEvidence"
    UNSUPPORTED_EVIDENCE = "UnsupportedEvidence"
    INVALID_REPORT = "InvalidReport"
    REPORT_DATA_MISMATCH = "ReportDataMismatch"
    INVALID_SIGNATURE = "InvalidSignature"
    INVALID_POLICY = "InvalidPolicy"
    VERIFIER_UNAVAILABLE = "VerifierUnavailable"
    VERIFICATION_FAILED = "VerificationFailed"
    INTERNAL_ERROR = "InternalError"


class SnpVerificationError(PermissionError):
    def __init__(self, category: VerificationFailureCategory, message: str):
        super().__init__(message)
        self.category = category


def _read_bounded(stream, limit: int, process, overflow: threading.Event) -> bytes:
    output = bytearray()
    try:
        while True:
            chunk = os.read(stream.fileno(), 4096)
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > limit:
                overflow.set()
                try:
                    process.kill()
                except OSError:
                    pass
                break
    finally:
        stream.close()
    return bytes(output[: limit + 1])


def _run_bounded(
    command: Sequence[str], request: bytes, timeout_seconds: float
) -> tuple[int, bytes, bytes]:
    if len(request) > MAX_REQUEST_BYTES:
        raise SnpVerificationError(
            VerificationFailureCategory.INVALID_INPUT,
            "SNP verification request exceeds the maximum size",
        )

    try:
        process = subprocess.Popen(
            list(command),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        raise SnpVerificationError(
            VerificationFailureCategory.VERIFIER_UNAVAILABLE,
            "SNP verifier executable could not be started",
        ) from exc
    assert process.stdin is not None
    assert process.stdout is not None
    assert process.stderr is not None

    stdout_overflow = threading.Event()
    stderr_overflow = threading.Event()
    outputs: dict[str, bytes] = {}

    def read_output(name, stream, limit, overflow):
        outputs[name] = _read_bounded(stream, limit, process, overflow)

    stdout_thread = threading.Thread(
        target=read_output,
        args=("stdout", process.stdout, MAX_STDOUT_BYTES, stdout_overflow),
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=read_output,
        args=("stderr", process.stderr, MAX_STDERR_BYTES, stderr_overflow),
        daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()

    def write_request():
        try:
            process.stdin.write(request)
        except (BrokenPipeError, OSError):
            pass
        finally:
            try:
                process.stdin.close()
            except OSError:
                pass

    stdin_thread = threading.Thread(target=write_request, daemon=True)
    stdin_thread.start()

    try:
        return_code = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        process.kill()
        process.wait()
        raise SnpVerificationError(
            VerificationFailureCategory.VERIFICATION_FAILED,
            "real SNP verification timed out",
        ) from exc
    finally:
        stdin_thread.join(timeout=1)
        stdout_thread.join(timeout=1)
        stderr_thread.join(timeout=1)
        if process.poll() is None:
            process.kill()
            process.wait()

    if stdin_thread.is_alive() or stdout_thread.is_alive() or stderr_thread.is_alive():
        raise SnpVerificationError(
            VerificationFailureCategory.INTERNAL_ERROR,
            "SNP verifier output reader did not terminate",
        )
    if stdout_overflow.is_set() or stderr_overflow.is_set():
        raise SnpVerificationError(
            VerificationFailureCategory.VERIFICATION_FAILED,
            "SNP verifier output exceeded the configured limit",
        )
    return return_code, outputs.get("stdout", b""), outputs.get("stderr", b"")


def _reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate protocol field: {key}")
        result[key] = value
    return result


def _decode_protocol(stdout: bytes) -> dict:
    if not stdout or len(stdout) > MAX_STDOUT_BYTES:
        raise ValueError("empty or oversized verifier protocol output")
    try:
        text = stdout.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("verifier protocol output is not UTF-8") from exc
    if text != text.strip():
        raise ValueError("verifier protocol output contains leading or trailing data")
    value = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    if not isinstance(value, dict):
        raise ValueError("verifier protocol output must be an object")
    return value


def _parse_success(value: dict) -> VerifiedSnpResult:
    if set(value) != {"protocol_version", "outcome", "security", "metadata"}:
        raise ValueError("unexpected verifier success fields")
    if value["protocol_version"] != PROTOCOL_VERSION or value["outcome"] != "verified":
        raise ValueError("unsupported verifier success protocol")
    security = value["security"]
    metadata = value["metadata"]
    if not isinstance(security, dict) or set(security) != {
        "tee",
        "verification_profile",
        "report_data_binding",
    }:
        raise ValueError("unexpected verifier security fields")
    if not isinstance(metadata, dict) or set(metadata) != {"verifier", "protocol"}:
        raise ValueError("unexpected verifier metadata fields")
    if metadata != {
        "verifier": "confidential-containers-trustee",
        "protocol": "akash-dstack-rust-verifier-v1",
    }:
        raise ValueError("unexpected verifier metadata values")
    return VerifiedSnpResult(
        tee=SnpTee(security["tee"]),
        verification_profile=SnpVerificationProfile(security["verification_profile"]),
        report_data_binding=ReportDataBinding(security["report_data_binding"]),
        metadata=SnpVerifierMetadata(**metadata),
    )


def _parse_failure(value: dict) -> SnpVerificationError:
    try:
        if set(value) != {"protocol_version", "outcome", "error"}:
            raise ValueError
        if value["protocol_version"] != PROTOCOL_VERSION or value["outcome"] != "error":
            raise ValueError
        error = value["error"]
        if not isinstance(error, dict) or set(error) != {"category", "code", "message"}:
            raise ValueError
        category = VerificationFailureCategory(error["category"])
        if not isinstance(error["code"], str) or not isinstance(error["message"], str):
            raise ValueError
        expected_code = {
            VerificationFailureCategory.INVALID_INPUT: "E_INVALID_INPUT",
            VerificationFailureCategory.MALFORMED_EVIDENCE: "E_MALFORMED_EVIDENCE",
            VerificationFailureCategory.UNSUPPORTED_EVIDENCE: "E_UNSUPPORTED_EVIDENCE",
            VerificationFailureCategory.INVALID_REPORT: "E_INVALID_REPORT",
            VerificationFailureCategory.REPORT_DATA_MISMATCH: "E_REPORT_DATA_MISMATCH",
            VerificationFailureCategory.INVALID_SIGNATURE: "E_INVALID_SIGNATURE",
            VerificationFailureCategory.INVALID_POLICY: "E_INVALID_POLICY",
            VerificationFailureCategory.VERIFIER_UNAVAILABLE: "E_VERIFIER_UNAVAILABLE",
            VerificationFailureCategory.VERIFICATION_FAILED: "E_VERIFICATION_FAILED",
            VerificationFailureCategory.INTERNAL_ERROR: "E_INTERNAL",
        }[category]
        if error["code"] != expected_code:
            raise ValueError
        if len(error["message"]) > 256:
            raise ValueError
        return SnpVerificationError(category, error["message"])
    except (KeyError, TypeError, ValueError) as exc:
        raise SnpVerificationError(
            VerificationFailureCategory.VERIFICATION_FAILED,
            "real SNP verifier returned an invalid failure response",
        ) from exc


class RealSnpVerifierAdapter:
    """Strict adapter for the packaged Rust/Trustee verification boundary."""

    def __init__(
        self,
        verifier_command: Sequence[str] | None = None,
        timeout_seconds: float = 10,
        *,
        allow_local_override: bool = False,
    ):
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0 or timeout_seconds > 60:
            raise ValueError("SNP verifier timeout must be greater than 0 and at most 60 seconds")
        command = tuple(verifier_command or (PACKAGED_SNP_VERIFIER,))
        if not command or any(not isinstance(part, str) or not part for part in command):
            raise ValueError("SNP verifier command is invalid")
        if command != (PACKAGED_SNP_VERIFIER,) and not allow_local_override:
            raise ValueError("production SNP verifier must use the packaged executable")
        self.verifier_command = command
        self.timeout_seconds = timeout_seconds

    def verify(
        self, evidence: AkashSnpEvidence, expected_report_data: bytes
    ) -> VerifiedSnpResult:
        if len(expected_report_data) != 32:
            raise ValueError("SNP expected workload commitment must be exactly 32 bytes")
        request = json.dumps(
            {
                "protocol_version": PROTOCOL_VERSION,
                "evidence_type": "sev-snp",
                "evidence": {
                    "report_b64": evidence.report_b64,
                    "cert_chain": evidence.cert_chain,
                },
                "expected_workload_commitment_hex": expected_report_data.hex(),
                "expected_init_data_hash_hex": None,
            },
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        return_code, stdout, _stderr = _run_bounded(
            self.verifier_command, request, self.timeout_seconds
        )
        try:
            response = _decode_protocol(stdout)
        except (json.JSONDecodeError, ValueError) as exc:
            raise SnpVerificationError(
                VerificationFailureCategory.VERIFICATION_FAILED,
                "real SNP verifier returned invalid protocol output",
            ) from exc

        if return_code != 0:
            raise _parse_failure(response)
        if response.get("outcome") != "verified":
            raise SnpVerificationError(
                VerificationFailureCategory.VERIFICATION_FAILED,
                "real SNP verifier did not return verified success",
            )
        try:
            return _parse_success(response)
        except (TypeError, ValueError) as exc:
            raise SnpVerificationError(
                VerificationFailureCategory.VERIFICATION_FAILED,
                "real SNP verifier returned an invalid success response",
            ) from exc
