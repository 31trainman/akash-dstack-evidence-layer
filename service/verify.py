import base64, math, os

from verifier.snp_subprocess_adapter import PACKAGED_SNP_VERIFIER


def test_evidence_enabled(toggle_name):
    return os.environ.get('APP_ENV') == 'local' and os.environ.get(toggle_name) == '1'


def local_verifier_override_enabled():
    return test_evidence_enabled('ALLOW_LOCAL_VERIFIER_OVERRIDE')


def snp_verifier_timeout_seconds():
    raw = os.environ.get('SNP_VERIFIER_TIMEOUT_SECONDS', '10')
    try:
        timeout = float(raw)
    except ValueError as exc:
        raise RuntimeError('SNP_VERIFIER_TIMEOUT_SECONDS must be a number') from exc
    if not math.isfinite(timeout) or timeout <= 0 or timeout > 60:
        raise RuntimeError('SNP_VERIFIER_TIMEOUT_SECONDS must be greater than 0 and at most 60')
    return timeout

def validate_sha256(name, value):
    if not value.startswith('sha256:') or len(value) != 71: raise PermissionError(f'{name} must be sha256:<64 hex>')
    try: int(value[7:], 16)
    except ValueError as exc: raise PermissionError(f'{name} has non-hex characters') from exc

def verify_with_real_or_fixture(snp_report_b64, cert_chain, tee_platform, expected_commitment):
    configured_binary = os.environ.get('SNP_VERIFIER_BINARY')
    if configured_binary and configured_binary != PACKAGED_SNP_VERIFIER:
        if not local_verifier_override_enabled():
            raise RuntimeError(
                'SNP_VERIFIER_BINARY override requires APP_ENV=local and '
                'ALLOW_LOCAL_VERIFIER_OVERRIDE=1'
            )
        binary = configured_binary
        allow_local_override = True
    else:
        binary = PACKAGED_SNP_VERIFIER
        allow_local_override = False

    if not test_evidence_enabled('ALLOW_TEST_EVIDENCE'):
        from verifier.snp_subprocess_adapter import RealSnpVerifierAdapter
        from verifier.models import AkashSnpEvidence
        if not allow_local_override and not (
            os.path.isfile(PACKAGED_SNP_VERIFIER)
            and os.access(PACKAGED_SNP_VERIFIER, os.X_OK)
        ):
            raise RuntimeError('Packaged SNP verifier is missing or not executable')
        adapter = RealSnpVerifierAdapter(
            (binary,),
            timeout_seconds=snp_verifier_timeout_seconds(),
            allow_local_override=allow_local_override,
        )
        return adapter.verify(
            AkashSnpEvidence(
                report_b64=snp_report_b64,
                cert_chain=cert_chain,
                tee_platform=tee_platform,
            ),
            expected_commitment,
        )
    if test_evidence_enabled('ALLOW_TEST_EVIDENCE'):
        raw = base64.b64decode(snp_report_b64)
        if raw != expected_commitment + (b'\x00' * 32): raise PermissionError('test evidence does not match expected REPORT_DATA')
        return None
    raise RuntimeError('No SNP verification path configured; refusing verification')
