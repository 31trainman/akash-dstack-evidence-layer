import hashlib

DOMAIN = b"akash-dstack-workload-identity/v0.1\0"
GPU_DOMAIN = b"akash-dstack-gpu-session/v0.1\0"

def _lp(x: bytes) -> bytes:
    return len(x).to_bytes(8, "big") + x

def validate_digest(name: str, value: str) -> None:
    if not value.startswith("sha256:") or len(value) != 71:
        raise ValueError(f"{name} must be sha256:<64 hex>")
    int(value[7:], 16)

def workload_commitment(pubkey: bytes, image_digest: str, config_digest: str, nonce: bytes) -> bytes:
    if not pubkey:
        raise ValueError("empty workload public key")
    if len(nonce) < 16:
        raise ValueError("nonce too short")
    validate_digest("image_digest", image_digest)
    validate_digest("config_digest", config_digest)
    return hashlib.sha256(
        DOMAIN
        + _lp(pubkey)
        + _lp(image_digest.encode())
        + _lp(config_digest.encode())
        + _lp(nonce)
    ).digest()

def gpu_session_binding(workload_commitment_bytes: bytes, nonce: bytes) -> bytes:
    """Prototype correlation token for GPU evidence/session binding.
    Real NVIDIA verification may expose a different native challenge field.
    This token is used by the unified verifier contract and tests.
    """
    if len(workload_commitment_bytes) != 32:
        raise ValueError("workload commitment must be 32 bytes")
    return hashlib.sha256(
        GPU_DOMAIN + _lp(workload_commitment_bytes) + _lp(nonce)
    ).digest()
