import hashlib, json

DOMAIN = b"akash-dstack-workload-claim/v0.1\0"

def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

def _check_sha256(name, value):
    if not isinstance(value, str) or not value.startswith("sha256:") or len(value) != 71:
        raise ValueError(f"{name} must be sha256:<64 hex>")
    int(value[7:], 16)

def validate_shape(claim):
    required = {"version","platform","tee_type","image_digest","config_digest","workload_key","nonce_b64","policy_version"}
    missing = required - set(claim)
    if missing:
        raise ValueError(f"missing fields: {sorted(missing)}")
    if claim["version"] != "0.1":
        raise ValueError("unsupported version")
    if claim["tee_type"] not in {"snp","snp-gpu","tdx","tdx-gpu"}:
        raise ValueError("unsupported tee_type")
    _check_sha256("image_digest", claim["image_digest"])
    _check_sha256("config_digest", claim["config_digest"])
    wk = claim["workload_key"]
    if wk.get("algorithm") not in {"X25519","Ed25519"} or not wk.get("public_key_b64"):
        raise ValueError("invalid workload_key")
    if not claim["nonce_b64"]:
        raise ValueError("nonce_b64 required")

def claim_hash(claim):
    validate_shape(claim)
    return "sha256:" + hashlib.sha256(DOMAIN + canonical_json(claim)).hexdigest()

def resolved_config_digest(config):
    return "sha256:" + hashlib.sha256(
        b"akash-dstack-resolved-config/v0.1\0" + canonical_json(config)
    ).hexdigest()
