import json
import os
from dataclasses import dataclass, field


def _validate_digest(name, value):
    if not isinstance(value, str) or not value.startswith("sha256:") or len(value) != 71:
        raise PermissionError(f"{name} must be sha256:<64 hex>")
    try:
        int(value[7:], 16)
    except ValueError as exc:
        raise PermissionError(f"{name} has non-hex characters") from exc


def _reject_duplicate_json_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PermissionError(f"WORKLOAD_POLICIES_JSON contains duplicate key: {key}")
        result[key] = value
    return result


def load_workload_policy(policy_id, raw_policies=None):
    """Load one strict live-service image policy from WORKLOAD_POLICIES_JSON.

    approved_configs is accepted as optional validated audit metadata, but it
    is not installed as a live authorization gate. config_digest remains bound
    into the workload commitment and returned for audit/telemetry.
    """
    raw = os.environ.get("WORKLOAD_POLICIES_JSON") if raw_policies is None else raw_policies
    if not raw:
        raise PermissionError("WORKLOAD_POLICIES_JSON is not configured")
    try:
        policies = json.loads(raw, object_pairs_hook=_reject_duplicate_json_keys)
    except (TypeError, json.JSONDecodeError) as exc:
        raise PermissionError("WORKLOAD_POLICIES_JSON is malformed") from exc
    if not isinstance(policies, dict) or not policies:
        raise PermissionError("WORKLOAD_POLICIES_JSON must be a non-empty object")
    configured = policies.get(policy_id)
    if configured is None:
        raise PermissionError(f"unknown workload policy: {policy_id}")
    if not isinstance(configured, dict):
        raise PermissionError(f"workload policy {policy_id} must be an object")
    if not set(configured).issubset({"approved_images", "approved_configs"}):
        raise PermissionError(
            f"workload policy {policy_id} must contain only approved_images and approved_configs"
        )

    images = configured.get("approved_images")
    configs = configured.get("approved_configs", [])
    if not isinstance(images, list) or not images:
        raise PermissionError(f"workload policy {policy_id} has no approved images")
    if not isinstance(configs, list):
        raise PermissionError(f"workload policy {policy_id} approved_configs must be a list")
    for digest in images:
        _validate_digest("approved image digest", digest)
    for digest in configs:
        _validate_digest("approved config digest", digest)
    if len(set(images)) != len(images) or len(set(configs)) != len(configs):
        raise PermissionError(f"workload policy {policy_id} contains duplicate digests")
    return WorkloadPolicy(approved_images=set(images))


@dataclass
class WorkloadPolicy:
    approved_images: set[str]=field(default_factory=set)
    approved_configs: set[str]=field(default_factory=set)
    def check(self,image_digest,config_digest):
        if self.approved_images and image_digest not in self.approved_images: raise PermissionError("image digest not approved")
        if self.approved_configs and config_digest not in self.approved_configs: raise PermissionError("config digest not approved")
Policy=WorkloadPolicy
