// Prototype for Kata Agent: canonical resolved runtime config digest.
//
// Target source context:
// kata-containers/kata-containers
// commit: 8feb5c9a7cf2a3704377dd9ff18c51ed19952dfd
//
// Intended call site:
// src/agent/src/rpc.rs::AgentService::do_create_container()
// AFTER:
//   update_container_namespaces(...)
//   append_guest_hooks(...)
// BEFORE:
//   setup_bundle(...)
//
// This means the digest sees the OCI Spec after Kata's in-guest mutations,
// rather than the unmodified host request.
//
// SECURITY NOTE:
// This digest is only meaningful when computed by the measured kata-agent
// and later bound to fresh attestation evidence. It must not be accepted
// from the tenant container itself.

use anyhow::{anyhow, Result};
use oci_spec::runtime::Spec;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const DOMAIN: &[u8] = b"akash-dstack-resolved-config/v0.1\0";

/// Security-relevant subset of the resolved OCI runtime spec.
///
/// We intentionally omit generated/runtime-noise fields such as container IDs,
/// timestamps, ephemeral IPs, bundle paths, and scheduler metadata.
///
/// This is a first reviewable policy surface, NOT a final standard.
pub fn resolved_runtime_config(spec: &Spec) -> Result<Value> {
    let raw = serde_json::to_value(spec)
        .map_err(|e| anyhow!("failed to serialize OCI spec: {e}"))?;

    let process = raw.get("process").cloned().unwrap_or(Value::Null);
    let root = raw.get("root").cloned().unwrap_or(Value::Null);
    let mounts = raw.get("mounts").cloned().unwrap_or(Value::Array(vec![]));
    let linux = raw.get("linux").cloned().unwrap_or(Value::Null);

    let mut out = Map::new();

    // Process identity / entry point.
    out.insert("process".into(), select_process_fields(&process));

    // Whether the rootfs is writable is security relevant.
    out.insert("root".into(), select_fields(&root, &["readonly"]));

    // Mount destination/type/options affect what the workload can observe/change.
    out.insert("mounts".into(), normalize_mounts(&mounts));

    // Selected Linux security/runtime controls.
    out.insert("linux".into(), select_linux_fields(&linux));

    Ok(sort_json(Value::Object(out)))
}

fn select_process_fields(v: &Value) -> Value {
    let mut out = Map::new();
    if let Some(o) = v.as_object() {
        for k in ["args", "cwd", "user", "capabilities", "noNewPrivileges", "apparmorProfile"] {
            if let Some(value) = o.get(k) {
                out.insert(k.to_string(), value.clone());
            }
        }

        // Environment needs policy, not blind inclusion.
        // v0.1 sorts the full environment to make the result deterministic.
        // Before production use, replace this with an explicit allowlist /
        // denylist agreed by the verifier policy.
        if let Some(Value::Array(env)) = o.get("env") {
            let mut env_strings: Vec<String> = env.iter()
                .filter_map(|x| x.as_str().map(ToOwned::to_owned))
                .collect();
            env_strings.sort();
            out.insert(
                "env".into(),
                Value::Array(env_strings.into_iter().map(Value::String).collect()),
            );
        }
    }
    Value::Object(out)
}

fn normalize_mounts(v: &Value) -> Value {
    let Some(mounts) = v.as_array() else {
        return Value::Array(vec![]);
    };

    let mut normalized = Vec::new();
    for m in mounts {
        let mut out = Map::new();
        if let Some(o) = m.as_object() {
            // Deliberately omit host/guest source path from v0.1 because it can
            // contain generated per-container paths. A future policy should
            // replace source with a stable policy identity where required.
            for k in ["destination", "type", "options"] {
                if let Some(value) = o.get(k) {
                    let value = if k == "options" {
                        sort_string_array(value)
                    } else {
                        value.clone()
                    };
                    out.insert(k.to_string(), value);
                }
            }
        }
        normalized.push(sort_json(Value::Object(out)));
    }

    // Mount order should not change the digest when semantics are identical.
    normalized.sort_by_key(|v| serde_json::to_string(v).unwrap_or_default());
    Value::Array(normalized)
}

fn select_linux_fields(v: &Value) -> Value {
    let mut out = Map::new();
    if let Some(o) = v.as_object() {
        for k in [
            "devices",
            "resources",
            "namespaces",
            "seccomp",
            "maskedPaths",
            "readonlyPaths",
        ] {
            if let Some(value) = o.get(k) {
                out.insert(k.to_string(), value.clone());
            }
        }
    }
    Value::Object(out)
}

fn select_fields(v: &Value, fields: &[&str]) -> Value {
    let mut out = Map::new();
    if let Some(o) = v.as_object() {
        for k in fields {
            if let Some(value) = o.get(*k) {
                out.insert((*k).to_string(), value.clone());
            }
        }
    }
    Value::Object(out)
}

fn sort_string_array(v: &Value) -> Value {
    let Some(arr) = v.as_array() else {
        return v.clone();
    };
    let mut values: Vec<String> = arr.iter()
        .filter_map(|x| x.as_str().map(ToOwned::to_owned))
        .collect();
    values.sort();
    Value::Array(values.into_iter().map(Value::String).collect())
}

/// Recursively sort JSON object keys so hashing is deterministic regardless
/// of serde_json map implementation/features.
fn sort_json(v: Value) -> Value {
    match v {
        Value::Object(map) => {
            let mut sorted = BTreeMap::new();
            for (k, value) in map {
                sorted.insert(k, sort_json(value));
            }
            let mut out = Map::new();
            for (k, value) in sorted {
                out.insert(k, value);
            }
            Value::Object(out)
        }
        Value::Array(values) => Value::Array(values.into_iter().map(sort_json).collect()),
        other => other,
    }
}

pub fn config_digest(spec: &Spec) -> Result<String> {
    let canonical = resolved_runtime_config(spec)?;
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|e| anyhow!("failed to encode canonical config: {e}"))?;

    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update(bytes);

    Ok(format!("sha256:{:x}", hasher.finalize()))
}
