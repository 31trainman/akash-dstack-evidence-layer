#[cfg(target_os = "linux")]
mod linux_capture {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use reqwest::{redirect::Policy, Client, Response, Url};
    use serde::Deserialize;
    use serde_json::{json, Value};
    use sev::{firmware::guest::{AttestationReport, Firmware}, parser::ByteParser};
    use sha2::{Digest, Sha256};
    use std::{env, fs, net::{IpAddr, Ipv4Addr, Ipv6Addr}, path::{Path, PathBuf}, time::{Duration, SystemTime, UNIX_EPOCH}};
    use verifier::{snp::Snp, InitDataHash, ReportData, Verifier};

    const TRUSTEE_REVISION: &str = "f8761b823952f71db40dd6b53050f3fd008c9758";
    const COMMITMENT_LABEL: &str = "akash-dstack-trustee-snp-fixture-v1";
    const COMMITMENT_HEX: &str = "a9101838fe1e450778a358747803d6ea9b3ff4563f77a79727d42923eeb3cf5a";
    const CONSENT_TEXT: &str = "I authorize publication of this non-production SEV-SNP report, chip ID, and public certificate material.";
    const DEFAULT_SIDECAR_URL: &str = "https://127.0.0.1:8790";
    const SIDECAR_PROTOCOL_VERSION: &str = "4";
    const SNP_REPORT_BYTES: usize = 1184;
    const MAX_INFO_RESPONSE_BYTES: usize = 8 * 1024;
    // SNP-GPU responses can include sizeable per-device evidence even though
    // this capture mode consumes only the CPU report.
    const MAX_QUOTE_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
    const MAX_VCEK_BYTES: usize = 16 * 1024;
    const MAX_CHAIN_BYTES: usize = 64 * 1024;
    const SIDECAR_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum CaptureMode { Direct, AkashSidecar }

    impl CaptureMode {
        fn metadata_name(self) -> &'static str {
            match self { Self::Direct => "direct-sev-guest", Self::AkashSidecar => "akash-sidecar" }
        }
    }

    struct Args {
        output: PathBuf,
        consent_file: PathBuf,
        source_revision: String,
        capture_mode: CaptureMode,
        sidecar_url: Option<String>,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct CaptureDetails {
        mode: CaptureMode,
        sidecar_protocol_version: Option<String>,
        sidecar_platform: Option<String>,
        tls_bound: Option<bool>,
    }

    struct CapturedReport { raw_report: Vec<u8>, details: CaptureDetails }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct InfoResponse {
        protocol_version: String,
        #[serde(default)] tee_platform: Option<String>,
        #[serde(default)] tee_type: Option<String>,
        #[serde(default)] gpu_available: Option<bool>,
        #[serde(default)] tls_public_key: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct QuoteResponse {
        report: String,
        #[serde(default)] cert_chain: String,
        #[serde(default)] tee_platform: Option<String>,
        #[serde(default)] tee_type: Option<String>,
        #[serde(default)] auxblob: String,
        #[serde(default)] gpu_reports: Vec<Value>,
        tls_bound: bool,
    }

    pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
        let args = parse_args()?;
        verify_consent(&args.consent_file)?;
        prepare_output(&args.output)?;
        let commitment: [u8; 32] = hex::decode(COMMITMENT_HEX)?.try_into().unwrap();
        let mut requested_report_data = [0u8; 64];
        requested_report_data[..32].copy_from_slice(&commitment);
        let captured = match args.capture_mode {
            CaptureMode::Direct => capture_direct(requested_report_data)?,
            CaptureMode::AkashSidecar => capture_akash_sidecar(
                args.sidecar_url.as_deref().unwrap_or(DEFAULT_SIDECAR_URL), requested_report_data
            ).await?,
        };
        validate_and_write(&args.output, &args.source_revision, &commitment, &requested_report_data, captured).await
    }

    // This is the original direct /dev/sev-guest collection operation.
    fn capture_direct(requested_report_data: [u8; 64]) -> Result<CapturedReport, Box<dyn std::error::Error>> {
        let mut firmware = Firmware::open().map_err(|e| format!("open /dev/sev-guest: {e}"))?;
        let raw_report = firmware.get_report(None, Some(requested_report_data), Some(0))
            .map_err(|e| format!("request hardware SEV-SNP report: {e}"))?;
        Ok(CapturedReport { raw_report, details: CaptureDetails {
            mode: CaptureMode::Direct, sidecar_protocol_version: None,
            sidecar_platform: None, tls_bound: None,
        }})
    }

    async fn capture_akash_sidecar(sidecar_url: &str, requested_report_data: [u8; 64])
        -> Result<CapturedReport, Box<dyn std::error::Error>> {
        let base_url = validate_sidecar_url(sidecar_url)?;
        // Akash uses an ephemeral self-signed certificate. Relaxed validation
        // is confined to a literal loopback URL with redirects disabled. This
        // client is never reused for AMD KDS.
        let client = Client::builder().https_only(true).danger_accept_invalid_certs(true)
            .redirect(Policy::none()).timeout(SIDECAR_REQUEST_TIMEOUT).build()?;
        let info_body = bounded_response(
            client.get(endpoint(&base_url, "info")?).send().await?.error_for_status()?,
            MAX_INFO_RESPONSE_BYTES, "Akash sidecar /info").await?;
        let (protocol_version, info_platform) = parse_info_response(&info_body)?;
        let request = quote_request(requested_report_data)?;
        let quote_body = bounded_response(
            client.post(endpoint(&base_url, "quote")?).header("Content-Type", "application/json")
                .body(request).send().await?.error_for_status()?,
            MAX_QUOTE_RESPONSE_BYTES, "Akash sidecar /quote").await?;
        let (raw_report, quote_platform, tls_bound) = parse_quote_response(&quote_body)?;
        if quote_platform != info_platform {
            return Err(format!("Akash sidecar platform changed between /info ({info_platform}) and /quote ({quote_platform})").into());
        }
        Ok(CapturedReport { raw_report, details: CaptureDetails {
            mode: CaptureMode::AkashSidecar,
            sidecar_protocol_version: Some(protocol_version),
            sidecar_platform: Some(quote_platform), tls_bound: Some(tls_bound),
        }})
    }

    fn validate_sidecar_url(value: &str) -> Result<Url, Box<dyn std::error::Error>> {
        let url = Url::parse(value).map_err(|e| format!("invalid Akash sidecar URL: {e}"))?;
        if url.scheme() != "https" { return Err("Akash sidecar URL must use HTTPS".into()); }
        if !url.username().is_empty() || url.password().is_some() {
            return Err("Akash sidecar URL must not contain credentials".into());
        }
        let serialized_host = url.host_str().ok_or("Akash sidecar URL must contain a host")?;
        let host = serialized_host.strip_prefix('[').and_then(|host| host.strip_suffix(']'))
            .unwrap_or(serialized_host)
            .parse::<IpAddr>().map_err(|_| "Akash sidecar host must be a literal loopback IP address")?;
        if !host.is_loopback()
            || (host != IpAddr::V4(Ipv4Addr::LOCALHOST) && host != IpAddr::V6(Ipv6Addr::LOCALHOST)) {
            return Err("Akash sidecar host must be exactly 127.0.0.1 or ::1".into());
        }
        if url.query().is_some() || url.fragment().is_some() || !matches!(url.path(), "" | "/") {
            return Err("Akash sidecar URL must not contain a path, query, or fragment".into());
        }
        Ok(url)
    }

    fn endpoint(base: &Url, path: &str) -> Result<Url, Box<dyn std::error::Error>> { Ok(base.join(path)?) }

    fn quote_request(report_data: [u8; 64]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(serde_json::to_vec(&json!({
            "nonce": B64.encode(report_data),
            "bind_tls": false
        }))?)
    }

    async fn bounded_response(mut response: Response, max: usize, source: &str)
        -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if response.content_length().is_some_and(|size| size > max as u64) {
            return Err(format!("{source} response exceeds {max} bytes").into());
        }
        let mut output = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if output.len() + chunk.len() > max {
                return Err(format!("{source} response exceeds {max} bytes").into());
            }
            output.extend_from_slice(&chunk);
        }
        Ok(output)
    }

    fn parse_info_response(body: &[u8]) -> Result<(String, String), Box<dyn std::error::Error>> {
        if body.len() > MAX_INFO_RESPONSE_BYTES { return Err("Akash sidecar /info response is oversized".into()); }
        let response: InfoResponse = serde_json::from_slice(body)
            .map_err(|e| format!("malformed Akash sidecar /info response: {e}"))?;
        if response.protocol_version != SIDECAR_PROTOCOL_VERSION {
            return Err(format!("unsupported Akash sidecar protocol version {}; expected {SIDECAR_PROTOCOL_VERSION}", response.protocol_version).into());
        }
        let _ = (response.gpu_available, response.tls_public_key);
        let platform = normalized_platform(response.tee_platform, response.tee_type)?;
        Ok((response.protocol_version, platform))
    }

    fn parse_quote_response(body: &[u8]) -> Result<(Vec<u8>, String, bool), Box<dyn std::error::Error>> {
        if body.len() > MAX_QUOTE_RESPONSE_BYTES { return Err("Akash sidecar /quote response is oversized".into()); }
        let response: QuoteResponse = serde_json::from_slice(body)
            .map_err(|e| format!("malformed Akash sidecar /quote response: {e}"))?;
        let platform = normalized_platform(response.tee_platform, response.tee_type)?;
        if response.tls_bound { return Err("Akash fixture capture requires tls_bound=false".into()); }
        let raw_report = B64.decode(response.report.as_bytes())
            .map_err(|_| "Akash sidecar report is not strict base64")?;
        if B64.encode(&raw_report) != response.report {
            return Err("Akash sidecar report is not canonical standard base64".into());
        }
        if raw_report.len() != SNP_REPORT_BYTES {
            return Err(format!("unexpected report size {}; expected {SNP_REPORT_BYTES}", raw_report.len()).into());
        }
        AttestationReport::from_bytes(&raw_report)
            .map_err(|_| "Akash sidecar report is not a parseable SNP AttestationReport")?;
        // These protocol fields are parsed but cannot become KDS or Trustee inputs.
        let _ = (response.cert_chain, response.auxblob, response.gpu_reports);
        Ok((raw_report, platform, false))
    }

    fn normalized_platform(tee_platform: Option<String>, tee_type: Option<String>)
        -> Result<String, Box<dyn std::error::Error>> {
        if let (Some(primary), Some(alias)) = (&tee_platform, &tee_type) {
            if primary != alias {
                return Err(format!("contradictory Akash sidecar platform fields: tee_platform={primary}, tee_type={alias}").into());
            }
        }
        let platform = tee_platform.or(tee_type).ok_or("Akash sidecar response is missing tee_platform")?;
        if platform != "snp" && platform != "snp-gpu" {
            return Err(format!("Akash sidecar returned unsupported TEE platform: {platform}").into());
        }
        Ok(platform)
    }

    async fn validate_and_write(output: &Path, source_revision: &str, commitment: &[u8; 32],
        requested_report_data: &[u8; 64], captured: CapturedReport)
        -> Result<(), Box<dyn std::error::Error>> {
        let raw_report = captured.raw_report;
        if raw_report.len() != SNP_REPORT_BYTES {
            return Err(format!("unexpected report size {}; expected {SNP_REPORT_BYTES}", raw_report.len()).into());
        }
        let report = AttestationReport::from_bytes(&raw_report)?;
        if !(3..=5).contains(&report.version) {
            return Err(format!("report version {} is outside pinned Trustee's 3..=5 range", report.version).into());
        }
        if report.report_data != *requested_report_data {
            return Err("hardware-signed REPORT_DATA does not equal commitment32 || zero32".into());
        }
        if report.vmpl != 0 { return Err(format!("unexpected VMPL {}; expected 0", report.vmpl).into()); }
        let generation = processor_generation(&report)?;
        let chip_id_hex = if generation == "Turin" { hex::encode(&report.chip_id[..8]) } else { hex::encode(report.chip_id) };
        if report.chip_id == [0u8; 64] { return Err("report masks chip ID; a matching VCEK cannot be retrieved".into()); }
        let vcek_url = vcek_url(generation, &chip_id_hex, &report)?;
        let chain_url = format!("https://kdsintf.amd.com/vcek/v1/{generation}/cert_chain");
        // Strict TLS client, deliberately separate from the loopback sidecar client.
        let client = Client::builder().https_only(true).build()?;
        let vcek = bounded_get(&client, &vcek_url, MAX_VCEK_BYTES).await?;
        let amd_chain = bounded_get(&client, &chain_url, MAX_CHAIN_BYTES).await?;
        let pem_begin_count = amd_chain.windows(b"-----BEGIN CERTIFICATE-----".len())
            .filter(|window| *window == b"-----BEGIN CERTIFICATE-----").count();
        if pem_begin_count != 2 {
            return Err(format!("AMD certificate-chain response must contain exactly ASK and ARK; found {pem_begin_count} PEM certificates").into());
        }
        let evidence = json!({"attestation_report": report, "cert_chain": [{"cert_type": "VCEK", "data": vcek}]});
        let snp = Snp::new(None).await?;
        snp.evaluate(evidence, &ReportData::Value(commitment), &InitDataHash::NotProvided).await
            .map_err(|e| format!("pinned Trustee rejected captured evidence: {e:#}"))?;
        fs::write(output.join("report.bin"), &raw_report)?;
        fs::write(output.join("vcek.der"), &vcek)?;
        fs::write(output.join("amd-cert-chain.pem"), &amd_chain)?;
        let metadata = json!({
            "schema_version": 1, "trustee_revision": TRUSTEE_REVISION,
            "capture_tool_source_revision": source_revision,
            "capture_tool_version": env!("CARGO_PKG_VERSION"),
            "capture_mode": captured.details.mode.metadata_name(),
            "sidecar_protocol_version": captured.details.sidecar_protocol_version,
            "sidecar_platform": captured.details.sidecar_platform,
            "tls_bound": captured.details.tls_bound,
            "captured_at_unix_seconds": SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            "guest_kernel_release": fs::read_to_string("/proc/sys/kernel/osrelease")?.trim(),
            "commitment_label": COMMITMENT_LABEL, "expected_commitment_hex": COMMITMENT_HEX,
            "report_data_layout": "commitment32_zero_pad32", "report_version": report.version,
            "report_size": raw_report.len(), "vmpl": report.vmpl, "processor_generation": generation,
            "cpuid": {"family": report.cpuid_fam_id, "model": report.cpuid_mod_id, "stepping": report.cpuid_step},
            "chip_id_hex": hex::encode(report.chip_id),
            "reported_tcb": {"fmc": report.reported_tcb.fmc, "bootloader": report.reported_tcb.bootloader,
                "tee": report.reported_tcb.tee, "snp": report.reported_tcb.snp,
                "microcode": report.reported_tcb.microcode},
            "kds": {"base_url": "https://kdsintf.amd.com", "vcek_url": vcek_url,
                "certificate_chain_url": chain_url},
            "publication": {"operator_consent_confirmed": true, "production_hardware": false,
                "warning": "The report and chip ID are persistent hardware identifiers."}
        });
        fs::write(output.join("metadata.json"), serde_json::to_vec_pretty(&metadata)?)?;
        write_readme(output, generation, &vcek_url, &chain_url, captured.details.mode)?;
        write_hashes(output)?;
        println!("Captured and Trustee-validated fixture at {}", output.display());
        Ok(())
    }

    fn parse_args() -> Result<Args, Box<dyn std::error::Error>> {
        let mut args = env::args().skip(1);
        let (mut output, mut consent, mut source_revision, mut sidecar_url) = (None, None, None, None);
        let mut capture_mode = CaptureMode::Direct;
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--output" => output = args.next().map(PathBuf::from),
                "--operator-consent-file" => consent = args.next().map(PathBuf::from),
                "--source-revision" => source_revision = args.next(),
                "--capture-mode" => capture_mode = match args.next().as_deref() {
                    Some("direct") => CaptureMode::Direct, Some("akash-sidecar") => CaptureMode::AkashSidecar,
                    Some(value) => return Err(format!("unknown capture mode: {value}").into()),
                    None => return Err("missing value for --capture-mode".into()),
                },
                "--sidecar-url" => sidecar_url = args.next(),
                _ => return Err(format!("unknown argument: {arg}").into()),
            }
        }
        if capture_mode == CaptureMode::Direct && sidecar_url.is_some() {
            return Err("--sidecar-url is only valid with --capture-mode akash-sidecar".into());
        }
        Ok(Args { output: output.ok_or("missing --output DIRECTORY")?,
            consent_file: consent.ok_or("missing --operator-consent-file FILE")?,
            source_revision: source_revision.ok_or("missing --source-revision COMMIT_SHA")?,
            capture_mode, sidecar_url })
    }

    fn verify_consent(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let text = fs::read_to_string(path)?;
        if text.trim() != CONSENT_TEXT { return Err(format!("consent file must contain exactly: {CONSENT_TEXT}").into()); }
        Ok(())
    }

    fn prepare_output(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        if path.exists() {
            if fs::read_dir(path)?.next().is_some() { return Err("output directory must be empty; capture never overwrites artifacts".into()); }
        } else { fs::create_dir_all(path)?; }
        Ok(())
    }

    fn processor_generation(report: &AttestationReport) -> Result<&'static str, Box<dyn std::error::Error>> {
        let family = report.cpuid_fam_id.ok_or("version 3+ report lacks CPU family")?;
        let model = report.cpuid_mod_id.ok_or("version 3+ report lacks CPU model")?;
        match (family, model) {
            (0x19, 0x00..=0x0f) => Ok("Milan"), (0x19, 0x10..=0x1f | 0xa0..=0xaf) => Ok("Genoa"),
            (0x1a, 0x00..=0x11) => Ok("Turin"),
            _ => Err(format!("processor family/model {family:#x}/{model:#x} is unsupported by pinned Trustee").into()),
        }
    }

    fn vcek_url(generation: &str, hw_id: &str, report: &AttestationReport) -> Result<String, Box<dyn std::error::Error>> {
        let tcb = &report.reported_tcb;
        let extra = if generation == "Turin" { format!("fmcSPL={:02}&", tcb.fmc.ok_or("Turin report lacks FMC TCB")?) } else { String::new() };
        Ok(format!("https://kdsintf.amd.com/vcek/v1/{generation}/{hw_id}?{extra}blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
            tcb.bootloader, tcb.tee, tcb.snp, tcb.microcode))
    }

    async fn bounded_get(client: &Client, url: &str, max: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        bounded_response(client.get(url).send().await?.error_for_status()?, max, url).await
    }

    fn write_hashes(output: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let mut lines = String::new();
        for name in ["report.bin", "vcek.der", "amd-cert-chain.pem", "metadata.json", "README.md"] {
            lines.push_str(&format!("{}  {name}\n", hex::encode(Sha256::digest(fs::read(output.join(name))?))));
        }
        fs::write(output.join("SHA256SUMS"), lines)?;
        Ok(())
    }

    fn write_readme(output: &Path, generation: &str, vcek_url: &str, chain_url: &str, capture_mode: CaptureMode)
        -> Result<(), Box<dyn std::error::Error>> {
        let body = format!(r#"# Current SEV-SNP fixture provenance

This non-secret fixture was captured from genuine {generation} SEV-SNP hardware
using capture mode `{capture_mode}`. The report and chip ID are persistent
hardware identifiers. The machine operator explicitly authorized publication
before capture. This material must not be captured from or committed for
production hardware without that approval.

The fixed public commitment is SHA-256(`{COMMITMENT_LABEL}`):
`{COMMITMENT_HEX}`.

Pinned Trustee revision: `{TRUSTEE_REVISION}`. Its accepted report-version
range is 3..=5; this is only a fixture sanity check. Trustee's `Snp::evaluate()`
is authoritative for acceptance.

AMD public certificate retrieval:

```sh
curl --fail --proto '=https' --tlsv1.2 --output vcek.der '{vcek_url}'
curl --fail --proto '=https' --tlsv1.2 --output amd-cert-chain.pem '{chain_url}'
sha256sum --check SHA256SUMS
```

`vcek.der` is supplied to Trustee. Trustee combines it with its pinned,
processor-specific embedded ASK and ARK and verifies that complete chain.
`amd-cert-chain.pem` preserves AMD's complete public ASK/ARK response for
independent provenance and reproducible retrieval; it does not replace the
embedded Trustee trust anchors.
"#, capture_mode = capture_mode.metadata_name());
        fs::write(output.join("README.md"), body)?;
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn legacy_report_b64() -> String {
            include_str!("../../tests/fixtures/trustee-test-report.b64").trim().to_owned()
        }
        fn info(protocol: &str, platform: &str) -> Vec<u8> {
            serde_json::to_vec(&json!({"protocol_version": protocol, "tee_platform": platform,
                "tls_public_key": "AA=="})).unwrap()
        }
        fn quote(platform_fields: Value, tls_bound: bool, report: &str, cert: &str) -> Vec<u8> {
            let mut value = json!({"report": report, "cert_chain": cert, "auxblob": "",
                "gpu_reports": [], "tls_bound": tls_bound});
            value.as_object_mut().unwrap().extend(platform_fields.as_object().unwrap().iter()
                .map(|(key, value)| (key.clone(), value.clone())));
            serde_json::to_vec(&value).unwrap()
        }

        #[test]
        fn rejects_remote_and_non_loopback_urls() {
            for url in ["https://example.com:8790", "https://localhost:8790",
                "https://127.0.0.2:8790", "https://10.0.0.1:8790",
                "https://[2001:db8::1]:8790"] {
                assert!(validate_sidecar_url(url).is_err(), "accepted {url}");
            }
            assert!(validate_sidecar_url(DEFAULT_SIDECAR_URL).is_ok());
            assert!(validate_sidecar_url("https://[::1]:8790").is_ok());
        }
        #[test] fn rejects_http_url() { assert!(validate_sidecar_url("http://127.0.0.1:8790").is_err()); }
        #[test]
        fn quote_request_preserves_commitment_and_zero_padding() {
            let commitment: [u8; 32] = hex::decode(COMMITMENT_HEX).unwrap().try_into().unwrap();
            let mut expected = [0u8; 64];
            expected[..32].copy_from_slice(&commitment);
            let request: Value = serde_json::from_slice(&quote_request(expected).unwrap()).unwrap();
            assert_eq!(request.as_object().unwrap().len(), 2);
            assert_eq!(request["bind_tls"], false);
            assert_eq!(B64.decode(request["nonce"].as_str().unwrap()).unwrap(), expected);
        }
        #[test] fn rejects_wrong_sidecar_protocol_version() { assert!(parse_info_response(&info("3", "snp")).is_err()); }
        #[test] fn rejects_tdx_response() {
            assert!(parse_quote_response(&quote(json!({"tee_platform": "tdx"}), false, "AA==", "")).is_err());
        }
        #[test] fn rejects_contradictory_platform_fields() {
            assert!(parse_quote_response(&quote(json!({"tee_platform": "snp", "tee_type": "tdx"}), false, "AA==", "")).is_err());
        }
        #[test] fn rejects_tls_bound_quote() {
            assert!(parse_quote_response(&quote(json!({"tee_platform": "snp"}), true, &legacy_report_b64(), "")).is_err());
        }
        #[test] fn rejects_malformed_and_oversized_quote_response() {
            assert!(parse_quote_response(b"not-json").is_err());
            assert!(parse_quote_response(&quote(
                json!({"tee_platform": "snp"}), false, "not-base64!", ""
            )).is_err());
            assert!(parse_quote_response(&vec![b' '; MAX_QUOTE_RESPONSE_BYTES + 1]).is_err());
        }
        #[test] fn rejects_wrong_report_length() {
            let report = B64.encode(vec![0u8; SNP_REPORT_BYTES - 1]);
            assert!(parse_quote_response(&quote(json!({"tee_platform": "snp"}), false, &report, "")).is_err());
        }
        #[test] fn sidecar_certificate_chain_is_ignored_for_trust() {
            let report = legacy_report_b64();
            let empty = parse_quote_response(&quote(json!({"tee_platform": "snp"}), false, &report, "")).unwrap();
            let hostile = parse_quote_response(&quote(json!({"tee_platform": "snp"}), false, &report,
                "attacker-controlled-certificate-material")).unwrap();
            assert_eq!(empty, hostile);
        }
        #[test] fn accepts_documented_platform_alias_when_unambiguous() {
            let (_, platform, tls_bound) = parse_quote_response(&quote(json!({"tee_type": "snp-gpu"}),
                false, &legacy_report_b64(), "")).unwrap();
            assert_eq!(platform, "snp-gpu"); assert!(!tls_bound);
        }
    }
}

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() {
    if print_version_if_requested() {
        return;
    }
    if let Err(error) = linux_capture::run().await {
        eprintln!("capture failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    if print_version_if_requested() {
        return;
    }
    eprintln!("capture requires Linux inside a genuine SEV-SNP guest with /dev/sev-guest or the Akash attestation sidecar");
    std::process::exit(1);
}

fn print_version_if_requested() -> bool {
    let mut args = std::env::args_os().skip(1);
    if args.next().as_deref() == Some(std::ffi::OsStr::new("--version")) && args.next().is_none() {
        println!("capture_snp_fixture {}", env!("CARGO_PKG_VERSION"));
        true
    } else {
        false
    }
}
