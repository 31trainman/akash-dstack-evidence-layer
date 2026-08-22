#[cfg(target_os = "linux")]
mod linux_capture {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use reqwest::Client;
    use serde_json::json;
    use sev::{
        firmware::guest::{AttestationReport, Firmware},
        parser::ByteParser,
    };
    use sha2::{Digest, Sha256};
    use std::{
        env, fs,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };
    use verifier::{snp::Snp, InitDataHash, ReportData, Verifier};

    const TRUSTEE_REVISION: &str = "f8761b823952f71db40dd6b53050f3fd008c9758";
    const COMMITMENT_LABEL: &str = "akash-dstack-trustee-snp-fixture-v1";
    const COMMITMENT_HEX: &str = "a9101838fe1e450778a358747803d6ea9b3ff4563f77a79727d42923eeb3cf5a";
    const CONSENT_TEXT: &str = "I authorize publication of this non-production SEV-SNP report, chip ID, and public certificate material.";
    const MAX_VCEK_BYTES: usize = 16 * 1024;
    const MAX_CHAIN_BYTES: usize = 64 * 1024;

    pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
        let (output, consent_file, source_revision) = parse_args()?;
        verify_consent(&consent_file)?;
        prepare_output(&output)?;

        let commitment: [u8; 32] = hex::decode(COMMITMENT_HEX)?.try_into().unwrap();
        let mut requested_report_data = [0u8; 64];
        requested_report_data[..32].copy_from_slice(&commitment);

        let mut firmware = Firmware::open().map_err(|e| format!("open /dev/sev-guest: {e}"))?;
        let raw_report = firmware
            .get_report(None, Some(requested_report_data), Some(0))
            .map_err(|e| format!("request hardware SEV-SNP report: {e}"))?;
        if raw_report.len() != 1184 {
            return Err(
                format!("unexpected report size {}; expected 1184", raw_report.len()).into(),
            );
        }

        let report = AttestationReport::from_bytes(&raw_report)?;
        // This range is only a fixture sanity check. Pinned Trustee remains the
        // authority that decides whether the report version is acceptable.
        if !(3..=5).contains(&report.version) {
            return Err(format!(
                "report version {} is outside pinned Trustee's 3..=5 range",
                report.version
            )
            .into());
        }
        if report.report_data != requested_report_data {
            return Err("hardware-signed REPORT_DATA does not equal commitment32 || zero32".into());
        }
        if report.vmpl != 0 {
            return Err(format!("unexpected VMPL {}; expected 0", report.vmpl).into());
        }

        let generation = processor_generation(&report)?;
        let chip_id_hex = if generation == "Turin" {
            hex::encode(&report.chip_id[..8])
        } else {
            hex::encode(report.chip_id)
        };
        if report.chip_id == [0u8; 64] {
            return Err("report masks chip ID; a matching VCEK cannot be retrieved".into());
        }
        let vcek_url = vcek_url(generation, &chip_id_hex, &report)?;
        let chain_url = format!("https://kdsintf.amd.com/vcek/v1/{generation}/cert_chain");

        let client = Client::builder().https_only(true).build()?;
        let vcek = bounded_get(&client, &vcek_url, MAX_VCEK_BYTES).await?;
        let amd_chain = bounded_get(&client, &chain_url, MAX_CHAIN_BYTES).await?;
        let pem_begin_count = amd_chain
            .windows(b"-----BEGIN CERTIFICATE-----".len())
            .filter(|window| *window == b"-----BEGIN CERTIFICATE-----")
            .count();
        if pem_begin_count != 2 {
            return Err(format!(
                "AMD certificate-chain response must contain exactly ASK and ARK; found {pem_begin_count} PEM certificates"
            ).into());
        }

        // This is the exact production Trustee path: the supplied VCEK is
        // combined with Trustee's embedded generation-specific ASK and ARK,
        // and the resulting chain, report signature, TCB, VMPL, and binding
        // are all verified by Snp::evaluate().
        let evidence = json!({
            "attestation_report": report,
            "cert_chain": [{"cert_type": "VCEK", "data": vcek}]
        });
        let snp = Snp::new(None).await?;
        snp.evaluate(
            evidence,
            &ReportData::Value(&commitment),
            &InitDataHash::NotProvided,
        )
        .await
        .map_err(|e| format!("pinned Trustee rejected captured evidence: {e:#}"))?;

        fs::write(output.join("report.bin"), &raw_report)?;
        fs::write(output.join("vcek.der"), &vcek)?;
        fs::write(output.join("amd-cert-chain.pem"), &amd_chain)?;

        let metadata = json!({
            "schema_version": 1,
            "trustee_revision": TRUSTEE_REVISION,
            "capture_tool_source_revision": source_revision,
            "capture_tool_version": env!("CARGO_PKG_VERSION"),
            "captured_at_unix_seconds": SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            "guest_kernel_release": fs::read_to_string("/proc/sys/kernel/osrelease")?.trim(),
            "commitment_label": COMMITMENT_LABEL,
            "expected_commitment_hex": COMMITMENT_HEX,
            "report_data_layout": "commitment32_zero_pad32",
            "report_version": report.version,
            "report_size": raw_report.len(),
            "vmpl": report.vmpl,
            "processor_generation": generation,
            "cpuid": {
                "family": report.cpuid_fam_id,
                "model": report.cpuid_mod_id,
                "stepping": report.cpuid_step
            },
            "chip_id_hex": hex::encode(report.chip_id),
            "reported_tcb": {
                "fmc": report.reported_tcb.fmc,
                "bootloader": report.reported_tcb.bootloader,
                "tee": report.reported_tcb.tee,
                "snp": report.reported_tcb.snp,
                "microcode": report.reported_tcb.microcode
            },
            "kds": {
                "base_url": "https://kdsintf.amd.com",
                "vcek_url": vcek_url,
                "certificate_chain_url": chain_url
            },
            "publication": {
                "operator_consent_confirmed": true,
                "production_hardware": false,
                "warning": "The report and chip ID are persistent hardware identifiers."
            }
        });
        fs::write(
            output.join("metadata.json"),
            serde_json::to_vec_pretty(&metadata)?,
        )?;
        write_readme(&output, generation, &vcek_url, &chain_url)?;
        write_hashes(&output)?;
        println!(
            "Captured and Trustee-validated fixture at {}",
            output.display()
        );
        Ok(())
    }

    fn parse_args() -> Result<(PathBuf, PathBuf, String), Box<dyn std::error::Error>> {
        let mut args = env::args().skip(1);
        let mut output = None;
        let mut consent = None;
        let mut source_revision = None;
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--output" => output = args.next().map(PathBuf::from),
                "--operator-consent-file" => consent = args.next().map(PathBuf::from),
                "--source-revision" => source_revision = args.next(),
                _ => return Err(format!("unknown argument: {arg}").into()),
            }
        }
        Ok((
            output.ok_or("missing --output DIRECTORY")?,
            consent.ok_or("missing --operator-consent-file FILE")?,
            source_revision.ok_or("missing --source-revision COMMIT_SHA")?,
        ))
    }

    fn verify_consent(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let text = fs::read_to_string(path)?;
        if text.trim() != CONSENT_TEXT {
            return Err(format!("consent file must contain exactly: {CONSENT_TEXT}").into());
        }
        Ok(())
    }

    fn prepare_output(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        if path.exists() {
            if fs::read_dir(path)?.next().is_some() {
                return Err(
                    "output directory must be empty; capture never overwrites artifacts".into(),
                );
            }
        } else {
            fs::create_dir_all(path)?;
        }
        Ok(())
    }

    fn processor_generation(
        report: &AttestationReport,
    ) -> Result<&'static str, Box<dyn std::error::Error>> {
        let family = report
            .cpuid_fam_id
            .ok_or("version 3+ report lacks CPU family")?;
        let model = report
            .cpuid_mod_id
            .ok_or("version 3+ report lacks CPU model")?;
        match (family, model) {
            (0x19, 0x00..=0x0f) => Ok("Milan"),
            (0x19, 0x10..=0x1f | 0xa0..=0xaf) => Ok("Genoa"),
            (0x1a, 0x00..=0x11) => Ok("Turin"),
            _ => Err(format!(
                "processor family/model {family:#x}/{model:#x} is unsupported by pinned Trustee"
            )
            .into()),
        }
    }

    fn vcek_url(
        generation: &str,
        hw_id: &str,
        report: &AttestationReport,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let tcb = &report.reported_tcb;
        let extra = if generation == "Turin" {
            format!(
                "fmcSPL={:02}&",
                tcb.fmc.ok_or("Turin report lacks FMC TCB")?
            )
        } else {
            String::new()
        };
        Ok(format!(
            "https://kdsintf.amd.com/vcek/v1/{generation}/{hw_id}?{extra}blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
            tcb.bootloader, tcb.tee, tcb.snp, tcb.microcode
        ))
    }

    async fn bounded_get(
        client: &Client,
        url: &str,
        max: usize,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut response = client.get(url).send().await?.error_for_status()?;
        if response.content_length().is_some_and(|n| n > max as u64) {
            return Err(format!("response from {url} exceeds {max} bytes").into());
        }
        let mut output = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if output.len() + chunk.len() > max {
                return Err(format!("response from {url} exceeds {max} bytes").into());
            }
            output.extend_from_slice(&chunk);
        }
        Ok(output)
    }

    fn write_hashes(output: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let mut lines = String::new();
        for name in [
            "report.bin",
            "vcek.der",
            "amd-cert-chain.pem",
            "metadata.json",
            "README.md",
        ] {
            let data = fs::read(output.join(name))?;
            lines.push_str(&format!("{}  {name}\n", hex::encode(Sha256::digest(data))));
        }
        fs::write(output.join("SHA256SUMS"), lines)?;
        Ok(())
    }

    fn write_readme(
        output: &Path,
        generation: &str,
        vcek_url: &str,
        chain_url: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let body = format!(
            r#"# Current SEV-SNP fixture provenance

This non-secret fixture was captured from genuine {generation} SEV-SNP hardware.
The report and chip ID are persistent hardware identifiers. The machine
operator explicitly authorized publication before capture. This material must
not be captured from or committed for production hardware without that approval.

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
"#
        );
        fs::write(output.join("README.md"), body)?;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() {
    if let Err(error) = linux_capture::run().await {
        eprintln!("capture failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("capture requires Linux inside a genuine SEV-SNP guest with /dev/sev-guest");
    std::process::exit(1);
}
