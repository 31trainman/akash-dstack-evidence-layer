use anyhow::{bail, Context, Result};
use akash_coco_snp_adapter::{verify_akash_snp, AkashSnpEnvelope};
use std::{env, fs};

fn decode_hex_arg(name: &str, s: &str) -> Result<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).with_context(|| format!("decode {name} as hex"))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        bail!(
            "usage: {} <akash-attestation.json> <expected-report-data-hex> [expected-init-data-hash-hex]",
            args[0]
        );
    }

    let body = fs::read_to_string(&args[1]).context("read attestation JSON")?;
    let envelope: AkashSnpEnvelope =
        serde_json::from_str(&body).context("parse Akash attestation JSON")?;

    let report_data = decode_hex_arg("REPORT_DATA", &args[2])?;
    let init_data = if args.len() >= 4 {
        Some(decode_hex_arg("Init-Data hash", &args[3])?)
    } else {
        None
    };

    let verified = verify_akash_snp(
        &envelope,
        &report_data,
        init_data.as_deref(),
    )
    .await?;

    println!("SEV-SNP verification: OK");
    println!("verified claim objects: {}", verified.claims.len());
    for (claim, class) in verified.claims {
        println!("TEE class: {class}");
        println!("{}", serde_json::to_string_pretty(&claim)?);
    }

    Ok(())
}
