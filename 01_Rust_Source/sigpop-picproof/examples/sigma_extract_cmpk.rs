//! Standalone CLI to extract cmPK and evaluate H_reg from a serialized pi_sigma,
//! with optional verify-and-derive mode.

use circ::ecdsa::pure_sigma::{ECDSASigmaPublicPrior, ECDSASigmaSetupParamsPrior};
use circ::ecdsa::pk_link::h_reg;
use circ::target::r1cs::proof::deserialize_from_file;
use elliptic_curve::sec1::ToEncodedPoint;
use rug::Integer;
use serde::{Serialize, Deserialize};
use std::fs::File;
use std::io::Write;
use std::path::Path;

#[derive(Serialize, Deserialize, Debug)]
pub struct PkLinkVector {
    pub profile: String,
    pub domain_tag_ascii: String,
    pub c0_sec1: String,
    pub c1_sec1: String,
    pub encode_cmpk_hex: String,
    pub encode_cmpk_bytes: usize,
    pub counter: u32,
    pub counter_encoding: String,
    pub digest_hex: String,
    pub digest_integer_endianness: String,
    pub leaf_decimal: String,
}

fn print_usage() {
    eprintln!(
        r#"sigma_extract_cmpk - Extract cmPK and compute H_reg from Sigma proof (pi_sigma)

USAGE:
    sigma_extract_cmpk [SUBCOMMAND] [OPTIONS]

SUBCOMMANDS:
    extract             Directly extract cmPK from pi_sigma statement (default)
    verify-and-derive   Verify Sigma proof against H_CBOR before deriving leaf*

OPTIONS:
    --proof-in <PATH>   Path to serialized pi_sigma binary file [required]
    --out <PATH>        Output path for pk_link_vector.json [required]
    --digest-hex <HEX>  64 hex chars of H_CBOR = SHA256(manifest_cbor) (preferred)
    --h-hi <VAL>        Legacy: higher 128-bit integer of digest
    --h-lo <VAL>        Legacy: lower 128-bit integer of digest
"#
    );
}

fn get_arg(args: &[String], flag: &str) -> Option<String> {
    for i in 0..args.len() {
        if args[i] == flag {
            if i + 1 < args.len() {
                return Some(args[i + 1].clone());
            }
        }
    }
    None
}

fn parse_integer(s: &str) -> Result<Integer, String> {
    let clean = s.trim();
    if clean.starts_with("0x") || clean.starts_with("0X") {
        Integer::from_str_radix(&clean[2..], 16)
            .map_err(|e| format!("Invalid hex integer '{}': {:?}", clean, e))
    } else {
        Integer::from_str_radix(clean, 10)
            .map_err(|e| format!("Invalid decimal integer '{}': {:?}", clean, e))
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 || args.contains(&"-h".to_string()) || args.contains(&"--help".to_string()) {
        print_usage();
        std::process::exit(1);
    }

    let is_verify_derive = args.contains(&"verify-and-derive".to_string())
        || get_arg(&args, "--digest-hex").is_some()
        || get_arg(&args, "--digest").is_some()
        || (get_arg(&args, "--h-hi").is_some() && get_arg(&args, "--h-lo").is_some());

    let proof_in = get_arg(&args, "--proof-in")
        .or_else(|| get_arg(&args, "--sigma-proof"))
        .expect("Missing --proof-in argument");
    let out_path = get_arg(&args, "--out")
        .or_else(|| get_arg(&args, "--cm-pk-out"))
        .expect("Missing --out argument");

    println!("[SIGMA_EXTRACT] Deserializing ECDSASigmaPublicPrior from: {}", proof_in);
    let sigma_pf: ECDSASigmaPublicPrior = deserialize_from_file(&proof_in)
        .map_err(|e| format!("Failed to deserialize pi_sigma from {}: {:?}", proof_in, e))?;

    if is_verify_derive {
        println!("[SIGMA_EXTRACT] Mode: verify-and-derive active");
        let digest_result = if let Some(digest_hex) = get_arg(&args, "--digest-hex").or_else(|| get_arg(&args, "--digest")) {
            let clean = digest_hex.trim().trim_start_matches("0x").trim_start_matches("0X");
            if clean.len() != 64 {
                return Err(format!("Digest hex must be 64 characters (32 bytes), got {}", clean.len()).into());
            }
            Integer::from_str_radix(clean, 16).map_err(|e| format!("Invalid hex integer: {:?}", e))?
        } else if let (Some(h_hi_str), Some(h_lo_str)) = (get_arg(&args, "--h-hi"), get_arg(&args, "--h-lo")) {
            let h_hi = parse_integer(&h_hi_str).map_err(|e| format!("Invalid h_hi: {}", e))?;
            let h_lo = parse_integer(&h_lo_str).map_err(|e| format!("Invalid h_lo: {}", e))?;
            (h_hi << 128) | h_lo
        } else {
            return Err("verify-and-derive requires either --digest-hex <HEX> or (--h-hi <VAL> and --h-lo <VAL>)".into());
        };

        println!("[SIGMA_EXTRACT] Verifying Sigma proof against digest = {}...", digest_result);
        let params = ECDSASigmaSetupParamsPrior::new();
        let prev_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let ver_res = std::panic::catch_unwind(|| {
            sigma_pf.verify(&digest_result, params);
        });
        std::panic::set_hook(prev_hook);

        if ver_res.is_err() {
            eprintln!("[SIGMA_EXTRACT] ERROR: Sigma proof verification REJECTED!");
            return Err("Sigma verification failed: proof is invalid for given (h_hi, h_lo)".into());
        }
        println!("[SIGMA_EXTRACT] Sigma proof verification PASSED!");
    } else {
        println!("[SIGMA_EXTRACT] Mode: statement extraction (without signature verification)");
    }

    let pt_c0 = sigma_pf.cm_pk[0].0;
    let pt_c1 = sigma_pf.cm_pk[1].0;

    let enc_c0 = pt_c0.to_encoded_point(true);
    let enc_c1 = pt_c1.to_encoded_point(true);

    let c0_bytes = enc_c0.as_bytes();
    let c1_bytes = enc_c1.as_bytes();

    let (leaf, counter, digest, encoded_cmpk) =
        h_reg(c0_bytes, c1_bytes)
            .map_err(|e| format!("H_reg failed: {}", e))?;

    let encode_cmpk_hex = hex::encode(&encoded_cmpk);
    let digest_hex = hex::encode(&digest);

    println!("C0 SEC1 bytes      = {}", c0_bytes.len());
    println!("C1 SEC1 bytes      = {}", c1_bytes.len());
    println!("Encode(cmPK) bytes = {}", encoded_cmpk.len());
    println!("counter            = {}", counter);
    println!("digest             = {}", digest_hex);
    println!("leaf               = {}", leaf);
    println!("H_REG_PASS");

    let vector = PkLinkVector {
        profile: "PicProof-PKI-CMPK-v1".to_string(),
        domain_tag_ascii: "PICPROOF-PKI-CMPK-v1".to_string(),

        c0_sec1: hex::encode(c0_bytes),
        c1_sec1: hex::encode(c1_bytes),

        encode_cmpk_hex,
        encode_cmpk_bytes: 66,

        counter,
        counter_encoding: "u32-big-endian".to_string(),

        digest_hex,
        digest_integer_endianness: "unsigned-big-endian".to_string(),

        leaf_decimal: leaf.to_string(),
    };

    if let Some(parent) = Path::new(&out_path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut f = File::create(&out_path)?;
    f.write_all(serde_json::to_string_pretty(&vector)?.as_bytes())?;
    println!("[SIGMA_EXTRACT] Saved pk_link_vector JSON to: {}", out_path);

    Ok(())
}
