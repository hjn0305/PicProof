//! Standalone CLI to generate ECDSA Sigma proof (pi_sigma) from an existing P-256 DER signature.
//!
//! USAGE:
//!   sigma_prove \
//!     --digest-hex <64 hex characters of H_CBOR> \
//!     --signature <path to existing DER signature> \
//!     --pubkey <path to camera public key PEM or SEC1> \
//!     --opening <path to opening_v.txt or camera_enrollment_private.json> \
//!     --proof-out <path to write pi_sigma>

use circ::ecdsa::pure_sigma::prover_existing_signature;
use circ::ecdsa::convert::integer_to_scalar;
use circ::ecdsa::ecdsa::EllipticCurveP256;
use elliptic_curve::sec1::FromEncodedPoint;
use p256::{EncodedPoint, ProjectivePoint, Scalar};
use rug::Integer;
use std::env;
use std::fs;
use std::path::Path;

fn get_arg(args: &[String], flag: &str) -> Option<String> {
    for i in 0..args.len() {
        if args[i] == flag && i + 1 < args.len() {
            return Some(args[i + 1].clone());
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

fn load_pubkey(path: &str) -> Result<ProjectivePoint, Box<dyn std::error::Error>> {
    let raw = fs::read(path)?;
    let content = String::from_utf8_lossy(&raw);
    let sec1_bytes = if content.contains("-----BEGIN") {
        let pkey = openssl::pkey::PKey::public_key_from_pem(&raw)?;
        let ec_key = pkey.ec_key()?;
        let group = ec_key.group();
        let mut ctx = openssl::bn::BigNumContext::new()?;
        ec_key.public_key().to_bytes(
            group,
            openssl::ec::PointConversionForm::COMPRESSED,
            &mut ctx,
        )?
    } else {
        raw
    };
    let enc = EncodedPoint::from_bytes(&sec1_bytes)
        .map_err(|e| format!("Invalid SEC1 public key: {:?}", e))?;
    let pt = ProjectivePoint::from_encoded_point(&enc)
        .into_option()
        .ok_or("Failed to convert EncodedPoint to ProjectivePoint")?;
    Ok(pt)
}

fn load_opening(path: &str) -> Result<Scalar, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(path)?;
    let clean = content.trim();
    let int_val = if clean.starts_with('{') {
        let val: serde_json::Value = serde_json::from_str(clean)?;
        let s = val["opening_v"]
            .as_str()
            .ok_or("Missing opening_v in private enrollment json")?;
        parse_integer(s)?
    } else {
        parse_integer(clean)?
    };

    // The opening is a P-256 scalar, not an arbitrary integer to be silently
    // reduced modulo q. In particular, zero would reveal PK_D in C1.
    let q = EllipticCurveP256::new().q;
    if int_val <= 0 || int_val >= q {
        return Err("opening_v must be a canonical non-zero P-256 scalar (0 < v < q)".into());
    }
    Ok(integer_to_scalar(&int_val))
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let clean = s.trim();
    if clean.len() % 2 != 0 {
        return Err("Hex string has odd length".to_string());
    }
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let digest_hex = get_arg(&args, "--digest-hex")
        .or_else(|| get_arg(&args, "--digest"))
        .expect("Missing required argument: --digest-hex");
    let sig_path = get_arg(&args, "--signature").expect("Missing required argument: --signature");
    let pubkey_path = get_arg(&args, "--pubkey").expect("Missing required argument: --pubkey");
    let opening_path = get_arg(&args, "--opening").expect("Missing required argument: --opening");
    let proof_out = get_arg(&args, "--proof-out").expect("Missing required argument: --proof-out");

    let digest_clean = digest_hex.trim().trim_start_matches("0x").trim_start_matches("0X");
    if digest_clean.len() != 64 {
        return Err(format!("Digest hex must be exactly 64 hex characters (32 bytes), got length {}", digest_clean.len()).into());
    }
    let digest_bytes_vec = decode_hex(digest_clean)?;
    let mut digest_bytes = [0u8; 32];
    digest_bytes.copy_from_slice(&digest_bytes_vec);

    let signature_der = fs::read(&sig_path)?;
    let pk_projective = load_pubkey(&pubkey_path)?;
    let opening_scalar = load_opening(&opening_path)?;

    if let Some(parent) = Path::new(&proof_out).parent() {
        std::fs::create_dir_all(parent)?;
    }

    let (_proof, _opening_int) = prover_existing_signature(
        &digest_bytes,
        &signature_der,
        pk_projective,
        opening_scalar,
        &proof_out,
    ).map_err(|e| format!("prover_existing_signature failed: {}", e))?;

    let bytes = std::fs::metadata(&proof_out)?.len();
    println!("SIGMA_PROVE_OK proof_out={} bytes={}", proof_out, bytes);
    Ok(())
}
