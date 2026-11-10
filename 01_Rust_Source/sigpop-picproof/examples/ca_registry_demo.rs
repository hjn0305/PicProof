//! CPU-only end-to-end demonstration of PicProof CA enrollment and root signing.
//!
//! This is a functional prototype for E7/E8 smoke testing. It deliberately uses
//! an ephemeral CA key; production experiments must load a persistent CA key from
//! protected storage and pin the CA certificate fingerprint in verifier config.

#[path = "spartan_merkle_linked.rs"]
mod spartan_merkle_linked;

use circ::ecdsa::ca_registry::{
    build_signed_registry, enrollment_pop_message, validate_enrollment,
    verify_signed_registry_root, CaAuthority, EnrollmentChallenge, EnrollmentRequest,
};
use circ::ecdsa::picproof_k::picproof_commitment_generator_k;
use p256::elliptic_curve::ff::{Field, PrimeField};
use p256::ecdsa::{signature::Signer, SigningKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{ProjectivePoint, Scalar};
use rand::rngs::OsRng;
use std::fs;
use std::time::Instant;

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    let out_dir = args.get(1).cloned().unwrap_or_else(|| "ca_registry_demo_out".to_string());
    let depth: usize = args.get(2).map(|s| s.parse().map_err(|e| format!("invalid depth: {e}")))
        .unwrap_or(Ok(4))?;
    fs::create_dir_all(&out_dir).map_err(|e| format!("create output directory: {e}"))?;

    // Device-side key generation and cmPK construction.
    let t_device = Instant::now();
    let sk_device = Scalar::random(&mut OsRng);
    let pk_device = ProjectivePoint::GENERATOR * sk_device;
    let opening = Scalar::random(&mut OsRng);
    let c0 = ProjectivePoint::GENERATOR * opening;
    let c1 = pk_device + picproof_commitment_generator_k() * opening;
    let device_pk_sec1 = pk_device.to_affine().to_encoded_point(true).as_bytes().to_vec();
    let c0_sec1 = c0.to_affine().to_encoded_point(true).as_bytes().to_vec();
    let c1_sec1 = c1.to_affine().to_encoded_point(true).as_bytes().to_vec();
    let mut cm_pk_encoded = [0u8; 66];
    cm_pk_encoded[..33].copy_from_slice(&c0_sec1);
    cm_pk_encoded[33..].copy_from_slice(&c1_sec1);
    let mut challenge = EnrollmentChallenge::generate();
    let device_signing_key = SigningKey::from_slice(&sk_device.to_repr())
        .map_err(|e| format!("device secret scalar is invalid: {e}"))?;
    let pop_message = enrollment_pop_message(&challenge.nonce, &cm_pk_encoded);
    let pop_signature: p256::ecdsa::Signature = device_signing_key.sign(&pop_message);
    // Enforce canonical low-S form for device proof-of-possession.
    let pop_signature = pop_signature.normalize_s().unwrap_or(pop_signature);
    let request = EnrollmentRequest {
        device_public_key_sec1: device_pk_sec1,
        opening_scalar: opening.to_repr().into(),
        cm_pk_c0_sec1: c0_sec1,
        cm_pk_c1_sec1: c1_sec1,
        proof_of_possession_signature: pop_signature.to_bytes().to_vec(),
    };
    let device_commitment_ms = t_device.elapsed().as_secs_f64() * 1000.0;

    // CA-side verification of PK_D and commitment opening.
    let t_enroll = Instant::now();
    let record = validate_enrollment(&request, &mut challenge)?;
    let ca_enrollment_verify_ms = t_enroll.elapsed().as_secs_f64() * 1000.0;

    // CA constructs a Merkle registry using exactly the Poseidon parameters used
    // by the Spartan Merkle circuit, then signs the root statement.
    let params = spartan_merkle_linked::load_p256_poseidon_params(None)?;
    let ca = CaAuthority::generate("PicProof-Demo-CA");
    let t_registry = Instant::now();
    let output = build_signed_registry(
        &[record],
        depth,
        "picproof-demo-registry-1",
        params.name.clone(),
        params.parameter_sha256.clone(),
        &ca,
        |left, right| spartan_merkle_linked::poseidon_p256_hash(left, right, &params),
    )?;
    let ca_tree_and_root_sign_ms = t_registry.elapsed().as_secs_f64() * 1000.0;

    // The fingerprint is an out-of-band trust pin, not a package-supplied trust claim.
    let pinned_fingerprint = output.signed_root.certificate.fingerprint_sha256.clone();
    let t_verify = Instant::now();
    verify_signed_registry_root(&output.signed_root, &pinned_fingerprint)?;
    let ca_root_verify_ms = t_verify.elapsed().as_secs_f64() * 1000.0;

    fs::write(
        format!("{out_dir}/signed_registry_root.json"),
        serde_json::to_vec_pretty(&output.signed_root).map_err(|e| e.to_string())?,
    ).map_err(|e| e.to_string())?;
    fs::write(
        format!("{out_dir}/private_path_0.json"),
        serde_json::to_vec_pretty(&output.enrollment_paths[0]).map_err(|e| e.to_string())?,
    ).map_err(|e| e.to_string())?;
    fs::write(
        format!("{out_dir}/private_credential_0.json"),
        serde_json::to_vec_pretty(&output.enrollment_credentials[0]).map_err(|e| e.to_string())?,
    ).map_err(|e| e.to_string())?;
    fs::write(
        format!("{out_dir}/trusted_ca_fingerprint.txt"),
        format!("{}\n", pinned_fingerprint),
    ).map_err(|e| e.to_string())?;

    let report = serde_json::json!({
        "experiment": "E7_E8_CA_registry_smoke_test",
        "warning": "single run with ephemeral demo CA; not publication-grade timing data",
        "merkle_depth": depth,
        "registered_devices": 1,
        "merkle_root_decimal": output.signed_root.statement.merkle_root_decimal,
        "device_commitment_generation_ms": device_commitment_ms,
        "ca_enrollment_validation_ms": ca_enrollment_verify_ms,
        "ca_tree_and_root_sign_ms": ca_tree_and_root_sign_ms,
        "ca_root_verify_ms": ca_root_verify_ms,
        "ca_certificate_fingerprint_sha256": pinned_fingerprint,
        "accepted": true
    });
    fs::write(format!("{out_dir}/timing_report.json"), serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;

    println!("CA registry demo accepted.");
    println!("Output: {out_dir}");
    println!("E7/E8 smoke timings (ms): device commitment={device_commitment_ms:.3}, CA enrollment={ca_enrollment_verify_ms:.3}, tree+root-sign={ca_tree_and_root_sign_ms:.3}, root-verify={ca_root_verify_ms:.3}");
    println!("NOTE: one smoke run only; do not report these as benchmark results.");
    // Keep secret material live only for the duration of this process.
    let _ = sk_device;
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("CA registry demo failed: {error}");
        std::process::exit(1);
    }
}
