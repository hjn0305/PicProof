//! Generate two independent device credentials and Sigma proofs under one CA registry.
//!
//! PicProof E2E-01 fixture adapted from the Phase 3 fixture with explicit
//! PrimeField import and canonical low-S device PoP signatures.
//!
//! This fixture is for Phase 3 adversarial testing only. It uses ephemeral
//! device/CA keys and a synthetic fixed message; do not use its outputs as
//! production credentials or publication-grade performance measurements.

#[path = "spartan_merkle_linked.rs"]
mod spartan_merkle_linked;

use circ::ecdsa::ca_registry::{
    build_signed_registry, enrollment_pop_message, validate_enrollment,
    verify_signed_registry_root, CaAuthority, EnrollmentChallenge, EnrollmentRecord,
    EnrollmentRequest,
};
use circ::ecdsa::ecdsa::ProverPrecomputeInput;
use circ::ecdsa::picproof_k::picproof_commitment_generator_k;
use circ::ecdsa::pure_sigma::{
    create_proof_from_digest_with_opening, ECDSASigmaSetupParamsPrior,
};
use circ::target::r1cs::proof::serialize_into_file;
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::SigningKey;
use p256::elliptic_curve::ff::{Field, PrimeField};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{ProjectivePoint, Scalar};
use rand::rngs::OsRng;
use rug::Integer;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

const FIXTURE_MESSAGE: &[u8] = b"PicProof phase-3 two-device adversarial integration fixture";

struct DeviceFixture {
    signing_key: SigningKey,
    opening: Scalar,
    public_key: ProjectivePoint,
    enrollment_record: EnrollmentRecord,
}

fn random_nonzero_scalar(rng: &mut OsRng) -> Scalar {
    loop {
        let value = Scalar::random(&mut *rng);
        if value != Scalar::ZERO {
            return value;
        }
    }
}

fn enroll_one_device() -> Result<DeviceFixture, String> {
    let mut rng = OsRng;
    let device_secret = random_nonzero_scalar(&mut rng);
    let opening = random_nonzero_scalar(&mut rng);
    let signing_key = SigningKey::from_slice(device_secret.to_repr().as_slice())
        .map_err(|e| format!("Cannot create device P-256 signing key: {e}"))?;
    let public_key = ProjectivePoint::GENERATOR * device_secret;
    let c0 = ProjectivePoint::GENERATOR * opening;
    let c1 = public_key + picproof_commitment_generator_k() * opening;

    let device_pk_sec1 = public_key.to_affine().to_encoded_point(true);
    let c0_sec1 = c0.to_affine().to_encoded_point(true);
    let c1_sec1 = c1.to_affine().to_encoded_point(true);
    let mut cm_pk_encoded = [0u8; 66];
    cm_pk_encoded[..33].copy_from_slice(c0_sec1.as_bytes());
    cm_pk_encoded[33..].copy_from_slice(c1_sec1.as_bytes());

    let mut challenge = EnrollmentChallenge::generate();
    let pop_message = enrollment_pop_message(&challenge.nonce, &cm_pk_encoded);
    let pop_signature: p256::ecdsa::Signature = signing_key.sign(&pop_message);
    // The CA's production verifier intentionally rejects ECDSA high-S signatures.
    let pop_signature = pop_signature.normalize_s().unwrap_or(pop_signature);
    let request = EnrollmentRequest {
        device_public_key_sec1: device_pk_sec1.as_bytes().to_vec(),
        opening_scalar: opening.to_repr().into(),
        cm_pk_c0_sec1: c0_sec1.as_bytes().to_vec(),
        cm_pk_c1_sec1: c1_sec1.as_bytes().to_vec(),
        proof_of_possession_signature: pop_signature.to_bytes().to_vec(),
    };
    let enrollment_record = validate_enrollment(&request, &mut challenge)?;

    Ok(DeviceFixture {
        signing_key,
        opening,
        public_key,
        enrollment_record,
    })
}

fn create_sigma_proof(
    device: &DeviceFixture,
    digest_bytes: &[u8; 32],
    digest_integer: &Integer,
    output_path: &Path,
) -> Result<(), String> {
    let signature: p256::ecdsa::Signature = device
        .signing_key
        .sign_prehash(digest_bytes)
        .map_err(|e| format!("Cannot sign fixture digest with device key: {e}"))?;
    let signature_der = signature.to_der();
    let precomputed = ProverPrecomputeInput::from_existing_der_prehash(
        digest_bytes,
        signature_der.as_bytes(),
        device.public_key.clone(),
    )?;
    let (sigma_proof, _opening_integer) = create_proof_from_digest_with_opening(
        device.public_key.clone(),
        precomputed.signature,
        digest_integer,
        device.opening,
        ECDSASigmaSetupParamsPrior::new(),
    )?;

    // Fail closed if the generated Sigma proof does not verify before it is saved.
    sigma_proof.verify(digest_integer, ECDSASigmaSetupParamsPrior::new());
    serialize_into_file(&sigma_proof, output_path)
        .map_err(|e| format!("Cannot serialize fixture Sigma proof: {e:?}"))
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    let output_dir = args.get(1).cloned().unwrap_or_else(|| "phase3_two_device_fixture".into());
    let depth: usize = args.get(2)
        .map(|v| v.parse().map_err(|e| format!("Invalid Merkle depth: {e}")))
        .unwrap_or(Ok(4))?;
    if depth == 0 || depth > spartan_merkle_linked::MAX_MERKLE_DEPTH {
        return Err(format!("Depth must be between 1 and {}", spartan_merkle_linked::MAX_MERKLE_DEPTH));
    }
    fs::create_dir_all(&output_dir)
        .map_err(|e| format!("Cannot create fixture output directory: {e}"))?;

    println!("[PHASE3 FIXTURE] Enrolling two independent devices...");
    let device_a = enroll_one_device()?;
    let device_b = enroll_one_device()?;
    let records = vec![device_a.enrollment_record.clone(), device_b.enrollment_record.clone()];

    let params = spartan_merkle_linked::load_p256_poseidon_params(None)?;
    let ca = CaAuthority::generate("PicProof-Phase3-Test-CA");
    let registry = build_signed_registry(
        &records,
        depth,
        "picproof-phase3-two-device-registry-v1",
        params.name.clone(),
        params.parameter_sha256.clone(),
        &ca,
        |left, right| spartan_merkle_linked::poseidon_p256_hash(left, right, &params),
    )?;

    let fingerprint = registry.signed_root.certificate.fingerprint_sha256.clone();
    verify_signed_registry_root(&registry.signed_root, &fingerprint)?;
    if registry.enrollment_credentials[0].cm_pk_encoded_hex
        == registry.enrollment_credentials[1].cm_pk_encoded_hex
        || registry.enrollment_credentials[0].leaf_decimal
            == registry.enrollment_credentials[1].leaf_decimal
    {
        return Err("Generated device commitments/leaves are not distinct".into());
    }
    fs::write(
        format!("{output_dir}/signed_registry_root.json"),
        serde_json::to_vec_pretty(&registry.signed_root).map_err(|e| e.to_string())?,
    ).map_err(|e| format!("Cannot write signed registry root: {e}"))?;
    fs::write(
        format!("{output_dir}/trusted_ca_fingerprint.txt"),
        format!("{fingerprint}\n"),
    ).map_err(|e| format!("Cannot write CA fingerprint pin: {e}"))?;

    let digest_bytes: [u8; 32] = Sha256::digest(FIXTURE_MESSAGE).into();
    let digest_hex = hex::encode(digest_bytes);
    let digest_integer = Integer::from_digits(&digest_bytes, rug::integer::Order::MsfBe);
    fs::write(format!("{output_dir}/manifest_digest.hex"), format!("{digest_hex}\n"))
        .map_err(|e| format!("Cannot write fixture digest: {e}"))?;

    for (index, device) in [&device_a, &device_b].iter().enumerate() {
        let device_dir = format!("{output_dir}/device_{index}");
        fs::create_dir_all(&device_dir)
            .map_err(|e| format!("Cannot create device output directory: {e}"))?;
        let credential = &registry.enrollment_credentials[index];
        fs::write(
            format!("{device_dir}/private_credential.json"),
            serde_json::to_vec_pretty(credential).map_err(|e| e.to_string())?,
        ).map_err(|e| format!("Cannot write device credential: {e}"))?;
        create_sigma_proof(
            device,
            &digest_bytes,
            &digest_integer,
            Path::new(&format!("{device_dir}/pi_sigma")),
        )?;
    }

    let report = json!({
        "fixture": "PicProof Phase 3 two-device E2E attack fixture",
        "warning": "ephemeral synthetic test keys and message; not production credentials or benchmark data",
        "registered_devices": 2,
        "registry_id": registry.signed_root.statement.registry_id.clone(),
        "merkle_depth": depth,
        "manifest_digest_sha256": digest_hex.clone(),
        "ca_fingerprint_sha256": fingerprint.clone(),
        "device_a_leaf": registry.enrollment_credentials[0].leaf_decimal.clone(),
        "device_b_leaf": registry.enrollment_credentials[1].leaf_decimal.clone(),
        "device_commitments_are_distinct": registry.enrollment_credentials[0].cm_pk_encoded_hex != registry.enrollment_credentials[1].cm_pk_encoded_hex,
        "accepted": true
    });
    fs::write(
        format!("{output_dir}/fixture_report.json"),
        serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?,
    ).map_err(|e| format!("Cannot write fixture report: {e}"))?;

    println!("[PHASE3 FIXTURE] Created one CA-signed registry with two distinct devices.");
    println!("[PHASE3 FIXTURE] Digest: {digest_hex}");
    println!("[PHASE3 FIXTURE] Output: {output_dir}");
    println!("[PHASE3 FIXTURE] Next: run picproof_authenticated_registry prove once for device_0 and once for device_1, then run attack-test.");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("[PHASE3 FIXTURE] ERROR: {error}");
        std::process::exit(1);
    }
}
