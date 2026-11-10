#[path = "spartan_merkle_linked.rs"]
mod spartan_merkle_linked;

use circ::ecdsa::ca_registry::{
    build_signed_registry, enrollment_pop_message, validate_enrollment,
    verify_signed_registry_root, CaAuthority, EnrollmentChallenge, EnrollmentRecord,
    EnrollmentRequest,
};
use circ::ecdsa::picproof_k::picproof_commitment_generator_k;
use circ::ecdsa::pure_sigma::{
    create_proof_from_digest_with_opening, ECDSASigmaSetupParamsPrior,
};
use circ::ecdsa::ecdsa::ProverPrecomputeInput;
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
use std::time::Instant;

const FIXTURE_MESSAGE: &[u8] = b"PicProof-Production-C2PA-Provenance-Binding-v2";

struct DeviceFixture {
    signing_key: SigningKey,
    public_key: ProjectivePoint,
    opening: Scalar,
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

fn enroll_one_device(dev_idx: usize) -> Result<DeviceFixture, String> {
    let mut rng = OsRng;
    let sk = random_nonzero_scalar(&mut rng);
    let opening = random_nonzero_scalar(&mut rng);
    let signing_key = SigningKey::from_slice(&sk.to_repr())
        .map_err(|e| format!("Invalid P-256 scalar for device {dev_idx}: {e}"))?;
    let pk = ProjectivePoint::GENERATOR * sk;
    let c0 = ProjectivePoint::GENERATOR * opening;
    let c1 = pk + picproof_commitment_generator_k() * opening;
    let device_public_key_sec1 = pk.to_affine().to_encoded_point(true).as_bytes().to_vec();
    let c0_sec1 = c0.to_affine().to_encoded_point(true).as_bytes().to_vec();
    let c1_sec1 = c1.to_affine().to_encoded_point(true).as_bytes().to_vec();
    let mut cm_pk_encoded = [0u8; 66];
    cm_pk_encoded[..33].copy_from_slice(&c0_sec1);
    cm_pk_encoded[33..].copy_from_slice(&c1_sec1);

    let mut challenge = EnrollmentChallenge::generate();
    let pop_message = enrollment_pop_message(&challenge.nonce, &cm_pk_encoded);
    let pop_signature: p256::ecdsa::Signature = signing_key.sign(&pop_message);
    let pop_signature = pop_signature.normalize_s().unwrap_or(pop_signature);

    let request = EnrollmentRequest {
        device_public_key_sec1,
        opening_scalar: opening.to_repr().into(),
        cm_pk_c0_sec1: c0_sec1,
        cm_pk_c1_sec1: c1_sec1,
        proof_of_possession_signature: pop_signature.to_bytes().to_vec(),
    };

    let enrollment_record = validate_enrollment(&request, &mut challenge)?;
    Ok(DeviceFixture {
        signing_key,
        public_key: pk,
        opening,
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
    let signature = signature.normalize_s().unwrap_or(signature);
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

    sigma_proof.verify(digest_integer, ECDSASigmaSetupParamsPrior::new());
    serialize_into_file(&sigma_proof, output_path)
        .map_err(|e| format!("Cannot serialize fixture Sigma proof: {e:?}"))
}

fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        return Err(format!("Usage: {} <output_dir> <depth> <num_devices>", args[0]));
    }
    let output_dir = &args[1];
    let depth: usize = args[2].parse().map_err(|e| format!("Invalid depth: {e}"))?;
    let num_devices: usize = args[3].parse().map_err(|e| format!("Invalid num_devices: {e}"))?;

    let capacity = 1usize.checked_shl(depth as u32).ok_or("Merkle capacity overflow")?;
    if num_devices > capacity {
        return Err(format!("num_devices ({num_devices}) exceeds Merkle capacity ({capacity}) for depth {depth}"));
    }

    fs::create_dir_all(output_dir).map_err(|e| format!("Cannot create output dir: {e}"))?;

    let t_start_enroll = Instant::now();
    println!("[SCALABILITY] Enrolling {num_devices} independent devices for Merkle depth {depth} (capacity {capacity})...");
    let mut devices = Vec::with_capacity(num_devices);
    let mut records = Vec::with_capacity(num_devices);
    for idx in 0..num_devices {
        let dev = enroll_one_device(idx)?;
        records.push(dev.enrollment_record.clone());
        devices.push(dev);
    }
    let total_enroll_ms = t_start_enroll.elapsed().as_secs_f64() * 1000.0;
    println!("[SCALABILITY] Enrolled {num_devices} devices in {total_enroll_ms:.2} ms (avg {:.2} ms/device)", total_enroll_ms / num_devices as f64);

    let t_start_tree = Instant::now();
    let params = spartan_merkle_linked::load_p256_poseidon_params(None)?;
    let ca = CaAuthority::generate("PicProof-Scalability-CA");
    let registry = build_signed_registry(
        &records,
        depth,
        format!("picproof-scalability-d{depth}-n{num_devices}"),
        params.name.clone(),
        params.parameter_sha256.clone(),
        &ca,
        |left, right| spartan_merkle_linked::poseidon_p256_hash(left, right, &params),
    )?;
    let tree_construction_ms = t_start_tree.elapsed().as_secs_f64() * 1000.0;
    println!("[SCALABILITY] Built and signed Merkle registry tree in {tree_construction_ms:.2} ms");

    let fingerprint = registry.signed_root.certificate.fingerprint_sha256.clone();
    verify_signed_registry_root(&registry.signed_root, &fingerprint)?;

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

    println!("[SCALABILITY] Generating Sigma proofs and credentials for all {num_devices} devices...");
    for (index, device) in devices.iter().enumerate() {
        let device_dir = format!("{output_dir}/device_{index}");
        fs::create_dir_all(&device_dir).map_err(|e| format!("Cannot create device directory: {e}"))?;
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

    let timing_report = json!({
        "depth": depth,
        "tree_capacity": capacity,
        "num_devices": num_devices,
        "total_enroll_ms": total_enroll_ms,
        "avg_enroll_ms": total_enroll_ms / num_devices as f64,
        "tree_construction_ms": tree_construction_ms,
        "merkle_root_decimal": registry.signed_root.statement.merkle_root_decimal.clone(),
        "ca_fingerprint": fingerprint,
    });
    fs::write(
        format!("{output_dir}/timing_report.json"),
        serde_json::to_string_pretty(&timing_report).unwrap(),
    ).map_err(|e| format!("Cannot write timing report: {e}"))?;

    println!("[SCALABILITY] Setup complete for depth {depth}, devices {num_devices}!");
    Ok(())
}
