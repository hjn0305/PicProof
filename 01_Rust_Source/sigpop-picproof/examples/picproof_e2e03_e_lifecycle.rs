#[path = "spartan_merkle_linked.rs"]
mod spartan_merkle_linked;

use circ::ecdsa::ca_registry::{
    build_signed_registry, enrollment_pop_message, validate_enrollment,
    CaAuthority, EnrollmentChallenge, EnrollmentRequest,
};
use circ::ecdsa::picproof_k::picproof_commitment_generator_k;
use p256::ecdsa::{signature::Signer, SigningKey, Signature as P256Signature};
use p256::elliptic_curve::ff::{Field, PrimeField};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{ProjectivePoint, Scalar};
use rand::rngs::OsRng;
use std::env;
use std::fs;

fn random_nonzero_scalar(rng: &mut OsRng) -> Scalar {
    loop {
        let value = Scalar::random(&mut *rng);
        if value != Scalar::ZERO {
            return value;
        }
    }
}

struct DeviceKit {
    device_pk_sec1: Vec<u8>,
    opening: Scalar,
    cm_pk_encoded: [u8; 66],
    c0_sec1: Vec<u8>,
    c1_sec1: Vec<u8>,
    signing_key: SigningKey,
}

fn create_device(rng: &mut OsRng) -> DeviceKit {
    let sk = random_nonzero_scalar(rng);
    let opening = random_nonzero_scalar(rng);
    let signing_key = SigningKey::from_slice(&sk.to_repr()).unwrap();
    let pk = ProjectivePoint::GENERATOR * sk;
    let c0 = ProjectivePoint::GENERATOR * opening;
    let c1 = pk + picproof_commitment_generator_k() * opening;
    let device_pk_sec1 = pk.to_affine().to_encoded_point(true).as_bytes().to_vec();
    let c0_sec1 = c0.to_affine().to_encoded_point(true).as_bytes().to_vec();
    let c1_sec1 = c1.to_affine().to_encoded_point(true).as_bytes().to_vec();
    let mut cm_pk_encoded = [0u8; 66];
    cm_pk_encoded[..33].copy_from_slice(&c0_sec1);
    cm_pk_encoded[33..].copy_from_slice(&c1_sec1);
    DeviceKit {
        device_pk_sec1,
        opening,
        cm_pk_encoded,
        c0_sec1,
        c1_sec1,
        signing_key,
    }
}

fn make_request(device: &DeviceKit, challenge: &EnrollmentChallenge) -> EnrollmentRequest {
    let pop_message = enrollment_pop_message(&challenge.nonce, &device.cm_pk_encoded);
    let pop_sig: P256Signature = device.signing_key.sign(&pop_message);
    let pop_sig = pop_sig.normalize_s().unwrap_or(pop_sig);
    EnrollmentRequest {
        device_public_key_sec1: device.device_pk_sec1.clone(),
        opening_scalar: device.opening.to_repr().into(),
        cm_pk_c0_sec1: device.c0_sec1.clone(),
        cm_pk_c1_sec1: device.c1_sec1.clone(),
        proof_of_possession_signature: pop_sig.to_bytes().to_vec(),
    }
}

fn main() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    let log_path = args.get(1).map(String::as_str).unwrap_or("lifecycle_results.log");
    let mut out_log = String::new();

    let mut rng = OsRng;

    // --- E19: Challenge Replay Test ---
    out_log.push_str("=== E19 CHALLENGE REPLAY TEST ===\n");
    let dev_19 = create_device(&mut rng);
    let mut challenge_19 = EnrollmentChallenge::generate();
    let req_19 = make_request(&dev_19, &challenge_19);

    // Call 1: First attempt with fresh challenge
    let res_1 = validate_enrollment(&req_19, &mut challenge_19);
    if res_1.is_ok() {
        out_log.push_str("[E19] First enrollment attempt: ACCEPTED (record validated)\n");
    } else {
        return Err("E19 failed: first enrollment attempt was rejected".into());
    }

    // Call 2: Replay the exact same challenge
    let res_2 = validate_enrollment(&req_19, &mut challenge_19);
    match res_2 {
        Err(err) if err == "Enrollment challenge has already been consumed" => {
            out_log.push_str(&format!("[E19] Second enrollment attempt: REJECTED with '{}'\n", err));
            out_log.push_str("[E19] STATUS=PASS\n");
        }
        _ => {
            return Err("E19 failed: expected challenge replay error".into());
        }
    }

    // --- E20: Duplicate cmPK in Same Batch Test ---
    out_log.push_str("\n=== E20 DUPLICATE CMPK IN SAME BATCH TEST ===\n");
    let dev_20 = create_device(&mut rng);

    // Create two distinct, fresh challenges
    let mut ch_a = EnrollmentChallenge::generate();
    let mut ch_b = EnrollmentChallenge::generate();
    assert_ne!(ch_a.nonce, ch_b.nonce);

    // Create two requests with the EXACT SAME cmPK but different challenges
    let req_a = make_request(&dev_20, &ch_a);
    let req_b = make_request(&dev_20, &ch_b);

    let rec_a = validate_enrollment(&req_a, &mut ch_a)
        .map_err(|e| format!("Record A enrollment validation failed: {e}"))?;
    let rec_b = validate_enrollment(&req_b, &mut ch_b)
        .map_err(|e| format!("Record B enrollment validation failed: {e}"))?;

    out_log.push_str("[E20] Both records independently validated with distinct challenges\n");
    assert_eq!(rec_a.cm_pk_encoded(), rec_b.cm_pk_encoded());

    let params = spartan_merkle_linked::load_p256_poseidon_params(None)?;
    let ca = CaAuthority::generate("PicProof-E20-Test-CA");
    let batch_res = build_signed_registry(
        &[rec_a, rec_b],
        1,
        "picproof-e20-duplicate-batch",
        "PicProof-P256Fp-Poseidon-t3-v1",
        &params.parameter_sha256,
        &ca,
        |l, r| spartan_merkle_linked::poseidon_p256_hash(l, r, &params),
    );

    match batch_res {
        Err(err) if err == "Duplicate cmPK commitment in one registry batch" => {
            out_log.push_str(&format!("[E20] Batch registry construction: REJECTED with '{}'\n", err));
            out_log.push_str("[E20] STATUS=PASS\n");
        }
        _ => {
            return Err("E20 failed: expected duplicate cmPK error".into());
        }
    }

    println!("{out_log}");
    fs::write(log_path, out_log).map_err(|e| format!("Cannot write log: {e}"))?;
    println!("[E_LIFECYCLE] PASS: both E19 and E20 completed successfully");
    Ok(())
}
