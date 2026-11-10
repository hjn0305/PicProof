use circ::ecdsa::ca_registry::SignedRegistryRoot;
use circ::ecdsa::pure_sigma::ECDSASigmaPublicPrior;

use libdoriant256::NIZK;

use serde::{Deserialize, Serialize};

use std::env;
use std::fs;
use std::process;

#[derive(Serialize, Deserialize)]
struct SpartanMerklePackage {
    proof: NIZK,
    depth: usize,
    version: String,
    profile: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthenticatedPicProofPackage {
    magic: String,
    version: u32,
    profile: String,
    registry_id: String,
    depth: usize,
    digest_sha256_hex: String,
    cm_pk_encoded_hex: String,
    leaf_decimal: String,
    signed_registry_root: SignedRegistryRoot,
    sigma_proof: ECDSASigmaPublicPrior,
    spartan_proof: SpartanMerklePackage,
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        return Err(
            "Usage: picproof_e2e03_d13_mutator <input.bundle> <output.bundle>"
                .into()
        );
    }

    let input = &args[1];
    let output = &args[2];

    let original = fs::read(input)
        .map_err(|e| format!("Cannot read original bundle: {e}"))?;

    let original_size = original.len();

    let mut package: AuthenticatedPicProofPackage =
        bincode::deserialize(&original)
            .map_err(|e| format!("Original bundle deserialization failed: {e}"))?;

    println!("[D13] Original bundle parsed successfully");
    println!("[D13] Original size={original_size}");

    // Only modify the claimed Spartan evaluation point.
    // The actual proof polynomial data remains unchanged.
    package
        .spartan_proof
        .proof
        .perturb_claimed_rx_first_for_testing()
        .map_err(|e| format!("Cannot mutate NIZK scalar: {e}"))?;

    let mutated = bincode::serialize(&package)
        .map_err(|e| format!("Serialization failed: {e}"))?;

    if mutated.len() != original_size {
        return Err(format!(
            "Unexpected serialization size change: {} -> {}",
            original_size,
            mutated.len()
        ));
    }

    // Verify that the mutated bundle is still structurally decodable.
    let _: AuthenticatedPicProofPackage =
        bincode::deserialize(&mutated)
            .map_err(|e| format!("Mutated bundle cannot be decoded: {e}"))?;

    fs::write(output, &mutated)
        .map_err(|e| format!("Cannot write mutant: {e}"))?;

    println!("[D13] Mutation target=NIZK.r.0[0]");
    println!("[D13] Original size={original_size}");
    println!("[D13] Mutated size={}", mutated.len());
    println!("[D13] Structural deserialization=PASS");
    println!("[D13] D13_MUTANT_GENERATION=PASS");

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("[D13 MUTATOR ERROR] {e}");
        process::exit(1);
    }
}
