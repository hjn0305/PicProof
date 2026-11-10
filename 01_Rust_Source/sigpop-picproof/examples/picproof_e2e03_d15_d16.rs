use circ::ecdsa::ca_registry::SignedRegistryRoot;
use circ::ecdsa::pure_sigma::ECDSASigmaPublicPrior;

use libdoriant256::NIZK;

use serde::{Deserialize, Serialize};
use rug::Integer;

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

    if args.len() != 4 {
        return Err(
            "Usage: picproof_e2e03_d15_d16 <bundle> <spartan.bin> <metadata.txt>"
                .into()
        );
    }

    let bundle_path = &args[1];
    let proof_path = &args[2];
    let metadata_path = &args[3];

    let bytes = fs::read(bundle_path)
        .map_err(|e| format!("Cannot read bundle: {e}"))?;

    let package: AuthenticatedPicProofPackage =
        bincode::deserialize(&bytes)
            .map_err(|e| format!("Bundle deserialization failed: {e}"))?;

    let leaf = Integer::from_str_radix(
        &package.leaf_decimal,
        10,
    )
    .map_err(|e| format!("Invalid leaf: {e:?}"))?;

    let root = Integer::from_str_radix(
        &package.signed_registry_root.statement.merkle_root_decimal,
        10,
    )
    .map_err(|e| format!("Invalid root: {e:?}"))?;

    let depth = package.spartan_proof.depth;

    let mut leaf_plus_one = leaf.clone();
    leaf_plus_one += 1;

    let mut root_plus_one = root.clone();
    root_plus_one += 1;

    // Preserve the complete original Spartan package.
    let spartan_bytes = bincode::serialize(
        &package.spartan_proof,
    )
    .map_err(|e| format!("Spartan serialization failed: {e}"))?;

    fs::write(proof_path, &spartan_bytes)
        .map_err(|e| format!("Cannot write Spartan proof: {e}"))?;

    let metadata = format!(
        "LEAF={}\nROOT={}\nDEPTH={}\nLEAF_PLUS_ONE={}\nROOT_PLUS_ONE={}\nDIGEST_HEX={}\n",
        leaf,
        root,
        depth,
        leaf_plus_one,
        root_plus_one,
        package.digest_sha256_hex
    );

    fs::write(metadata_path, metadata)
        .map_err(|e| format!("Cannot write metadata: {e}"))?;

    println!("[D15/D16] Original bundle decoded");
    println!("[D15/D16] Spartan proof extracted");
    println!("[D15/D16] Spartan proof bytes={}", spartan_bytes.len());
    println!("[D15/D16] depth={depth}");
    println!("[D15/D16] leaf={leaf}");
    println!("[D15/D16] root={root}");
    println!("[D15/D16] leaf_plus_one={leaf_plus_one}");
    println!("[D15/D16] root_plus_one={root_plus_one}");
    println!("[D15/D16] EXTRACTION_STATUS=PASS");

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("[D15/D16 ERROR] {e}");
        process::exit(1);
    }
}
