use circ::ecdsa::ca_registry::SignedRegistryRoot;
use circ::ecdsa::pure_sigma::ECDSASigmaPublicPrior;
use p256::elliptic_curve::group::Group;
use p256::ProjectivePoint;
use rug::Integer;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

// Keep this field order and types identical to
// examples/picproof_authenticated_registry.rs.
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
    spartan_proof: spartan_merkle_linked::SpartanMerklePackage,
}

// Reuse the exact Spartan package type from the existing example.
// Its main() is simply an unused function when compiled as a module.
#[path = "spartan_merkle_linked.rs"]
mod spartan_merkle_linked;

fn replacement_point(old: ProjectivePoint) -> Result<ProjectivePoint, String> {
    // Select a valid, non-identity P-256 point different from the original.
    // Trying successive generator multiples avoids the rare case where the
    // original point equals one of the first candidates.
    let g = ProjectivePoint::GENERATOR;
    let mut candidate = g;
    for _ in 0..16 {
        if candidate != old && !bool::from(candidate.is_identity()) {
            return Ok(candidate);
        }
        candidate = candidate + g;
    }
    Err("could not find a distinct non-identity P-256 replacement point".into())
}

fn load_original(bytes: &[u8]) -> Result<AuthenticatedPicProofPackage, String> {
    bincode::deserialize(bytes)
        .map_err(|e| format!("cannot deserialize original authenticated bundle: {e}"))
}

fn write_new_bundle(
    out_dir: &Path,
    filename: &str,
    package: &AuthenticatedPicProofPackage,
) -> Result<PathBuf, String> {
    let path = out_dir.join(filename);
    if path.exists() {
        return Err(format!("refusing to overwrite existing mutant: {}", path.display()));
    }
    let bytes = bincode::serialize(package)
        .map_err(|e| format!("cannot serialize mutated package: {e}"))?;
    fs::write(&path, bytes)
        .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    println!("[MUTATOR] wrote {} ({} bytes)", path.display(), fs::metadata(&path).map_err(|e| e.to_string())?.len());
    Ok(path)
}

fn mutate_b05(bytes: &[u8], out_dir: &Path) -> Result<(), String> {
    let mut package = load_original(bytes)?;
    let old = package.sigma_proof.cm_pk[0].0;
    let new = replacement_point(old)?;
    package.sigma_proof.cm_pk[0].0 = new;
    if package.sigma_proof.cm_pk[0].0 == old
        || bool::from(package.sigma_proof.cm_pk[0].0.is_identity())
    {
        return Err("B05 replacement point sanity check failed".into());
    }
    // Deliberately leave cm_pk_encoded_hex and leaf_decimal unchanged.
    write_new_bundle(out_dir, "B05_mutated_cm_pk_c0.bundle", &package)?;
    Ok(())
}

fn mutate_b06(bytes: &[u8], out_dir: &Path) -> Result<(), String> {
    let mut package = load_original(bytes)?;
    let old = package.sigma_proof.cm_pk[1].0;
    let new = replacement_point(old)?;
    package.sigma_proof.cm_pk[1].0 = new;
    if package.sigma_proof.cm_pk[1].0 == old
        || bool::from(package.sigma_proof.cm_pk[1].0.is_identity())
    {
        return Err("B06 replacement point sanity check failed".into());
    }
    // Deliberately leave cm_pk_encoded_hex and leaf_decimal unchanged.
    write_new_bundle(out_dir, "B06_mutated_cm_pk_c1.bundle", &package)?;
    Ok(())
}

fn mutate_b07(bytes: &[u8], out_dir: &Path) -> Result<(), String> {
    let mut package = load_original(bytes)?;
    let mut leaf = Integer::from_str_radix(&package.leaf_decimal, 10)
        .map_err(|e| format!("cannot parse package leaf as decimal Integer: {e}"))?;
    leaf += Integer::from(1);
    package.leaf_decimal = leaf.to_string();
    // Sigma proof, cmPK, signed root and Spartan proof remain untouched.
    write_new_bundle(out_dir, "B07_mutated_top_level_leaf.bundle", &package)?;
    Ok(())
}

fn mutate_b08(bytes: &[u8], out_dir: &Path) -> Result<(), String> {
    let mut package = load_original(bytes)?;
    package.signed_registry_root.statement.commitment_profile_id =
        "PicProof-P256-Corrupted-v1".to_string();
    // Deliberately retain the original CA signature: signature verification
    // should fail before the verifier reaches its explicit profile comparison.
    write_new_bundle(out_dir, "B08_mutated_commitment_profile.bundle", &package)?;
    Ok(())
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        return Err(format!(
            "usage: {} <original_device_0.bundle> <new_mutants_directory>",
            args.first().map(String::as_str).unwrap_or("picproof_e2e03_mutator")
        ));
    }

    let input = Path::new(&args[1]);
    let out_dir = Path::new(&args[2]);

    if !input.is_file() {
        return Err(format!("input bundle does not exist: {}", input.display()));
    }
    if out_dir.exists() {
        return Err(format!(
            "refusing to reuse existing output directory: {}",
            out_dir.display()
        ));
    }

    fs::create_dir_all(out_dir)
        .map_err(|e| format!("cannot create output directory: {e}"))?;

    let original = fs::read(input)
        .map_err(|e| format!("cannot read original bundle: {e}"))?;

    // Parse once before mutation to ensure the input is a valid package.
    let _: AuthenticatedPicProofPackage = load_original(&original)?;

    println!("[MUTATOR] source={}", input.display());
    println!("[MUTATOR] source_bytes={}", original.len());
    println!("[MUTATOR] each mutant is independently deserialized from original bytes");

    mutate_b05(&original, out_dir)?;
    mutate_b06(&original, out_dir)?;
    mutate_b07(&original, out_dir)?;
    mutate_b08(&original, out_dir)?;

    println!("[MUTATOR] PASS: generated four independent single-field mutants");
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("[MUTATOR] ERROR: {e}");
        std::process::exit(2);
    }
}
