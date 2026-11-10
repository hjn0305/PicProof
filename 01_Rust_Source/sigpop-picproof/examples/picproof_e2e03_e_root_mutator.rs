use circ::ecdsa::ca_registry::{
    CaAuthority, SignedRegistryRoot,
};
use circ::ecdsa::pure_sigma::ECDSASigmaPublicPrior;
use libdoriant256::NIZK;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

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

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn main() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        return Err("Usage: picproof_e2e03_e_root_mutator <input_bundle> <output_dir>".into());
    }
    let input = Path::new(&args[1]);
    let out_dir = Path::new(&args[2]);
    fs::create_dir_all(out_dir).map_err(|e| format!("Cannot create output dir: {e}"))?;

    let bytes = fs::read(input).map_err(|e| format!("Cannot read bundle: {e}"))?;
    let orig: AuthenticatedPicProofPackage = bincode::deserialize(&bytes)
        .map_err(|e| format!("Cannot deserialize bundle: {e}"))?;

    // Create a deterministic test CA whose fingerprint will be pinned in verifier config
    let ca_secret = [0x5Au8; 32];
    let ca = CaAuthority::from_secret_bytes("PicProof-E-Group-Test-CA", ca_secret)?;
    let cert = ca.certificate();
    let fingerprint = cert.fingerprint_sha256.clone();
    fs::write(out_dir.join("trusted_ca_fingerprint.txt"), format!("{fingerprint}\n"))
        .map_err(|e| format!("Cannot write fingerprint: {e}"))?;

    let now = now_unix();

    // E17: Expired Root
    // issued_at = now - 7200, expires_at = now - 3600 (both in the past, duration = 3600 <= MAX)
    let mut e17_package = bincode::deserialize::<AuthenticatedPicProofPackage>(&bytes).unwrap();
    let mut e17_stmt = orig.signed_registry_root.statement.clone();
    e17_stmt.issued_at_unix = now.saturating_sub(7200);
    e17_stmt.expires_at_unix = now.saturating_sub(3600);
    let e17_signed_root = ca.sign_registry_root(e17_stmt)?;
    e17_package.signed_registry_root = e17_signed_root;
    let e17_bytes = bincode::serialize(&e17_package).map_err(|e| e.to_string())?;
    fs::write(out_dir.join("E17_expired_root.bundle"), &e17_bytes).map_err(|e| e.to_string())?;
    println!("[E17] wrote E17_expired_root.bundle ({} bytes)", e17_bytes.len());

    // E18: Future Root (not yet valid)
    // issued_at = now + 3600, expires_at = now + 7200 (in the future, > now + 300s skew)
    let mut e18_package = bincode::deserialize::<AuthenticatedPicProofPackage>(&bytes).unwrap();
    let mut e18_stmt = orig.signed_registry_root.statement.clone();
    e18_stmt.issued_at_unix = now.saturating_add(3600);
    e18_stmt.expires_at_unix = now.saturating_add(7200);
    let e18_signed_root = ca.sign_registry_root(e18_stmt)?;
    e18_package.signed_registry_root = e18_signed_root;
    let e18_bytes = bincode::serialize(&e18_package).map_err(|e| e.to_string())?;
    fs::write(out_dir.join("E18_future_root.bundle"), &e18_bytes).map_err(|e| e.to_string())?;
    println!("[E18] wrote E18_future_root.bundle ({} bytes)", e18_bytes.len());

    println!("[E_ROOT_MUTATOR] PASS: generated E17 and E18 bundles with valid test CA signature");
    Ok(())
}
