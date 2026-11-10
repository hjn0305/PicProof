//! JISA Standalone Package Verifier
//!
//! Validates a standalone `PicProofPackage` purely from public inputs:
//! 1. Verifies package format and schema version (v3).
//! 2. Loads one external trusted profile and runs ProfileGuard before any verifier.
//! 3. Reconstructs initial_state, current_state, and Sigmabus binding from package public instance.
//! 4. Deserializes external Decider verifier key from `--verifier-key`.
//! 5. Verifies pi_final (472-B LegoGroth16 + Nova compressed proof) => H_img.
//! 6. Parses `manifest_cbor` strictly (canonical v1 profile) and binds
//!    Manifest.digest == H_img, plus metadata cross-checks.
//! 7. Recomputes H_CBOR = SHA-256(manifest_cbor) itself (never trusts the
//!    stored `cbor_manifest_hash` audit field).
//! 8. Verifies pi_sigma (447-B ECDSA Sigma proof) against H_CBOR, deriving cmPK and leaf*.
//! 9. Asserts derived cmPK and leaf* match package public instance fields.
//! 10. Verifies pi_merkle (15,962-B Spartan NIZK proof) showing leaf* in trusted_root.
//!
//! Full chain: pi_final => H_img == Manifest.digest; H_CBOR = SHA256(Manifest);
//! pi_sigma => ECDSA.Verify(PK, H_CBOR, sigma) AND cmPK == Com(PK; v);
//! H_reg(cmPK) => leaf*; pi_merkle => leaf* in R_PKI*.
//!
//! STRICT SECURITY CONSTRAINTS:
//! - NO prover key (dpk, pk).
//! - NO prover execution or circuits preprocessing.
//! - NO private keys.
//! - NO private Merkle paths / witnesses.
//! - NO access to image or prover-side in-memory trace.

use std::env;
use std::error::Error;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

use ark_bn254::Fr;
use bincode::Options;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sonobe_ivc::compilers::cyclefold::DefaultDecider;
use sonobe_ivc::jisa_manifest::{parse_manifest_v1, public_digest_bytes, to_hex};
use sonobe_ivc::sha256_step::{
    reconstruct_sha256_state, reconstruct_sigmabus_binding, sha256_initial_state,
    Sha256PaddedCircuit,
};
use sonobe_ivc::IVCProofCompressor;

type FC = Sha256PaddedCircuit<Fr>;
type Decider = DefaultDecider;

pub const PACKAGE_VERSION: u32 = 4;
pub const MAX_PACKAGE_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_MERKLE_DEPTH: usize = 32;

struct TemporaryWorkspace {
    path: PathBuf,
}

impl TemporaryWorkspace {
    fn create() -> Result<Self, Box<dyn Error>> {
        let base = env::temp_dir();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("System clock is before UNIX_EPOCH: {}", e))?
            .as_nanos();

        for attempt in 0..64u32 {
            let path = base.join(format!(
                "picproof-standalone-{}-{}-{}",
                std::process::id(),
                timestamp,
                attempt
            ));
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            builder.mode(0o700);

            match builder.create(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => {
                    return Err(format!(
                        "Failed to create private temporary directory '{}': {}",
                        path.display(),
                        e
                    )
                    .into());
                }
            }
        }

        Err("Failed to allocate a unique private temporary directory".into())
    }
}

impl Drop for TemporaryWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);

    let mut file = options.open(path).map_err(|e| {
        format!(
            "Failed to create temporary file '{}': {}",
            path.display(),
            e
        )
    })?;
    file.write_all(bytes)
        .map_err(|e| format!("Failed to write temporary file '{}': {}", path.display(), e))?;
    file.sync_all()
        .map_err(|e| format!("Failed to sync temporary file '{}': {}", path.display(), e))?;
    Ok(())
}

fn read_package_bytes(path: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let file =
        fs::File::open(path).map_err(|e| format!("Failed to open package '{}': {}", path, e))?;
    let declared_len = file
        .metadata()
        .map_err(|e| format!("Failed to stat package '{}': {}", path, e))?
        .len();

    if declared_len > MAX_PACKAGE_BYTES {
        return Err(format!(
            "Package '{}' is {} bytes, exceeding the {} byte limit",
            path, declared_len, MAX_PACKAGE_BYTES
        )
        .into());
    }

    let mut bytes = Vec::with_capacity(declared_len as usize);
    file.take(MAX_PACKAGE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("Failed to read package '{}': {}", path, e))?;

    if bytes.len() as u64 > MAX_PACKAGE_BYTES {
        return Err(format!(
            "Package '{}' grew beyond the {} byte limit while being read",
            path, MAX_PACKAGE_BYTES
        )
        .into());
    }

    Ok(bytes)
}

fn deserialize_package(bytes: &[u8]) -> Result<PicProofPackage, Box<dyn Error>> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_limit(MAX_PACKAGE_BYTES)
        .deserialize(bytes)
        .map_err(|e| format!("Failed to deserialize PicProofPackage: {:?}", e).into())
}

fn validate_profile_depth(depth: usize) -> Result<(), Box<dyn Error>> {
    if depth > MAX_MERKLE_DEPTH {
        return Err(format!(
            "Trusted profile Merkle depth {} exceeds the supported maximum {}",
            depth, MAX_MERKLE_DEPTH
        )
        .into());
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String, Box<dyn Error>> {
    let bytes = fs::read(path).map_err(|e| {
        format!(
            "Failed to read fingerprint target '{}': {}",
            path.display(),
            e
        )
    })?;
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    Ok(to_hex(&digest))
}

fn load_trusted_profile(path: &Path) -> Result<TrustedProfile, Box<dyn Error>> {
    let bytes = fs::read(path)
        .map_err(|e| format!("Failed to read trusted profile '{}': {}", path.display(), e))?;
    let profile: TrustedProfile = serde_json::from_slice(&bytes)
        .map_err(|e| format!("Invalid trusted profile JSON '{}': {}", path.display(), e))?;
    validate_profile_depth(profile.merkle_depth)?;
    if profile.package_version != PACKAGE_VERSION {
        return Err(format!(
            "Trusted profile package_version {} does not match supported {}",
            profile.package_version, PACKAGE_VERSION
        )
        .into());
    }
    for (name, value) in [
        ("profile_id", profile.profile_id.as_str()),
        ("rid_hashfold", profile.rid_hashfold.as_str()),
        ("rid_sigma", profile.rid_sigma.as_str()),
        ("rid_merkle", profile.rid_merkle.as_str()),
        ("trusted_root", profile.trusted_root.as_str()),
        ("decider_vk_sha256", profile.decider_vk_sha256.as_str()),
        (
            "sigma_verifier_sha256",
            profile.sigma_verifier_sha256.as_str(),
        ),
        (
            "spartan_verifier_sha256",
            profile.spartan_verifier_sha256.as_str(),
        ),
        (
            "merkle_profile_fingerprint",
            profile.merkle_profile_fingerprint.as_str(),
        ),
    ] {
        if value.trim().is_empty() {
            return Err(format!("Trusted profile field '{}' must not be empty", name).into());
        }
    }
    Ok(profile)
}

fn profile_guard(
    package: &PicProofPackage,
    profile: &TrustedProfile,
    verifier_key_path: &str,
    sigpop_dir: &Path,
) -> Result<(), Box<dyn Error>> {
    if package.version != profile.package_version {
        return Err(format!(
            "PROFILE GUARD REJECT: package version mismatch (package={}, profile={})",
            package.version, profile.package_version
        )
        .into());
    }
    if package.public_instance.merkle_root != profile.trusted_root {
        return Err(format!(
            "PROFILE GUARD REJECT: trusted_root mismatch (package='{}', profile='{}')",
            package.public_instance.merkle_root, profile.trusted_root
        )
        .into());
    }
    if package.metadata.merkle_depth != profile.merkle_depth {
        return Err(format!(
            "PROFILE GUARD REJECT: merkle_depth mismatch (package={}, profile={})",
            package.metadata.merkle_depth, profile.merkle_depth
        )
        .into());
    }
    if package.metadata.profile_id != profile.profile_id {
        return Err(format!(
            "PROFILE GUARD REJECT: profile_id mismatch (package='{}', profile='{}')",
            package.metadata.profile_id, profile.profile_id
        )
        .into());
    }
    if package.metadata.rid_hashfold != profile.rid_hashfold {
        return Err(format!(
            "PROFILE GUARD REJECT: rid_hashfold mismatch (package='{}', profile='{}')",
            package.metadata.rid_hashfold, profile.rid_hashfold
        )
        .into());
    }
    if package.metadata.rid_sigma != profile.rid_sigma {
        return Err(format!(
            "PROFILE GUARD REJECT: rid_sigma mismatch (package='{}', profile='{}')",
            package.metadata.rid_sigma, profile.rid_sigma
        )
        .into());
    }
    if package.metadata.rid_merkle != profile.rid_merkle {
        return Err(format!(
            "PROFILE GUARD REJECT: rid_merkle mismatch (package='{}', profile='{}')",
            package.metadata.rid_merkle, profile.rid_merkle
        )
        .into());
    }
    if package.metadata.merkle_profile_fingerprint != profile.merkle_profile_fingerprint {
        return Err(format!(
            "PROFILE GUARD REJECT: merkle_profile_fingerprint mismatch (package='{}', profile='{}')",
            package.metadata.merkle_profile_fingerprint, profile.merkle_profile_fingerprint
        )
        .into());
    }

    let sigma_bin = sigpop_dir.join("target/release/examples/sigma_extract_cmpk");
    let spartan_bin = sigpop_dir.join("target/release/examples/spartan_merkle_linked");

    let decider_vk_sha256 = sha256_file(Path::new(verifier_key_path))?;
    if !decider_vk_sha256.eq_ignore_ascii_case(&profile.decider_vk_sha256) {
        return Err(format!(
            "PROFILE GUARD REJECT: Decider VK fingerprint mismatch (actual='{}', profile='{}')",
            decider_vk_sha256, profile.decider_vk_sha256
        )
        .into());
    }

    let sigma_verifier_sha256 = sha256_file(&sigma_bin)?;
    if !sigma_verifier_sha256.eq_ignore_ascii_case(&profile.sigma_verifier_sha256) {
        return Err(format!(
            "PROFILE GUARD REJECT: Sigma verifier fingerprint mismatch (actual='{}', profile='{}')",
            sigma_verifier_sha256, profile.sigma_verifier_sha256
        )
        .into());
    }

    let spartan_verifier_sha256 = sha256_file(&spartan_bin)?;
    if !spartan_verifier_sha256.eq_ignore_ascii_case(&profile.spartan_verifier_sha256) {
        return Err(format!(
            "PROFILE GUARD REJECT: Spartan verifier fingerprint mismatch (actual='{}', profile='{}')",
            spartan_verifier_sha256, profile.spartan_verifier_sha256
        )
        .into());
    }

    Ok(())
}

fn take_argument_value(
    args: &[String],
    index: &mut usize,
    flag: &str,
) -> Result<String, Box<dyn Error>> {
    *index += 1;
    args.get(*index)
        .cloned()
        .ok_or_else(|| format!("Missing value for {}", flag).into())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicInstance {
    pub num_blocks: usize,
    pub h_hi: String,
    pub h_lo: String,

    /// Redundant audit-only copy of H_CBOR. The verifier MUST recompute it
    /// from `manifest_cbor` and merely cross-check this field.
    pub cbor_manifest_hash: String,

    // Public PK-link anchor extracted from verified Sigma statement.
    pub cm_pk_c0: Vec<u8>,
    pub cm_pk_c1: Vec<u8>,

    // Deterministically derived from cmPK by H_reg.
    pub registration_leaf: String,

    // Informational copy only; verifier MUST compare against
    // independently supplied trusted_root.
    pub merkle_root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofMetadata {
    pub image_bytes: usize,
    pub sha256_blocks: usize,
    pub cbor_bytes: usize,
    pub merkle_depth: usize,
    pub timestamp: u64,

    pub profile_id: String,
    pub rid_hashfold: String,
    pub rid_sigma: String,
    pub rid_merkle: String,
    pub merkle_profile_fingerprint: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedProfile {
    pub profile_id: String,
    pub package_version: u32,
    pub merkle_depth: usize,

    pub rid_hashfold: String,
    pub rid_sigma: String,
    pub rid_merkle: String,

    pub trusted_root: String,

    pub decider_vk_sha256: String,
    pub sigma_verifier_sha256: String,
    pub spartan_verifier_sha256: String,

    pub merkle_profile_fingerprint: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PicProofPackage {
    pub version: u32,
    pub public_instance: PublicInstance,

    /// Exact PicProof Manifest v1 CBOR bytes signed by the camera (v3+).
    /// H_CBOR is recomputed by the verifier from these bytes.
    pub manifest_cbor: Vec<u8>,

    pub pi_final: Vec<u8>,
    pub pi_sigma: Vec<u8>,
    pub pi_merkle: Vec<u8>,
    pub metadata: ProofMetadata,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StandaloneVerificationResult {
    pub package_version: u32,
    pub merkle_depth: usize,
    pub sha256_blocks: usize,
    pub profile_guard_ms: f64,
    pub decider_verify_ms: u64,
    pub sigma_verify_ms: u64,
    pub merkle_verify_ms: u64,
    pub total_verify_ms: u64,
    pub pi_final_bytes: usize,
    pub pi_sigma_bytes: usize,
    pub pi_merkle_bytes: usize,
    pub decider_verify: bool,
    pub sigma_verify: bool,
    pub pk_link_verify: bool,
    pub merkle_verify: bool,
    pub root_match: bool,

    /// v3: Decider-proven H_img was bound to the camera-signed manifest and
    /// H_CBOR was recomputed by the verifier itself.
    pub manifest_binding: bool,

    /// Optional media-file binding (only meaningful when `--image` is given).
    pub media_checked: bool,
    pub media_matches: bool,
    pub media_digest_hex: String,

    pub total_wallclock_ms: u64,
    pub accept: bool,
}

fn decode_hex(hex_str: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let clean = hex_str.trim().strip_prefix("0x").unwrap_or(hex_str.trim());
    if clean.len() % 2 != 0 {
        return Err("Hex string has odd length".into());
    }
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).map_err(|e| e.into()))
        .collect()
}

/// Verify Sigma proof against a verifier-computed H_CBOR digest (32-byte hex)
/// and derive (leaf*, cmPK_C0, cmPK_C1).
fn sigma_verify_and_derive(
    digest_hex: &str,
    pi_sigma: &str,
    out_json: &str,
    sigpop_dir: &Path,
) -> Result<(String, Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let bin = sigpop_dir.join("target/release/examples/sigma_extract_cmpk");
    if !bin.is_file() {
        return Err(format!(
            "Sigma verifier binary not found at '{}' (build sigpop release examples first)",
            bin.display()
        )
        .into());
    }
    let output = Command::new(bin)
        .current_dir(sigpop_dir)
        .arg("verify-and-derive")
        .arg("--proof-in")
        .arg(pi_sigma)
        .arg("--digest-hex")
        .arg(digest_hex)
        .arg("--out")
        .arg(out_json)
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "sigma_verify_and_derive failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }

    let val: serde_json::Value = serde_json::from_str(&fs::read_to_string(out_json)?)?;
    let leaf = val["leaf_decimal"]
        .as_str()
        .ok_or("Missing leaf_decimal in pk_link_vector")?
        .to_string();
    let c0_hex = val["c0_sec1"].as_str().ok_or("Missing c0_sec1")?;
    let c1_hex = val["c1_sec1"].as_str().ok_or("Missing c1_sec1")?;
    let c0_bytes = decode_hex(c0_hex)?;
    let c1_bytes = decode_hex(c1_hex)?;

    Ok((leaf, c0_bytes, c1_bytes))
}

/// Spartan Merkle verifier wrapper calling sigpop's spartan_merkle_linked verify.
fn spartan_merkle_verify(
    leaf: &str,
    trusted_root: &str,
    depth: usize,
    proof_in: &str,
    sigpop_dir: &Path,
) -> Result<(), Box<dyn Error>> {
    let bin = sigpop_dir.join("target/release/examples/spartan_merkle_linked");
    if !bin.is_file() {
        return Err(format!(
            "Spartan verifier binary not found at '{}' (build sigpop release examples first)",
            bin.display()
        )
        .into());
    }
    let output = Command::new(bin)
        .current_dir(sigpop_dir)
        .arg("verify")
        .arg("--leaf")
        .arg(leaf)
        .arg("--root")
        .arg(trusted_root)
        .arg("--depth")
        .arg(depth.to_string())
        .arg("--proof-in")
        .arg(proof_in)
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "spartan_merkle_verify failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    let mut proof_path: Option<String> = None;
    let mut trusted_profile_path: Option<String> = None;
    let mut verifier_key_path: Option<String> = None;
    let mut sigpop_dir: Option<PathBuf> = None;
    let mut output_json: Option<String> = None;
    let mut image_path: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--proof" => {
                proof_path = Some(take_argument_value(&args, &mut i, "--proof")?);
            }
            "--trusted-profile" => {
                trusted_profile_path =
                    Some(take_argument_value(&args, &mut i, "--trusted-profile")?);
            }
            "--verifier-key" => {
                verifier_key_path = Some(take_argument_value(&args, &mut i, "--verifier-key")?);
            }
            "--sigpop-dir" => {
                sigpop_dir = Some(PathBuf::from(take_argument_value(
                    &args,
                    &mut i,
                    "--sigpop-dir",
                )?));
            }
            "--output" => {
                output_json = Some(take_argument_value(&args, &mut i, "--output")?);
            }
            "--image" => {
                image_path = Some(take_argument_value(&args, &mut i, "--image")?);
            }
            "--privkey" | "--merkle-path" => {
                return Err(format!(
                    "SECURITY VIOLATION: Standalone verifier must not accept prover secrets ({})",
                    args[i]
                )
                .into());
            }
            _ => {
                return Err(format!("Unknown argument: {}", args[i]).into());
            }
        }
        i += 1;
    }

    let proof_path = proof_path.ok_or("Missing required --proof argument")?;
    let trusted_profile_path =
        trusted_profile_path.ok_or("Missing required --trusted-profile argument")?;
    let verifier_key_path = verifier_key_path.ok_or("Missing required --verifier-key argument")?;
    let sigpop_dir = sigpop_dir.ok_or("Missing required --sigpop-dir argument")?;

    if !sigpop_dir.is_dir() {
        return Err(format!("--sigpop-dir '{}' is not a directory", sigpop_dir.display()).into());
    }
    let trusted_profile = load_trusted_profile(Path::new(&trusted_profile_path))?;

    println!("============================================================");
    println!(" [JISA STANDALONE VERIFIER] Initializing independent verification");
    println!(" Proof Package:  {}", proof_path);
    println!(" Verifier Key:   {}", verifier_key_path);
    println!(" Trusted Profile: {}", trusted_profile_path);
    println!(" Profile ID:     {}", trusted_profile.profile_id);
    println!(" Trusted Root:   {}", trusted_profile.trusted_root);
    println!(" Sig-PoP Dir:    {}", sigpop_dir.display());
    println!(
        " Profile depth:  {} (externally configured)",
        trusted_profile.merkle_depth
    );
    match &image_path {
        Some(p) => println!(" Media File:     {} (optional binding check)", p),
        None => println!(" Media File:     <not supplied>"),
    }
    println!("============================================================");

    let t_total_start = Instant::now();

    // 1. Read and deserialize PicProofPackage with an explicit size bound.
    let package_bytes = read_package_bytes(&proof_path)?;
    let package = deserialize_package(&package_bytes)?;
    println!("[1/6] Package parsed");

    // 2. Guard every authenticated profile/relation/fingerprint binding
    //    before constructing any statement or running any verifier.
    let t_guard = Instant::now();
    profile_guard(&package, &trusted_profile, &verifier_key_path, &sigpop_dir).map_err(|e| {
        format!(
            "{}; guard stopped before statement construction/verification",
            e
        )
    })?;
    let profile_guard_ms = t_guard.elapsed().as_secs_f64() * 1000.0;
    println!(
        "[2/6] PROFILE GUARD PASS (profile='{}', depth={}, guard={:.3} ms)",
        trusted_profile.profile_id, trusted_profile.merkle_depth, profile_guard_ms
    );

    let num_blocks = package.public_instance.num_blocks;
    if package.metadata.sha256_blocks != num_blocks {
        return Err(format!(
            "Package sha256_blocks metadata mismatch: metadata={}, public_instance={}",
            package.metadata.sha256_blocks, num_blocks
        )
        .into());
    }
    println!(
        "       Metadata cross-check:      PASS (blocks={}, depth={})",
        package.metadata.sha256_blocks, package.metadata.merkle_depth
    );

    let h_hi = package
        .public_instance
        .h_hi
        .parse::<u128>()
        .map_err(|e| format!("Invalid h_hi in package: {:?}", e))?;
    let h_lo = package
        .public_instance
        .h_lo
        .parse::<u128>()
        .map_err(|e| format!("Invalid h_lo in package: {:?}", e))?;

    // 5. Reconstruct initial_state, current_state, Sigmabus binding
    let initial_state = sha256_initial_state::<Fr>();
    let current_state = reconstruct_sha256_state::<Fr>(h_hi, h_lo);
    let binding = reconstruct_sigmabus_binding::<Fr>(num_blocks, h_hi, h_lo);
    println!(
        "[3/6] Protocol state reconstructed from public instance (blocks={}, h_hi={}, h_lo={})",
        num_blocks, h_hi, h_lo
    );

    // 6. Deserialize complete 472-B pi_final
    if package.pi_final.len() != 472 {
        return Err(format!(
            "Decider artifact must be strictly 472 bytes, got {}",
            package.pi_final.len()
        )
        .into());
    }
    let compressed =
        Decider::deserialize_compressed_proof::<FC>(&package.pi_final).map_err(|e| {
            format!(
                "Failed to deserialize Decider proof artifact (pi_final): {:?}",
                e
            )
        })?;

    // 7. Deserialize external Decider verifier key
    let dvk_bytes = fs::read(&verifier_key_path).map_err(|e| {
        format!(
            "Failed to read verifier key from {}: {:?}",
            verifier_key_path, e
        )
    })?;
    let dvk = Decider::deserialize_verifier_key::<FC>(&dvk_bytes)
        .map_err(|e| format!("Failed to deserialize Decider verifier key: {:?}", e))?;
    println!(
        "[4/6] Decider verifier key loaded ({} bytes)",
        dvk_bytes.len()
    );

    // 8. Decider::verify
    let t_dec = Instant::now();
    <Decider as IVCProofCompressor>::verify::<FC>(
        &dvk,
        num_blocks,
        &initial_state,
        &current_state,
        &compressed,
        Some(binding),
    )
    .map_err(|e| format!("Decider verification failed: {:?}", e))?;
    let decider_verify_ms = t_dec.elapsed().as_millis() as u64;
    println!(
        "       Decider pi_final:          PASS ({} ms)",
        decider_verify_ms
    );

    // 9. Bind Decider-proven H_img to the camera-signed manifest.
    let proved_image_digest =
        public_digest_bytes(&package.public_instance.h_hi, &package.public_instance.h_lo)
            .map_err(|e| format!("Package public instance digest is malformed: {}", e))?;

    let manifest = parse_manifest_v1(&package.manifest_cbor)
        .map_err(|e| format!("Manifest v1 parse failed: {}", e))?;

    if manifest.digest != proved_image_digest {
        return Err("Manifest digest does not match Decider-proven image digest".into());
    }
    println!("       H_img == Manifest.digest:  PASS");

    if manifest.image_bytes != package.metadata.image_bytes as u64 {
        return Err("Manifest image_bytes / package metadata mismatch".into());
    }
    if manifest.timestamp != package.metadata.timestamp {
        return Err("Manifest timestamp / package metadata mismatch".into());
    }
    if package.manifest_cbor.len() != package.metadata.cbor_bytes {
        return Err("Manifest CBOR length / metadata mismatch".into());
    }
    println!("       Manifest/metadata binding: PASS");

    // 10. Verifier recomputes H_CBOR itself; the stored hash is audit-only.
    let manifest_hash: [u8; 32] = Sha256::digest(&package.manifest_cbor).into();
    let manifest_hash_hex = to_hex(&manifest_hash);

    if !package
        .public_instance
        .cbor_manifest_hash
        .eq_ignore_ascii_case(&manifest_hash_hex)
    {
        return Err("Stored cbor_manifest_hash does not match SHA-256(manifest_cbor)".into());
    }
    println!("       H_CBOR = SHA256(Manifest): PASS");

    // 11. Sigma verify-and-derive against the verifier-computed H_CBOR
    let temp_workspace = TemporaryWorkspace::create()?;
    let verify_sigma_tmp = temp_workspace.path.join("pi_sigma.bin");
    let verify_pklink_tmp = temp_workspace.path.join("pklink.json");
    write_private_file(&verify_sigma_tmp, &package.pi_sigma)?;

    let t_sig = Instant::now();
    let (verified_leaf, verified_c0, verified_c1) = sigma_verify_and_derive(
        &manifest_hash_hex,
        verify_sigma_tmp
            .to_str()
            .ok_or("Temporary Sigma proof path is not valid UTF-8")?,
        verify_pklink_tmp
            .to_str()
            .ok_or("Temporary PK-link output path is not valid UTF-8")?,
        &sigpop_dir,
    )?;
    let sigma_verify_ms = t_sig.elapsed().as_millis() as u64;
    println!(
        "       Sigma pi_sigma:            PASS ({} ms)",
        sigma_verify_ms
    );

    // 11. Compare derived cmPK and leaf with package fields
    if verified_leaf != package.public_instance.registration_leaf {
        return Err(format!(
            "Registration leaf mismatch: derived '{}', package has '{}'",
            verified_leaf, package.public_instance.registration_leaf
        )
        .into());
    }
    if verified_c0 != package.public_instance.cm_pk_c0 {
        return Err("cmPK C0 mismatch between derived and package instance".into());
    }
    if verified_c1 != package.public_instance.cm_pk_c1 {
        return Err("cmPK C1 mismatch between derived and package instance".into());
    }
    println!(
        "       PK-link H_reg:             PASS (leaf*={})",
        verified_leaf
    );

    // 12. Spartan verify against external trusted root
    let verify_merkle_tmp = temp_workspace.path.join("pi_merkle.bin");
    write_private_file(&verify_merkle_tmp, &package.pi_merkle)?;

    let t_spa = Instant::now();
    spartan_merkle_verify(
        &verified_leaf,
        &trusted_profile.trusted_root,
        trusted_profile.merkle_depth,
        verify_merkle_tmp
            .to_str()
            .ok_or("Temporary Merkle proof path is not valid UTF-8")?,
        &sigpop_dir,
    )?;
    let merkle_verify_ms = t_spa.elapsed().as_millis() as u64;
    println!(
        "       Spartan pi_merkle:         PASS ({} ms)",
        merkle_verify_ms
    );

    // 13. Optional media binding: does a concrete media file hash to H_img?
    //
    //     This is the only step that answers "does this package belong to THIS
    //     file?". It is plain SHA-256 over the supplied bytes, no ZK involved,
    //     so it is reported separately from the cryptographic package verify.
    let mut media_check: Option<(String, bool)> = None;
    if let Some(path) = &image_path {
        let t_media = Instant::now();
        let media_bytes =
            fs::read(path).map_err(|e| format!("Failed to read media file '{}': {:?}", path, e))?;

        if media_bytes.len() as u64 != manifest.image_bytes {
            return Err(format!(
                "Supplied media length mismatch for '{}': got {} bytes, signed Manifest declares {} bytes",
                path,
                media_bytes.len(),
                manifest.image_bytes
            )
            .into());
        }

        let actual_digest: [u8; 32] = Sha256::digest(&media_bytes).into();
        if actual_digest != proved_image_digest {
            return Err(format!(
                "Supplied media does not match provenance package (H_img mismatch for '{}')",
                path
            )
            .into());
        }

        let media_ms = t_media.elapsed().as_millis() as u64;
        println!(
            "       Supplied media {} bytes: PASS ({} ms, matches H_img)",
            media_bytes.len(),
            media_ms
        );
        media_check = Some((to_hex(&actual_digest), true));
    }

    let total_verify_ms = decider_verify_ms + sigma_verify_ms + merkle_verify_ms;
    let total_wallclock_ms = t_total_start.elapsed().as_millis() as u64;

    println!("[5/6] All cryptographic predicates satisfied!");
    println!("[6/6] Result Summary:");
    println!("       ----------------------------------------------------");
    println!(
        "       Decider pi_final (472 B):       PASS ({} ms)",
        decider_verify_ms
    );
    println!(
        "       Sigma pi_sigma (447 B):         PASS ({} ms)",
        sigma_verify_ms
    );
    println!("       PK-link H_reg verification:     PASS");
    println!(
        "       Spartan pi_merkle ({} B): PASS ({} ms)",
        package.pi_merkle.len(),
        merkle_verify_ms
    );
    println!("       External trusted root check:    PASS");
    println!("       ----------------------------------------------------");
    println!(
        "       Total Cryptographic Verify:     {} ms",
        total_verify_ms
    );
    println!(
        "       Total Standalone Wallclock:     {} ms",
        total_wallclock_ms
    );
    println!("============================================================");
    println!(" STANDALONE PACKAGE VERIFY ACCEPT");
    println!("============================================================");

    if let Some(out_json_path) = output_json {
        let result = StandaloneVerificationResult {
            package_version: package.version,
            merkle_depth: package.metadata.merkle_depth,
            sha256_blocks: num_blocks,
            profile_guard_ms,
            decider_verify_ms,
            sigma_verify_ms,
            merkle_verify_ms,
            total_verify_ms,
            pi_final_bytes: package.pi_final.len(),
            pi_sigma_bytes: package.pi_sigma.len(),
            pi_merkle_bytes: package.pi_merkle.len(),
            decider_verify: true,
            sigma_verify: true,
            pk_link_verify: true,
            merkle_verify: true,
            root_match: true,
            manifest_binding: true,
            media_checked: media_check.is_some(),
            media_matches: media_check.as_ref().map(|(_, ok)| *ok).unwrap_or(false),
            media_digest_hex: media_check.map(|(hex, _)| hex).unwrap_or_default(),
            total_wallclock_ms,
            accept: true,
        };
        if let Some(parent) = Path::new(&out_json_path).parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&out_json_path, serde_json::to_string_pretty(&result)?)?;
        println!("Saved standalone audit result to {}", out_json_path);
    }

    Ok(())
}
