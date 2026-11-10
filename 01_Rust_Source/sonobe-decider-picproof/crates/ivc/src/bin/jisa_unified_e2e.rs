//! JISA Unified End-to-End Evaluation Binary
//!
//! Executes the complete provenance verification pipeline in a single unified run:
//! Raw Image -> SHA-256(image) -> PicProof Manifest v1 fixed CBOR profile ->
//! (the manifest carries a per-manifest 16-byte `salt` that is signed as part
//!  of the manifest CBOR bytes, but does NOT participate in the image digest)
//! P-256 Signature -> CycleFold HashFold -> Sigmabus (h_hi, h_lo) Binding ->
//! Private Merkle + Spartan NIZK / Sigma -> LegoGroth16 Decider ->
//! Proof Package Serialization -> Unified Verifier.

use std::error::Error;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Instant;

use ark_bn254::{Bn254, Fr, G1Projective as C1};
use ark_grumpkin::Projective as C2;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::thread_rng;
use ark_std::rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use sonobe_fs::nova::{CycleFoldNova, Nova};
use sonobe_ivc::compilers::cyclefold::{CycleFoldBasedIVC, CycleFoldBasedIVCDecider};
use sonobe_ivc::jisa_manifest::{parse_manifest_v1, public_digest_bytes, to_hex};
use sonobe_ivc::sha256_step::{sha256_padded_blocks, Sha256PaddedCircuit};
use sonobe_ivc::{
    IVCKeyGenerator, IVCPreprocessor, IVCProofCompressor, IVCStatefulProver, IVCVerifier,
};
use sonobe_primitives::circuits::FCircuit;
use sonobe_primitives::commitments::pedersen::Pedersen;
use sonobe_primitives::transcripts::griffin::{sponge::GriffinSponge, GriffinParams};
use sonobe_snarks::cp::legogroth16::LegoGroth16;

type FC = Sha256PaddedCircuit<Fr>;
type IVCType = CycleFoldBasedIVC<
    Nova<Pedersen<C1, true>>,
    CycleFoldNova<Pedersen<C2, true>>,
    GriffinSponge<Fr>,
>;
type Decider = CycleFoldBasedIVCDecider<
    Nova<Pedersen<C1, true>>,
    CycleFoldNova<Pedersen<C2, true>>,
    GriffinSponge<Fr>,
    LegoGroth16<Bn254>,
>;

pub const PACKAGE_VERSION: u32 = 4;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicInstance {
    pub num_blocks: usize,
    pub h_hi: String,
    pub h_lo: String,
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
pub struct PicProofPackage {
    pub version: u32,
    pub public_instance: PublicInstance,

    /// Exact PicProof Manifest v1 CBOR bytes signed by the camera (v3+).
    /// The verifier MUST recompute H_CBOR = SHA-256(manifest_cbor) from these
    /// bytes; `public_instance.cbor_manifest_hash` is a redundant audit field.
    pub manifest_cbor: Vec<u8>,

    pub pi_final: Vec<u8>,
    pub pi_sigma: Vec<u8>,
    pub pi_merkle: Vec<u8>,
    pub metadata: ProofMetadata,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonAuditResult {
    pub image_bytes: usize,
    pub sha256_blocks: usize,
    pub cbor_bytes: usize,

    pub manifest_ms: u64,
    pub p256_sign_ms: u64,
    pub hashfold_ms: u64,
    pub dorian_prove_ms: u64,
    pub decider_setup_ms: u64,
    pub decider_prove_ms: u64,

    pub online_cryptographic_prove_ms: u64,
    pub total_online_prove_ms: u64,
    pub total_prove_ms: u64,

    pub hashfold_verify_ms: u64,
    pub sigma_verify_ms: u64,
    pub merkle_verify_ms: u64,
    pub decider_verify_ms: u64,
    pub pipeline_selfcheck_ms: u64,
    pub package_verify_ms: u64,
    pub total_verify_ms: u64,

    pub pi_final_bytes: usize,
    pub pi_sigma_bytes: usize,
    pub pi_merkle_bytes: usize,
    pub public_instance_bytes: usize,
    pub metadata_bytes: usize,
    pub container_overhead_bytes: usize,
    pub proof_package_bytes: usize,

    pub rss_after_folding_kib: u64,
    pub peak_rss_kib: u64,

    pub decider_verify: bool,
    pub sigma_verify: bool,
    pub merkle_verify: bool,
    pub pk_link_verify: bool,
    pub profile_sha256_before_prove: String,
    pub profile_sha256_after_prove: String,
    pub trusted_profile_committed_before_prove: bool,
    pub trusted_profile_unchanged: bool,
    pub accept: bool,
    pub return_code: i32,
}

fn peak_rss_kb() -> u64 {
    let Ok(status) = fs::read_to_string("/proc/self/status") else {
        return 0;
    };
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            if let Some(value) = rest.split_whitespace().next() {
                return value.parse().unwrap_or(0);
            }
        }
    }
    0
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    to_hex(&digest)
}

fn write_file_atomic(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    {
        let mut file = fs::File::create(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    if let Some(parent) = path.parent() {
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

fn decode_hex(s: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| format!("Invalid hex: {:?}", e).into())
        })
        .collect()
}

fn encode_cbor_uint(val: u64, buf: &mut Vec<u8>, major: u8) {
    let m = major << 5;
    if val < 24 {
        buf.push(m | (val as u8));
    } else if val <= 0xFF {
        buf.push(m | 24);
        buf.push(val as u8);
    } else if val <= 0xFFFF {
        buf.push(m | 25);
        buf.extend_from_slice(&(val as u16).to_be_bytes());
    } else if val <= 0xFFFF_FFFF {
        buf.push(m | 26);
        buf.extend_from_slice(&(val as u32).to_be_bytes());
    } else {
        buf.push(m | 27);
        buf.extend_from_slice(&val.to_be_bytes());
    }
}

fn encode_cbor_text(s: &str, buf: &mut Vec<u8>) {
    encode_cbor_uint(s.len() as u64, buf, 3);
    buf.extend_from_slice(s.as_bytes());
}

fn encode_cbor_bytes(bytes: &[u8], buf: &mut Vec<u8>) {
    encode_cbor_uint(bytes.len() as u64, buf, 2);
    buf.extend_from_slice(bytes);
}

fn encode_picproof_manifest_v1(
    img_len: usize,
    digest: &[u8; 32],
    salt: &[u8; 16],
    timestamp: u64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    buf.push(0xA5); // map of 5 items

    encode_cbor_text("algorithm", &mut buf);
    encode_cbor_text("sha-256", &mut buf);

    encode_cbor_text("digest", &mut buf);
    encode_cbor_bytes(digest, &mut buf);

    encode_cbor_text("image_bytes", &mut buf);
    encode_cbor_uint(img_len as u64, &mut buf, 0);

    encode_cbor_text("salt", &mut buf);
    encode_cbor_bytes(salt, &mut buf);

    encode_cbor_text("timestamp", &mut buf);
    encode_cbor_uint(timestamp, &mut buf, 0);

    buf
}

fn sign_p256(privkey: &str, data: &[u8], sig_path: &Path) -> Result<Vec<u8>, Box<dyn Error>> {
    let tmp_data = "/tmp/cbor_manifest_to_sign.bin";
    fs::write(tmp_data, data)?;
    let status = Command::new("openssl")
        .args([
            "dgst",
            "-sha256",
            "-sign",
            privkey,
            "-out",
            sig_path.to_str().unwrap(),
            tmp_data,
        ])
        .status()?;
    if !status.success() {
        return Err(format!("OpenSSL sign failed: {:?}", status).into());
    }
    let sig_bytes = fs::read(sig_path)?;
    Ok(sig_bytes)
}

fn verify_p256_manifest(pubkey: &str, data: &[u8], sig_path: &Path) -> bool {
    let tmp_data = "/tmp/cbor_manifest_to_verify.bin";
    if fs::write(tmp_data, data).is_err() {
        return false;
    }
    let res = Command::new("openssl")
        .args([
            "dgst",
            "-sha256",
            "-verify",
            pubkey,
            "-signature",
            sig_path.to_str().unwrap(),
            tmp_data,
        ])
        .output();
    match res {
        Ok(out) => String::from_utf8_lossy(&out.stdout).contains("Verified OK"),
        Err(_) => false,
    }
}

/// Standalone ECDSA Sigma prover wrapper calling sigpop's sigma_prove.
///
/// Offline proving path: takes H_CBOR, an EXISTING DER signature, the public
/// key and the persistent enrollment opening. It never touches the signing key.
fn sigma_prove(
    digest_hex: &str,
    signature_path: &str,
    pubkey_path: &str,
    opening_path: &str,
    proof_out: &str,
) -> Result<(), Box<dyn Error>> {
    let sigpop_dir = Path::new("/root/autodl-tmp/sigpop");
    let bin = sigpop_dir.join("target/release/examples/sigma_prove");
    let output = Command::new(bin)
        .current_dir(sigpop_dir)
        .arg("--digest-hex")
        .arg(digest_hex)
        .arg("--signature")
        .arg(signature_path)
        .arg("--pubkey")
        .arg(pubkey_path)
        .arg("--opening")
        .arg(opening_path)
        .arg("--proof-out")
        .arg(proof_out)
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "sigma_prove failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(())
}

/// Verify Sigma proof against H_CBOR and derive (leaf*, cmPK_C0, cmPK_C1).
fn sigma_verify_and_derive(
    digest_hex: &str,
    pi_sigma: &str,
    out_json: &str,
) -> Result<(String, Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let sigpop_dir = Path::new("/root/autodl-tmp/sigpop");
    let bin = sigpop_dir.join("target/release/examples/sigma_extract_cmpk");
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

/// Spartan Merkle prover wrapper calling sigpop's spartan_merkle_linked prove.
fn spartan_merkle_prove(
    leaf: &str,
    trusted_root: &str,
    depth: usize,
    path_file: &str,
    proof_out: &str,
    timing_out: &str,
) -> Result<(), Box<dyn Error>> {
    let sigpop_dir = Path::new("/root/autodl-tmp/sigpop");
    let bin = sigpop_dir.join("target/release/examples/spartan_merkle_linked");
    let output = Command::new(bin)
        .current_dir(sigpop_dir)
        .arg("prove")
        .arg("--leaf")
        .arg(leaf)
        .arg("--root")
        .arg(trusted_root)
        .arg("--depth")
        .arg(depth.to_string())
        .arg("--path-file")
        .arg(path_file)
        .arg("--proof-out")
        .arg(proof_out)
        .arg("--timing-out")
        .arg(timing_out)
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "spartan_merkle_prove failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(())
}

/// Spartan Merkle verifier wrapper calling sigpop's spartan_merkle_linked verify.
/// Verifier NEVER touches path, siblings, directions, or --merkle-path.
fn spartan_merkle_verify(
    leaf: &str,
    trusted_root: &str,
    depth: usize,
    proof_in: &str,
) -> Result<(), Box<dyn Error>> {
    let sigpop_dir = Path::new("/root/autodl-tmp/sigpop");
    let bin = sigpop_dir.join("target/release/examples/spartan_merkle_linked");
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

#[allow(dead_code)]
fn bound_merkle_prove(
    h_hi: u128,
    h_lo: u128,
    privkey_path: &str,
    merkle_depth: usize,
    pi_sigma_path: &str,
    pi_merkle_path: &str,
    root_out_path: &str,
) -> Result<String, Box<dyn Error>> {
    let sigpop_dir = Path::new("/root/autodl-tmp/sigpop");
    let bin = sigpop_dir.join("target/release/examples/bound_merkle");
    let output = Command::new(bin)
        .current_dir(sigpop_dir)
        .arg("--action")
        .arg("prove")
        .arg("--h-hi")
        .arg(h_hi.to_string())
        .arg("--h-lo")
        .arg(h_lo.to_string())
        .arg("--privkey")
        .arg(privkey_path)
        .arg("--depth")
        .arg(merkle_depth.to_string())
        .arg("--proof-sigma")
        .arg(pi_sigma_path)
        .arg("--proof-merkle")
        .arg(pi_merkle_path)
        .arg("--root-out")
        .arg(root_out_path)
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "Bound Merkle prove failed: {:?}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let root = fs::read_to_string(root_out_path)?;
    Ok(root.trim().to_string())
}

#[allow(dead_code)]
fn bound_merkle_verify(
    h_hi: u128,
    h_lo: u128,
    pi_sigma_path: &str,
    pi_merkle_path: &str,
    merkle_root: &str,
) -> bool {
    let sigpop_dir = Path::new("/root/autodl-tmp/sigpop");
    let bin = sigpop_dir.join("target/release/examples/bound_merkle");
    let output = Command::new(bin)
        .current_dir(sigpop_dir)
        .arg("--action")
        .arg("verify")
        .arg("--h-hi")
        .arg(h_hi.to_string())
        .arg("--h-lo")
        .arg(h_lo.to_string())
        .arg("--proof-sigma")
        .arg(pi_sigma_path)
        .arg("--proof-merkle")
        .arg(pi_merkle_path)
        .arg("--merkle-root")
        .arg(merkle_root)
        .output();
    match output {
        Ok(out) => out.status.success(),
        Err(_) => false,
    }
}

#[allow(dead_code)]
fn run_negative_controls(
    h_hi: u128,
    h_lo: u128,
    privkey_path: &str,
    merkle_depth: usize,
) -> Result<bool, Box<dyn Error>> {
    let sigpop_dir = Path::new("/root/autodl-tmp/sigpop");
    let bin = sigpop_dir.join("target/release/examples/bound_merkle");
    let output = Command::new(bin)
        .current_dir(sigpop_dir)
        .arg("--action")
        .arg("test-negatives")
        .arg("--h-hi")
        .arg(h_hi.to_string())
        .arg("--h-lo")
        .arg(h_lo.to_string())
        .arg("--privkey")
        .arg(privkey_path)
        .arg("--depth")
        .arg(merkle_depth.to_string())
        .output()?;
    let out_str = String::from_utf8_lossy(&output.stdout);
    println!("{}", out_str);
    Ok(output.status.success() && out_str.contains("ALL_NEGATIVES_PASSED_100%"))
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    let mut image_path = "data/jisa/64k.bin".to_string();
    let mut merkle_depth: usize = 16;
    let mut output_json = "results/jisa_final_server/e2e_64k_full.json".to_string();
    let mut proof_out = "results/jisa_final_server/e2e_64k_full.proof".to_string();
    let privkey_path = "/root/autodl-tmp/camera_privkey.pem".to_string();
    let pubkey_path = "/root/autodl-tmp/camera_pubkey.pem".to_string();

    let mut trusted_root: Option<String> = None;
    let mut merkle_path: Option<String> = None;
    let mut opening_path: Option<String> = None;
    let mut decider_vk_out: Option<String> = None;
    let mut trusted_profile_path: Option<String> = None;
    let mut trusted_profile_out: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--image" => {
                i += 1;
                image_path = args[i].clone();
            }
            "--merkle-depth" => {
                i += 1;
                merkle_depth = args[i].parse()?;
            }
            "--trusted-root" => {
                i += 1;
                trusted_root = Some(args[i].clone());
            }
            "--trusted-profile" => {
                i += 1;
                trusted_profile_path = Some(args[i].clone());
            }
            "--trusted-profile-out" => {
                i += 1;
                trusted_profile_out = Some(args[i].clone());
            }
            "--merkle-path" => {
                i += 1;
                merkle_path = Some(args[i].clone());
            }
            "--opening" => {
                i += 1;
                opening_path = Some(args[i].clone());
            }
            "--output" => {
                i += 1;
                output_json = args[i].clone();
            }
            "--proof-out" => {
                i += 1;
                proof_out = args[i].clone();
            }
            "--verifier-key-out" | "--decider-vk-out" => {
                i += 1;
                decider_vk_out = Some(args[i].clone());
            }
            other => {
                return Err(format!("Unknown argument: {}", other).into());
            }
        }
        i += 1;
    }

    let trusted_root = trusted_root.ok_or("--trusted-root is required for final linked profile")?;

    let trusted_profile_path =
        trusted_profile_path.ok_or("--trusted-profile is required for v4 package generation")?;
    let trusted_profile_out = trusted_profile_out
        .ok_or("--trusted-profile-out is required for trusted setup commitment")?;
    let decider_vk_out = decider_vk_out
        .as_ref()
        .ok_or("--decider-vk-out is required for trusted setup commitment")?
        .clone();
    let profile_template: TrustedProfile =
        serde_json::from_slice(&fs::read(&trusted_profile_path)?).map_err(|e| {
            format!(
                "Invalid trusted profile JSON '{}': {}",
                trusted_profile_path, e
            )
        })?;
    if profile_template.package_version != PACKAGE_VERSION {
        return Err(format!(
            "Trusted profile package_version {} does not match PACKAGE_VERSION {}",
            profile_template.package_version, PACKAGE_VERSION
        )
        .into());
    }
    if profile_template.trusted_root != trusted_root {
        return Err(format!(
            "CLI trusted root '{}' does not match trusted profile '{}'",
            trusted_root, profile_template.trusted_root
        )
        .into());
    }
    if profile_template.merkle_depth != merkle_depth {
        return Err(format!(
            "CLI Merkle depth {} does not match trusted profile {}",
            merkle_depth, profile_template.merkle_depth
        )
        .into());
    }

    let merkle_path = merkle_path.ok_or("--merkle-path is required for prover")?;

    let opening_path =
        opening_path.ok_or("--opening is required for final linked prover profile")?;

    if !Path::new(&opening_path).is_file() {
        return Err(format!("Enrollment opening not found: {}", opening_path).into());
    }

    println!("============================================================");
    println!(" [JISA UNIFIED E2E RUNNER] Starting end-to-end verification");
    println!(" Image:        {}", image_path);
    println!(" Merkle Depth: {}", merkle_depth);
    println!(" Trusted Root: {}", trusted_root);
    println!(" Merkle Path:  {}", merkle_path);
    println!(" Enrollment:   {}", opening_path);
    println!(" Output JSON:  {}", output_json);
    println!(" Proof Output: {}", proof_out);
    println!("============================================================");

    let raw_image = fs::read(&image_path)
        .unwrap_or_else(|_| panic!("Failed to read image file: {}", image_path));
    let img_len = raw_image.len();
    println!("[1/10] Loaded raw image: {} bytes", img_len);

    // 1. SHA-256(image) & salt
    let mut rng = thread_rng();
    let mut salt = [0u8; 16];
    rng.fill_bytes(&mut salt);
    let digest: [u8; 32] = Sha256::digest(&raw_image).into();

    let h_hi = u128::from_be_bytes(digest[0..16].try_into().unwrap());
    let h_lo = u128::from_be_bytes(digest[16..32].try_into().unwrap());
    let h_hi_fr = Fr::from(h_hi);
    let h_lo_fr = Fr::from(h_lo);
    println!(
        "[2/10] SHA-256 digest: {:x?} (h_hi={}, h_lo={})",
        digest, h_hi, h_lo
    );

    // 2. PicProof Manifest v1 fixed CBOR profile
    let t_manifest = Instant::now();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let manifest_cbor = encode_picproof_manifest_v1(img_len, &digest, &salt, timestamp);
    let manifest_ms = t_manifest.elapsed().as_millis() as u64;
    let cbor_bytes = manifest_cbor.len();
    let manifest_hash: [u8; 32] = Sha256::digest(&manifest_cbor).into();
    let manifest_hash_hex: String = manifest_hash.iter().map(|b| format!("{:02x}", b)).collect();
    println!(
        "[3/10] PicProof Manifest v1 CBOR: {} bytes generated in {} ms",
        cbor_bytes, manifest_ms
    );

    // 3. P-256 Hardware Signature
    let t_sign = Instant::now();
    let sig_tmp = PathBuf::from("/tmp/jisa_e2e_manifest_sig.der");
    let _sig_der = sign_p256(&privkey_path, &manifest_cbor, &sig_tmp)?;
    let p256_sign_ms = t_sign.elapsed().as_millis() as u64;
    let sig_valid = verify_p256_manifest(&pubkey_path, &manifest_cbor, &sig_tmp);
    assert!(
        sig_valid,
        "P-256 Manifest signature must verify with OpenSSL"
    );
    println!(
        "[4/10] P-256 signature generated in {} ms and verified OK",
        p256_sign_ms
    );

    // 4. HashFold / CycleFold Proving
    let blocks = sha256_padded_blocks(&raw_image);
    let sha256_blocks = blocks.len();
    println!(
        "[5/10] Starting CycleFold HashFold: {} blocks...",
        sha256_blocks
    );

    let circuit = Sha256PaddedCircuit::<Fr>::new(img_len);
    assert_eq!(circuit.num_blocks(), sha256_blocks);

    let pp = <IVCType as IVCPreprocessor>::preprocess(
        (131072, 16384, Arc::new(GriffinParams::new(16, 5, 9))),
        &mut rng,
    )?;
    let (pk, vk) = <IVCType as IVCKeyGenerator>::generate_keys(pp, &circuit)?;
    let initial_state = circuit.dummy_state();

    let mut prover = IVCStatefulProver::<_, IVCType>::new(&pk, &circuit, initial_state.clone())?;

    let t_hf = Instant::now();
    for block in blocks.iter() {
        prover.prove_step(*block, &mut rng)?;
    }
    let hashfold_ms = t_hf.elapsed().as_millis() as u64;
    let rss_after_folding_kib = peak_rss_kb();
    println!(
        "       HashFold completed in {} ms (mean {:.2} ms/step, RSS={:.2} MB)",
        hashfold_ms,
        hashfold_ms as f64 / sha256_blocks as f64,
        rss_after_folding_kib as f64 / 1024.0
    );

    // Verify IVC
    let t_hfv = Instant::now();
    IVCType::verify::<FC>(
        &vk,
        prover.i,
        &prover.initial_state,
        &prover.current_state,
        &prover.current_proof,
    )?;
    let hashfold_verify_ms = t_hfv.elapsed().as_millis() as u64;
    println!("       IVC state verification: {} ms", hashfold_verify_ms);

    // 5. Sigmabus Cross-System State Binding
    let current_state = prover.current_state.clone();
    let binding = <FC as FCircuit>::sigmabus_final_binding(sha256_blocks, &current_state)
        .expect("SHA-256 circuit must publish a Sigmabus binding");
    assert_eq!(binding.h_hi, h_hi_fr, "Sigmabus h_hi binding mismatch");
    assert_eq!(binding.h_lo, h_lo_fr, "Sigmabus h_lo binding mismatch");
    println!("[6/10] Sigmabus cross-system binding: PASS (h_hi and h_lo match exactly)");

    // 6. Sigma Proof & Spartan Merkle Membership
    println!("[7/10] Proving ECDSA Sigma & Spartan Merkle Membership...");
    let pi_sigma_tmp = "/tmp/pi_sigma_jisa_e2e_full.bin";
    let pi_merkle_tmp = "/tmp/pi_merkle_jisa_e2e_full.bin";
    let pk_link_tmp = "/tmp/verified_pk_link_jisa_e2e.json";
    let timing_merkle_tmp = "/tmp/spartan_merkle_prove_timing.json";

    // 6.1 Generate Sigma proof from H_CBOR + existing DER signature (no SK)
    let t_sig_p = Instant::now();
    let sig_tmp_str = sig_tmp.to_str().unwrap();
    sigma_prove(
        &manifest_hash_hex,
        sig_tmp_str,
        &pubkey_path,
        &opening_path,
        pi_sigma_tmp,
    )?;
    let sigma_prove_ms = t_sig_p.elapsed().as_millis() as u64;

    // 6.2 Verify Sigma against H_CBOR and derive cmPK + leaf* (consistency check)
    let t_pklink_vd = Instant::now();
    let (prover_verified_leaf, cm_pk_c0, cm_pk_c1) =
        sigma_verify_and_derive(&manifest_hash_hex, pi_sigma_tmp, pk_link_tmp)?;
    let pklink_verify_derive_ms = t_pklink_vd.elapsed().as_millis() as u64;

    // 6.3 Prove Spartan Merkle membership
    let t_spa_p = Instant::now();
    spartan_merkle_prove(
        &prover_verified_leaf,
        &trusted_root,
        merkle_depth,
        &merkle_path,
        pi_merkle_tmp,
        timing_merkle_tmp,
    )?;
    let spartan_prove_ms = t_spa_p.elapsed().as_millis() as u64;

    let pi_sigma_bytes = fs::read(pi_sigma_tmp)?;
    let pi_merkle_bytes = fs::read(pi_merkle_tmp)?;
    println!(
        "       ECDSA Sigma Proof:    {} bytes (proved in {} ms)",
        pi_sigma_bytes.len(),
        sigma_prove_ms
    );
    println!(
        "       PK-link Verify/Derive: {} ms (derived leaf: {})",
        pklink_verify_derive_ms, prover_verified_leaf
    );
    println!(
        "       Spartan Merkle Proof: {} bytes (proved in {} ms, Root: {})",
        pi_merkle_bytes.len(),
        spartan_prove_ms,
        trusted_root
    );

    // 7. LegoGroth16 Decider
    println!("[8/10] Compressing via LegoGroth16 Decider...");

    // ------------------------------------------------------------
    // Decider one-time preprocessing / key generation
    // ------------------------------------------------------------
    let t_dec_setup = Instant::now();

    let (dpk, dvk) =
        <Decider as IVCProofCompressor>::preprocess_and_generate_keys(&circuit, vk, &mut rng)?;

    let decider_setup_ms = t_dec_setup.elapsed().as_millis() as u64;

    println!("       Decider setup/keygen: {} ms", decider_setup_ms);

    println!("DECIDER KEYGEN COMPLETE");

    let dvk_bytes = Decider::serialize_verifier_key::<FC>(&dvk)?;
    write_file_atomic(Path::new(&decider_vk_out), &dvk_bytes)?;
    let dvk_sha256 = sha256_hex(&dvk_bytes);
    println!(
        "       Decider Verifier Key saved to {} ({} bytes, sha256={})",
        decider_vk_out,
        dvk_bytes.len(),
        dvk_sha256
    );

    let mut committed_profile = profile_template.clone();
    committed_profile.decider_vk_sha256 = dvk_sha256;
    let profile_json_bytes = serde_json::to_vec_pretty(&committed_profile)?;
    write_file_atomic(Path::new(&trusted_profile_out), &profile_json_bytes)?;

    let committed_profile_bytes = fs::read(&trusted_profile_out)?;
    let profile_sha256_before_prove = sha256_hex(&committed_profile_bytes);
    println!("TRUSTED PROFILE WRITTEN {}", trusted_profile_out);
    println!(
        "TRUSTED_SETUP_COMMITTED profile_sha256={}",
        profile_sha256_before_prove
    );

    // ------------------------------------------------------------
    // Decider online proving
    // ------------------------------------------------------------
    println!("PROVING_PHASE_BEGIN");
    let t_dec_prove = Instant::now();

    let compressed = <Decider as IVCProofCompressor>::prove::<FC>(
        &dpk,
        sha256_blocks,
        &initial_state,
        &current_state,
        &prover.current_proof,
        Some(binding),
        &mut rng,
    )?;

    let decider_prove_ms = t_dec_prove.elapsed().as_millis() as u64;

    println!("       Decider online prove: {} ms", decider_prove_ms);

    // Decider prover-side self-check
    let t_dec_selfcheck = Instant::now();
    <Decider as IVCProofCompressor>::verify::<FC>(
        &dvk,
        sha256_blocks,
        &initial_state,
        &current_state,
        &compressed,
        Some(binding),
    )
    .map_err(|e| format!("LegoGroth16 prover-side self-check failed: {:?}", e))?;
    let decider_selfcheck_ms = t_dec_selfcheck.elapsed().as_millis() as u64;
    println!(
        "       Decider prover-side self-check: {} ms",
        decider_selfcheck_ms
    );

    // Serialize complete Decider proof artifact (472 bytes)
    let pi_final_bytes = Decider::serialize_compressed_proof::<FC>(&compressed)?;

    println!(
        "       Complete Decider Proof Artifact: {} bytes ({:.2} KB)",
        pi_final_bytes.len(),
        pi_final_bytes.len() as f64 / 1024.0
    );
    assert_eq!(
        pi_final_bytes.len(),
        472,
        "unexpected complete Decider artifact size"
    );

    // 8. Package Serialization
    println!("[9/10] Serializing complete PicProofPackage (pi_final, pi_sigma, pi_merkle)...");
    let cbor_hex: String = manifest_hash.iter().map(|b| format!("{:02x}", b)).collect();
    let public_instance = PublicInstance {
        num_blocks: sha256_blocks,
        h_hi: h_hi.to_string(),
        h_lo: h_lo.to_string(),
        cbor_manifest_hash: cbor_hex,
        cm_pk_c0,
        cm_pk_c1,
        registration_leaf: prover_verified_leaf.clone(),
        merkle_root: trusted_root.clone(),
    };
    let metadata = ProofMetadata {
        image_bytes: img_len,
        sha256_blocks,
        cbor_bytes,
        merkle_depth: committed_profile.merkle_depth,
        timestamp,
        profile_id: committed_profile.profile_id.clone(),
        rid_hashfold: committed_profile.rid_hashfold.clone(),
        rid_sigma: committed_profile.rid_sigma.clone(),
        rid_merkle: committed_profile.rid_merkle.clone(),
        merkle_profile_fingerprint: committed_profile.merkle_profile_fingerprint.clone(),
    };

    assert_eq!(
        manifest_cbor.len(),
        metadata.cbor_bytes,
        "manifest length / metadata mismatch"
    );

    let package = PicProofPackage {
        version: PACKAGE_VERSION,
        public_instance: public_instance.clone(),
        manifest_cbor: manifest_cbor.clone(),
        pi_final: pi_final_bytes.clone(),
        pi_sigma: pi_sigma_bytes.clone(),
        pi_merkle: pi_merkle_bytes.clone(),
        metadata: metadata.clone(),
    };

    let serialized_proof = bincode::serialize(&package)?;
    if let Some(parent) = Path::new(&proof_out).parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&proof_out, &serialized_proof)?;

    let pi_final_len = package.pi_final.len();
    let pi_sigma_len = package.pi_sigma.len();
    let pi_merkle_len = package.pi_merkle.len();
    let public_instance_bytes = bincode::serialized_size(&package.public_instance)? as usize;
    let metadata_bytes = bincode::serialized_size(&package.metadata)? as usize;
    let proof_package_bytes = serialized_proof.len();

    println!(
        "       Serialized Proof Package: {} bytes ({:.2} KB)",
        proof_package_bytes,
        proof_package_bytes as f64 / 1024.0
    );
    println!("         - pi_final:        {} bytes", pi_final_len);
    println!("         - pi_sigma:        {} bytes", pi_sigma_len);
    println!("         - pi_merkle:       {} bytes", pi_merkle_len);
    println!(
        "         - public_instance: {} bytes",
        public_instance_bytes
    );
    println!("         - metadata:        {} bytes", metadata_bytes);
    println!(
        "         - container overhead: {} bytes",
        proof_package_bytes
            - (pi_final_len
                + pi_sigma_len
                + pi_merkle_len
                + public_instance_bytes
                + metadata_bytes)
    );

    // Unified verifier check using the proof package
    // plus verifier-supplied external trust root.
    println!("[10/10] Unified Verification & Linked PKI Security Controls Audit...");
    let loaded_package: PicProofPackage = bincode::deserialize(&fs::read(&proof_out)?)?;
    if loaded_package.version != PACKAGE_VERSION {
        return Err(format!(
            "unsupported PicProof package version: {}",
            loaded_package.version
        )
        .into());
    }
    assert_eq!(
        loaded_package.metadata.merkle_depth, merkle_depth,
        "package Merkle depth does not match verifier profile"
    );
    assert_eq!(loaded_package.public_instance.num_blocks, sha256_blocks);
    assert_eq!(loaded_package.public_instance.h_hi, h_hi.to_string());
    assert_eq!(loaded_package.public_instance.h_lo, h_lo.to_string());

    // 1. Trusted root is external.
    let verifier_trusted_root = trusted_root.clone();

    // 2. Package is not a trust source.
    assert_eq!(
        loaded_package.public_instance.merkle_root, verifier_trusted_root,
        "package root does not match verifier trusted root"
    );

    // True package consumer verification of pi_final
    let loaded_compressed = Decider::deserialize_compressed_proof::<FC>(&loaded_package.pi_final)?;

    let t_dec_pkg_v = Instant::now();
    <Decider as IVCProofCompressor>::verify::<FC>(
        &dvk,
        loaded_package.public_instance.num_blocks,
        &initial_state,
        &current_state,
        &loaded_compressed,
        Some(binding),
    )
    .map_err(|e| format!("package Decider verification failed: {:?}", e))?;
    let decider_verify_ms = t_dec_pkg_v.elapsed().as_millis() as u64;
    let decider_verify = true;
    println!(
        "       Package pi_final (Decider) Verified OK in {} ms",
        decider_verify_ms
    );

    // Extract pi_sigma & pi_merkle from loaded package to verify
    let verify_sigma_tmp = "/tmp/verify_loaded_pi_sigma.bin";
    let verify_merkle_tmp = "/tmp/verify_loaded_pi_merkle.bin";
    let verify_pklink_tmp = "/tmp/verify_loaded_pklink.json";
    fs::write(verify_sigma_tmp, &loaded_package.pi_sigma)?;
    fs::write(verify_merkle_tmp, &loaded_package.pi_merkle)?;

    let t_ver = Instant::now();

    // 3. Bind Decider-proven H_img to the camera-signed manifest.
    let proved_image_digest = public_digest_bytes(
        &loaded_package.public_instance.h_hi,
        &loaded_package.public_instance.h_lo,
    )
    .map_err(|e| format!("Package public instance digest is malformed: {}", e))?;

    let loaded_manifest = parse_manifest_v1(&loaded_package.manifest_cbor)
        .map_err(|e| format!("Manifest v1 parse failed: {}", e))?;

    if loaded_manifest.digest != proved_image_digest {
        return Err("Manifest digest does not match Decider-proven image digest".into());
    }
    if loaded_manifest.image_bytes != loaded_package.metadata.image_bytes as u64 {
        return Err("Manifest image_bytes / package metadata mismatch".into());
    }
    if loaded_manifest.timestamp != loaded_package.metadata.timestamp {
        return Err("Manifest timestamp / package metadata mismatch".into());
    }
    if loaded_package.manifest_cbor.len() != loaded_package.metadata.cbor_bytes {
        return Err("Manifest CBOR length / metadata mismatch".into());
    }
    println!("       H_img == Manifest.digest:  PASS");

    // 4. Verify Sigma against verifier-recomputed H_CBOR and derive cmPK + leaf.
    let t_sig_v = Instant::now();
    // Package v3: re-derive H_CBOR from the exact serialized manifest bytes
    // instead of trusting the redundant `cbor_manifest_hash` audit field.
    let loaded_manifest_hash: [u8; 32] = Sha256::digest(&loaded_package.manifest_cbor).into();
    let loaded_manifest_hash_hex: String = to_hex(&loaded_manifest_hash);
    if !loaded_package
        .public_instance
        .cbor_manifest_hash
        .eq_ignore_ascii_case(&loaded_manifest_hash_hex)
    {
        return Err("Stored cbor_manifest_hash does not match SHA-256(manifest_cbor)".into());
    }
    let (verified_leaf, verified_c0, verified_c1) = sigma_verify_and_derive(
        &loaded_manifest_hash_hex,
        verify_sigma_tmp,
        verify_pklink_tmp,
    )?;
    let sigma_verify_ms = t_sig_v.elapsed().as_millis() as u64;

    // 4. Ensure package's informational leaf agrees.
    assert_eq!(
        loaded_package.public_instance.registration_leaf, verified_leaf,
        "package registration_leaf does not match verified derived leaf"
    );
    assert_eq!(
        loaded_package.public_instance.cm_pk_c0, verified_c0,
        "package cm_pk_c0 does not match verified c0"
    );
    assert_eq!(
        loaded_package.public_instance.cm_pk_c1, verified_c1,
        "package cm_pk_c1 does not match verified c1"
    );

    // 5. Verify Spartan against EXTERNAL trusted root.
    let t_spa_v = Instant::now();
    spartan_merkle_verify(
        &verified_leaf,
        &verifier_trusted_root,
        merkle_depth,
        verify_merkle_tmp,
    )?;
    let merkle_verify_ms = t_spa_v.elapsed().as_millis() as u64;

    let linked_pki_verify_ms = sigma_verify_ms + merkle_verify_ms;
    println!(
        "       Honest Package Verified OK in {} ms (Sigma verify: {} ms, Spartan verify: {} ms)",
        linked_pki_verify_ms, sigma_verify_ms, merkle_verify_ms
    );

    // 6. Security Negative Control: Tampered pi_final (byte 200 flip)
    println!("       [NEG CONTROL 1/1] Testing Tampered pi_final (byte 200 flip)...");
    let mut tampered_bytes = loaded_package.pi_final.clone();
    assert!(
        tampered_bytes.len() > 200,
        "pi_final too short for byte 200 tampering"
    );
    tampered_bytes[200] ^= 0x01;

    let tampered_dec_res: Result<(), Box<dyn Error>> = (|| {
        let tampered_compressed = Decider::deserialize_compressed_proof::<FC>(&tampered_bytes)?;
        <Decider as IVCProofCompressor>::verify::<FC>(
            &dvk,
            loaded_package.public_instance.num_blocks,
            &initial_state,
            &current_state,
            &tampered_compressed,
            Some(binding),
        )?;
        Ok(())
    })();
    assert!(
        tampered_dec_res.is_err(),
        "SECURITY AUDIT FAILED: Tampered pi_final was ACCEPTED!"
    );
    println!(
        "       [NEG CONTROL 1/3] Tampered pi_final: PASS (REJECTED as expected: {:?})",
        tampered_dec_res.unwrap_err()
    );

    // 7. NEG CONTROL 2/3 (T9): tamper the manifest's own digest byte.
    //    pi_final is untouched, so the Decider still proves the original H_img.
    //    This MUST be rejected at the H_img == Manifest.digest binding.
    println!(
        "       [NEG CONTROL 2/3] T9: Tampered manifest digest[0] (Decider <-> Manifest binding)..."
    );
    let mut t9_manifest = loaded_package.manifest_cbor.clone();
    // Locate the PicProof Manifest v1 "digest" key + bytes(32) header, then flip one
    // byte inside the digest payload itself.
    let digest_marker: &[u8] = b"\x66digest\x58\x20";
    let digest_pos = t9_manifest
        .windows(digest_marker.len())
        .position(|w| w == digest_marker)
        .expect("PicProof Manifest v1 digest marker not found");
    let digest_off = digest_pos + digest_marker.len();
    assert!(
        t9_manifest.len() >= digest_off + 32,
        "manifest too short for digest tampering"
    );
    t9_manifest[digest_off] ^= 0x01;

    let t9_res: Result<(), Box<dyn Error>> = (|| {
        let m = parse_manifest_v1(&t9_manifest)?;
        if m.digest != proved_image_digest {
            return Err("Manifest digest does not match Decider-proven image digest".into());
        }
        Ok(())
    })();
    assert!(
        t9_res.is_err(),
        "SECURITY AUDIT FAILED: Tampered manifest digest was ACCEPTED by T9 binding!"
    );
    println!(
        "       [NEG CONTROL 2/3] T9 manifest digest: PASS (REJECTED: {})",
        t9_res.unwrap_err()
    );

    // 8. NEG CONTROL 3/3 (T10): tamper the manifest's salt byte only.
    //    Manifest.digest still equals the Decider-proven H_img, so T9 passes;
    //    but H_CBOR changes, so the untouched pi_sigma MUST fail.
    println!(
        "       [NEG CONTROL 3/3] T10: Tampered manifest salt[0] (Manifest <-> Sigma binding)..."
    );
    let mut t10_manifest = loaded_package.manifest_cbor.clone();
    // Locate the PicProof Manifest v1 "salt" key + bytes(16) header, then flip one byte
    // inside the salt payload only (digest stays untouched).
    let salt_marker: &[u8] = b"\x64salt\x50";
    let salt_pos = t10_manifest
        .windows(salt_marker.len())
        .position(|w| w == salt_marker)
        .expect("PicProof Manifest v1 salt marker not found");
    let salt_off = salt_pos + salt_marker.len();
    assert!(
        t10_manifest.len() >= salt_off + 16,
        "manifest too short for salt tampering"
    );
    t10_manifest[salt_off] ^= 0x01;

    let t10_parse = parse_manifest_v1(&t10_manifest);
    assert!(
        t10_parse.is_ok(),
        "T10 setup error: tampered manifest must still parse, got {:?}",
        t10_parse.err()
    );
    let t10_manifest_parsed = t10_parse.unwrap();
    assert_eq!(
        t10_manifest_parsed.digest, proved_image_digest,
        "T10 setup error: digest must remain equal to Decider-proven H_img"
    );

    let t10_hash: [u8; 32] = Sha256::digest(&t10_manifest).into();
    let t10_hash_hex: String = to_hex(&t10_hash);
    assert_ne!(
        t10_hash_hex, manifest_hash_hex,
        "T10 setup error: tampered manifest must change H_CBOR"
    );

    fs::write("/tmp/t10_tampered_pi_sigma.bin", &loaded_package.pi_sigma)?;
    let t10_res = sigma_verify_and_derive(
        &t10_hash_hex,
        "/tmp/t10_tampered_pi_sigma.bin",
        "/tmp/t10_tampered_pklink.json",
    );
    assert!(
        t10_res.is_err(),
        "SECURITY AUDIT FAILED: pi_sigma accepted a tampered H_CBOR!"
    );
    println!(
        "       [NEG CONTROL 3/3] T10 manifest salt: PASS (REJECTED: pi_sigma invalid for H_CBOR')"
    );

    let online_cryptographic_prove_ms =
        hashfold_ms + sigma_prove_ms + spartan_prove_ms + decider_prove_ms;

    let total_online_prove_ms = manifest_ms + p256_sign_ms + online_cryptographic_prove_ms;

    let total_with_decider_setup_ms = total_online_prove_ms + decider_setup_ms;

    println!(
        "       Online cryptographic prove: {} ms",
        online_cryptographic_prove_ms
    );

    println!(
        "       Total online prove incl. manifest/signature: {} ms",
        total_online_prove_ms
    );

    println!("       Decider setup/keygen: {} ms", decider_setup_ms);

    println!(
        "       Online prove + Decider setup: {} ms",
        total_with_decider_setup_ms
    );

    let linked_aux_prove_ms = sigma_prove_ms + spartan_prove_ms;
    let dorian_prove_ms = linked_aux_prove_ms; // for backward compatibility in JsonAuditResult
    let total_prove_ms = total_online_prove_ms;

    let pipeline_selfcheck_ms = hashfold_verify_ms + decider_selfcheck_ms + pklink_verify_derive_ms;

    let committed_profile_bytes_after_prove = fs::read(&trusted_profile_out)?;
    let profile_sha256_after_prove = sha256_hex(&committed_profile_bytes_after_prove);
    if profile_sha256_after_prove != profile_sha256_before_prove {
        return Err(format!(
            "TRUST ORDER VIOLATION: trusted profile changed during proving ({} -> {})",
            profile_sha256_before_prove, profile_sha256_after_prove
        )
        .into());
    }
    println!(
        "TRUSTED_PROFILE_UNCHANGED profile_sha256={}",
        profile_sha256_after_prove
    );

    let package_verify_ms = decider_verify_ms + sigma_verify_ms + merkle_verify_ms;
    let total_verify_ms = package_verify_ms;

    println!(
        "       Pipeline self-check overhead: {} ms",
        pipeline_selfcheck_ms
    );

    println!(
        "       Final package cryptographic verify: {} ms",
        package_verify_ms
    );

    let peak_rss_kib = peak_rss_kb();

    let json_result = JsonAuditResult {
        image_bytes: img_len,
        sha256_blocks,
        cbor_bytes,
        manifest_ms,
        p256_sign_ms,
        hashfold_ms,
        dorian_prove_ms,
        decider_setup_ms,
        decider_prove_ms,
        online_cryptographic_prove_ms,
        total_online_prove_ms,
        total_prove_ms,
        hashfold_verify_ms,
        sigma_verify_ms,
        merkle_verify_ms,
        decider_verify_ms,
        pipeline_selfcheck_ms,
        package_verify_ms,
        total_verify_ms,
        pi_final_bytes: pi_final_len,
        pi_sigma_bytes: pi_sigma_len,
        pi_merkle_bytes: pi_merkle_len,
        public_instance_bytes,
        metadata_bytes,
        container_overhead_bytes: proof_package_bytes
            - (pi_final_len
                + pi_sigma_len
                + pi_merkle_len
                + public_instance_bytes
                + metadata_bytes),
        proof_package_bytes,
        rss_after_folding_kib,
        peak_rss_kib,
        decider_verify: true,
        sigma_verify: true,
        merkle_verify: true,
        pk_link_verify: true,
        profile_sha256_before_prove,
        profile_sha256_after_prove,
        trusted_profile_committed_before_prove: true,
        trusted_profile_unchanged: true,
        accept: true,
        return_code: 0,
    };

    if let Some(parent) = Path::new(&output_json).parent() {
        fs::create_dir_all(parent)?;
    }
    let json_str = serde_json::to_string_pretty(&json_result)?;
    fs::write(&output_json, &json_str)?;

    println!("\n============================================================");
    println!(" [UNIFIED E2E SUCCESS] ALL ASSERTIONS AND AUDITS PASSED");
    println!(
        " Full Proof Size: {} bytes ({:.2} KB)",
        proof_package_bytes,
        proof_package_bytes as f64 / 1024.0
    );
    println!(" Output JSON:     {}", output_json);
    println!(" Proof Package:   {}", proof_out);
    println!(" Return Code:     0");
    println!("============================================================\n");

    Ok(())
}
