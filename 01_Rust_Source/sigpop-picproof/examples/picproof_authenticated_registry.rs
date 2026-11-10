use bincode::Options;
// Authenticated PicProof bundle: Sigma cmPK -> H_reg leaf -> CA-signed root -> Spartan.
//
// The verifier receives no Merkle path. It verifies the CA trust pin and signed
// root, verifies Sigma against an externally supplied manifest digest, derives
// cmPK and H_reg itself, and verifies Spartan against that derived leaf/root.

#[path = "spartan_merkle_linked.rs"]
mod spartan_merkle_linked;

use circ::ecdsa::ca_registry::{
    verify_signed_registry_root, DeviceRegistryCredential, SignedRegistryRoot,
    REGISTRY_MERKLE_HASH_ALGORITHM,
    REGISTRY_SIGNATURE_ALGORITHM,
};
use circ::ecdsa::picproof_k::PROFILE as COMMITMENT_PROFILE;
use circ::ecdsa::pure_sigma::{ECDSASigmaPublicPrior, ECDSASigmaSetupParamsPrior};
use circ::ecdsa::registry_binding::{derive_sigma_cm_pk_leaf, verify_sigma_cm_pk_credential};
use circ::target::r1cs::proof::deserialize_from_file;
use libdoriant256::{InputsAssignment, NIZK, NIZKGens};
use merlin::Transcript;
use p256::ProjectivePoint;
use rug::Integer;
use serde::{Deserialize, Serialize};
use std::fs;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::time::Instant;

const BUNDLE_MAGIC: &str = "PICPROOF-AUTHENTICATED-REGISTRY-BUNDLE";
const BUNDLE_VERSION: u32 = 2;
const BUNDLE_PROFILE: &str = "PicProof-CA-Sigma-Spartan-v2";
const LEAF_HASH_PROFILE: &str = "PicProof-PKI-CMPK-v1";
const LEAF_HASH_ALGORITHM: &str = "SHA-256-rejection-sampling-P256Fp";
const MAX_AUTHENTICATED_PACKAGE_BYTES: usize = 256 * 1024 * 1024;

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

fn get_arg(args: &[String], flag: &str) -> Option<String> {
    args.iter().position(|arg| arg == flag)
        .and_then(|index| args.get(index + 1).cloned())
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &str, label: &str) -> Result<T, String> {
    let bytes = fs::read(path).map_err(|e| format!("Cannot read {label} '{path}': {e}"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("Cannot parse {label} '{path}': {e}"))
}

fn read_trust_pin(path: &str) -> Result<String, String> {
    let raw = fs::read_to_string(path)
        .map_err(|e| format!("Cannot read out-of-band CA fingerprint pin '{path}': {e}"))?;
    let pin = raw.trim().to_ascii_lowercase();
    if pin.len() != 64 || !pin.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("Trusted CA fingerprint pin must be exactly 32-byte hexadecimal".into());
    }
    Ok(pin)
}

fn parse_digest_hex(value: &str) -> Result<(String, Integer), String> {
    let clean = value.trim().trim_start_matches("0x").trim_start_matches("0X");
    if clean.len() != 64 || !clean.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("--digest-hex must contain exactly 64 hexadecimal characters".into());
    }
    let bytes = hex::decode(clean).map_err(|e| format!("Invalid digest hex: {e}"))?;
    if bytes.len() != 32 {
        return Err("Manifest digest must be exactly 32 bytes".into());
    }
    let digest = Integer::from_digits(&bytes, rug::integer::Order::MsfBe);
    Ok((clean.to_ascii_lowercase(), digest))
}

fn verify_sigma_or_reject(
    sigma: &ECDSASigmaPublicPrior,
    digest: &Integer,
) -> Result<(), String> {
    let result = catch_unwind(AssertUnwindSafe(|| {
        sigma.verify(digest, ECDSASigmaSetupParamsPrior::new());
    }));
    result.map_err(|_| "Sigma proof verification rejected (invalid proof or digest)".to_string())
}

fn load_verified_poseidon_params() -> Result<spartan_merkle_linked::P256PoseidonParams, String> {
    let params = spartan_merkle_linked::load_p256_poseidon_params(None)?;
    if params.name != spartan_merkle_linked::PROFILE {
        return Err(format!("Unexpected Poseidon profile '{}'; expected '{}'", params.name, spartan_merkle_linked::PROFILE));
    }
    let expected_modulus = Integer::from_str_radix(
        circ::ecdsa::pk_link::P256_BASE_FIELD_DEC, 10,
    ).map_err(|e| format!("Cannot parse P-256 base-field modulus: {e}"))?;
    if params.modulus != expected_modulus || params.t != 3 || params.input_rate != 2
        || params.alpha != 7 || params.full_rounds != 8 || params.partial_rounds != 46
        || params.round_constants.len() != 162 || params.mds.len() != 3
        || params.mds.iter().any(|row| row.len() != 3) {
        return Err("Poseidon parameters do not match the pinned P-256 t=3 circuit shape".into());
    }
    Ok(params)
}

fn verify_root_and_profile(
    signed_root: &SignedRegistryRoot,
    trusted_fingerprint: &str,
    params: &spartan_merkle_linked::P256PoseidonParams,
) -> Result<(), String> {
    verify_signed_registry_root(signed_root, trusted_fingerprint)?;
    let statement = &signed_root.statement;
    if statement.signature_algorithm != REGISTRY_SIGNATURE_ALGORITHM {
        return Err("Registry root is not signed with ES256".into());
    }
    if statement.commitment_profile_id != COMMITMENT_PROFILE {
        return Err("CA root commitment profile does not match the Sigma commitment profile".into());
    }
    if statement.leaf_hash_profile_id != LEAF_HASH_PROFILE
        || statement.leaf_hash_algorithm != LEAF_HASH_ALGORITHM {
        return Err("CA root leaf-hash profile does not match H_reg(cmPK)".into());
    }
    if statement.merkle_hash_algorithm != REGISTRY_MERKLE_HASH_ALGORITHM
        || statement.merkle_profile_id != params.name
        || !statement.merkle_parameters_sha256.eq_ignore_ascii_case(&params.parameter_sha256) {
        return Err("CA root Poseidon profile/parameter fingerprint does not match the verifier's authenticated parameters".into());
    }
    if statement.depth as usize > spartan_merkle_linked::MAX_MERKLE_DEPTH {
        return Err("CA root depth exceeds Spartan's supported maximum".into());
    }
    Ok(())
}

fn validate_spartan_package_metadata(
    package: &spartan_merkle_linked::SpartanMerklePackage,
    expected_depth: usize,
) -> Result<(), String> {
    if package.version != spartan_merkle_linked::VERSION {
        return Err(format!("Unsupported inner Spartan package version '{}'", package.version));
    }
    if package.profile != spartan_merkle_linked::PROFILE {
        return Err(format!("Unsupported inner Spartan profile '{}'", package.profile));
    }
    if package.depth != expected_depth {
        return Err("Inner Spartan proof depth does not match the CA-signed registry depth".into());
    }
    Ok(())
}

fn verify_spartan(
    package: &spartan_merkle_linked::SpartanMerklePackage,
    leaf: &Integer,
    root: &Integer,
    params: &spartan_merkle_linked::P256PoseidonParams,
) -> Result<(), String> {
    let depth = package.depth;
    let (instance, generators, _num_constraints, _num_vars, _num_inputs) =
        spartan_merkle_linked::synthesize_merkle_instance_with_params(depth, params);
    let public_inputs = vec![
        spartan_merkle_linked::integer_to_bytes32(leaf),
        spartan_merkle_linked::integer_to_bytes32(root),
    ];
    let inputs = InputsAssignment::new(&public_inputs)
        .map_err(|e| format!("Cannot construct Spartan public inputs: {e:?}"))?;
    let mut transcript = Transcript::new(spartan_merkle_linked::DOMAIN_TAG);
    package.proof.verify(&instance, &inputs, &mut transcript, &generators)
        .map_err(|e| format!("Spartan membership proof rejected: {e:?}"))
}

fn verify_authenticated_bundle(
    package: &AuthenticatedPicProofPackage,
    expected_digest_hex: &str,
    trusted_fingerprint: &str,
    params: &spartan_merkle_linked::P256PoseidonParams,
) -> Result<(), String> {
    if package.magic != BUNDLE_MAGIC || package.version != BUNDLE_VERSION || package.profile != BUNDLE_PROFILE {
        return Err("Unsupported authenticated PicProof bundle format/version/profile".into());
    }
    let (expected_digest, digest_integer) = parse_digest_hex(expected_digest_hex)?;
    if package.digest_sha256_hex != expected_digest {
        return Err("Externally supplied manifest digest does not match the digest bound into this package".into());
    }
    verify_root_and_profile(&package.signed_registry_root, trusted_fingerprint, params)?;
    let statement = &package.signed_registry_root.statement;
    if package.registry_id != statement.registry_id {
        return Err("Bundle registry ID does not match the CA-signed registry ID".into());
    }
    if package.depth != statement.depth as usize {
        return Err("Bundle depth does not match the CA-signed registry depth".into());
    }
    validate_spartan_package_metadata(&package.spartan_proof, package.depth)?;

    verify_sigma_or_reject(&package.sigma_proof, &digest_integer)?;
    let cm_pk: [ProjectivePoint; 2] = [
        package.sigma_proof.cm_pk[0].0,
        package.sigma_proof.cm_pk[1].0,
    ];
    let (derived_cm_pk_hex, leaf) = derive_sigma_cm_pk_leaf(&cm_pk)?;
    if !derived_cm_pk_hex.eq_ignore_ascii_case(&package.cm_pk_encoded_hex) {
        return Err("Serialized cmPK does not match the cmPK in the verified Sigma statement".into());
    }
    if leaf.to_string() != package.leaf_decimal {
        return Err("Bundle leaf is not H_reg(cmPK) derived from the verified Sigma statement".into());
    }
    let root = Integer::from_str_radix(&statement.merkle_root_decimal, 10)
        .map_err(|e| format!("Invalid CA-signed Merkle root: {e}"))?;
    verify_spartan(&package.spartan_proof, &leaf, &root, params)?;
    Ok(())
}

fn run_prove(args: &[String]) -> Result<(), String> {
    let sigma_path = get_arg(args, "--sigma-proof").ok_or("Missing --sigma-proof")?;
    let digest_arg = get_arg(args, "--digest-hex").ok_or("Missing --digest-hex")?;
    let credential_path = get_arg(args, "--credential").ok_or("Missing --credential")?;
    let root_path = get_arg(args, "--signed-root").ok_or("Missing --signed-root")?;
    let pin_path = get_arg(args, "--trusted-ca-fingerprint").ok_or("Missing --trusted-ca-fingerprint")?;
    let proof_out = get_arg(args, "--proof-out").ok_or("Missing --proof-out")?;

    let (digest_hex, digest_integer) = parse_digest_hex(&digest_arg)?;
    let trusted_fingerprint = read_trust_pin(&pin_path)?;
    let credential: DeviceRegistryCredential = read_json(&credential_path, "device registry credential")?;
    let signed_root: SignedRegistryRoot = read_json(&root_path, "signed registry root")?;
    let params = load_verified_poseidon_params()?;
    verify_root_and_profile(&signed_root, &trusted_fingerprint, &params)?;

    let sigma_proof: ECDSASigmaPublicPrior = catch_unwind(AssertUnwindSafe(|| {
        deserialize_from_file(&sigma_path)
    }))
        .map_err(|_| "Sigma proof deserialization panicked on malformed point encoding".to_string())?
        .map_err(|e| format!("Cannot deserialize Sigma proof with the project's canonical proof reader: {e:?}"))?;
    verify_sigma_or_reject(&sigma_proof, &digest_integer)?;

    let statement = &signed_root.statement;
    if credential.registry_id != statement.registry_id {
        return Err("Device credential belongs to a different registry".into());
    }
    if credential.depth != statement.depth {
        return Err("Device credential depth does not match CA-signed root depth".into());
    }
    if credential.path.siblings.len() != credential.depth as usize
        || credential.path.directions.len() != credential.depth as usize {
        return Err("Device credential Merkle path length is invalid".into());
    }
    let cm_pk: [ProjectivePoint; 2] = [sigma_proof.cm_pk[0].0, sigma_proof.cm_pk[1].0];
    let (cm_pk_encoded_hex, leaf) = verify_sigma_cm_pk_credential(&cm_pk, &credential)?;
    let root = Integer::from_str_radix(&statement.merkle_root_decimal, 10)
        .map_err(|e| format!("Invalid CA-signed Merkle root: {e}"))?;

    let mut siblings = Vec::with_capacity(credential.path.siblings.len());
    for (index, sibling) in credential.path.siblings.iter().enumerate() {
        let value = Integer::from_str_radix(sibling, 10)
            .map_err(|e| format!("Invalid Merkle sibling at level {index}: {e}"))?;
        if value.to_string() != sibling.as_str() {
            return Err(format!("Merkle sibling at level {index} is not canonical unsigned decimal"));
        }
        if value < 0 || value >= params.modulus {
            return Err(format!("Merkle sibling at level {index} is outside the P-256 base field"));
        }
        siblings.push(value);
    }
    println!("[PICPROOF V2] Synthesizing Spartan circuit from CA-issued private path...");
    let t_synth = Instant::now();
    let (instance, vars, public_inputs, num_constraints, num_vars, num_inputs) =
        spartan_merkle_linked::synthesize_merkle_circuit_with_params(
            credential.depth as usize,
            &leaf,
            &siblings,
            &credential.path.directions,
            &root,
            &params,
        );
    if !instance.is_sat(&vars, &public_inputs)
        .map_err(|e| format!("Spartan R1CS satisfiability check failed: {e:?}"))? {
        return Err("CA-issued credential path is not a valid member path for the signed root".into());
    }
    let synth_ms = t_synth.elapsed().as_secs_f64() * 1000.0;

    let generators = NIZKGens::new(num_constraints, num_vars, num_inputs);
    let mut transcript = Transcript::new(spartan_merkle_linked::DOMAIN_TAG);
    let t_prove = Instant::now();
    let spartan_proof = NIZK::prove(&instance, vars, &public_inputs, &generators, &mut transcript);
    let prove_ms = t_prove.elapsed().as_secs_f64() * 1000.0;
    let spartan_package = spartan_merkle_linked::SpartanMerklePackage {
        proof: spartan_proof,
        depth: credential.depth as usize,
        version: spartan_merkle_linked::VERSION.to_string(),
        profile: spartan_merkle_linked::PROFILE.to_string(),
    };

    let package = AuthenticatedPicProofPackage {
        magic: BUNDLE_MAGIC.to_string(),
        version: BUNDLE_VERSION,
        profile: BUNDLE_PROFILE.to_string(),
        registry_id: statement.registry_id.clone(),
        depth: credential.depth as usize,
        digest_sha256_hex: digest_hex,
        cm_pk_encoded_hex,
        leaf_decimal: leaf.to_string(),
        signed_registry_root: signed_root,
        sigma_proof,
        spartan_proof: spartan_package,
    };
    verify_authenticated_bundle(&package, &digest_arg, &trusted_fingerprint, &params)?;

    let serialized = bincode::serialize(&package)
        .map_err(|e| format!("Cannot serialize authenticated PicProof package: {e}"))?;
    if let Some(parent) = Path::new(&proof_out).parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| format!("Cannot create proof output directory: {e}"))?;
        }
    }
    fs::write(&proof_out, &serialized).map_err(|e| format!("Cannot write proof package '{proof_out}': {e}"))?;
    println!("[PICPROOF V2] Authenticated package saved: {proof_out}");
    println!("[PICPROOF V2] registry_id={} depth={} leaf={} root={}", package.registry_id, package.depth, package.leaf_decimal, package.signed_registry_root.statement.merkle_root_decimal);
    println!("[PICPROOF V2] Spartan synthesis={synth_ms:.3} ms, prove={prove_ms:.3} ms, package={} bytes", serialized.len());
    Ok(())
}

fn run_verify(args: &[String]) -> Result<(), String> {
    if get_arg(args, "--path-file").is_some() || get_arg(args, "--credential").is_some() {
        return Err("CRITICAL SECURITY ERROR: verifier must not accept a private Merkle path or device credential".into());
    }
    let proof_in = get_arg(args, "--proof-in").ok_or("Missing --proof-in")?;
    let digest_arg = get_arg(args, "--digest-hex").ok_or("Missing --digest-hex")?;
    let pin_path = get_arg(args, "--trusted-ca-fingerprint").ok_or("Missing --trusted-ca-fingerprint")?;
    let trusted_fingerprint = read_trust_pin(&pin_path)?;
    let params = load_verified_poseidon_params()?;
    let bytes = fs::read(&proof_in).map_err(|e| format!("Cannot read authenticated proof '{proof_in}': {e}"))?;
    if bytes.len() > MAX_AUTHENTICATED_PACKAGE_BYTES {
        return Err(format!("Authenticated proof package exceeds the {} MiB safety limit", MAX_AUTHENTICATED_PACKAGE_BYTES / (1024 * 1024)));
    }
    let package: AuthenticatedPicProofPackage = catch_unwind(AssertUnwindSafe(|| {
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(MAX_AUTHENTICATED_PACKAGE_BYTES as u64)
            .reject_trailing_bytes()
            .deserialize::<AuthenticatedPicProofPackage>(&bytes)
    }))
    .map_err(|_| "Authenticated package deserialization panicked; malformed EC point encoding rejected".to_string())?
    .map_err(|e| format!("Cannot deserialize authenticated PicProof package: {e}"))?;
    let t_verify = Instant::now();
    verify_authenticated_bundle(&package, &digest_arg, &trusted_fingerprint, &params)?;
    println!("[PICPROOF V2 VERIFIER] ACCEPT");
    println!("[PICPROOF V2 VERIFIER] CA signature, CA pin, root freshness, Sigma, cmPK/leaf binding and Spartan membership all verified.");
    println!("[PICPROOF V2 VERIFIER] registry_id={} depth={} leaf={} root={}", package.registry_id, package.depth, package.leaf_decimal, package.signed_registry_root.statement.merkle_root_decimal);
    println!("[PICPROOF V2 VERIFIER] elapsed={:.3} ms, package={} bytes", t_verify.elapsed().as_secs_f64() * 1000.0, bytes.len());
    Ok(())
}

fn print_usage() {
    eprintln!(r#"picproof_authenticated_registry - CA-authenticated Sigma + Spartan proof bundle

USAGE:
  cargo run --release --example picproof_authenticated_registry -- prove \
    --sigma-proof pi_sigma --digest-hex <64-hex> --credential private_credential_0.json \
    --signed-root signed_registry_root.json --trusted-ca-fingerprint trusted_ca_fingerprint.txt \
    --proof-out picproof_v2.bundle

  cargo run --release --example picproof_authenticated_registry -- verify \
    --proof-in picproof_v2.bundle --digest-hex <64-hex> \
    --trusted-ca-fingerprint trusted_ca_fingerprint.txt

The verifier never receives the private Merkle path or device credential.
The manifest digest and CA fingerprint must be supplied independently.
"#);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 || args.iter().any(|arg| arg == "-h" || arg == "--help") {
        print_usage();
        return;
    }
    let result = match args[1].as_str() {
        "prove" => run_prove(&args[2..]),
        "verify" => run_verify(&args[2..]),
        _ => Err(format!("Unknown subcommand '{}'; expected prove or verify", args[1])),
    };
    if let Err(error) = result {
        eprintln!("[PICPROOF V2] REJECT/ERROR: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use circ::ecdsa::ca_registry::{CaAuthority, RegistryRootStatement, REGISTRY_STATEMENT_VERSION, REGISTRY_DEFAULT_VALIDITY_SECS};

    #[test]
    fn signed_root_profile_rejects_wrong_poseidon_parameter_fingerprint() {
        let ca = CaAuthority::generate("bundle-test-ca");
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let statement = RegistryRootStatement {
            version: REGISTRY_STATEMENT_VERSION,
            registry_id: "bundle-test-registry".into(),
            merkle_root_decimal: "1".into(),
            depth: 1,
            signature_algorithm: REGISTRY_SIGNATURE_ALGORITHM.into(),
            issued_at_unix: now,
            expires_at_unix: now + REGISTRY_DEFAULT_VALIDITY_SECS,
            commitment_profile_id: COMMITMENT_PROFILE.into(),
            leaf_hash_profile_id: LEAF_HASH_PROFILE.into(),
            leaf_hash_algorithm: LEAF_HASH_ALGORITHM.into(),
            merkle_profile_id: spartan_merkle_linked::PROFILE.into(),
            merkle_hash_algorithm: REGISTRY_MERKLE_HASH_ALGORITHM.into(),
            merkle_parameters_sha256: "00".repeat(32),
        };
        let signed = ca.sign_registry_root(statement).unwrap();
        let mut params = load_verified_poseidon_params().unwrap();
        params.parameter_sha256 = "11".repeat(32);
        assert!(verify_root_and_profile(&signed, &signed.certificate.fingerprint_sha256, &params).is_err());
    }
}
