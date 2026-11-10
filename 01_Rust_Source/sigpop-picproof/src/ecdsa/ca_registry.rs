//! CA-side device registration and authenticated Merkle-root support.
//!
//! The CA learns the device public key and commitment opening during enrollment.
//! The verifier learns only the CA trust-anchor certificate, the public cmPK,
//! and the CA-authenticated registry root. The CA certificate fingerprint MUST
//! be pinned in verifier configuration; an untrusted package-supplied key is
//! never accepted as a trust anchor.

use p256::ecdsa::{signature::{Signer, Verifier}, Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey};
use p256::elliptic_curve::ff::{Field, PrimeField};
use p256::elliptic_curve::group::Group;
use p256::elliptic_curve::sec1::FromEncodedPoint;
use p256::{AffinePoint, EncodedPoint, FieldBytes, ProjectivePoint, Scalar};
use rug::Integer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::convert::TryInto;
use std::collections::{BTreeMap, BTreeSet};

use super::picproof_k::picproof_commitment_generator_k;
use super::pk_link::{h_reg, P256_BASE_FIELD_DEC};

pub const CA_CERT_VERSION: u32 = 1;
pub const REGISTRY_STATEMENT_VERSION: u32 = 2;
pub const CA_ROOT_DOMAIN: &[u8] = b"PICPROOF-CA-REGISTRY-ROOT-v2";
pub const CA_CERT_DOMAIN: &[u8] = b"PICPROOF-CA-CERT-v1";
pub const MAX_REGISTRY_DEPTH: usize = 32;
pub const REGISTRY_SIGNATURE_ALGORITHM: &str = "ES256";
pub const REGISTRY_MERKLE_HASH_ALGORITHM: &str = "Poseidon";
pub const REGISTRY_DEFAULT_VALIDITY_SECS: u64 = 365 * 24 * 60 * 60;
pub const REGISTRY_CLOCK_SKEW_SECS: u64 = 300;

/// Compact prototype CA certificate. Its fingerprint is pinned out-of-band.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CaCertificate {
    pub version: u32,
    pub ca_id: String,
    /// Compressed SEC1 P-256 CA public key, lowercase hex encoding (33 bytes).
    pub public_key_hex: String,
    pub fingerprint_sha256: String,
}

/// Registry-root statement signed by the CA.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RegistryRootStatement {
    pub version: u32,
    pub registry_id: String,
    /// Canonical unsigned decimal representation of a P-256 base-field element.
    pub merkle_root_decimal: String,
    pub depth: u32,
    pub signature_algorithm: String,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub commitment_profile_id: String,
    pub leaf_hash_profile_id: String,
    pub leaf_hash_algorithm: String,
    pub merkle_profile_id: String,
    pub merkle_hash_algorithm: String,
    pub merkle_parameters_sha256: String,
}

/// Public certificate, root statement, and CA signature distributed to verifiers.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedRegistryRoot {
    pub certificate: CaCertificate,
    pub statement: RegistryRootStatement,
    /// P-256 ECDSA signature r||s, lowercase hex encoding (64 bytes).
    pub signature_hex: String,
}

/// Device-to-CA enrollment request. The CA sees PK_D and v.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentRequest {
    /// Compressed SEC1 P-256 device public key (33 bytes).
    pub device_public_key_sec1: Vec<u8>,
    /// Canonical nonzero P-256 scalar v, big-endian (32 bytes).
    pub opening_scalar: [u8; 32],
    /// Compressed SEC1 encodings of C0 and C1 (33 bytes each).
    pub cm_pk_c0_sec1: Vec<u8>,
    pub cm_pk_c1_sec1: Vec<u8>,
    /// Raw fixed-width P-256 ECDSA signature over the CA challenge and cmPK.
    /// This proves possession of SK_D without disclosing it.
    pub proof_of_possession_signature: Vec<u8>,
}

/// One-time challenge issued by the CA before device enrollment.
#[derive(Debug)]
pub struct EnrollmentChallenge {
    pub nonce: [u8; 32],
    consumed: bool,
}

impl EnrollmentChallenge {
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut nonce = [0u8; 32];
        let mut rng = rand::rngs::OsRng;
        rng.fill_bytes(&mut nonce);
        Self { nonce, consumed: false }
    }

    #[cfg(test)]
    fn test_nonce(nonce: [u8; 32]) -> Self {
        Self { nonce, consumed: false }
    }
}

/// CA-internal validated enrollment record; never place this in a public package.
#[derive(Clone)]
pub struct EnrollmentRecord {
    // CA-internal mapping key retained for registry administration/revocation.
    // The opening v is deliberately not retained after the opening check.
    device_public_key_sec1: [u8; 33],
    cm_pk_encoded: [u8; 66],
    leaf: Integer,
}

impl EnrollmentRecord {
    /// CA-internal device mapping key; never copy this into a verifier package.
    pub fn device_public_key_sec1(&self) -> &[u8; 33] {
        &self.device_public_key_sec1
    }

    pub fn cm_pk_encoded(&self) -> &[u8; 66] {
        &self.cm_pk_encoded
    }

    pub fn leaf(&self) -> &Integer {
        &self.leaf
    }
}

/// Private path format consumed by examples/spartan_merkle_linked.rs.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerklePath {
    pub siblings: Vec<String>,
    /// true means the current node is the left child, matching the Spartan circuit.
    pub directions: Vec<bool>,
}

/// Binary Merkle tree using the exact hash function supplied by the caller.
/// Pass the same P-256 Poseidon implementation/parameters used by the Spartan circuit.
#[derive(Clone, Debug)]
pub struct RegistryMerkleTree {
    depth: usize,
    leaf_count: usize,
    /// Sparse non-default nodes at each level; avoids allocating 2^depth leaves.
    levels: Vec<BTreeMap<usize, Integer>>,
    /// Default subtree root for each level, with an all-zero leaf value.
    defaults: Vec<Integer>,
}

/// Result of CA registry construction. Each path is private and must be delivered
/// only to the corresponding enrolled device/prover, not placed in public metadata.
#[derive(Clone)]
pub struct RegistryBuildOutput {
    pub signed_root: SignedRegistryRoot,
    /// Legacy path-only output retained for existing scripts.
    pub enrollment_paths: Vec<MerklePath>,
    /// Device-private credential that binds the exact cmPK, H_reg leaf and path.
    pub enrollment_credentials: Vec<DeviceRegistryCredential>,
}

/// Device/prover credential. This is private because it contains a Merkle path.
/// It intentionally excludes PK_D and the opening scalar v.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeviceRegistryCredential {
    pub version: u32,
    pub registry_id: String,
    pub depth: u32,
    pub cm_pk_encoded_hex: String,
    pub leaf_decimal: String,
    pub path: MerklePath,
}

/// Build a registry from CA-validated enrollment records, create one private path
/// per record, and authenticate the resulting root. The `hash` closure MUST be
/// the exact Poseidon hash implementation and parameter set used by Spartan.
pub fn build_signed_registry<F>(
    records: &[EnrollmentRecord],
    depth: usize,
    registry_id: impl Into<String>,
    merkle_profile_id: impl Into<String>,
    merkle_parameters_sha256: impl Into<String>,
    ca: &CaAuthority,
    hash: F,
) -> Result<RegistryBuildOutput, String>
where
    F: FnMut(&Integer, &Integer) -> Integer,
{
    if records.is_empty() {
        return Err("Cannot sign an empty registry".into());
    }
    let mut seen_commitments = BTreeSet::new();
    let mut seen_leaves = BTreeSet::new();
    for record in records {
        if !seen_commitments.insert(record.cm_pk_encoded) {
            return Err("Duplicate cmPK commitment in one registry batch".into());
        }
        if !seen_leaves.insert(record.leaf.clone()) {
            return Err("Duplicate H_reg leaf in one registry batch; refusing ambiguous membership".into());
        }
    }
    let leaves: Vec<Integer> = records.iter().map(|record| record.leaf.clone()).collect();
    let tree = RegistryMerkleTree::build(&leaves, depth, hash)?;
    let registry_id = registry_id.into();
    let now = unix_time_now()?;
    let statement = RegistryRootStatement {
        version: REGISTRY_STATEMENT_VERSION,
        registry_id: registry_id.clone(),
        merkle_root_decimal: tree.root().to_string(),
        depth: depth as u32,
        signature_algorithm: REGISTRY_SIGNATURE_ALGORITHM.to_string(),
        issued_at_unix: now,
        expires_at_unix: now.checked_add(REGISTRY_DEFAULT_VALIDITY_SECS)
            .ok_or("Registry root expiry timestamp overflow")?,
        commitment_profile_id: crate::ecdsa::picproof_k::PROFILE.to_string(),
        leaf_hash_profile_id: "PicProof-PKI-CMPK-v1".to_string(),
        leaf_hash_algorithm: "SHA-256-rejection-sampling-P256Fp".to_string(),
        merkle_profile_id: merkle_profile_id.into(),
        merkle_hash_algorithm: REGISTRY_MERKLE_HASH_ALGORITHM.to_string(),
        merkle_parameters_sha256: merkle_parameters_sha256.into(),
    };
    let signed_root = ca.sign_registry_root(statement)?;
    let mut enrollment_paths = Vec::with_capacity(records.len());
    let mut enrollment_credentials = Vec::with_capacity(records.len());
    for (index, record) in records.iter().enumerate() {
        let path = tree.path(index)?;
        enrollment_credentials.push(DeviceRegistryCredential {
            version: 1,
            registry_id: registry_id.clone(),
            depth: depth as u32,
            cm_pk_encoded_hex: hex::encode(record.cm_pk_encoded),
            leaf_decimal: record.leaf.to_string(),
            path: path.clone(),
        });
        enrollment_paths.push(path);
    }
    Ok(RegistryBuildOutput { signed_root, enrollment_paths, enrollment_credentials })
}

impl RegistryMerkleTree {
    pub fn build<F>(leaves: &[Integer], depth: usize, mut hash: F) -> Result<Self, String>
    where
        F: FnMut(&Integer, &Integer) -> Integer,
    {
        if depth > MAX_REGISTRY_DEPTH {
            return Err(format!("Merkle depth {} exceeds maximum {}", depth, MAX_REGISTRY_DEPTH));
        }
        if leaves.is_empty() {
            return Err("Cannot build a registry tree without registered leaves".into());
        }
        let capacity = 1usize.checked_shl(depth as u32).ok_or("Merkle capacity overflow")?;
        if leaves.len() > capacity {
            return Err(format!("{} leaves exceed Merkle capacity {}", leaves.len(), capacity));
        }
        let modulus = Integer::from_str_radix(P256_BASE_FIELD_DEC, 10)
            .map_err(|_| "Invalid P-256 base-field modulus")?;
        let mut level0 = BTreeMap::new();
        for (index, leaf) in leaves.iter().enumerate() {
            if leaf < &Integer::from(0) || leaf >= &modulus {
                return Err(format!("Merkle leaf at index {index} is outside the P-256 base field"));
            }
            level0.insert(index, leaf.clone());
        }
        let mut levels = vec![level0];
        let mut defaults = vec![Integer::from(0)];

        // Sparse construction: only parents of non-default nodes are materialized.
        // The all-zero subtree hash is computed once per level, making depth-16
        // registration practical even on a low-memory CPU-only machine.
        for level in 0..depth {
            let current = levels.last().expect("leaf level exists");
            let mut parent_indices = BTreeSet::new();
            for index in current.keys() {
                parent_indices.insert(index / 2);
            }
            let default_child = defaults[level].clone();
            let mut next = BTreeMap::new();
            for parent in parent_indices {
                let left_index = parent * 2;
                let right_index = left_index + 1;
                let left = current.get(&left_index).unwrap_or(&default_child);
                let right = current.get(&right_index).unwrap_or(&default_child);
                let parent_hash = hash(left, right);
                if parent_hash < 0 || parent_hash >= modulus {
                    return Err(format!("Merkle hash output at level {level} is outside the P-256 base field"));
                }
                next.insert(parent, parent_hash);
            }
            let default_parent = hash(&default_child, &default_child);
            if default_parent < 0 || default_parent >= modulus {
                return Err(format!("Merkle default hash output at level {level} is outside the P-256 base field"));
            }
            levels.push(next);
            defaults.push(default_parent);
        }
        Ok(Self { depth, leaf_count: leaves.len(), levels, defaults })
    }

    pub fn depth(&self) -> usize { self.depth }
    pub fn root(&self) -> &Integer {
        self.levels[self.depth].get(&0).unwrap_or(&self.defaults[self.depth])
    }

    pub fn path(&self, leaf_index: usize) -> Result<MerklePath, String> {
        if leaf_index >= self.leaf_count {
            return Err("Leaf index is outside the registered leaf set".into());
        }
        let mut index = leaf_index;
        let mut siblings = Vec::with_capacity(self.depth);
        let mut directions = Vec::with_capacity(self.depth);
        for level in 0..self.depth {
            let sibling = self.levels[level].get(&(index ^ 1)).unwrap_or(&self.defaults[level]);
            siblings.push(sibling.to_string());
            directions.push(index % 2 == 0);
            index /= 2;
        }
        Ok(MerklePath { siblings, directions })
    }
}

/// CA signing authority. Keep its signing key secret and outside proof packages.
pub struct CaAuthority {
    signing_key: P256SigningKey,
    ca_id: String,
}

impl CaAuthority {
    pub fn generate(ca_id: impl Into<String>) -> Self {
        Self { signing_key: P256SigningKey::random(&mut rand::rngs::OsRng), ca_id: ca_id.into() }
    }

    pub fn from_secret_bytes(ca_id: impl Into<String>, secret: [u8; 32]) -> Result<Self, String> {
        let signing_key = P256SigningKey::from_slice(&secret)
            .map_err(|e| format!("Invalid CA P-256 secret scalar: {e}"))?;
        Ok(Self { signing_key, ca_id: ca_id.into() })
    }

    pub fn certificate(&self) -> CaCertificate {
        let mut cert = CaCertificate {
            version: CA_CERT_VERSION,
            ca_id: self.ca_id.clone(),
            public_key_hex: hex::encode(self.signing_key.verifying_key().to_encoded_point(true).as_bytes()),
            fingerprint_sha256: String::new(),
        };
        cert.fingerprint_sha256 = certificate_fingerprint(&cert);
        cert
    }

    pub fn sign_registry_root(&self, statement: RegistryRootStatement) -> Result<SignedRegistryRoot, String> {
        let message = statement.canonical_bytes()?;
        let signature: P256Signature = self.signing_key.sign(&message);
        // Enforce canonical low-S form for CA registry-root signatures.
        let signature = signature.normalize_s().unwrap_or(signature);
        Ok(SignedRegistryRoot {
            certificate: self.certificate(),
            statement,
            signature_hex: hex::encode(signature.to_bytes()),
        })
    }
}

impl RegistryRootStatement {
    /// Canonical binary encoding; do not sign JSON serialization.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        validate_registry_statement(self)?;
        let root = parse_canonical_field_decimal(&self.merkle_root_decimal)?;
        let root_bytes = integer_to_be_32(&root)?;
        let mut out = Vec::new();
        out.extend_from_slice(CA_ROOT_DOMAIN);
        out.push(0);
        out.extend_from_slice(&self.version.to_be_bytes());
        append_len_prefixed(&mut out, self.registry_id.as_bytes())?;
        out.extend_from_slice(&root_bytes);
        out.extend_from_slice(&self.depth.to_be_bytes());
        append_len_prefixed(&mut out, self.signature_algorithm.as_bytes())?;
        out.extend_from_slice(&self.issued_at_unix.to_be_bytes());
        out.extend_from_slice(&self.expires_at_unix.to_be_bytes());
        append_len_prefixed(&mut out, self.commitment_profile_id.as_bytes())?;
        append_len_prefixed(&mut out, self.leaf_hash_profile_id.as_bytes())?;
        append_len_prefixed(&mut out, self.leaf_hash_algorithm.as_bytes())?;
        append_len_prefixed(&mut out, self.merkle_profile_id.as_bytes())?;
        append_len_prefixed(&mut out, self.merkle_hash_algorithm.as_bytes())?;
        let params_fingerprint = decode_fixed_hex::<32>(&self.merkle_parameters_sha256)?;
        out.extend_from_slice(&params_fingerprint);
        Ok(out)
    }
}

/// Validate the CA certificate fingerprint against an out-of-band pin, then
/// verify the CA signature over the registry statement.
pub fn verify_signed_registry_root(signed: &SignedRegistryRoot, trusted_fingerprint: &str) -> Result<(), String> {
    verify_signed_registry_root_at(signed, trusted_fingerprint, unix_time_now()?)
}

/// Deterministic-time variant used by tests and archival verification tools.
pub fn verify_signed_registry_root_at(
    signed: &SignedRegistryRoot,
    trusted_fingerprint: &str,
    now_unix: u64,
) -> Result<(), String> {
    validate_certificate(&signed.certificate)?;
    let actual = certificate_fingerprint(&signed.certificate);
    if !actual.eq_ignore_ascii_case(&signed.certificate.fingerprint_sha256) {
        return Err("CA certificate fingerprint field is invalid".into());
    }
    if !actual.eq_ignore_ascii_case(trusted_fingerprint) {
        return Err("CA certificate is not the configured trust anchor".into());
    }
    let public_bytes = decode_fixed_hex::<33>(&signed.certificate.public_key_hex)?;
    let verifying_key = P256VerifyingKey::from_sec1_bytes(&public_bytes)
        .map_err(|e| format!("Invalid CA P-256 public key: {e}"))?;
    let signature_bytes = decode_fixed_hex::<64>(&signed.signature_hex)?;
    let signature = P256Signature::from_slice(&signature_bytes)
        .map_err(|e| format!("Invalid CA ECDSA signature encoding: {e}"))?;
    if signature.normalize_s().is_some() {
        return Err("CA ECDSA signature is not canonical low-S form".into());
    }
    let message = signed.statement.canonical_bytes()?;
    if signed.statement.issued_at_unix > now_unix.saturating_add(REGISTRY_CLOCK_SKEW_SECS) {
        return Err("CA registry root is not yet valid".into());
    }
    if signed.statement.expires_at_unix <= now_unix {
        return Err("CA registry root has expired".into());
    }
    verifying_key.verify(&message, &signature)
        .map_err(|_| "CA registry-root signature verification failed".into())
}

/// Validate P-256 public-key encoding and the commitment opening
/// cmPK = (vG, PK_D + vK), then derive the registered H_reg leaf.
pub fn validate_enrollment(
    request: &EnrollmentRequest,
    challenge: &mut EnrollmentChallenge,
) -> Result<EnrollmentRecord, String> {
    if challenge.consumed {
        return Err("Enrollment challenge has already been consumed".into());
    }
    let device_pk: [u8; 33] = request.device_public_key_sec1.as_slice().try_into()
        .map_err(|_| "Device public key must be 33-byte compressed SEC1")?;
    let c0: [u8; 33] = request.cm_pk_c0_sec1.as_slice().try_into()
        .map_err(|_| "cmPK C0 must be 33-byte compressed SEC1")?;
    let c1: [u8; 33] = request.cm_pk_c1_sec1.as_slice().try_into()
        .map_err(|_| "cmPK C1 must be 33-byte compressed SEC1")?;
    let pk_point = decode_p256_point(&device_pk, "device public key")?;
    let c0_point = decode_p256_point(&c0, "cmPK C0")?;
    let c1_point = decode_p256_point(&c1, "cmPK C1")?;
    let opening = Option::<Scalar>::from(Scalar::from_repr(FieldBytes::from(request.opening_scalar)))
        .ok_or("Opening value is not a canonical P-256 scalar")?;
    if opening == Scalar::ZERO { return Err("Opening value v must be nonzero".into()); }
    if c0_point != ProjectivePoint::GENERATOR * opening {
        return Err("cmPK C0 does not equal v*G".into());
    }
    if c1_point != pk_point + picproof_commitment_generator_k() * opening {
        return Err("cmPK C1 does not equal PK_D + v*K".into());
    }
    let (leaf, _counter, _digest, encoded) = h_reg(&c0, &c1)?;

    // Bind proof-of-possession to this one-time CA challenge and this exact cmPK.
    let pop_message = enrollment_pop_message(&challenge.nonce, &encoded);
    let pop_signature = P256Signature::from_slice(&request.proof_of_possession_signature)
        .map_err(|e| format!("Invalid device proof-of-possession signature: {e}"))?;
    if pop_signature.normalize_s().is_some() {
        return Err("Device proof-of-possession signature is not canonical low-S form".into());
    }
    let pop_verifying_key = P256VerifyingKey::from_sec1_bytes(&device_pk)
        .map_err(|e| format!("Invalid device P-256 public key: {e}"))?;
    pop_verifying_key.verify(&pop_message, &pop_signature)
        .map_err(|_| "Device proof-of-possession challenge verification failed".to_string())?;
    challenge.consumed = true;

    Ok(EnrollmentRecord {
        device_public_key_sec1: device_pk,
        cm_pk_encoded: encoded,
        leaf,
    })
}

/// Domain-separated message signed by the device to prove control of SK_D.
pub fn enrollment_pop_message(challenge_nonce: &[u8; 32], cm_pk_encoded: &[u8; 66]) -> Vec<u8> {
    let mut message = Vec::with_capacity(32 + 1 + 32 + 66);
    message.extend_from_slice(b"PICPROOF-DEVICE-ENROLLMENT-POP-v1");
    message.push(0);
    message.extend_from_slice(challenge_nonce);
    message.extend_from_slice(cm_pk_encoded);
    message
}

pub fn certificate_fingerprint(certificate: &CaCertificate) -> String {
    let mut hasher = Sha256::new();
    hasher.update(CA_CERT_DOMAIN);
    hasher.update([0]);
    hasher.update(certificate.version.to_be_bytes());
    hasher.update((certificate.ca_id.len() as u64).to_be_bytes());
    hasher.update(certificate.ca_id.as_bytes());
    if let Ok(pk) = decode_fixed_hex::<33>(&certificate.public_key_hex) { hasher.update(pk); }
    else { hasher.update(certificate.public_key_hex.as_bytes()); }
    hex::encode(hasher.finalize())
}

fn validate_certificate(certificate: &CaCertificate) -> Result<(), String> {
    if certificate.version != CA_CERT_VERSION { return Err("Unsupported CA certificate version".into()); }
    if certificate.ca_id.trim().is_empty() { return Err("CA identifier must not be empty".into()); }
    if certificate.ca_id.len() > 1024 { return Err("CA identifier exceeds 1024 bytes".into()); }
    let pk = decode_fixed_hex::<33>(&certificate.public_key_hex)?;
    P256VerifyingKey::from_sec1_bytes(&pk).map_err(|e| format!("Invalid CA P-256 public key: {e}"))?;
    Ok(())
}

fn validate_registry_statement(statement: &RegistryRootStatement) -> Result<(), String> {
    if statement.version != REGISTRY_STATEMENT_VERSION { return Err("Unsupported registry statement version".into()); }
    if statement.registry_id.trim().is_empty()
        || statement.commitment_profile_id.trim().is_empty()
        || statement.leaf_hash_profile_id.trim().is_empty()
        || statement.merkle_profile_id.trim().is_empty() {
        return Err("Registry ID and cryptographic profile IDs must not be empty".into());
    }
    if statement.commitment_profile_id != super::picproof_k::PROFILE
        || statement.leaf_hash_profile_id != "PicProof-PKI-CMPK-v1" {
        return Err("Unsupported commitment or registration leaf profile".into());
    }
    if statement.depth as usize > MAX_REGISTRY_DEPTH { return Err("Registry depth exceeds supported maximum".into()); }
    if statement.signature_algorithm != REGISTRY_SIGNATURE_ALGORITHM {
        return Err("Unsupported registry-root signature algorithm".into());
    }
    if statement.merkle_hash_algorithm != REGISTRY_MERKLE_HASH_ALGORITHM {
        return Err("Unsupported registry Merkle hash algorithm".into());
    }
    if statement.leaf_hash_algorithm != "SHA-256-rejection-sampling-P256Fp" {
        return Err("Unsupported registry leaf hash algorithm".into());
    }
    if statement.issued_at_unix == 0 || statement.expires_at_unix <= statement.issued_at_unix {
        return Err("Registry root validity interval is invalid".into());
    }
    if statement.expires_at_unix - statement.issued_at_unix > REGISTRY_DEFAULT_VALIDITY_SECS {
        return Err("Registry root validity interval exceeds policy maximum".into());
    }
    if statement.merkle_parameters_sha256.len() != 64 || !statement.merkle_parameters_sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("Merkle parameter fingerprint must be 32-byte hexadecimal".into());
    }
    parse_canonical_field_decimal(&statement.merkle_root_decimal)?;
    Ok(())
}

fn parse_canonical_field_decimal(value: &str) -> Result<Integer, String> {
    if value.is_empty() || (value.len() > 1 && value.starts_with('0')) || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err("Merkle root must use canonical unsigned decimal encoding".into());
    }
    let root = Integer::from_str_radix(value, 10).map_err(|_| "Invalid Merkle root decimal encoding")?;
    let modulus = Integer::from_str_radix(P256_BASE_FIELD_DEC, 10).map_err(|_| "Invalid P-256 base-field modulus")?;
    if root < 0 || root >= modulus { return Err("Merkle root is outside the P-256 base field".into()); }
    Ok(root)
}

fn unix_time_now() -> Result<u64, String> {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| "System clock is before UNIX epoch".to_string())
}

fn integer_to_be_32(value: &Integer) -> Result<[u8; 32], String> {
    let digits = value.to_digits::<u8>(rug::integer::Order::MsfBe);
    if digits.len() > 32 { return Err("Integer does not fit in 32 bytes".into()); }
    let mut out = [0u8; 32];
    out[32 - digits.len()..].copy_from_slice(&digits);
    Ok(out)
}

fn append_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), String> {
    let len: u32 = bytes.len().try_into().map_err(|_| "Field too long")?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn decode_fixed_hex<const N: usize>(value: &str) -> Result<[u8; N], String> {
    let decoded = hex::decode(value).map_err(|e| format!("Invalid hexadecimal encoding: {e}"))?;
    decoded.as_slice().try_into().map_err(|_| format!("Expected exactly {} decoded bytes", N))
}

fn decode_p256_point(bytes: &[u8; 33], label: &str) -> Result<ProjectivePoint, String> {
    if !matches!(bytes[0], 0x02 | 0x03) { return Err(format!("{label} must use compressed SEC1 encoding")); }
    let encoded = EncodedPoint::from_bytes(bytes).map_err(|e| format!("Invalid {label} SEC1 encoding: {e}"))?;
    let affine = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))
        .ok_or_else(|| format!("{label} is not a valid P-256 point"))?;
    let point = ProjectivePoint::from(affine);
    if point == ProjectivePoint::IDENTITY { return Err(format!("{label} must not be point at infinity")); }
    Ok(point)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    // Deterministic toy hash used only by unit tests; never used by production.
    // Materialize each rug operation as Integer to avoid adding lazy Incomplete values.
    fn toy_merkle_hash(left: &Integer, right: &Integer) -> Integer {
        let mut value = left.clone();
        value *= 31;
        let mut term = right.clone();
        term *= 17;
        value += term;
        value
    }

    fn toy_merkle_hash_mod(left: &Integer, right: &Integer, modulus: &Integer) -> Integer {
        let mut value = toy_merkle_hash(left, right);
        value %= modulus;
        value
    }

    fn request(challenge: &EnrollmentChallenge) -> EnrollmentRequest {
        use p256::ecdsa::signature::Signer as P256Signer;
        let sk = Scalar::from(7u64);
        let signing_key = P256SigningKey::from_slice(&sk.to_repr()).unwrap();
        let pk = ProjectivePoint::GENERATOR * sk;
        let v = Scalar::from(11u64);
        let c0 = ProjectivePoint::GENERATOR * v;
        let c1 = pk + picproof_commitment_generator_k() * v;
        let c0_bytes = c0.to_affine().to_encoded_point(true);
        let c1_bytes = c1.to_affine().to_encoded_point(true);
        let mut encoded_cmpk = [0u8; 66];
        encoded_cmpk[..33].copy_from_slice(c0_bytes.as_bytes());
        encoded_cmpk[33..].copy_from_slice(c1_bytes.as_bytes());
        let pop_message = enrollment_pop_message(&challenge.nonce, &encoded_cmpk);
        let pop_signature: P256Signature = signing_key.sign(&pop_message);
        let pop_signature = pop_signature.normalize_s().unwrap_or(pop_signature);
        EnrollmentRequest {
            device_public_key_sec1: pk.to_affine().to_encoded_point(true).as_bytes().to_vec(),
            opening_scalar: v.to_repr().into(),
            cm_pk_c0_sec1: c0_bytes.as_bytes().to_vec(),
            cm_pk_c1_sec1: c1_bytes.as_bytes().to_vec(),
            proof_of_possession_signature: pop_signature.to_bytes().to_vec(),
        }
    }

    #[test]
    fn enrollment_accepts_valid_commitment_opening() {
        let mut challenge = EnrollmentChallenge::test_nonce([0x42; 32]);
        let req = request(&challenge);
        assert!(validate_enrollment(&req, &mut challenge).is_ok());
    }

    #[test]
    fn enrollment_rejects_wrong_opening() {
        let mut challenge = EnrollmentChallenge::test_nonce([0x42; 32]);
        let mut req = request(&challenge);
        req.opening_scalar = Scalar::from(12u64).to_repr().into();
        assert!(validate_enrollment(&req, &mut challenge).is_err());
    }

    #[test]
    fn enrollment_rejects_zero_opening() {
        let mut challenge = EnrollmentChallenge::test_nonce([0x43; 32]);
        let mut req = request(&challenge);
        req.opening_scalar = Scalar::ZERO.to_repr().into();
        assert!(validate_enrollment(&req, &mut challenge).is_err());
    }

    #[test]
    fn enrollment_proof_of_possession_is_bound_to_challenge() {
        let challenge = EnrollmentChallenge::test_nonce([0x42; 32]);
        let mut other_challenge = EnrollmentChallenge::test_nonce([0x43; 32]);
        let req = request(&challenge);
        assert!(validate_enrollment(&req, &mut other_challenge).is_err());
    }

    #[test]
    fn consumed_enrollment_challenge_cannot_be_replayed() {
        let mut challenge = EnrollmentChallenge::test_nonce([0x55; 32]);
        let req = request(&challenge);
        assert!(validate_enrollment(&req, &mut challenge).is_ok());
        assert!(validate_enrollment(&req, &mut challenge).is_err());
    }

    #[test]
    fn root_signature_requires_pinned_ca_and_rejects_tampering() {
        let ca = CaAuthority::generate("picproof-test-ca");
        let cert = ca.certificate();
        let now = unix_time_now().unwrap();
        let statement = RegistryRootStatement {
            version: REGISTRY_STATEMENT_VERSION,
            registry_id: "registry-test-1".into(),
            merkle_root_decimal: "12345".into(),
            depth: 4,
            signature_algorithm: REGISTRY_SIGNATURE_ALGORITHM.into(),
            issued_at_unix: now,
            expires_at_unix: now + REGISTRY_DEFAULT_VALIDITY_SECS,
            commitment_profile_id: crate::ecdsa::picproof_k::PROFILE.to_string(),
            leaf_hash_profile_id: "PicProof-PKI-CMPK-v1".into(),
            leaf_hash_algorithm: "SHA-256-rejection-sampling-P256Fp".into(),
            merkle_profile_id: "PicProof-P256Fp-Poseidon-t3-v1".into(),
            merkle_hash_algorithm: REGISTRY_MERKLE_HASH_ALGORITHM.into(),
            merkle_parameters_sha256: "00".repeat(32),
        };
        let mut signed = ca.sign_registry_root(statement).unwrap();
        verify_signed_registry_root(&signed, &cert.fingerprint_sha256).unwrap();
        assert!(verify_signed_registry_root(&signed, &"11".repeat(32)).is_err());
        signed.statement.merkle_root_decimal = "12346".into();
        assert!(verify_signed_registry_root(&signed, &cert.fingerprint_sha256).is_err());
    }

    #[test]
    fn ca_builds_and_signs_registry_from_validated_enrollments() {
        let mut challenge = EnrollmentChallenge::test_nonce([0x77; 32]);
        let record = validate_enrollment(&request(&challenge), &mut challenge).unwrap();
        let ca = CaAuthority::generate("picproof-test-ca");
        let modulus = Integer::from_str_radix(P256_BASE_FIELD_DEC, 10).unwrap();
        let built = build_signed_registry(
            &[record],
            4,
            "registry-test-2",
            "PicProof-P256Fp-Poseidon-t3-v1",
            "ab".repeat(32),
            &ca,
            |left, right| toy_merkle_hash_mod(left, right, &modulus),
        ).unwrap();
        verify_signed_registry_root(
            &built.signed_root,
            &built.signed_root.certificate.fingerprint_sha256,
        ).unwrap();
        let sig_bytes = decode_fixed_hex::<64>(&built.signed_root.signature_hex).unwrap();
        let sig = P256Signature::from_slice(&sig_bytes).unwrap();
        assert!(sig.normalize_s().is_none(), "CA must always emit canonical low-S signatures");
        assert_eq!(built.enrollment_paths.len(), 1);
        assert_eq!(built.enrollment_paths[0].siblings.len(), 4);
    }

    #[test]
    fn registry_batch_rejects_duplicate_commitment() {
        let mut challenge = EnrollmentChallenge::test_nonce([0x79; 32]);
        let record = validate_enrollment(&request(&challenge), &mut challenge).unwrap();
        let ca = CaAuthority::generate("picproof-duplicate-test-ca");
        let modulus = Integer::from_str_radix(P256_BASE_FIELD_DEC, 10).unwrap();
        let result = build_signed_registry(
            &[record.clone(), record], 2, "registry-duplicate", "PicProof-P256Fp-Poseidon-t3-v1",
            "ab".repeat(32), &ca,
            |left, right| toy_merkle_hash_mod(left, right, &modulus),
        );
        assert!(result.is_err());
    }

    #[test]
    fn merkle_path_uses_spartan_direction_convention() {
        let leaves = vec![Integer::from(10), Integer::from(20), Integer::from(30)];
        let tree = RegistryMerkleTree::build(&leaves, 2, toy_merkle_hash).unwrap();
        let path = tree.path(1).unwrap();
        assert_eq!(path.directions, vec![false, true]);
        let mut current = leaves[1].clone();
        for (s, current_is_left) in path.siblings.iter().zip(path.directions.iter()) {
            let sibling = Integer::from_str_radix(s, 10).unwrap();
            current = if *current_is_left {
                toy_merkle_hash(&current, &sibling)
            } else {
                toy_merkle_hash(&sibling, &current)
            };
        }
        assert_eq!(current, *tree.root());
    }
    #[test]
    fn expired_root_is_rejected_even_with_valid_signature() {
        let ca = CaAuthority::generate("picproof-expired-test-ca");
        let mut statement = RegistryRootStatement {
            version: REGISTRY_STATEMENT_VERSION,
            registry_id: "registry-expired".into(),
            merkle_root_decimal: "1".into(),
            depth: 1,
            signature_algorithm: REGISTRY_SIGNATURE_ALGORITHM.into(),
            issued_at_unix: 100,
            expires_at_unix: 200,
            commitment_profile_id: crate::ecdsa::picproof_k::PROFILE.into(),
            leaf_hash_profile_id: "PicProof-PKI-CMPK-v1".into(),
            leaf_hash_algorithm: "SHA-256-rejection-sampling-P256Fp".into(),
            merkle_profile_id: "PicProof-P256Fp-Poseidon-t3-v1".into(),
            merkle_hash_algorithm: REGISTRY_MERKLE_HASH_ALGORITHM.into(),
            merkle_parameters_sha256: "00".repeat(32),
        };
        let signed = ca.sign_registry_root(statement.clone()).unwrap();
        assert!(verify_signed_registry_root_at(&signed, &signed.certificate.fingerprint_sha256, 201).is_err());
        statement.expires_at_unix = statement.issued_at_unix + REGISTRY_DEFAULT_VALIDITY_SECS + 1;
        assert!(statement.canonical_bytes().is_err());
    }

    #[test]
    fn credential_contains_cm_pk_leaf_and_private_path_without_opening_or_device_key() {
        let mut challenge = EnrollmentChallenge::test_nonce([0x78; 32]);
        let record = validate_enrollment(&request(&challenge), &mut challenge).unwrap();
        let ca = CaAuthority::generate("picproof-credential-test-ca");
        let modulus = Integer::from_str_radix(P256_BASE_FIELD_DEC, 10).unwrap();
        let built = build_signed_registry(
            &[record], 2, "registry-credential", "PicProof-P256Fp-Poseidon-t3-v1",
            "ab".repeat(32), &ca,
            |left, right| toy_merkle_hash_mod(left, right, &modulus),
        ).unwrap();
        let credential = &built.enrollment_credentials[0];
        assert_eq!(credential.depth, 2);
        assert_eq!(credential.path.siblings.len(), 2);
        let leaf = Integer::from_str_radix(&credential.leaf_decimal, 10).unwrap();
        assert!(leaf >= 0 && leaf < modulus);
        assert_eq!(hex::decode(&credential.cm_pk_encoded_hex).unwrap().len(), 66);
        let serialized = serde_json::to_value(credential).unwrap();
        assert!(serialized.get("opening_scalar").is_none());
        assert!(serialized.get("device_public_key_sec1").is_none());
    }

    #[test]
    fn merkle_builder_rejects_non_field_hash_outputs() {
        let modulus = Integer::from_str_radix(P256_BASE_FIELD_DEC, 10).unwrap();
        assert!(RegistryMerkleTree::build(&[Integer::from(1)], 1, |_l, _r| modulus.clone()).is_err());
    }

}
