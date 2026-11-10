//! Transparent PicProof commitment generator `K`.
//!
//! This module is the single source of truth for the generator `K` used by the
//! committed-public-key sigma protocol. It pins three things together:
//!
//! * the RFC 9380 hash-to-curve derivation of `K`,
//! * the SEC1 encoded point and parameter fingerprint recorded in
//!   `test_vectors/cmpk_generator_kat.json`,
//! * the fixed affine coordinates baked into the runtime for speed.
//!
//! The commitment is `cm_PK = (vG, PK + vK)`, while `L = G` is the standard
//! P-256 generator. `K` is a nothing-up-my-sleeve point: nobody knows
//! `log_G(K)`, which is exactly what makes the second component binding.
//!
//! Profile (fixed forever, do not edit ad hoc):
//!
//! ```text
//! profile : PicProof-P256-CmPK-K-v1
//! curve   : P-256
//! suite   : P256_XMD:SHA-256_SSWU_RO_
//! expand  : XMD:SHA-256
//! map     : SSWU (random oracle)
//! dst     : PICPROOF-P256-CMPK-K-v1
//! message : PicProof commitment generator K
//! ```

use p256::elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{NistP256, ProjectivePoint};
use sha2::{Digest, Sha256};

/// Canonical profile identifier.
pub const PROFILE: &str = "PicProof-P256-CmPK-K-v1";
/// Curve identifier.
pub const CURVE: &str = "P-256";
/// RFC 9380 suite identifier.
pub const SUITE: &str = "P256_XMD:SHA-256_SSWU_RO_";
/// Expansion function identifier.
pub const EXPAND: &str = "XMD:SHA-256";
/// Mapping identifier.
pub const MAP: &str = "SSWU";
/// Domain separation tag, fixed forever by this profile.
pub const DST: &[u8] = b"PICPROOF-P256-CMPK-K-v1";
/// Message hashed to the curve, fixed forever by this profile.
pub const MESSAGE: &[u8] = b"PicProof commitment generator K";

/// X coordinate of `K` in decimal, as recorded by the KAT.
pub const K_X_DECIMAL: &str =
    "47017973193027729375240351988462345240701012035971187641129361731386586706639";
/// Y coordinate of `K` in decimal, as recorded by the KAT.
pub const K_Y_DECIMAL: &str =
    "112026181996455947215465513042656222973312915275591910249576387678346211656878";
/// SEC1 compressed encoding of `K` in lowercase hex.
pub const K_SEC1_COMPRESSED: &str =
    "0267f33ad19ab684bfb58d469d1342ad2a30ea7656237ae07b8058dca8aca032cf";
/// SEC1 uncompressed encoding of `K` in lowercase hex.
pub const K_SEC1_UNCOMPRESSED: &str = concat!(
    "0467f33ad19ab684bfb58d469d1342ad2a30ea7656237ae07b8058dca8aca032cf",
    "f7ac9270fe2a05b2e8893b17c05b5e36fd3f048bdb2b65f5e12239c3b1ae84ae",
);
/// SHA-256 fingerprint over the canonical parameter serialization.
pub const K_PARAMETER_SHA256: &str =
    "03c65102522ecce14e0e3c8a5722996a6e59ee5db3dddf3f0746ceac79edbd7f";

/// Derives `K` from scratch with `P256_XMD:SHA-256_SSWU_RO_`.
///
/// This is the transparent, reproducible derivation. Runtime code should call
/// [`picproof_commitment_generator_k`] instead and rely on the KAT test to keep
/// the two in sync.
pub fn derive_picproof_commitment_generator_k() -> ProjectivePoint {
    NistP256::hash_from_bytes::<ExpandMsgXmd<Sha256>>(&[MESSAGE], &[DST])
        .expect("RFC 9380 P-256 hash-to-curve must not fail for valid parameters")
}

/// Returns the fixed deployment value of `K`.
///
/// The coordinates are the output of
/// [`derive_picproof_commitment_generator_k`]; the KAT test below fails if they
/// ever diverge.
pub fn picproof_commitment_generator_k() -> ProjectivePoint {
    let compressed = hex_decode_array::<33>(K_SEC1_COMPRESSED);
    ProjectivePoint::from_encoded_point(&p256::EncodedPoint::from_bytes(compressed).unwrap())
        .unwrap()
}

/// Canonical fingerprint input. The preimage is exactly these seven fields,
/// each terminated by a single `\n` (ASCII 0x0a), with no other separators:
///
/// ```text
/// 1: profile              "PicProof-P256-CmPK-K-v1"
/// 2: curve                "P-256"
/// 3: expand               "XMD:SHA-256"
/// 4: map                  "SSWU"
/// 5: dst                  "PICPROOF-P256-CMPK-K-v1"
/// 6: message              "PicProof commitment generator K"
/// 7: SEC1 compressed K    "0267f33a...a032cf"  (lowercase hex, 33 bytes)
/// ```
///
/// `parameter_sha256` is `SHA-256` over that byte string. The concrete preimage
/// is:
///
/// ```text
/// PicProof-P256-CmPK-K-v1\n
/// P-256\n
/// XMD:SHA-256\n
/// SSWU\n
/// PICPROOF-P256-CMPK-K-v1\n
/// PicProof commitment generator K\n
/// 0267f33ad19ab684bfb58d469d1342ad2a30ea7656237ae07b8058dca8aca032cf\n
/// ```
pub fn parameter_fingerprint_input(compressed_hex: &str) -> String {
    format!(
        "{PROFILE}\n{CURVE}\n{EXPAND}\n{MAP}\n{}\n{}\n{compressed_hex}\n",
        core::str::from_utf8(DST).unwrap(),
        core::str::from_utf8(MESSAGE).unwrap(),
    )
}

/// SEC1 compressed encoding of `point` in lowercase hex.
pub fn sec1_compressed_hex(point: &ProjectivePoint) -> String {
    hex_lower(point.to_affine().to_encoded_point(true).as_bytes())
}

/// SEC1 uncompressed encoding of `point` in lowercase hex.
pub fn sec1_uncompressed_hex(point: &ProjectivePoint) -> String {
    hex_lower(point.to_affine().to_encoded_point(false).as_bytes())
}

/// Decimal x and y coordinates of `point`.
pub fn affine_decimal_coordinates(point: &ProjectivePoint) -> (String, String) {
    let encoded = point.to_affine().to_encoded_point(false);
    let (x, y) = match encoded.coordinates() {
        p256::elliptic_curve::sec1::Coordinates::Uncompressed { x, y } => (x, y),
        _ => unreachable!("uncompressed encoding always yields coordinates"),
    };
    (bytes_decimal(x), bytes_decimal(y))
}

/// Computes the canonical parameter fingerprint of the fixed `K`.
pub fn parameter_sha256() -> String {
    let mut hasher = Sha256::new();
    hasher.update(parameter_fingerprint_input(K_SEC1_COMPRESSED).as_bytes());
    hex_lower(&hasher.finalize())
}

fn bytes_decimal(bytes: &[u8]) -> String {
    let mut digits: Vec<u8> = vec![0];
    for byte in bytes {
        let mut carry = *byte as u32;
        for d in digits.iter_mut() {
            let v = (*d as u32) * 256 + carry;
            *d = (v % 10) as u8;
            carry = v / 10;
        }
        while carry > 0 {
            digits.push((carry % 10) as u8);
            carry /= 10;
        }
    }
    if digits == vec![0] {
        return "0".to_string();
    }
    digits
        .iter()
        .rev()
        .map(|d| char::from(b'0' + *d))
        .collect()
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_decode_array<const N: usize>(hex: &str) -> [u8; N] {
    assert_eq!(hex.len(), N * 2, "unexpected hex length");
    let mut out = [0u8; N];
    for (i, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let s = core::str::from_utf8(chunk).unwrap();
        out[i] = u8::from_str_radix(s, 16).unwrap();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Locks the transparent derivation to the hardcoded deployment point.
    #[test]
    fn commitment_generator_k_matches_kat() {
        let derived = derive_picproof_commitment_generator_k();
        let fixed = picproof_commitment_generator_k();
        assert_eq!(derived, fixed, "hardcoded K diverged from RFC 9380 derivation");

        assert_eq!(sec1_compressed_hex(&derived), K_SEC1_COMPRESSED);
        assert_eq!(sec1_uncompressed_hex(&derived), K_SEC1_UNCOMPRESSED);

        let (x, y) = affine_decimal_coordinates(&derived);
        assert_eq!(x, K_X_DECIMAL);
        assert_eq!(y, K_Y_DECIMAL);
    }

    #[test]
    fn parameter_fingerprint_matches_kat() {
        assert_eq!(parameter_sha256(), K_PARAMETER_SHA256);
    }

    /// The tracked KAT file is an artifact of the same derivation.
    #[test]
    fn kat_file_matches_constants() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("test_vectors/cmpk_generator_kat.json");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let kat: serde_json::Value = serde_json::from_str(&text).expect("parse KAT JSON");

        assert_eq!(kat["profile"], PROFILE);
        assert_eq!(kat["curve"], CURVE);
        assert_eq!(kat["suite"], SUITE);
        assert_eq!(kat["expand"], EXPAND);
        assert_eq!(kat["map"], MAP);
        assert_eq!(kat["dst"], core::str::from_utf8(DST).unwrap());
        assert_eq!(kat["message"], core::str::from_utf8(MESSAGE).unwrap());
        assert_eq!(kat["x_decimal"], K_X_DECIMAL);
        assert_eq!(kat["y_decimal"], K_Y_DECIMAL);
        assert_eq!(kat["sec1_compressed"], K_SEC1_COMPRESSED);
        assert_eq!(kat["sec1_uncompressed"], K_SEC1_UNCOMPRESSED);
        assert_eq!(kat["parameter_sha256"], K_PARAMETER_SHA256);
    }
}
