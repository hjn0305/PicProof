//! PicProof Manifest v1 fixed CBOR profile shared by the JISA prover and
//! the standalone verifier.
//!
//! The manifest is produced by `encode_picproof_manifest_v1` in
//! `jisa_unified_e2e` under this exact byte layout:
//!
//! ```text
//! map(5) {
//!   "algorithm"   : "sha-256"
//!   "digest"      : bytes(32)   // H_img = SHA-256(image)
//!   "image_bytes" : uint
//!   "salt"        : bytes(16)   // per-manifest nonce, NOT part of H_img
//!   "timestamp"   : uint
//! }
//! ```
//!
//! PicProof Manifest v1 fixed CBOR profile.
//!
//! Encoding rules:
//! - definite-length RFC 8949 CBOR items;
//! - fixed five-field schema and protocol-defined field order;
//! - preferred/minimal unsigned-integer encodings;
//! - exact byte/string lengths required by the profile;
//! - no trailing bytes.
//!
//! This profile is protocol-specific and is not described as the
//! RFC 8949 deterministic/canonical map-order profile.

#![allow(dead_code)]

/// Lowercase hex encoding helper shared by the JISA binaries.
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Rebuild the canonical 32-byte H_img proven by the Decider from the
/// decimal `h_hi` / `h_lo` u128 halves of the package public instance.
///
/// Prover side: digest[0..16] -> h_hi, digest[16..32] -> h_lo (big-endian).
pub fn public_digest_bytes(h_hi: &str, h_lo: &str) -> Result<[u8; 32], String> {
    let hi: u128 = h_hi.parse().map_err(|_| "Invalid h_hi u128")?;
    let lo: u128 = h_lo.parse().map_err(|_| "Invalid h_lo u128")?;

    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&hi.to_be_bytes());
    out[16..].copy_from_slice(&lo.to_be_bytes());
    Ok(out)
}

/// Strictly-parsed PicProof Manifest v1 fixed CBOR profile.
#[derive(Debug)]
/// Parsed PicProof Manifest v1 fields.
pub struct ManifestV1 {
    /// H_img = SHA-256(image), 32 bytes.
    pub digest: [u8; 32],
    /// Declared size of the signed media, in bytes.
    pub image_bytes: u64,
    /// Per-manifest diversification nonce; NOT part of H_img.
    pub salt: [u8; 16],
    /// Unix timestamp captured when the manifest was built.
    pub timestamp: u64,
}

/// Assert that `expected` occurs at `*pos` and advance the cursor.
pub fn expect_bytes(input: &[u8], pos: &mut usize, expected: &[u8]) -> Result<(), String> {
    if input.get(*pos..*pos + expected.len()) != Some(expected) {
        return Err(format!("Manifest CBOR mismatch at offset {}", *pos));
    }
    *pos += expected.len();
    Ok(())
}

/// Read a minimally-encoded CBOR unsigned integer, rejecting non-minimal forms.
pub fn read_canonical_cbor_uint(input: &[u8], pos: &mut usize) -> Result<u64, String> {
    let b = *input
        .get(*pos)
        .ok_or("Unexpected EOF while reading CBOR uint")?;
    *pos += 1;

    let major = b >> 5;
    let ai = b & 0x1f;

    if major != 0 {
        return Err("Expected unsigned CBOR integer".into());
    }

    match ai {
        0..=23 => Ok(ai as u64),
        24 => {
            let v = *input.get(*pos).ok_or("Truncated CBOR uint8")?;
            *pos += 1;
            if v < 24 {
                return Err("Non-minimal CBOR uint8".into());
            }
            Ok(v as u64)
        }
        25 => {
            let bytes = input.get(*pos..*pos + 2).ok_or("Truncated CBOR uint16")?;
            *pos += 2;
            let v = u16::from_be_bytes([bytes[0], bytes[1]]) as u64;
            if v <= u8::MAX as u64 {
                return Err("Non-minimal CBOR uint16".into());
            }
            Ok(v)
        }
        26 => {
            let bytes = input.get(*pos..*pos + 4).ok_or("Truncated CBOR uint32")?;
            *pos += 4;
            let v = u32::from_be_bytes(bytes.try_into().unwrap()) as u64;
            if v <= u16::MAX as u64 {
                return Err("Non-minimal CBOR uint32".into());
            }
            Ok(v)
        }
        27 => {
            let bytes = input.get(*pos..*pos + 8).ok_or("Truncated CBOR uint64")?;
            *pos += 8;
            let v = u64::from_be_bytes(bytes.try_into().unwrap());
            if v <= u32::MAX as u64 {
                return Err("Non-minimal CBOR uint64".into());
            }
            Ok(v)
        }
        _ => Err("Unsupported/indefinite CBOR integer".into()),
    }
}

/// Parse the camera-signed manifest under the exact PicProof Manifest v1
/// fixed CBOR profile:
/// map(5) { algorithm:"sha-256", digest:bytes(32), image_bytes:uint,
///          salt:bytes(16), timestamp:uint }
///
/// Key order, types, integer encodings and extra fields are all rejected
/// unless they match this profile byte-for-byte.
pub fn parse_manifest_v1(input: &[u8]) -> Result<ManifestV1, String> {
    let mut pos = 0usize;

    // map(5)
    expect_bytes(input, &mut pos, &[0xA5])?;

    // "algorithm" -> "sha-256"
    expect_bytes(input, &mut pos, b"\x69algorithm")?;
    expect_bytes(input, &mut pos, b"\x67sha-256")?;

    // "digest" -> bytes(32)
    expect_bytes(input, &mut pos, b"\x66digest")?;
    expect_bytes(input, &mut pos, &[0x58, 0x20])?;

    let digest_slice = input
        .get(pos..pos + 32)
        .ok_or("Truncated manifest digest")?;

    let mut digest = [0u8; 32];
    digest.copy_from_slice(digest_slice);
    pos += 32;

    // "image_bytes" -> uint
    expect_bytes(input, &mut pos, b"\x6bimage_bytes")?;
    let image_bytes = read_canonical_cbor_uint(input, &mut pos)?;

    // "salt" -> bytes(16)
    expect_bytes(input, &mut pos, b"\x64salt")?;
    expect_bytes(input, &mut pos, &[0x50])?;

    let salt_slice = input.get(pos..pos + 16).ok_or("Truncated manifest salt")?;

    let mut salt = [0u8; 16];
    salt.copy_from_slice(salt_slice);
    pos += 16;

    // "timestamp" -> uint
    expect_bytes(input, &mut pos, b"\x69timestamp")?;
    let timestamp = read_canonical_cbor_uint(input, &mut pos)?;

    if pos != input.len() {
        return Err(format!(
            "Trailing bytes in PicProof Manifest v1: {}",
            input.len() - pos
        ));
    }

    Ok(ManifestV1 {
        digest,
        image_bytes,
        salt,
        timestamp,
    })
}
