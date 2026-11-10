//! Derives the PicProof commitment generator `K` via RFC 9380 hash-to-curve and
//! writes `test_vectors/cmpk_generator_kat.json`.
//!
//! Profile: PicProof-P256-CmPK-K-v1
//!   curve   : P-256
//!   suite   : P256_XMD:SHA-256_SSWU_RO_
//!   expand  : XMD:SHA-256
//!   map     : SSWU (random oracle)
//!   dst     : PICPROOF-P256-CMPK-K-v1
//!   message : PicProof commitment generator K
//!
//! The commitment is `cm_PK = (vG, PK + vK)`, while `L = G` is the standard
//! P-256 generator.
//!
//! Run with:
//!   cargo run --release --example derive_cmpk_generator

use std::fs;
use std::path::Path;

use circ::ecdsa::picproof_k::{
    affine_decimal_coordinates, derive_picproof_commitment_generator_k, parameter_fingerprint_input,
    sec1_compressed_hex, sec1_uncompressed_hex, CURVE, DST, EXPAND, MAP, MESSAGE, PROFILE, SUITE,
};
use sha2::{Digest, Sha256};

fn main() {
    let k = derive_picproof_commitment_generator_k();

    let (x_decimal, y_decimal) = affine_decimal_coordinates(&k);
    let compressed = sec1_compressed_hex(&k);
    let uncompressed = sec1_uncompressed_hex(&k);

    let fingerprint_input = parameter_fingerprint_input(&compressed);
    let parameter_sha256 = hex_lower(&Sha256::digest(fingerprint_input.as_bytes()));

    println!("profile = {PROFILE}");
    println!("curve = {CURVE}");
    println!("suite = {SUITE}");
    println!("expand = {EXPAND}");
    println!("map = {MAP}");
    println!("dst = {}", core::str::from_utf8(DST).unwrap());
    println!("message = {}", core::str::from_utf8(MESSAGE).unwrap());
    println!();
    println!("x_decimal = {x_decimal}");
    println!("y_decimal = {y_decimal}");
    println!("sec1_compressed = {compressed}");
    println!("sec1_uncompressed = {uncompressed}");
    println!("parameter_sha256 = {parameter_sha256}");

    let kat = format!(
        "{{\n\
         \x20 \"profile\": \"{PROFILE}\",\n\
         \x20 \"curve\": \"{CURVE}\",\n\
         \x20 \"suite\": \"{SUITE}\",\n\
         \x20 \"expand\": \"{EXPAND}\",\n\
         \x20 \"map\": \"{MAP}\",\n\
         \x20 \"dst\": \"{}\",\n\
         \x20 \"message\": \"{}\",\n\
         \x20 \"x_decimal\": \"{x_decimal}\",\n\
         \x20 \"y_decimal\": \"{y_decimal}\",\n\
         \x20 \"sec1_compressed\": \"{compressed}\",\n\
         \x20 \"sec1_uncompressed\": \"{uncompressed}\",\n\
         \x20 \"parameter_sha256\": \"{parameter_sha256}\"\n\
         }}\n",
        core::str::from_utf8(DST).unwrap(),
        core::str::from_utf8(MESSAGE).unwrap(),
    );

    let out = Path::new("test_vectors/cmpk_generator_kat.json");
    if let Some(parent) = out.parent() {
        fs::create_dir_all(parent).expect("create test_vectors directory");
    }
    fs::write(out, kat).expect("write KAT file");
    println!();
    println!("wrote {}", out.display());
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
