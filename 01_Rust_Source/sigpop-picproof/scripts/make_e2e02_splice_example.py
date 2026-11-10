#!/usr/bin/env python3
"""Add-only splice-builder example generated from the local, tested Phase 2 verifier source.

Never overwrites the existing authenticator example or core Rust modules.
"""
from pathlib import Path
import sys

if len(sys.argv) != 2:
    sys.exit('Usage: python3 scripts/make_e2e02_splice_example.py /path/to/circ/project')
root = Path(sys.argv[1]).resolve()
src = root / 'examples/picproof_authenticated_registry.rs'
dst = root / 'examples/picproof_e2e02_splice.rs'
if not src.is_file():
    sys.exit(f'ERROR: original verifier source missing: {src}')
if dst.exists():
    sys.exit(f'ERROR: destination already exists; refusing to overwrite: {dst}')
s = src.read_text(encoding='utf-8')
insert_before = 'fn print_usage() {'
new_arm_anchor = '        "verify" => run_verify(&args[2..]),'
if s.count(insert_before) != 1 or s.count(new_arm_anchor) != 1:
    sys.exit('ERROR: unexpected existing source layout; no file written')
if 'fn run_e2e02_splice' in s:
    sys.exit('ERROR: splice implementation already exists; no file written')

addition = r'''
// E2E-02 test-only tool: construct genuine cross-device proof splices.
// The ORIGINAL compiled Phase 2 verifier independently tests the output bundles.
// This tool is not a production verifier and must never overwrite existing files.
fn e2e02_read_baseline(
    path: &str,
    digest: &str,
    pin: &str,
    params: &spartan_merkle_linked::P256PoseidonParams,
) -> Result<AuthenticatedPicProofPackage, String> {
    let meta = fs::metadata(path).map_err(|e| format!("Cannot stat baseline '{path}': {e}"))?;
    if meta.len() > MAX_AUTHENTICATED_PACKAGE_BYTES as u64 {
        return Err(format!("Baseline exceeds max package bytes: {path}"));
    }
    let bytes = fs::read(path).map_err(|e| format!("Cannot read baseline '{path}': {e}"))?;
    let package: AuthenticatedPicProofPackage =
        catch_unwind(AssertUnwindSafe(|| bincode::deserialize(&bytes)))
            .map_err(|_| format!("Deserialization panic for baseline '{path}'"))?
            .map_err(|e| format!("Cannot decode baseline '{path}': {e}"))?;
    verify_authenticated_bundle(&package, digest, pin, params)
        .map_err(|e| format!("Baseline '{path}' is not valid: {e}"))?;
    Ok(package)
}

fn e2e02_create_new(path: &str, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| format!("Refusing to overwrite or create '{path}': {e}"))?;
    file.write_all(bytes)
        .map_err(|e| format!("Cannot write spliced bundle '{path}': {e}"))?;
    file.sync_all().map_err(|e| format!("Cannot sync spliced bundle '{path}': {e}"))?;
    Ok(())
}

fn run_e2e02_splice(args: &[String]) -> Result<(), String> {
    let path_a = get_arg(args, "--proof-a").ok_or("Missing --proof-a")?;
    let path_b = get_arg(args, "--proof-b").ok_or("Missing --proof-b")?;
    let digest = get_arg(args, "--digest-hex").ok_or("Missing --digest-hex")?;
    let pin_path = get_arg(args, "--trusted-ca-fingerprint").ok_or("Missing --trusted-ca-fingerprint")?;
    let output_ab = get_arg(args, "--out-ab").ok_or("Missing --out-ab")?;
    let output_ba = get_arg(args, "--out-ba").ok_or("Missing --out-ba")?;
    if output_ab == output_ba || output_ab == path_a || output_ab == path_b
        || output_ba == path_a || output_ba == path_b || path_a == path_b {
        return Err("Input/output paths must all be distinct".into());
    }
    if Path::new(&output_ab).exists() || Path::new(&output_ba).exists() {
        return Err("Refusing to overwrite existing splice output".into());
    }
    let pin = read_trust_pin(&pin_path)?;
    let params = load_verified_poseidon_params()?;
    let mut a = e2e02_read_baseline(&path_a, &digest, &pin, &params)?;
    let mut b = e2e02_read_baseline(&path_b, &digest, &pin, &params)?;
    if a.signed_registry_root != b.signed_registry_root
        || a.registry_id != b.registry_id || a.depth != b.depth
        || a.digest_sha256_hex != b.digest_sha256_hex {
        return Err("A and B must share the same signed registry and external digest".into());
    }
    if a.cm_pk_encoded_hex == b.cm_pk_encoded_hex || a.leaf_decimal == b.leaf_decimal {
        return Err("A and B must be distinct registered devices".into());
    }
    // Exchange ONLY the genuine Spartan NIZK objects. All other fields stay as-is.
    // As a result, A keeps Sigma_A, cmPK_A and leaf_A but carries Spartan_B;
    // B keeps Sigma_B, cmPK_B and leaf_B but carries Spartan_A.
    std::mem::swap(&mut a.spartan_proof, &mut b.spartan_proof);
    let bytes_ab = bincode::serialize(&a)
        .map_err(|e| format!("Cannot serialize A+Spartan_B: {e}"))?;
    let bytes_ba = bincode::serialize(&b)
        .map_err(|e| format!("Cannot serialize B+Spartan_A: {e}"))?;
    if bytes_ab.len() > MAX_AUTHENTICATED_PACKAGE_BYTES || bytes_ba.len() > MAX_AUTHENTICATED_PACKAGE_BYTES {
        return Err("Spliced packages exceed maximum allowed size".into());
    }
    e2e02_create_new(&output_ab, &bytes_ab)?;
    e2e02_create_new(&output_ba, &bytes_ba)?;
    println!("[E2E-02] BASELINE A verified; BASELINE B verified; both use same CA root/digest");
    println!("[E2E-02] WROTE Sigma_A+Spartan_B: {output_ab} ({} bytes)", bytes_ab.len());
    println!("[E2E-02] WROTE Sigma_B+Spartan_A: {output_ba} ({} bytes)", bytes_ba.len());
    Ok(())
}

'''
s = s.replace(insert_before, addition + insert_before, 1)
s = s.replace(new_arm_anchor, new_arm_anchor + '\n        "splice" => run_e2e02_splice(&args[2..]),', 1)
# Preserve tested Phase 2 verification implementation exactly: only a new standalone example is generated.
dst.write_text(s, encoding='utf-8')
print(f'[E2E-02] New add-only source: {dst}')
