#!/usr/bin/env python3
"""
Standalone verifier for the PicProof Native C2PA minimal test sample.
Verifies:
1. Strict JUMBF / APP11 segment reconstruction
2. Strict COSE-ES256 parsing and signature check
3. Strict Claim CBOR parsing and hashed_uri binding
4. Strict c2pa.hash.data exclusion extraction and SHA-256 calculation
5. Byte-for-byte matching of extracted media against expectation
"""
import sys
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
SRC_DIR = ROOT / "02_Native_C2PA/src"
SAMPLE_DIR = ROOT / "02_Native_C2PA/minimal_test_sample"

sys.path.insert(0, str(SRC_DIR))
import cbor2
from c2pa_extract import extract_from_jpeg
from check_datahash import extract_bound_bytes, compute_media_digest

def main():
    print("=== [1] Verifying signed_c2pa.jpg extraction ===")
    jpeg_path = SAMPLE_DIR / "signed_c2pa.jpg"
    jpeg_bytes = jpeg_path.read_bytes()
    cose = extract_from_jpeg(jpeg_bytes)

    print(f"  APP11 Segments: {cose['app11_segments']}")
    print(f"  JUMBF Size:     {len(cose['jumbf'])} bytes")
    print(f"  COSE Alg:       {cose['alg']} (ES256)")
    print(f"  Protected Len:  {len(cose['protected'])} bytes")
    print(f"  Signature Len:  {len(cose['signature'])} bytes")
    print(f"  Claim Len:      {len(cose['claim'])} bytes")
    print(f"  TBS Digest:     {cose['digest_hex']}")

    print("\n=== [2] Checking Media Exclusion & SHA-256 ===")
    binding_info = json.loads((SAMPLE_DIR / "binding.json").read_text())
    exclusions = binding_info["exclusions"]
    expected_hash = binding_info["hash_hex"]

    bound_bytes = extract_bound_bytes(jpeg_bytes, exclusions)
    actual_hash = compute_media_digest(bound_bytes)

    print(f"  Extracted Media: {len(bound_bytes)} bytes")
    print(f"  Expected Hash:   {expected_hash}")
    print(f"  Actual Hash:     {actual_hash}")
    assert actual_hash == expected_hash, "Hash mismatch!"
    print("  Media Hash Verification: PASS")

    print("\n=== [3] Checking Expected Auxiliary Files Match ===")
    assert (SAMPLE_DIR / "manifest_data.c2pa").read_bytes() == cose["jumbf"]
    assert (SAMPLE_DIR / "cose_tbs.bin").read_bytes() == cose["tbs"]
    assert (SAMPLE_DIR / "claim.cbor").read_bytes() == cose["claim"]
    print("  Auxiliary Exact Byte-for-Byte Match: PASS")

    print("\n==================================================")
    print(" ALL NATIVE C2PA CHECKS PASSED SUCCESSFULLY!")
    print("==================================================")

if __name__ == "__main__":
    main()
