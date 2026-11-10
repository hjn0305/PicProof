#!/usr/bin/env python3
"""
Media Byte Extraction and SHA-256 Calculation based on C2PA c2pa.hash.data Exclusions.
"""
import sys
import json
import hashlib
from pathlib import Path

def extract_bound_bytes(signed_bytes: bytes, exclusions: list) -> bytes:
    """Extract media bytes excluding JUMBF/manifest ranges as specified in c2pa.hash.data."""
    parts = []
    cursor = 0
    for item in exclusions:
        start = int(item["start"])
        length = int(item["length"])
        assert start >= cursor, f"Exclusion start {start} precedes cursor {cursor}"
        assert length > 0, "Exclusion length must be positive"
        assert start + length <= len(signed_bytes), "Exclusion exceeds container bounds"
        parts.append(signed_bytes[cursor:start])
        cursor = start + length
    parts.append(signed_bytes[cursor:])
    return b"".join(parts)

def compute_media_digest(bound_bytes: bytes) -> str:
    """Compute SHA-256 digest of extracted media bytes (hex string)."""
    return hashlib.sha256(bound_bytes).hexdigest()

def verify_media_hash(signed_bytes: bytes, exclusions: list, expected_hex: str) -> bool:
    bound = extract_bound_bytes(signed_bytes, exclusions)
    actual = compute_media_digest(bound)
    return actual.lower() == expected_hex.lower()

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python check_datahash.py <signed.jpg> <binding.json>")
        sys.exit(1)
    signed = Path(sys.argv[1]).read_bytes()
    info = json.loads(Path(sys.argv[2]).read_text())
    exclusions = info["exclusions"]
    expected = info["hash_hex"]
    bound = extract_bound_bytes(signed, exclusions)
    actual = compute_media_digest(bound)
    print(f"Container size:   {len(signed)} bytes")
    print(f"Bound media size: {len(bound)} bytes")
    print(f"Expected SHA256:  {expected}")
    print(f"Actual SHA256:    {actual}")
    print(f"Match:            {actual == expected}")
