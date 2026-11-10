#!/usr/bin/env python3
import argparse
import hashlib
import json
import struct
from pathlib import Path

MAGIC_EXPECTED = "PICPROOF-AUTHENTICATED-REGISTRY-BUNDLE"
EXPECTED_SOURCE_SHA256 = "56a2ff77211f5945700aa818da551c2a7726281fe5c45947187f4810d89879ae"

def sha256(data):
    return hashlib.sha256(data).hexdigest()

def read_str(d, off):
    sz = struct.unpack_from("<Q", d, off)[0]
    val = d[off+8:off+8+sz].decode("utf-8")
    return val, off+8+sz

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--out-dir", required=True)
    args = parser.parse_args()

    src_path = Path(args.source).resolve()
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    data = src_path.read_bytes()
    src_sha = sha256(data)
    print(f"[MUTATOR] Source: {src_path}")
    print(f"[MUTATOR] Source bytes: {len(data)}")
    print(f"[MUTATOR] Source SHA-256: {src_sha}")
    if src_sha != EXPECTED_SOURCE_SHA256:
        raise ValueError(f"Source SHA mismatch: expected {EXPECTED_SOURCE_SHA256}, got {src_sha}")

    # Parse header fields
    off = 0
    magic, off = read_str(data, off)
    ver_off = off
    ver = struct.unpack_from("<I", data, off)[0]; off += 4
    prof, off = read_str(data, off)
    reg_id, off = read_str(data, off)
    depth = struct.unpack_from("<Q", data, off)[0]; off += 8
    digest, off = read_str(data, off)
    cm_pk_hex, off = read_str(data, off)
    leaf, off = read_str(data, off)

    print(f"[MUTATOR] Parsed header: magic={magic}, version={ver}, depth={depth}, digest={digest}")
    if magic != MAGIC_EXPECTED or ver != 2:
        raise ValueError("Unexpected header format")

    meta = {
        "source": str(src_path),
        "source_sha256": src_sha,
        "package_header": {
            "magic": magic,
            "version": ver,
            "profile": prof,
            "registry_id": reg_id,
            "depth": depth,
            "digest_sha256_hex": digest,
            "cm_pk_encoded_hex": cm_pk_hex,
            "leaf_decimal": leaf,
        },
        "mutations": {}
    }

    # F21: Mutate version from 2 to 999
    f21_data = bytearray(data)
    struct.pack_into("<I", f21_data, ver_off, 999)
    f21_path = out_dir / "F21_version_999.bundle"
    f21_path.write_bytes(f21_data)
    meta["mutations"]["F21"] = {
        "file": str(f21_path.name),
        "sha256": sha256(f21_data),
        "size": len(f21_data),
        "target": f"version at offset {ver_off} set to 999",
    }
    print(f"[MUTATOR] Wrote {f21_path.name} ({len(f21_data)} bytes)")

    # F22: Truncate to 100 bytes
    f22_data = data[:100]
    f22_path = out_dir / "F22_truncated_100bytes.bundle"
    f22_path.write_bytes(f22_data)
    meta["mutations"]["F22"] = {
        "file": str(f22_path.name),
        "sha256": sha256(f22_data),
        "size": len(f22_data),
        "target": "truncated to exactly 100 bytes",
    }
    print(f"[MUTATOR] Wrote {f22_path.name} ({len(f22_data)} bytes)")

    # F23: Append 64 bytes trailing garbage DEADBEEF...
    f23_data = data + bytes.fromhex("DEADBEEF" * 16)
    f23_path = out_dir / "F23_trailing_garbage.bundle"
    f23_path.write_bytes(f23_data)
    meta["mutations"]["F23"] = {
        "file": str(f23_path.name),
        "sha256": sha256(f23_data),
        "size": len(f23_data),
        "target": "appended 64 trailing bytes of 0xDEADBEEF",
    }
    print(f"[MUTATOR] Wrote {f23_path.name} ({len(f23_data)} bytes)")

    # F24: Invalid SEC1 point in sigma_proof.cm_pk[0]
    # Locate sigma_proof.cm_pk[0] in bytes
    c0_bytes = bytes.fromhex(cm_pk_hex[:66])
    needle_c0 = struct.pack("<Q", 33) + c0_bytes
    if data.count(needle_c0) != 1:
        raise ValueError(f"needle_c0 count {data.count(needle_c0)} != 1")
    c0_idx = data.index(needle_c0)
    # Payload is 33 bytes starting at c0_idx + 8
    # Replace with prefix 0x02 + 32 bytes 0xFF (not on curve)
    bad_point = bytes.fromhex("02" + "FF"*32)
    f24_data = bytearray(data)
    f24_data[c0_idx+8 : c0_idx+8+33] = bad_point
    f24_path = out_dir / "F24_invalid_sec1_cm_pk0.bundle"
    f24_path.write_bytes(f24_data)
    meta["mutations"]["F24"] = {
        "file": str(f24_path.name),
        "sha256": sha256(f24_data),
        "size": len(f24_data),
        "target": f"sigma_proof.cm_pk[0] at offset {c0_idx+8} replaced with non-curve 0x02||0xFF*32",
    }
    print(f"[MUTATOR] Wrote {f24_path.name} ({len(f24_data)} bytes)")

    meta_path = out_dir / "mutation_metadata.json"
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"[MUTATOR] Wrote {meta_path.name}")
    print("[MUTATOR] PASS: all 4 independent mutants generated")

if __name__ == "__main__":
    main()
