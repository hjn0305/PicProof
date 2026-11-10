# JISA / PicProof package v3 - FINAL 12-point negative regression matrix.
#
# Canonical paper-facing tamper matrix. Every test mutates exactly one
# artifact of an otherwise valid package and asserts the standalone verifier
# REJECTS it at the expected binding layer.
#
# T01 external trusted root     -> root binding
# T02 pi_final                  -> Decider
# T03 pi_sigma                  -> Sigma
# T04 pi_merkle                 -> Spartan / deserialize
# T05 registration_leaf         -> derived leaf mismatch
# T06 cmPK                      -> derived cmPK mismatch
# T07 h_hi                      -> Decider
# T08 num_blocks                -> Decider (circuit shape)
# T09 manifest.digest           -> H_img == Manifest.digest
# T10 manifest.salt + audit hash-> Sigma over new H_CBOR
# T11 cbor_manifest_hash only   -> audit consistency
# T12 wrong --image             -> media <-> proven digest
#
# Usage:
#   python3 tests/final_v3_negatives.py \
#     --package   <pkg> \
#     --verifier-key <dvk> \
#     --trusted-root <root-decimal> \
#     --image <media-file>

import argparse
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
import time

VERIFIER = "/root/autodl-tmp/sonobe-decider/target/release/jisa_package_verify"

# --------------------------------------------------------------------------
# bincode 1.3 (fixint, little-endian) package layout
# --------------------------------------------------------------------------

def parse_layout(d):
    p = 0
    def u32():
        nonlocal p
        v = struct.unpack_from("<I", d, p)[0]
        p += 4
        return v
    def u64():
        nonlocal p
        v = struct.unpack_from("<Q", d, p)[0]
        p += 8
        return v
    def vec():
        nonlocal p
        n = u64()
        s = p
        p += n
        return {"off": s, "len": n}

    lay = {}
    lay["version_off"] = p
    lay["version"] = u32()
    lay["num_blocks_off"] = p
    lay["num_blocks"] = u64()
    lay["h_hi"] = vec()
    lay["h_lo"] = vec()
    lay["cbor_manifest_hash"] = vec()
    lay["cm_pk_c0"] = vec()
    lay["cm_pk_c1"] = vec()
    lay["registration_leaf"] = vec()
    lay["merkle_root"] = vec()
    lay["manifest_cbor"] = vec()
    lay["pi_final"] = vec()
    lay["pi_sigma"] = vec()
    lay["pi_merkle"] = vec()
    lay["meta_image_bytes_off"] = p
    lay["meta_image_bytes"] = u64()
    lay["meta_sha256_blocks"] = u64()
    lay["meta_cbor_bytes"] = u64()
    lay["meta_merkle_depth"] = u64()
    lay["meta_timestamp"] = u64()
    lay["end"] = p
    return lay


def field_bytes(d, f):
    return bytes(d[f["off"]:f["off"] + f["len"]])


# --------------------------------------------------------------------------
# mutation helpers
# --------------------------------------------------------------------------

def flip_last_digit(d, f):
    """Flip the last ASCII decimal digit, preserving magnitude and length."""
    b = bytearray(d)
    for i in range(f["len"] - 1, -1, -1):
        c = b[f["off"] + i]
        if 0x30 <= c <= 0x39:
            b[f["off"] + i] = 0x30 + ((c - 0x30 + 1) % 10)
            return bytes(b)
    raise RuntimeError("no decimal digit found to flip")


def flip_byte_in_vec(d, f, rel=0):
    b = bytearray(d)
    if f["len"] == 0:
        raise RuntimeError("empty vector")
    b[f["off"] + rel] ^= 0x01
    return bytes(b)


def _cbor_text(s):
    """CBOR text-string (major type 3) header + payload."""
    n = len(s)
    if n < 24:
        return bytes([0x60 | n]) + s.encode()
    raise RuntimeError("manifest keys longer than 23 bytes unsupported")


def manifest_marker(man, key):
    """Return payload offset of key inside the canonical manifest."""
    kb = _cbor_text(key)
    i = man.find(kb)
    if i < 0:
        raise RuntimeError("manifest key '%s' not found" % key)
    j = i + len(kb)
    # value header: byte-string (major 2) or unsigned int (major 0)
    hdr = man[j]
    if (hdr >> 5) == 2:
        ai = hdr & 0x1F
        if ai < 24:
            return j + 1
        if ai == 24:
            return j + 2
        if ai == 25:
            return j + 3
        if ai == 26:
            return j + 5
        if ai == 27:
            return j + 9
        raise RuntimeError("indefinite CBOR length not supported")
    return j


def flip_manifest_field(d, lay, key, rel=0):
    """Flip one payload byte of a manifest field; returns (new_bytes, new_manifest)."""
    mf = lay["manifest_cbor"]
    man = bytearray(field_bytes(d, mf))
    po = manifest_marker(bytes(man), key)
    man[po + rel] ^= 0x01
    b = bytearray(d)
    b[mf["off"]:mf["off"] + mf["len"]] = man
    return bytes(b), bytes(man)


def rewrite_audit_hash(d, lay, new_man):
    """Overwrite cbor_manifest_hash with hex(SHA-256(new_man)) in place."""
    hf = lay["cbor_manifest_hash"]
    old = field_bytes(d, hf)
    new = hashlib.sha256(new_man).hexdigest().encode()
    if len(new) != len(old):
        raise RuntimeError("audit hash length changed")
    b = bytearray(d)
    b[hf["off"]:hf["off"] + hf["len"]] = new
    return bytes(b)


# --------------------------------------------------------------------------
# verifier driver
# --------------------------------------------------------------------------

def run_verifier(pkg_path, trusted_root, vkey, image=None):
    cmd = [
        VERIFIER,
        "--proof", pkg_path,
        "--trusted-root", str(trusted_root),
        "--verifier-key", vkey,
    ]
    if image:
        cmd += ["--image", image]
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def first_reason(out, needle):
    errs = []
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("Error:"):
            errs.append(s)
    for e in errs:
        if needle.lower() in e.lower():
            return e
    if errs:
        return errs[0]
    for line in out.splitlines():
        if needle.lower() in line.lower():
            return line.strip()
    return ""


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--package", required=True)
    ap.add_argument("--verifier-key", required=True)
    ap.add_argument("--trusted-root", default=None)
    ap.add_argument("--image", default=None)
    ap.add_argument("--out-json", default=None)
    ap.add_argument("--out-txt", default=None)
    args = ap.parse_args()

    package = args.package
    vkey = args.verifier_key
    image = args.image

    trusted_root = args.trusted_root
    if not trusted_root:
        ts = "/root/picproof_exp/final_enrollment/tree16/trusted_statement_16.json"
        with open(ts) as f:
            trusted_root = json.load(f)["root"]

    d0 = bytearray(open(package, "rb").read())
    lay = parse_layout(d0)

    print("============================================================")
    print(" [JISA / PicProof package v3] FINAL 12-POINT NEGATIVE MATRIX")
    print(" Package:      %s" % package)
    print(" Verifier key: %s" % vkey)
    print(" Trusted root: %s" % trusted_root)
    print(" Version:      %d   (blocks=%d, manifest=%d B)" % (
        lay["version"], lay["num_blocks"], lay["manifest_cbor"]["len"]))
    print("============================================================")

    tmpdir = tempfile.mkdtemp(prefix="picproof_v3_neg_")

    def w(name, data):
        p = os.path.join(tmpdir, name)
        with open(p, "wb") as f:
            f.write(data)
        return p

    # --- build all 12 tampered artifacts --------------------------------
    t01_pkg = package
    t01_root = str(int(trusted_root) + 1)

    t02_pkg = w("t02_pi_final.pkg", flip_byte_in_vec(d0, lay["pi_final"], 200))
    t03_pkg = w("t03_pi_sigma.pkg", flip_byte_in_vec(d0, lay["pi_sigma"], 10))
    t04_pkg = w("t04_pi_merkle.pkg", flip_byte_in_vec(d0, lay["pi_merkle"], 100))
    t05_pkg = w("t05_leaf.pkg", flip_last_digit(d0, lay["registration_leaf"]))
    t06_pkg = w("t06_cmpk.pkg", flip_byte_in_vec(d0, lay["cm_pk_c0"], 5))

    b07 = bytearray(d0)
    struct.pack_into("<Q", b07, lay["num_blocks_off"], lay["num_blocks"] + 1)
    t07_pkg = w("t07_num_blocks.pkg", bytes(b07))

    t08_pkg = w("t08_h_hi.pkg", flip_last_digit(d0, lay["h_hi"]))

    t09_bytes, _ = flip_manifest_field(d0, lay, "digest", 0)
    t09_pkg = w("t09_manifest_digest.pkg", t09_bytes)

    t10_bytes, t10_man = flip_manifest_field(d0, lay, "salt", 0)
    t10_bytes = rewrite_audit_hash(t10_bytes, lay, t10_man)
    t10_pkg = w("t10_manifest_salt.pkg", t10_bytes)

    hf = lay["cbor_manifest_hash"]
    b11 = bytearray(d0)
    b11[hf["off"]] = ord("f") if b11[hf["off"]] != ord("f") else ord("e")
    t11_pkg = w("t11_audit_hash.pkg", bytes(b11))

    wrong_img = os.path.join(tmpdir, "t12_wrong.bin")
    with open(wrong_img, "wb") as f:
        f.write(b"\x00" * 64)

    # --- test table ------------------------------------------------------
    # (id, name, layer, pkg, trusted_root_override, image_override, needle)
    tests = [
        ("T01", "trusted_root_tamper", "root binding",
         t01_pkg, t01_root, image, "external trusted root"),
        ("T02", "pi_final_tamper", "Decider",
         t02_pkg, None, image, "Decider"),
        ("T03", "pi_sigma_tamper", "Sigma",
         t03_pkg, None, image, "sigma"),
        ("T04", "pi_merkle_tamper", "Spartan/deserialize",
         t04_pkg, None, image, "merkle"),
        ("T05", "registration_leaf_tamper", "derived leaf mismatch",
         t05_pkg, None, image, "Registration leaf mismatch"),
        ("T06", "cmPK_tamper", "derived cmPK mismatch",
         t06_pkg, None, image, "cmPK"),
        ("T07", "h_hi_tamper", "Decider",
         t08_pkg, None, image, "Decider"),
        ("T08", "num_blocks_tamper", "Decider",
         t07_pkg, None, image, "Decider"),
        ("T09", "manifest_digest_tamper", "H_img == Manifest.digest",
         t09_pkg, None, image, "Manifest digest does not match"),
        ("T10", "manifest_salt_tamper_audit_updated", "Sigma over new H_CBOR",
         t10_pkg, None, image, "sigma"),
        ("T11", "audit_hash_tamper", "audit consistency",
         t11_pkg, None, image, "cbor_manifest_hash"),
        ("T12", "wrong_media", "media <-> proven digest",
         t01_pkg, None, wrong_img, "Supplied media does not match"),
    ]

    results = []
    print("")
    for tid, name, layer, pkg, root_ovr, img, needle in tests:
        root = root_ovr or trusted_root
        rc, out = run_verifier(pkg, root, vkey, img)
        rejected = rc != 0
        reason = first_reason(out, needle)
        matched = needle.lower() in out.lower()
        ok = rejected and matched
        results.append({
            "id": tid,
            "name": name,
            "expected_layer": layer,
            "rejected": bool(rejected),
            "expected_reason_matched": bool(matched),
            "reason": reason,
            "passed": bool(ok),
        })
        verdict = "REJECT PASS" if ok else ("ACCEPT FAIL" if not rejected else "REASON FAIL")
        print("%s %-36s %s" % (tid, name, verdict))
        if reason:
            print("       -> rc=%d  %s" % (rc, reason))

    total = len(results)
    rejected_n = sum(1 for r in results if r["rejected"] and r["expected_reason_matched"])
    all_pass = rejected_n == total

    print("")
    print("============================================================")
    print(" SUMMARY: %d/%d targeted tampering tests rejected" % (rejected_n, total))
    print("============================================================")

    report = {
        "profile": "PicProof package v3",
        "total": total,
        "rejected": rejected_n,
        "passed": all_pass,
        "timestamp": time.time(),
        "tests": results,
    }

    out_json = args.out_json or os.path.join(tmpdir, "final_v3_negatives.json")
    with open(out_json, "w") as f:
        json.dump(report, f, indent=2)
    print("Saved JSON report to %s" % out_json)

    txt = "EXIT=%d" % (0 if all_pass else 1)
    print(txt)
    if args.out_txt:
        with open(args.out_txt, "w") as f:
            f.write(("%d/%d\n" % (rejected_n, total)))
    if all_pass:
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
