#!/usr/bin/env python3
"""E5-B Hard Binding 提取适配器。

复用 E5-A 的严格解析器（c2pa_extract.py），不重新实现 JPEG/JUMBF/COSE 解析。
从当前签名 JPEG 导出：
  public/manifest_data.c2pa  原生 Manifest Store
  public/claim.cbor          原始 Claim CBOR（被 COSE 签名保护）
  public/cose_tbs.bin        COSE Sig_structure
  public/binding.json        Hard Binding 断言元数据

认证链：
  COSE 有效签名 -> 原始 Claim -> Claim 引用的断言完整性
  -> Hard Binding 断言 -> 媒体摘要
"""

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, "/root/autodl-tmp/PicProof_E5/scripts")

import cbor2
from c2pa_extract import C2PAExtractError, extract_from_jpeg, walk_boxes

ROOT = Path(__file__).resolve().parent.parent
SIGNED = ROOT / "private" / "signed_c2pa.jpg"
PUB = ROOT / "public"


def jumd_label(desc):
    """从 jumd 描述盒内容提取 label（尾部 UTF-8，NUL 结尾）。"""
    body = desc[:-1] if desc.endswith(b"\x00") else desc
    i = len(body)
    while i > 0 and 32 <= body[i - 1] < 127:
        i -= 1
    return body[i:].decode("ascii", "replace")


def build_label_index(raw):
    """返回 [(superbox_offset, superbox_size, first_child_offset)]。"""
    boxes = walk_boxes(raw)
    out = []
    for b in boxes:
        if b["type"] != "jumb":
            continue
        off, size = b["offset"], b["size"]
        end = off + size
        # superbox 的第一个 jumd 是其描述盒
        desc = None
        for d in boxes:
            if d["type"] == "jumd" and off < d["offset"] < end:
                desc = d
                break
        if desc is None:
            continue
        dcs, dce = desc["content"]
        label = jumd_label(raw[dcs:dce])
        # 在本 superbox 内查找紧随 jumd 的 cbor 盒
        cpos = None
        p = desc["offset"] + desc["size"]
        while p + 8 <= end:
            csize = int.from_bytes(raw[p:p + 4], "big")
            ctype = raw[p + 4:p + 8]
            if csize < 8 or p + csize > end:
                break
            if ctype == b"cbor":
                cpos = (p, csize)
                break
            p += csize
        out.append((off, size, label, cpos))
    return out


def find_cbor_in(raw, start, end):
    """在 [start,end) 内找第一个 cbor 盒（深度优先）。"""
    p = start
    while p + 8 <= end:
        size = int.from_bytes(raw[p:p + 4], "big")
        typ = raw[p + 4:p + 8]
        if size < 8 or p + size > end:
            return None
        name = typ.decode("ascii", "replace")
        if name == "cbor":
            return p, size
        if name in ("jumb", "c2pa"):
            r = find_cbor_in(raw, p + 8, p + size)
            if r:
                return r
        elif name == "uuid":
            r = find_cbor_in(raw, p + 8 + 16, p + size)
            if r:
                return r
        p += size
    return None


def main():
    jpeg = SIGNED.read_bytes()
    PUB.mkdir(parents=True, exist_ok=True)

    info = extract_from_jpeg(jpeg)
    raw = info["jumbf"]
    claim = info["claim"]
    tbs = info["tbs"]

    (PUB / "manifest_data.c2pa").write_bytes(raw)
    (PUB / "claim.cbor").write_bytes(claim)
    (PUB / "cose_tbs.bin").write_bytes(tbs)

    claim_obj = cbor2.loads(claim)
    refs = claim_obj.get("assertions", [])
    ref_by_url = {r.get("url"): r.get("hash") for r in refs}
    print(f"claim asserts {len(refs)} assertion(s):")
    for r in refs:
        h = r.get("hash")
        print(f"  {r.get('url')}")
        print(f"    claim_recorded_hash = {h.hex() if isinstance(h, bytes) else h}")

    labels = build_label_index(raw)
    print("\n=== JUMBF superboxes ===")
    for off, size, lab, cpos in labels:
        shown = f"cbor@{cpos[0]}" if cpos else "-"
        print(f"  off={off:6d} size={size:6d} label={lab:40s} {shown}")

    hb = [x for x in labels if x[2] == "c2pa.hash.data"]
    if not hb:
        raise SystemExit("c2pa.hash.data assertion not found")
    sb_off, sb_size, _, cpos = hb[0]

    if not cpos:
        raise SystemExit("no cbor box inside c2pa.hash.data")
    c_off, c_size = cpos
    # c_size 是盒总长（含 8 字节 LBox+TBox），内容为 [c_off+8, c_off+c_size)
    c_lo, c_hi = c_off + 8, c_off + c_size
    hb_data = cbor2.loads(raw[c_lo:c_hi])

    print("\n=== c2pa.hash.data assertion data ===")
    print(json.dumps(hb_data, indent=2,
                     default=lambda o: o.hex() if isinstance(o, bytes) else str(o)))

    # ---- 断言完整性：C2PA hashed-URI 针对整个断言盒（含 LBox/TBox/jumd/cbor）----
    full_box = raw[sb_off:sb_off + sb_size]
    h_full = hashlib.sha256(full_box).digest()
    h_cbor = hashlib.sha256(raw[c_lo:c_hi]).digest()

    # 也尝试「盒内容（去掉 LBox+TBox）」的变体
    h_boxcontent = hashlib.sha256(raw[sb_off + 8:sb_off + sb_size]).digest()

    ref_url, claimed = None, None
    for k, v in ref_by_url.items():
        if k and "c2pa.hash.data" in k:
            ref_url, claimed = k, v
            break

    print("\n=== assertion integrity (claim hash vs actual) ===")
    print(f"  claim_ref_url      = {ref_url}")
    print(f"  claim_hash         = {claimed.hex() if isinstance(claimed, bytes) else claimed}")
    print(f"  sha256(full_box)   = {h_full.hex()}   match={claimed == h_full}")
    print(f"  sha256(box content)= {h_boxcontent.hex()}   match={claimed == h_boxcontent}")
    print(f"  sha256(cbor only)  = {h_cbor.hex()}   match={claimed == h_cbor}")

    integrity_full = claimed == h_full
    integrity_content = claimed == h_boxcontent

    # ---- 绑定的媒体摘要 vs 原始 JPEG ----
    declared = hb_data.get("hash")
    original = (ROOT / "private" / "original.jpg").read_bytes()
    orig_sha = hashlib.sha256(original).digest()
    print("\n=== media digest comparison ===")
    print(f"  assertion.hash      = {declared.hex() if isinstance(declared, bytes) else declared}")
    print(f"  sha256(original.jpg)= {orig_sha.hex()}")
    print(f"  equal               = {declared == orig_sha}")

    alg = hb_data.get("alg")
    binding = {
        "label": "c2pa.hash.data",
        "alg": alg,
        "hash_hex": declared.hex() if isinstance(declared, (bytes, bytearray)) else None,
        "exclusions": [
            {"start": int(e["start"]), "length": int(e["length"])}
            for e in hb_data.get("exclusions", [])
        ],
        "name": hb_data.get("name"),
        "pad": hb_data.get("pad").hex() if isinstance(hb_data.get("pad"), (bytes, bytearray)) else hb_data.get("pad"),
        "claim_sha256": hashlib.sha256(claim).hexdigest(),
        "cose_tbs_sha256": hashlib.sha256(tbs).hexdigest(),
        "signer_pk": info["x5chain"][0].hex() if info["x5chain"] else None,
        "manifest_sha256": info["jumbf_sha256"],
        "jpeg_sha256": info["jpeg_sha256"],
        "assertion_superbox_offset": sb_off,
        "assertion_superbox_size": sb_size,
        "assertion_cbor_offset": c_off,
        "assertion_cbor_size": c_size,
        "claim_ref_url": ref_url,
        "claim_ref_hash_hex": claimed.hex() if isinstance(claimed, (bytes, bytearray)) else None,
        "integrity_full_box_match": integrity_full,
        "integrity_box_content_match": integrity_content,
        "assertion_hash_equals_original_sha256": declared == orig_sha,
    }
    (PUB / "binding.json").write_text(json.dumps(binding, indent=2))

    print("\n=== binding.json ===")
    print(json.dumps(binding, indent=2))


if __name__ == "__main__":
    try:
        main()
    except C2PAExtractError as e:
        raise SystemExit(f"extract error: {e}")
