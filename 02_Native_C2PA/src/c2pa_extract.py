#!/usr/bin/env python3
"""
E5-A 原生 C2PA 提取（纯函数版）

从签名 JPEG 重新提取 COSE 结构，不读写 adapter_output/，不依赖既有中间文件。
供 e5_public_verify.py 在运行时调用，确保验证器永远基于原始 JPEG 重新计算。

已验证的 JUMBF 布局（本样例实测）：
  - JPEG 用 N 个连续 APP11 段承载 JUMBF
  - APP11 信封头 12 字节：'JP'(2) ver(2) seq(4) totalLen(4)
  - 各段去掉 12 字节头按 seq 拼接 = raw JUMBF，以 'jumb' 类型名开头（无 LBox）
  - jumb 内容直接从 p+8 开始；uuid 盒内容前 16 字节为 UUID
  - COSE 位于 uuid 盒内的 cbor 盒，内容以 tag18(d2) + array4(84) 开头
  - COSE 四元组：protected(bstr) / unprotected(map, 含 pad) / null / signature(bstr)
"""

import collections.abc
import hashlib
from io import BytesIO

import cbor2


class C2PAExtractError(Exception):
    pass


# ---------------- JPEG ----------------

def extract_app11(jpeg):
    if jpeg[:2] != b"\xff\xd8":
        raise C2PAExtractError("not a JPEG")
    segs = []
    i, n = 2, len(jpeg)
    while i < n:
        if jpeg[i] != 0xFF:
            raise C2PAExtractError(f"unexpected byte at {i}")
        while i < n and jpeg[i] == 0xFF:
            i += 1
        if i >= n:
            break
        marker = jpeg[i]
        i += 1
        if marker in (0xD9, 0xDA):
            break
        if marker == 0x01 or 0xD0 <= marker <= 0xD7:
            continue
        if i + 2 > n:
            raise C2PAExtractError("truncated segment length")
        length = int.from_bytes(jpeg[i:i + 2], "big")
        if length < 2 or i + length > n:
            raise C2PAExtractError("malformed segment")
        if marker == 0xEB:
            segs.append(jpeg[i + 2:i + length])
        i += length
    return segs


def rebuild_jumbf(segs):
    """按 JPEG XT / JUMBF 规范重组。

    APP11 信封（8 字节）：'JP'(2) + En(2) + Z(4)
    之后是 JUMBF 原始字节，每段都携带同一份 'LBox + TBox'（8 字节）头部，
    这是规范为乱序重组设计的。拼接时只保留首段头部，续片去掉 8 字节。

    实测验证：本规则重组结果与 c2patool --ingredient 导出的
              manifest_data.c2pa 逐字节相同。
    """
    if not segs:
        raise C2PAExtractError("no APP11 segments")

    groups = {}
    for p in segs:
        if p[:2] != b"JP":
            raise C2PAExtractError("invalid APP11 JUMBF header")
        if len(p) < 8:
            raise C2PAExtractError("APP11 payload too short")
        instance = int.from_bytes(p[2:4], "big")
        seq = int.from_bytes(p[4:8], "big")
        groups.setdefault(instance, []).append((seq, p[8:]))

    candidates = []
    for inst, parts in groups.items():
        parts.sort(key=lambda x: x[0])
        seqs = [s for s, _ in parts]
        if seqs != list(range(1, len(seqs) + 1)):
            raise C2PAExtractError(f"JUMBF instance {inst} bad sequence {seqs}")
        # 首段保留完整头部，续片去掉重复的 LBox+TBox
        first = parts[0][1]
        rest = b"".join(c[8:] for _, c in parts[1:])
        manifest = first + rest
        if len(manifest) < 8:
            continue
        if manifest[4:8] != b"jumb":
            continue
        lbox = int.from_bytes(manifest[:4], "big")
        if lbox != len(manifest):
            raise C2PAExtractError(
                f"JUMBF LBox mismatch: declared {lbox}, actual {len(manifest)}")
        candidates.append((inst, manifest))

    if len(candidates) != 1:
        raise C2PAExtractError(
            f"expected exactly one C2PA JUMBF, got {len(candidates)}")
    return candidates[0][1]


# ---------------- JUMBF 盒遍历 ----------------

def _box_children_span(raw, name, cs, ce):
    """返回 (子盒起点, 子盒终点)。"""
    if name == "uuid":
        return cs + 16, ce
    return cs, ce


def walk_boxes(raw):
    """遍历标准 JUMBF 盒（顶层带 LBox + TBox）。"""
    out = []
    _walk(raw, 0, len(raw), out)
    return out


def _walk(raw, start, end, out):
    p = start
    while p + 8 <= end:
        size = int.from_bytes(raw[p:p + 4], "big")
        typ = raw[p + 4:p + 8]
        if size < 8 or p + size > end:
            return
        name = typ.decode("ascii", "replace")
        cs, ce = p + 8, p + size
        out.append({"type": name, "offset": p, "size": size,
                    "content": (cs, ce)})
        if name in ("jumb", "c2pa", "uuid"):
            sub_start, sub_end = _box_children_span(raw, name, cs, ce)
            _walk(raw, sub_start, sub_end, out)
        p += size


def find_cose_box(raw):
    """返回内容以 d2 84 开头的 cbor 盒 (box_offset, cs, ce)。"""
    for b in walk_boxes(raw):
        if b["type"] != "cbor":
            continue
        cs, ce = b["content"]
        if cs + 2 <= ce and raw[cs:cs + 2] == b"\xd2\x84":
            return (b["offset"], cs, ce)
    return None


def find_claim_box(raw, skip):
    """返回内容为含 dc:format 的 map 的 cbor 盒。"""
    for b in walk_boxes(raw):
        if b["type"] != "cbor":
            continue
        cs, ce = b["content"]
        if (cs, ce) == skip[1:]:
            continue
        content = raw[cs:ce]
        if content[:1] == b"\xd2":
            continue
        try:
            v = cbor2.loads(content)
        except Exception:
            continue
        if isinstance(v, collections.abc.Mapping) and "dc:format" in v:
            return (b["offset"], cs, ce)
    return None


# ---------------- CBOR 编码（Sig_structure）----------------

def cbor_head(major, n):
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 0x100:
        return bytes([(major << 5) | 24, n])
    if n < 0x10000:
        return bytes([(major << 5) | 25]) + n.to_bytes(2, "big")
    if n < 0x100000000:
        return bytes([(major << 5) | 26]) + n.to_bytes(4, "big")
    return bytes([(major << 5) | 27]) + n.to_bytes(8, "big")


def cbor_encode(v):
    if isinstance(v, bytes):
        return cbor_head(2, len(v)) + v
    if isinstance(v, str):
        e = v.encode()
        return cbor_head(3, len(e)) + e
    if isinstance(v, bool):
        return b"\xf5" if v else b"\xf4"
    if isinstance(v, int):
        return cbor_head(0, v) if v >= 0 else cbor_head(1, -1 - v)
    if isinstance(v, list):
        return cbor_head(4, len(v)) + b"".join(cbor_encode(x) for x in v)
    if isinstance(v, dict):
        o = cbor_head(5, len(v))
        for k, val in v.items():
            o += cbor_encode(k) + cbor_encode(val)
        return o
    raise TypeError(type(v))


# ---------------- COSE 严格解析 ----------------

def parse_cose_strict(raw):
    found = find_cose_box(raw)
    if not found:
        raise C2PAExtractError("COSE box not found")
    box_off, cs, ce = found
    body = raw[cs:ce]

    stream = BytesIO(body)
    if stream.read(2) != b"\xd2\x84":
        raise C2PAExtractError("COSE prefix mismatch")
    dec = cbor2.CBORDecoder(stream)
    fields, bounds = [], []
    for _ in range(4):
        b = stream.tell()
        v = dec.decode()
        f = stream.tell()
        fields.append(v)
        bounds.append((b, f))

    if stream.tell() != len(body):
        raise C2PAExtractError(
            f"COSE not fully consumed: {stream.tell()} != {len(body)}")

    protected, unprotected, payload, signature = fields
    if not isinstance(protected, bytes):
        raise C2PAExtractError("protected is not bytes")
    # cbor2 把 map 解码为 frozendict，必须用 Mapping 判定而非 dict
    if not isinstance(unprotected, collections.abc.Mapping):
        raise C2PAExtractError("unprotected is not a map")
    if payload is not None:
        raise C2PAExtractError("payload is not null (detached expected)")
    if not isinstance(signature, bytes):
        raise C2PAExtractError("signature is not bytes")

    headers = cbor2.loads(protected)
    if not isinstance(headers, collections.abc.Mapping):
        raise C2PAExtractError("protected header is not a map")
    alg = headers.get(1)
    if alg != -7:
        raise C2PAExtractError(f"algorithm is not ES256: {alg}")

    claim_box = find_claim_box(raw, found)
    if not claim_box:
        raise C2PAExtractError("claim box not found")
    claim_off, ccs, cce = claim_box
    claim = raw[ccs:cce]

    tbs = cbor_encode(["Signature1", protected, b"", claim])
    digest = hashlib.sha256(tbs).digest()

    return {
        "cose_box_offset": box_off,
        "cose_content": (cs, ce),
        "cose_length": len(body),
        "field_boundaries": bounds,
        "protected": protected,
        "unprotected_keys": sorted(str(k) for k in unprotected.keys()),
        "signature": signature,
        "alg": alg,
        "x5chain": normalize_x5chain(headers.get(33)),
        "claim": claim,
        "claim_box_offset": claim_off,
        "tbs": tbs,
        "digest": digest,
        "digest_hex": digest.hex(),
    }


def normalize_x5chain(v):
    if v is None:
        return []
    if isinstance(v, bytes):
        return [v]
    if isinstance(v, list):
        return [c for c in v if isinstance(c, bytes)]
    return []


# ---------------- 顶层 ----------------

def extract_from_jpeg(jpeg_bytes):
    """从 JPEG 原始字节提取全部 C2PA 材料（纯函数，不落盘）。"""
    segs = extract_app11(jpeg_bytes)
    raw = rebuild_jumbf(segs)
    cose = parse_cose_strict(raw)
    cose["jumbf"] = raw
    cose["jumbf_sha256"] = hashlib.sha256(raw).hexdigest()
    cose["jpeg_sha256"] = hashlib.sha256(jpeg_bytes).hexdigest()
    cose["app11_segments"] = len(segs)
    return cose
