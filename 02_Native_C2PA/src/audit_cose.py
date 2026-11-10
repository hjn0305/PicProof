"""E5-A 严格 COSE 结构审计。

使用 cbor2 规范解码器，不再依赖手写解析器或字节特征扫描来认定结构。

检查项：
  1. claim.cbor 是单个完整 CBOR 对象，无尾随字节
  2. JUMBF 中恰好存在一个 COSE_Sign1 候选，且各字段与独立提取件一致
  3. COSE 为 tag18 + 4 元素数组（标准形状，不是五元组）
  4. payload 为 null（detached）
  5. signature 为 64 字节 ES256 raw
  6. protected 可解码且 alg = -7
  7. SHA256(TBS) 与 cose_digest.hex 一致
  8. 记录 COSE 在重建 JUMBF 中的精确位置与编码长度

注意：候选定位仍用 `d2 84` 扫描；第 2 项的 assert len == 1 与字段逐项比对
把「碰巧扫到」的概率压到可忽略，但严格盒边界审计见 audit_jumbf.py。
"""
import hashlib
import sys
from io import BytesIO
from pathlib import Path

import cbor2

BASE = Path(sys.argv[1] if len(sys.argv) > 1 else "/root/autodl-tmp/PicProof_E5")
ADP = BASE / "adapter_output"

jumbf = (ADP / "jumbf.bin").read_bytes()
claim = (ADP / "claim.cbor").read_bytes()
expected_protected = (ADP / "cose_protected.bin").read_bytes()
expected_signature = (ADP / "signature.raw").read_bytes()
expected_digest = (ADP / "cose_digest.hex").read_text().strip().lower()

print(f"jumbf.bin       : {len(jumbf)} 字节")
print(f"claim.cbor      : {len(claim)} 字节")
print(f"protected       : {len(expected_protected)} 字节")
print(f"signature.raw   : {len(expected_signature)} 字节")
print(f"expected digest : {expected_digest}")
print()

# ---- 1. Claim 必须是单个完整 CBOR 对象 ----
claim_stream = BytesIO(claim)
claim_value = cbor2.CBORDecoder(claim_stream).decode()
assert claim_stream.tell() == len(claim), \
    f"claim 有尾随字节: {len(claim) - claim_stream.tell()}"
assert isinstance(claim_value, dict), f"claim 不是 map: {type(claim_value)}"
print("1. Claim 解码: OK (单个 CBOR map，无尾随字节)")
print(f"   顶层键: {list(claim_value.keys())}")
print()

# ---- 2. 扫描 COSE 候选 ----
matches = []
for offset in range(len(jumbf) - 1):
    if jumbf[offset:offset + 2] != b"\xd2\x84":
        continue
    stream = BytesIO(jumbf[offset:])
    try:
        obj = cbor2.CBORDecoder(stream).decode()
    except Exception:
        continue
    if not isinstance(obj, cbor2.CBORTag) or obj.tag != 18:
        continue
    fields = obj.value
    # cbor2 默认把数组解码为 tuple，需同时接受 list
    if not isinstance(fields, (list, tuple)) or len(fields) != 4:
        continue
    protected, unprotected, payload, signature = fields
    if not isinstance(protected, bytes):
        continue
    if not isinstance(unprotected, dict):
        continue
    if payload is not None:
        continue
    if not isinstance(signature, bytes) or len(signature) != 64:
        continue
    if protected != expected_protected:
        continue
    if signature != expected_signature:
        continue
    headers = cbor2.loads(protected)
    if not isinstance(headers, dict) or headers.get(1) != -7:
        continue
    tbs = cbor2.dumps(["Signature1", protected, b"", claim])
    digest = hashlib.sha256(tbs).hexdigest()
    if digest != expected_digest:
        continue
    matches.append({
        "offset": offset,
        "cose_length": stream.tell(),
        "tbs_length": len(tbs),
        "digest": digest,
        "headers": headers,
        "unprotected_keys": list(unprotected.keys()),
        "signature": signature,
    })

assert len(matches) == 1, f"期望恰好 1 个匹配的 COSE 候选，实际 {len(matches)}"
m = matches[0]

print("2. COSE 候选扫描: 恰好 1 个匹配")
print(f"   裁剪前 JUMBF 偏移: {m['offset']}")
print(f"   COSE 编码长度    : {m['cose_length']}")
print()

# ---- 3-7. 逐项断言 ----
assert m["tbs_length"] == 1894, f"TBS 长度 {m['tbs_length']} != 1894"
assert len(claim) == 590, f"Claim 长度 {len(claim)} != 590"
assert len(expected_signature) == 64, "签名非 64 字节"
assert m["headers"].get(1) == -7, "算法不是 ES256"
assert 33 in m["headers"], "缺少 x5chain"

x5 = m["headers"][33]
if isinstance(x5, bytes):
    x5 = [x5]

print("COSE STRUCTURE CHECK: PASS")
print("COSE tag: 18")
print("COSE array length: 4")
print("COSE algorithm: ES256 (-7)")
print("Detached payload: null")
print(f"COSE offset in reconstructed JUMBF: {m['offset']}")
print(f"COSE encoded length: {m['cose_length']}")
print(f"TBS length: {m['tbs_length']}")
print(f"SHA256(TBS): {m['digest']}")
print(f"Unprotected header keys: {m['unprotected_keys']}")
print(f"Protected header keys: {list(m['headers'].keys())}")
print(f"x5chain certificates: {len(x5)}")
print(f"x5chain sizes: {[len(c) for c in x5]}")
print(f"Signature (raw hex): {m['signature'].hex()}")
