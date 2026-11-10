#!/usr/bin/env python3
"""E5-B 联合验证器（Public 模式，不接收原始 JPEG）。

复用 E5-A 经过验证的解析与验证函数：
    - c2pa_extract.extract_from_jpeg   (JPEG/APP11/JUMBF/COSE 严格解析)
    - e5_public_verify.check_sigma     (Sigma 验证 + 派生 cmPK/leaf)
    - e5_public_verify.check_merkle    (Spartan 成员验证)
    - e5_public_verify.check_same_signer (DLEQ 同签名者)

E5-B 与 E5-A 的关键差异
------------------------
E5-A 接收完整签名 JPEG，因此 c2patool 可以直接执行
assertion.dataHash.match（媒体完整性由原生验证器承担）。

E5-B 的验证器**不接收**签名 JPEG，也不接收原始媒体。
它只拿到：
    - Manifest Store (JUMBF) 与其认证链材料
    - Sigma / Spartan / DLEQ 三项证明
    - 本地受信注册配置
再加上（作为辅助材料，逐字节核对）：
    - cose_tbs.bin / claim.cbor

因此媒体完整性无法由原生验证器直接检查，必须由 HashFold/Decider 证明承担。
Decider 尚未实现，所以正常样本只能达到 PENDING_DECIDER。

安全约束（四条）
----------------
1. 不信任辅助 JSON 中声明的公开输入。所有安全相关值从 Manifest Store
   独立重算，或与辅助材料做逐字节一致性检查。
2. 验证的是原生 C2PA 签名与断言认证链。
3. 注册根与期望叶只来自受信配置，绝不采信证明包自报的 root。
4. fold-only 执行日志不作为验证依据。

三个摘要各司其职
----------------
    h_sig   = SHA256(COSE Sig_structure)        -> Sigma
    h_C2PA  = 当前 Claim 认证的 c2pa.hash.data   -> HashFold/Decider
    H_reg   = 由 cmPK + counter 派生的注册叶摘要  -> Spartan

注意：E5-A 的 pk_link.json 中 `digest_hex` 字段实际是 H_reg（注册叶 hex），
不是 COSE TBS 摘要。本验证器内部统一称其为 registry_leaf_digest，
但为了不破坏 E5-A 文件格式，不修改该字段名。
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

BASE = Path("/root/autodl-tmp/picproof-e5b")
E5A = Path("/root/autodl-tmp/PicProof_E5")
E5A_SCRIPTS = E5A / "scripts"

sys.path.insert(0, str(E5A_SCRIPTS))

import cbor2
from c2pa_extract import C2PAExtractError, extract_from_jpeg
from e5_public_verify import (
    check_merkle,
    check_same_signer,
    check_sigma,
    parse_der_cert,
)

# 结果常量
REJECT = "REJECT"
PENDING = "PENDING_DECIDER"
ACCEPT = "ACCEPT"

# Decider 验证器子进程环境：固定并行度，避免影响内存/时序复现
DECIDER_ENV = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "RAYON_NUM_THREADS": "4",
    "MALLOC_ARENA_MAX": "2",
    **{k: v for k, v in os.environ.items() if k.startswith("LD_LIBRARY")},
}


class Verifier:
    def __init__(self):
        self.report = {}
        self.checks = {}

    def fail(self, stage, detail):
        self.checks[stage] = "FAIL"
        self.report.setdefault("failures", []).append({"stage": stage, "detail": detail})
        return False

    def ok(self, stage):
        self.checks[stage] = "PASS"
        return True


def sha256_hex(b):
    return hashlib.sha256(b).hexdigest()


def derive_leaf_from_link(pk_link):
    """从验证通过的 Sigma 派生结果取注册叶（不接受外部声明的叶）。"""
    return int(pk_link["leaf_decimal"])


def verify_binding_assertion_authentic(v: Verifier, raw_jumbf, claim, cose_info):
    """核对 Claim 通过 hashed-URI 认证 c2pa.hash.data 断言，并取出 h_C2PA。

    只采信 Claim 内记录、且与 JUMBF 实际内容哈希一致的断言。
    不采信 binding.json 自报的 hash_hex。
    """
    claim_obj = cbor2.loads(claim)
    refs = claim_obj.get("assertions", [])
    if not isinstance(refs, list):
        return v.fail("claim_assertions", "claim.assertions is not a list"), None

    # 定位 c2pa.hash.data 断言盒（按 jumd label）
    hb_box = find_assertion_box(raw_jumbf, "c2pa.hash.data")
    if hb_box is None:
        return v.fail("claim_assertions", "c2pa.hash.data assertion not present"), None

    sb_off, sb_size, c_off, c_size = hb_box
    box_content = raw_jumbf[sb_off + 8: sb_off + sb_size]
    actual_content_hash = hashlib.sha256(box_content).digest()

    # 在 Claim 里找到对应引用
    claimed_hash = None
    ref_url = None
    for r in refs:
        url = r.get("url")
        if url and "c2pa.hash.data" in url:
            claimed_hash = r.get("hash")
            ref_url = url
            break

    if claimed_hash is None:
        return v.fail("claim_assertions", "claim does not reference c2pa.hash.data"), None

    if claimed_hash != actual_content_hash:
        return v.fail(
            "claim_assertions",
            "claim-recorded hash does not match actual assertion box content "
            f"(claim={claimed_hash.hex()}, actual={actual_content_hash.hex()})",
        ), None

    hb = cbor2.loads(raw_jumbf[c_off + 8: c_off + c_size])
    if hb.get("alg") != "sha256":
        return v.fail("claim_assertions", f"unexpected hard binding alg {hb.get('alg')}"), None
    if hb.get("name") != "jumbf manifest":
        return v.fail("claim_assertions", f"unexpected exclusions name {hb.get('name')}"), None

    excl = hb.get("exclusions")
    if not isinstance(excl, list) or not excl:
        return v.fail("claim_assertions", "missing exclusions"), None

    declared = hb.get("hash")
    if not isinstance(declared, (bytes, bytearray)) or len(declared) != 32:
        return v.fail("claim_assertions", "hard binding hash is not 32 bytes"), None

    v.report["claim_assertions"] = {
        "assertion_present": True,
        "claim_ref_url": ref_url,
        "claim_recorded_hash_hex": claimed_hash.hex(),
        "actual_box_content_hash_hex": actual_content_hash.hex(),
        "hashed_uri_match": True,
        "hard_binding_name": hb.get("name"),
        "hard_binding_alg": hb.get("alg"),
        "exclusions": [
            {"start": int(e["start"]), "length": int(e["length"])} for e in excl
        ],
        "h_C2PA": declared.hex(),
        "pad_len": len(hb.get("pad") or b""),
    }
    v.ok("claim_assertions")
    return True, declared.hex()


def iter_boxes(raw, start, end):
    p = start
    while p + 8 <= end:
        size = int.from_bytes(raw[p:p + 4], "big")
        typ = raw[p + 4:p + 8]
        if size < 8 or p + size > end:
            return
        yield p, typ.decode("ascii", "replace"), size
        p += size


def jumd_label(desc):
    body = desc[:-1] if desc.endswith(b"\x00") else desc
    i = len(body)
    while i > 0 and 32 <= body[i - 1] < 127:
        i -= 1
    return body[i:].decode("ascii", "replace")


def find_assertion_box(raw, wanted_label):
    """深度遍历所有 jumb superbox，返回 (superbox_off, superbox_size, cbor_off, cbor_size)。

    JUMBF 布局：外层的 jumb(c2pa) 里套 jumb(urn:uuid:...)，其下再套
    jumb(c2pa.assertions) / jumb(c2pa.claim) / jumb(c2pa.signature)。
    每个 superbox 的第一个子盒是 jumd 描述盒，携带 label。
    """
    want = wanted_label
    stack = [(0, len(raw))]
    while stack:
        start, end = stack.pop()
        for off, typ, size in iter_boxes(raw, start, end):
            if typ != "jumb":
                continue
            box_end = off + size
            desc = None
            for c_off, c_typ, c_size in iter_boxes(raw, off + 8, box_end):
                if c_typ == "jumd":
                    desc = (c_off, c_size)
                    break
            if desc is None:
                continue
            label = jumd_label(raw[desc[0] + 8: desc[0] + desc[1]])
            if label == want:
                for c_off, c_typ, c_size in iter_boxes(raw, desc[0] + desc[1], box_end):
                    if c_typ == "cbor":
                        return off, size, c_off, c_size
                return None
            # 继续深入这个 jumb（跳过其 jumd）
            stack.append((desc[0] + desc[1], box_end))
    return None


def verify_es256(tbs, signature, x5chain):
    """验证 COSE Sig_structure 上的 ECDSA P-256 / SHA-256 签名。

    信任起点：签名者公钥只从 COSE x5chain 的叶证书取，
    不接受证明包自报公钥。
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    from cryptography import x509

    if not x5chain:
        return False, "x5chain is empty"
    try:
        cert = x509.load_der_x509_certificate(x5chain[0])
    except Exception as e:
        return False, f"leaf certificate unparsable: {e}"

    pub = cert.public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        return False, f"leaf key is not EC: {type(pub).__name__}"
    if not isinstance(pub.curve, ec.SECP256R1):
        return False, f"leaf curve is {pub.curve.name}, expected secp256r1"

    if len(signature) == 64:
        der = encode_dss_signature(
            int.from_bytes(signature[:32], "big"),
            int.from_bytes(signature[32:], "big"))
        enc = "COSE r||s (64B)"
    elif len(signature) > 64:
        der = signature
        enc = "DER"
    else:
        return False, f"unexpected signature length {len(signature)}"

    try:
        pub.verify(der, tbs, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False, "ES256 signature does not verify over rebuilt Sig_structure"
    except Exception as e:
        return False, f"ES256 verification error: {e}"

    return True, f"ES256 over {len(tbs)}-byte Sig_structure, sig={enc}"


def main():
    ap = argparse.ArgumentParser(
        description="E5-B joint verifier (no original JPEG, no decider yet)")
    ap.add_argument("--manifest", default=str(BASE / "public/manifest_data.c2pa"),
                    help="C2PA Manifest Store (JUMBF)")
    ap.add_argument("--pi-sigma", default=str(BASE / "proofs/pi_sigma.bin"))
    ap.add_argument("--pi-merkle", default=str(BASE / "proofs/pi_merkle.bin"))
    ap.add_argument("--pi-dleq", default=str(BASE / "proofs/pi_dleq.json"))
    ap.add_argument("--trusted-root", default=str(E5A / "enrollment/trusted_root.json"))
    ap.add_argument("--aux-cose-tbs", default=str(BASE / "public/cose_tbs.bin"),
                    help="辅助材料：已认证 COSE TBS（逐字节核对，不作为信任源）")
    ap.add_argument("--aux-claim", default=str(BASE / "public/claim.cbor"),
                    help="辅助材料：已认证 Claim CBOR（逐字节核对，不作为信任源）")
    ap.add_argument("--report", default=str(BASE / "reports/e5b_verify.json"))
    ap.add_argument("--workdir", default=str(BASE / "reports/_verify_work"))
    ap.add_argument("--decider-dir", default=str(BASE / "proofs/decider"),
                    help="directory holding decider_vk.bin / pi_decider.bin / public inputs")
    ap.add_argument("--trusted-decider-vk-sha256",
                    default="4fb5dc1cd8e56a98442014a3bce6c43667fdf58c589f9d0fa8d7f6b45fa783c5",
                    help="受信配置固定的 Decider vk sha256；必须显式提供，"
                         "不得信任证明包自带 vk。传空字符串将导致 REJECT。")
    ap.add_argument("--decider-verify-bin",
                    default="/root/autodl-tmp/sonobe-decider/target/release/e5b_decider_verify",
                    help="standalone decider verifier executable")
    args = ap.parse_args()

    work = Path(args.workdir)
    work.mkdir(parents=True, exist_ok=True)

    v = Verifier()
    v.report["stage"] = "E5-B joint public verification (no JPEG, no decider)"
    v.report["inputs"] = {
        "manifest": args.manifest,
        "pi_sigma": args.pi_sigma,
        "pi_merkle": args.pi_merkle,
        "pi_dleq": args.pi_dleq,
        "trusted_root": args.trusted_root,
        "aux_cose_tbs": args.aux_cose_tbs,
        "aux_claim": args.aux_claim,
    }

    # ---------------- [1] 从 Manifest Store 严格解析 C2PA ----------------
    print("[1] 从 Manifest Store 重建 C2PA 材料")
    raw = Path(args.manifest).read_bytes()
    if raw[:4] == b"\x00\x00\x00\x00" or len(raw) < 8:
        return finish(v, args.report, REJECT, "manifest too small")

    # 用 E5-A 的严格解析器验证 structure：将其包装成最小 APP11 载体
    # 直接校验 LBox 与 jumb 类型
    lbox = int.from_bytes(raw[:4], "big")
    if raw[4:8] != b"jumb" or lbox != len(raw):
        return finish(v, args.report, REJECT, "manifest LBox/type mismatch")
    v.report["manifest_sha256"] = sha256_hex(raw)
    v.report["manifest_size"] = len(raw)
    print(f"    JUMBF {len(raw)} B, LBox OK, type=jumb")

    # 定位 claim 盒与 signature 盒
    claim_box = find_assertion_box(raw, "c2pa.claim")
    sig_box = find_assertion_box(raw, "c2pa.signature")
    if claim_box is None:
        return finish(v, args.report, REJECT, "c2pa.claim box not found")
    if sig_box is None:
        return finish(v, args.report, REJECT, "c2pa.signature box not found")

    claim_cbor = raw[claim_box[2] + 8: claim_box[2] + claim_box[3]]
    cose_body = raw[sig_box[2] + 8: sig_box[2] + sig_box[3]]
    if cose_body[:2] != b"\xd2\x84":
        return finish(v, args.report, REJECT, "signature box is not a COSE_Sign1")

    # 用 E5-A 的严格 COSE 解析：构造最小 JPEG 交给 extract_from_jpeg 会麻烦，
    # 这里直接复用其 parse_cose_strict 的语义，通过一个合成 JPEG
    parsed = parse_cose_from_jumbf(raw, cose_body, claim_cbor)
    if parsed is None:
        return finish(v, args.report, REJECT, "COSE strict parse failed")
    protected, signature, x5chain, alg, tbs, digest = parsed

    if alg != -7:
        return finish(v, args.report, REJECT, f"unexpected COSE alg {alg}")

    # [1c] 验证 ES256 签名本身。这是 E5-B 的信任起点：
    #      没有这一步，篡改 Claim/签名后重建的 TBS 会跟着变，
    #      Sigma 也会被重新匹配，攻击即可通过。
    print("[1c] ES256 签名验证")
    sig_ok, sig_msg = verify_es256(tbs, signature, x5chain)
    v.report["c2pa_signature"] = {"valid": sig_ok, "detail": sig_msg}
    if not sig_ok:
        v.fail("c2pa_signature", sig_msg)
        return finish(v, args.report, REJECT, "COSE signature invalid")
    v.ok("c2pa_signature")
    print(f"    PASS ({sig_msg})")

    h_sig = digest.hex()
    v.report["cose"] = {
        "alg": alg,
        "alg_name": "ES256",
        "signature_bytes": len(signature),
        "x5chain_len": len(x5chain),
        "tbs_sha256": h_sig,
        "claim_sha256": sha256_hex(claim_cbor),
        "digest_recomputed_by_verifier": True,
    }
    print(f"    COSE alg={alg} (ES256), signature {len(signature)} B, chain {len(x5chain)}")
    print(f"    h_sig (重建) = {h_sig}")

    # ---------------- [1b] 辅助材料逐字节核对（不作为信任源） ----------------
    aux_issues = []
    if Path(args.aux_cose_tbs).exists():
        aux_tbs = Path(args.aux_cose_tbs).read_bytes()
        same = aux_tbs == tbs
        v.report.setdefault("aux_consistency", {})["cose_tbs_matches_rebuilt"] = same
        if not same:
            aux_issues.append(
                f"aux cose_tbs.bin ({sha256_hex(aux_tbs)}) != rebuilt Sig_structure ({h_sig})")
    if Path(args.aux_claim).exists():
        aux_claim = Path(args.aux_claim).read_bytes()
        same = aux_claim == claim_cbor
        v.report["aux_consistency"]["claim_matches_rebuilt"] = same
        if not same:
            aux_issues.append("aux claim.cbor != rebuilt claim")

    if aux_issues:
        v.report["aux_consistency"]["issues"] = aux_issues
        v.fail("aux_consistency", "; ".join(aux_issues))
        return finish(v, args.report, REJECT, "auxiliary material inconsistent")
    v.ok("aux_consistency") if Path(args.aux_cose_tbs).exists() else None
    print("    辅助材料逐字节核对: OK")

    # ---------------- [2] 断言认证链 + 取 h_C2PA ----------------
    print("[2] Claim 断言认证链")
    chain_ok, h_c2pa = verify_binding_assertion_authentic(v, raw, claim_cbor, None)
    if not chain_ok:
        return finish(v, args.report, REJECT, "claim assertion chain failed")
    print(f"    h_C2PA (认证的 Hard Binding) = {h_c2pa}")

    # ---------------- [3] Sigma ----------------
    print("[3] Sigma（用验证器重建的 h_sig）")
    sigma_json = work / "_pk_link_e5b.json"
    sigma_ok, sigma_log, pk_link = check_sigma(h_sig, Path(args.pi_sigma), sigma_json)
    v.report["sigma_log"] = sigma_log
    if not sigma_ok:
        v.fail("sigma", sigma_log[-800:])
        return finish(v, args.report, REJECT, "sigma verification failed")
    sigma_leaf = derive_leaf_from_link(pk_link)
    v.report["sigma"] = {
        "leaf_decimal": str(sigma_leaf),
        "cmpk_hex": pk_link["encode_cmpk_hex"],
        "registry_leaf_digest": pk_link["digest_hex"],
        "counter": pk_link["counter"],
        "digest_used_for_verification": h_sig,
        "note": "registry_leaf_digest 是 E5-A 的 digest_hex 字段名，实为 H_reg，不是 h_sig",
    }
    v.ok("sigma")
    print(f"    PASS, leaf={str(sigma_leaf)[:24]}..., proof {(Path(args.pi_sigma).stat().st_size)} B")

    # ---------------- [4] Spartan + DLEQ ----------------
    print("[4] Spartan 成员验证（受信根）")
    trusted = json.loads(Path(args.trusted_root).read_text())
    root_dec = int(trusted["root"])
    depth = int(trusted["depth"])
    trusted_leaf = int(trusted["leaf"])
    v.report["trusted_root"] = {
        "root": trusted["root"],
        "depth": depth,
        "registry_id": trusted.get("registry_id"),
        "profile": trusted.get("profile"),
        "trusted_leaf": str(trusted_leaf),
    }

    merkle_ok, merkle_log = check_merkle(sigma_leaf, root_dec, depth, Path(args.pi_merkle))
    v.report["merkle_log"] = merkle_log
    if not merkle_ok:
        v.fail("spartan", merkle_log[-800:])
        return finish(v, args.report, REJECT, "spartan membership failed")
    v.ok("spartan")
    print(f"    PASS, proof {Path(args.pi_merkle).stat().st_size} B")

    # 叶绑定：Sigma 派生叶必须等于受信配置固定的叶
    if sigma_leaf != trusted_leaf:
        v.fail("leaf_binding",
               f"sigma-derived leaf {sigma_leaf} != trusted leaf {trusted_leaf}")
        return finish(v, args.report, REJECT, "leaf binding failed")
    v.report["leaf_binding"] = {
        "sigma_leaf": str(sigma_leaf),
        "trusted_leaf": str(trusted_leaf),
        "equal": True,
    }
    v.ok("leaf_binding")
    print("    叶绑定: PASS")

    print("[5] DLEQ 同签名者")
    dleq_path = Path(args.pi_dleq)
    try:
        dleq_proof = json.loads(dleq_path.read_text())
    except Exception as e:
        v.fail("dleq", f"DLEQ unreadable: {e}")
        return finish(v, args.report, REJECT, "dleq unreadable")

    cose_pubkey = parse_der_cert(x5chain[0])
    signer_ok, signer_msg = check_same_signer(
        pk_link["encode_cmpk_hex"], cose_pubkey, dleq_proof)
    v.report["dleq_detail"] = signer_msg
    if not signer_ok:
        v.fail("dleq", signer_msg)
        return finish(v, args.report, REJECT, "dleq failed")
    v.ok("dleq")
    print(f"    PASS ({Path(args.pi_dleq).stat().st_size} B)")

    # ---------------- [5] Possession 目标摘要锁定 ----------------
    print("[6] Possession 目标绑定")
    # 验证器在这里锁定：Decider 的公开目标必须是 h_C2PA。
    # 由于 Decider 未实现，仅核对"目标已唯一确定且被认证"。
    target_ok = (
        isinstance(h_c2pa, str)
        and len(h_c2pa) == 64
        and v.report["claim_assertions"]["hashed_uri_match"] is True
        and v.report["claim_assertions"]["hard_binding_alg"] == "sha256"
    )
    if not target_ok:
        v.fail("possession_target_binding", "could not lock authenticated C2PA digest")
        return finish(v, args.report, REJECT, "possession target not locked")
    v.report["possession_target_binding"] = {
        "h_C2PA": h_c2pa,
        "locked_from": "authenticated c2pa.hash.data assertion in claim",
        "decider_public_target_must_equal": h_c2pa,
        "note": "PASS 仅表示验证器已锁定认证摘要并核对公开输入；"
                "不代表私有媒体持有证明已验收",
    }
    v.ok("possession_target_binding")
    print(f"    目标锁定 = {h_c2pa}")

    # ---------------- [6] Decider ----------------
    print("[7] Decider")
    ddir = Path(args.decider_dir)
    vk_p = ddir / "decider_vk.bin"
    pi_p = ddir / "pi_decider.bin"
    pub_p = ddir / "decider_public_inputs.json"

    if not (vk_p.exists() and pi_p.exists() and pub_p.exists()):
        v.report["decider"] = {
            "executed": False,
            "reason": f"no decider proof bundle in {ddir}",
            "expected_files": ["decider_vk.bin", "pi_decider.bin",
                               "decider_public_inputs.json"],
        }
        v.checks["decider"] = "NOT_EXECUTED"
        return finish(v, args.report, None, None)

    # 关键：认证摘要由验证器自己从 Claim 重建（h_c2pa），
    # 用 --expect-sha256 传给 Decider 验证器，而不是采信证明包自报值。
    dec_bin = Path(args.decider_verify_bin)
    if not dec_bin.exists():
        v.fail("decider", f"decider verifier binary not found: {dec_bin}")
        return finish(v, args.report, REJECT, "decider verifier missing")

    # 验证密钥信任锚：必须由受信配置固定，不得信任证明包自带的任意 vk。
    # 缺少锚点时直接拒绝——不允许"没配置就默认通过"。
    trusted_vk_sha = (args.trusted_decider_vk_sha256 or "").strip().lower()
    if not trusted_vk_sha:
        v.fail("decider", "no trusted decider vk sha256 configured "
                          "(--trusted-decider-vk-sha256)")
        return finish(v, args.report, REJECT, "trusted vk anchor not configured")

    actual_vk_sha = hashlib.sha256(vk_p.read_bytes()).hexdigest()
    if actual_vk_sha != trusted_vk_sha:
        v.fail(
            "decider",
            f"decider vk sha256 {actual_vk_sha} != trusted anchor {trusted_vk_sha}",
        )
        return finish(v, args.report, REJECT, "decider vk not pinned")
    v.report["decider_vk_pinned"] = {
        "sha256": actual_vk_sha,
        "trusted": True,
        "source": "trusted configuration (--trusted-decider-vk-sha256)",
    }
    print(f"    vk 已固定 = {actual_vk_sha[:16]}…（受信配置）")

    r = subprocess.run(
        [str(dec_bin), "--vk", str(vk_p), "--proof", str(pi_p),
         "--public-inputs", str(pub_p), "--expect-sha256", h_c2pa],
        capture_output=True, text=True, timeout=900, env=DECIDER_ENV)
    dlog = r.stdout + r.stderr
    (Path(args.workdir) / "decider_verify.log").write_text(dlog)

    if "STATUS: ACCEPT" not in dlog:
        tail = "\n".join(dlog.strip().splitlines()[-6:])
        v.fail("decider", f"Decider verification failed: {tail}")
        return finish(v, args.report, REJECT, "decider verification failed")

    # 交叉核对：证明包自报摘要必须与验证器重建值一致（防御性检查）
    try:
        declared = json.loads(pub_p.read_text()).get("sha256_authenticated", "")
    except Exception as e:
        v.fail("decider", f"decider public inputs unreadable: {e}")
        return finish(v, args.report, REJECT, "decider public inputs unreadable")
    if declared != h_c2pa:
        v.fail(
            "decider",
            f"decider public inputs declare {declared} but verifier rebuilt {h_c2pa}",
        )
        return finish(v, args.report, REJECT, "decider digest mismatch")

    v.report["decider"] = {
        "executed": True,
        "verified": True,
        "vk_bytes": vk_p.stat().st_size,
        "proof_bytes": pi_p.stat().st_size,
        "digest_used": h_c2pa,
        "digest_source": "verifier-rebuilt from authenticated Claim",
        "log_tail": "\n".join(dlog.strip().splitlines()[-8:]),
    }
    v.checks["decider"] = "PASS"
    print(f"    PASS (vk {vk_p.stat().st_size} B, proof {pi_p.stat().st_size} B)")
    print(f"    认证摘要 = {h_c2pa}（验证器重建，非采信证明包）")

    return finish(v, args.report, None, None)


def parse_cose_from_jumbf(raw, cose_body, claim_cbor):
    """复用 E5-A 的 COSE 严格解析语义（字段边界、payload=null、alg=-7）。

    返回 (protected, signature, x5chain, alg, tbs, digest)。
    """
    from io import BytesIO

    from c2pa_extract import cbor_encode

    stream = BytesIO(cose_body)
    if stream.read(2) != b"\xd2\x84":
        return None
    dec = cbor2.CBORDecoder(stream)
    fields = [dec.decode() for _ in range(4)]
    if stream.tell() != len(cose_body):
        return None

    protected, unprotected, payload, signature = fields
    if not isinstance(protected, bytes):
        return None
    if not isinstance(unprotected, dict) and not hasattr(unprotected, "keys"):
        return None
    if payload is not None:
        return None
    if not isinstance(signature, bytes):
        return None

    headers = cbor2.loads(protected)
    alg = headers.get(1)
    x5 = headers.get(33)
    if isinstance(x5, bytes):
        x5chain = [x5]
    elif isinstance(x5, list):
        x5chain = [c for c in x5 if isinstance(c, bytes)]
    else:
        x5chain = []

    tbs = cbor_encode(["Signature1", protected, b"", claim_cbor])
    digest = hashlib.sha256(tbs).digest()
    return protected, signature, x5chain, alg, tbs, digest


def finish(v, report_path, forced, reason):
    """三态结论：REJECT / PENDING_DECIDER / ACCEPT。"""
    all_checks = list(v.checks.values())
    if forced == REJECT or "FAIL" in all_checks:
        status = REJECT
        if reason:
            v.report["reject_reason"] = reason
    elif any(c in ("NOT_EXECUTED", "NOT_IMPLEMENTED") for c in all_checks):
        status = PENDING
    elif all(c == "PASS" for c in all_checks):
        status = ACCEPT
    else:
        status = REJECT

    v.report["checks"] = dict(v.checks)

    # 用户要求的标准结果视图
    view = {
        "c2pa_signature": v.checks.get("c2pa_signature", "SKIP"),
        "claim_assertions": v.checks.get("claim_assertions", "SKIP"),
        "sigma": v.checks.get("sigma", "SKIP"),
        "spartan": v.checks.get("spartan", "SKIP"),
        "dleq": v.checks.get("dleq", "SKIP"),
        "possession_target_binding": v.checks.get("possession_target_binding", "SKIP"),
        "decider": v.checks.get("decider", "SKIP"),
        "status": status,
    }
    v.report["summary"] = view
    v.report["status"] = status

    Path(report_path).parent.mkdir(parents=True, exist_ok=True)
    Path(report_path).write_text(
        json.dumps(v.report, indent=2, ensure_ascii=False), encoding="utf-8")

    print()
    print("=" * 62)
    print(f" STATUS: {status}")
    print("=" * 62)
    for k, val in view.items():
        if k != "status":
            print(f"  {k:28s} {val}")
    print(f"\n report -> {report_path}")
    return 0 if status in (PENDING, ACCEPT) else 1


if __name__ == "__main__":
    sys.exit(main())
