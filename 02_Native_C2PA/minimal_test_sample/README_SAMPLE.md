# PicProof 最小原生 C2PA 测试样本说明

本目录提供原生 C2PA 图像及 JUMBF/COSE 的完整工程测试样本（合成测试凭证，无真实设备私钥）：

## 包含文件清单
1. `signed_c2pa.jpg`: 原生签署 C2PA Manifest 的 JPEG 图像容器文件（大小 95,569 字节）
2. `manifest_data.c2pa`: 从 JPEG APP11 重建的完整 JUMBF Manifest Store（大小 67,183 字节）
3. `claim.cbor`: 预期的 Claim 原始 CBOR 字节（大小 592 字节）
4. `cose_signature.der`: 从 JUMBF c2pa.signature 提取的 COSE-ES256 签名对象（DER 编码，70 字节）
5. `cose_tbs.bin`: 重构的 COSE Sig_structure 原始待签名字节（1,896 字节）
6. `binding.json`: 完整的绑定与排除区间元数据，记录了：
   - 排除区间 `exclusions`: [{"start": 20, "length": 67215}]
   - 媒体摘要 `hash_hex`: `ef29c5d15ca4adf940c28fe801e3fb8fdcd6edc7e43f25a1595bb02a0123c90b`
   - Claim 哈希 `claim_sha256`: `4a67c933ce886e5d9310b97dd575d7e39c5949a56d25fb58d348e8f3b4293453`
   - COSE TBS 哈希 `cose_tbs_sha256`: `e88e6602f9465d1580b12b998d601bf04abf984aa60b84a11bc903413ea975d5`
   - 证明引用 `claim_ref_url`: `self#jumbf=c2pa.assertions/c2pa.hash.data`
   - 证明引用哈希 `claim_ref_hash_hex`: `d24f8a57bcfdd16fbc955cc238eb444f9400e28e5fc81d38d2a0e668a5e9ff11`
7. `bound_bytes.bin`: 按照排除区间剔除 JUMBF 后提取的媒体原始字节（28,354 字节，SHA-256 与 `hash_hex` 完全匹配）
8. `signer_cert.der`: 测试签名者 X.509 公钥证书（用于核验 COSE ES256 签名）

## 验证流程
运行 `../../03_Configs_and_Test_Vectors/test_scripts/verify_c2pa_minimal.py` 即可自动执行完整的 C2PA 解析与字节匹配核验。
