# PicProof: Zero-Knowledge Provenance Verification for C2PA Media

本仓库为 **PicProof** 系统的完整开源工程实现与复现证据集，包含最新实验版本的 Rust 密码学核心源码、原生 C2PA (JUMBF / COSE-ES256 / `c2pa.hash.data`) 解析与绑定验证实现、受信参数配置文件以及可复现测试向量。

This repository contains the complete implementation of **PicProof** used in our experiments, including the full Rust crates (without build `target/` directories or private keys), native C2PA parser & media-range extractor, trusted profiles, and reproducible test vectors.

---

## 1. 模块与审稿清单对照索引 (Implementation Index)

| 核心模块 / 清单项 | 仓库路径 | 实现内容说明 |
| :--- | :--- | :--- |
| **依赖与版本锁定**<br>(`Cargo.toml` / `Cargo.lock`) | `01_Rust_Source/sigpop-picproof/Cargo.toml`<br>`01_Rust_Source/sigpop-picproof/Cargo.lock`<br>`01_Rust_Source/sonobe-decider-picproof/Cargo.toml`<br>`01_Rust_Source/sonobe-decider-picproof/Cargo.lock` | 锁定 P-256、Arkworks、Sonobe、Rug、Dorian 等全部依赖版本 |
| **Committed-PK Sigma** | `01_Rust_Source/sigpop-picproof/src/ecdsa/pure_sigma.rs`<br>`01_Rust_Source/sigpop-picproof/src/ecdsa/sigma.rs`<br>`01_Rust_Source/sigpop-picproof/src/ecdsa/transcript.rs` | 完整 Schnorr/Sigma 证明生成、验证及基于 Merlin 的 Fiat–Shamir 转录实现 |
| **Commitment 模块** | `01_Rust_Source/sigpop-picproof/src/commitment/commitment.rs`<br>`01_Rust_Source/sigpop-picproof/src/ecdsa/picproof_k.rs`<br>`01_Rust_Source/sigpop-picproof/src/ecdsa/pk_link.rs` | 透明生成元 $K$（RFC 9380 SSWU）、公钥承诺 $cm_{PK} = PK + v \cdot K$、开启值与 SEC1 编码 |
| **Spartan 模块** | `01_Rust_Source/sigpop-picproof/src/target/r1cs/spartan/p256.rs`<br>`01_Rust_Source/sigpop-picproof/src/target/r1cs/spartan/spartan.rs`<br>`01_Rust_Source/sigpop-picproof/examples/spartan_merkle_linked.rs` | 基于 Dorian/Spartan 的 P-256 基域 R1CS 构造、公开输入 `(leaf, root, depth)` 与私有见证求解 |
| **Poseidon 参数文件** | `01_Rust_Source/sigpop-picproof/p256_poseidon_t3_params.json`<br>`03_Configs_and_Test_Vectors/configs/p256_poseidon_t3_params.json` | 实际使用的参数（$t=3$、$\alpha=7$、8 full rounds、46 partial rounds）及参数 SHA-256 指纹 |
| **HashFold** | `01_Rust_Source/sonobe-decider-picproof/crates/ivc/src/sha256_step.rs` | SHA-256 64 字节分块、压缩函数状态递推与 IVC Step 电路 |
| **CycleFold** | `01_Rust_Source/sonobe-decider-picproof/crates/ivc/src/compilers/cyclefold/` | Nova + CycleFold 双椭圆曲线折叠过程与接口 |
| **Decider** | `01_Rust_Source/sonobe-decider-picproof/crates/ivc/src/bin/e5b_decider.rs`<br>`01_Rust_Source/sonobe-decider-picproof/crates/ivc/src/bin/e5b_decider_verify.rs`<br>`01_Rust_Source/sonobe-decider-picproof/crates/ivc/src/bin/jisa_unified_e2e.rs` | 最终压缩证明生成（LegoGroth16/Spartan Decider）与验证 |
| **CA 注册与 Merkle 树** | `01_Rust_Source/sigpop-picproof/src/ecdsa/ca_registry.rs`<br>`01_Rust_Source/sigpop-picproof/src/ecdsa/registry_binding.rs`<br>`01_Rust_Source/sigpop-picproof/examples/picproof_authenticated_registry.rs` | 设备注册与 PoP 校验、承诺检查、Poseidon Merkle 树更新与 CA ES256 根签名 |
| **Package 序列化模块** | `01_Rust_Source/sonobe-decider-picproof/crates/ivc/src/bin/jisa_package_verify.rs`<br>`01_Rust_Source/sigpop-picproof/examples/picproof_authenticated_registry.rs` | `PicProofPackage` / `AuthenticatedPicProofPackage` 紧凑序列化与反序列化 |
| **Verifier 联合验证模块** | `01_Rust_Source/sonobe-decider-picproof/crates/ivc/src/bin/jisa_package_verify.rs`<br>`02_Native_C2PA/src/e5b_verify.py` | 联合验证流程（ProfileGuard 校验、逐字节核对、严格输入拒绝规则） |
| **原生 C2PA 解析实现** | `02_Native_C2PA/src/c2pa_extract.py`<br>`02_Native_C2PA/src/check_datahash.py`<br>`02_Native_C2PA/src/e5b_verify.py` | COSE-ES256 解析、Protected Header 提取、Claim CBOR 处理、`hashed_uri` 与 JUMBF 哈希校验、`c2pa.hash.data` 排除区间媒体字节提取 |
| **原生 C2PA 最小样本** | `02_Native_C2PA/minimal_test_sample/` | 原生 C2PA 测试 JPEG、JUMBF Manifest、COSE 签名、Claim CBOR、排除区间与媒体摘要测试样本（合成测试凭证，无真实私钥） |
| **配置与测试向量** | `03_Configs_and_Test_Vectors/` | Trusted Profile、CA 测试凭证与指纹、注册根、Sigma/Spartan/HashFold/DLEQ 测试向量与真实证明包样本 |

---

## 2. 仓库目录结构 (Repository Layout)

```text
.
├── 01_Rust_Source/                 # 完整 Rust 工程源码（不含 target/）
│   ├── sigpop-picproof/            # pure_sigma, ca_registry, spartan_merkle_linked, commitment
│   └── sonobe-decider-picproof/    # sha256_step (HashFold), cyclefold, decider, jisa_package_verify
├── 02_Native_C2PA/                 # 原生 C2PA 解析、排除区间提取与联合验证代码
│   ├── requirements.txt
│   ├── src/                        # c2pa_extract.py, check_datahash.py, e5b_verify.py
│   └── minimal_test_sample/        # signed_c2pa.jpg, manifest_data.c2pa, claim.cbor, binding.json 等
├── 03_Configs_and_Test_Vectors/    # 配置文件、测试向量及运行脚本
│   ├── configs/                    # Trusted Profile, CA 证书/指纹, Poseidon 参数
│   ├── test_vectors/               # 注册根、Sigma、Spartan、HashFold、证明包样本及预期输出
│   └── test_scripts/               # verify_c2pa_minimal.py, run_cleanroom_smoke.sh
├── .gitattributes
├── .gitignore
├── LICENSE                         # MIT 开源协议
├── README.md
└── SHA256SUMS                      # 仓库全量文件 SHA-256 校验清单
```

---

## 3. 快速验证与复现 (Quick Start)

### 3.1 原生 C2PA 解析与媒体排除区间核验
安装 Python 依赖后，运行内置的最小 C2PA 测试样本验证脚本：
```bash
python -m pip install -r 02_Native_C2PA/requirements.txt
python 03_Configs_and_Test_Vectors/test_scripts/verify_c2pa_minimal.py
```
预期结果：脚本从 `signed_c2pa.jpg` 提取 APP11/JUMBF 与 COSE-ES256 结构，按 `c2pa.hash.data` 排除区间重构媒体字节（28,354 B），输出 `ef29c5d15ca4adf940c28fe801e3fb8fdcd6edc7e43f25a1595bb02a0123c90b` 并逐字节匹配通过。

### 3.2 Rust 独立验证器与真实证明包复现 (Linux x86_64)
在配置好 Rust 工具链及系统依赖（`gmp` / `openssl` / `pkg-config`）的环境上构建验证器：
```bash
# 1. 构建 Sig-PoP 组件
cargo build --manifest-path 01_Rust_Source/sigpop-picproof/Cargo.toml --release \
  --example sigma_extract_cmpk \
  --example spartan_merkle_linked

# 2. 构建 Sonobe 独立包验证器
cargo build --manifest-path 01_Rust_Source/sonobe-decider-picproof/Cargo.toml --release \
  --bin jisa_package_verify

# 3. 验证归档的真实 64B 证明包样本
./01_Rust_Source/sonobe-decider-picproof/target/release/jisa_package_verify \
  --proof 03_Configs_and_Test_Vectors/test_vectors/05_package_sample/picproof_v3_64b.proof \
  --verifier-key 03_Configs_and_Test_Vectors/test_vectors/05_package_sample/decider_vk.bin \
  --trusted-root 64698499199980403925688120801330752921757523768671178302817662098597633920419 \
  --sigpop-dir 01_Rust_Source/sigpop-picproof \
  --expected-merkle-depth 16
```
预期输出：`STANDALONE PACKAGE VERIFY ACCEPT`。

---

## 4. 安全与数据脱敏声明 (Sanitization Notice)

为遵循公开源码与安全最小暴露原则，本仓库仅包含算法源码、受信配置、参数文件及合成/公开测试样本，**不包含**任何真实设备私钥、公钥承诺开启值（opening scalar）、私有 Merkle 路径或未披露敏感生产凭证。

---

## 5. 开源协议 (License)

* 本仓库由 PicProof 作者贡献的全部新增代码、原生 C2PA 解析与验证实现、配置及测试向量均遵循 **[MIT License](LICENSE)** 开源协议发布。
* 上游基础框架保留其原有开源协议与版权声明：
  * `01_Rust_Source/sigpop-picproof`（基于 `circ` / `Sig-PoP`）：采用 Apache-2.0 / MIT 双重许可（详见目录内 `COPYING`、`LICENSE-MIT`、`LICENSE-APACHE`）。
  * `01_Rust_Source/sonobe-decider-picproof`（基于 `sonobe`）：采用 MIT License（详见目录内 `LICENSE`）。
