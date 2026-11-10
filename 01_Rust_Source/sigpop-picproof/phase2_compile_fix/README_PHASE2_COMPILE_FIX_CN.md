# PicProof Phase 2：首轮 Cargo 编译错误修复补丁

## 修复范围

仅修改：
- `src/ecdsa/ca_registry.rs`
- `src/ecdsa/registry_binding.rs`

修复内容：
1. 嵌套测试模块中的 `picproof_k::PROFILE` 路径改为绝对路径 `crate::ecdsa::picproof_k::PROFILE`。
2. CA 根签名显式标注为 `p256::ecdsa::Signature`（源码别名 `P256Signature`）。这是 ES256/P-256 签名，不是 Ed25519。
3. 测试用 `rug::Integer` 运算先物化为 `Integer`，避免对两个惰性 `Incomplete` 表达式直接相加。
4. Sigma/credential 测试中叶子加一改为显式 `Integer` 加法。

没有修改：
- 生产 Merkle 哈希算法或 Poseidon 参数；
- `H_reg`、cmPK 编码、CA 根签名消息格式；
- Sigma、Spartan 证明关系；
- 历史实验数据。

## 应用方式

把 `picproof_phase2_compile_fixes.patch` 和 `apply_phase2_compile_fixes.sh` 上传到服务器工程根目录（包含 `Cargo.toml` 的目录），然后执行：

```bash
chmod +x apply_phase2_compile_fixes.sh
./apply_phase2_compile_fixes.sh picproof_phase2_compile_fixes.patch
```

脚本会先备份两个原文件，再 dry-run，随后应用补丁并检查旧表达式是否仍存在。

## 应用后重新测试

保持原有 Cargo 缓存，不运行 `cargo clean`：

```bash
export CARGO_BUILD_JOBS=1
export CARGO_INCREMENTAL=0
set -o pipefail
cargo test --lib ecdsa::ca_registry -- --nocapture \
  2>&1 | tee phase2_test_logs/01_ca_registry_after_fix.log
```

若仍报错，保留现场，提供第一条错误及上下文。不要继续批量改动。

## 重要说明

本补丁是依据当前归档的 Phase 2 源码和用户报告的编译错误制作的源代码修复补丁。当前没有在用户服务器上执行 Rust 编译，因此不能把补丁应用后的测试视为已通过。`toy_merkle_hash` 只用于单元测试，绝不能替代生产 Poseidon 哈希。
