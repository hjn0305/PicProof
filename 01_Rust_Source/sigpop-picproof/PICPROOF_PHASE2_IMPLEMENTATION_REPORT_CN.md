# PicProof 第二阶段实现报告

## 1. 本阶段目标与边界

本阶段以第一阶段 Sigma CSPRNG 修复版为代码基线，完成 CA 设备注册、承诺开启验证、注册 Merkle Tree、设备私有成员路径、CA 根签名，以及 Sigma cmPK 到 Spartan leaf/root 的强绑定。

保留旧版 `spartan_merkle_linked` v1 CLI 和历史证明/实验文件；新增 CA 注册根声明 v2 与 PicProof authenticated bundle v2。没有覆盖原始 ZIP，也没有修改既有实验结果。

## 2. 主要实现

### 2.1 CA 设备注册认证

新增/完善 `src/ecdsa/ca_registry.rs`：

- CA 生成一次性 32-byte 随机挑战；设备对挑战和精确的 66-byte `Encode(cmPK)` 进行 P-256 ECDSA PoP 签名。
- CA 校验设备公钥、C0/C1 的压缩 SEC1 编码及实际 P-256 曲线点有效性。
- CA 校验开启值是规范、非零 P-256 scalar。
- CA 逐项检查 `C0 = vG`、`C1 = PK_D + vK`。
- CA 验证设备对一次性挑战的签名，成功后将内存挑战标记为 consumed。
- CA 内部 `EnrollmentRecord` 保留 `PK_D` 映射键、cmPK 编码和 H_reg leaf，便于 CA 后续管理注册关系；开启值 `v` 在验证后不继续保留。该内部记录不序列化进证明包。
- 发给设备/证明者的 `DeviceRegistryCredential` 不包含 `PK_D` 或 `v`，只含 cmPK 编码、leaf 和私有路径。

### 2.2 Merkle Tree 与私有成员凭证

- 通过 `H_reg(cmPK)` 生成注册 leaf，沿用项目既有 `PICPROOF-PKI-CMPK-v1` 域分离、66-byte 压缩 SEC1 编码和 P-256 base-field rejection sampling。
- 新增稀疏 Merkle Tree 构建，空叶为 0，调用方必须传入与 Spartan 电路一致的 Poseidon 哈希函数。
- 路径方向约定与 Spartan 电路一致：`true` 表示当前节点是左子节点。
- 对叶、内部节点和默认节点哈希结果增加 P-256 base-field 范围检查；拒绝重复 cmPK 和重复 leaf。
- 新增 `DeviceRegistryCredential`，包含 registry ID、depth、cmPK 编码、leaf 和私有 siblings/directions；不包含设备公钥或开启值。该文件属于私有 witness，不应公开发布。

### 2.3 CA 根签名与信任锚

CA 根声明升级为 version 2，域分离为 `PICPROOF-CA-REGISTRY-ROOT-v2`。ES256 根签名的规范二进制消息覆盖：

- registry ID、Merkle Root、depth；
- 签名算法标识；
- issued-at 与 expires-at；
- commitment profile、leaf-hash profile/algorithm；
- Merkle profile/hash algorithm；
- Poseidon 参数 SHA-256 指纹。

根声明有效期为一年。验证端先用包外固定的 CA 证书 SHA-256 指纹校验 CA trust anchor，再验证根签名；并拒绝过期、未生效或非规范 high-S ECDSA 签名。

当前 CA certificate 是紧凑型自定义 trust-anchor 结构，不是完整 X.509 实现。它只携带 CA 标识和 P-256 公钥；信任来自验证者包外固定的指纹，不来自证明包自带的公钥。

### 2.4 Sigma–H_reg–Spartan 严格绑定

新增 `src/ecdsa/registry_binding.rs` 和 `examples/picproof_authenticated_registry.rs`。

**Prover**：

1. 验证 Sigma proof 对外部给定的 manifest digest 成立。
2. 从 Sigma statement 的两个 cmPK 点重新编码 `Encode(cmPK)`。
3. 重新计算 `H_reg(cmPK)`。
4. 要求重新计算的 cmPK 和 leaf 与 CA 发放的 device credential 完全一致。
5. 使用 credential 中的私有路径和 CA 签名 Root 生成现有 Spartan R1CS/NIZK。
6. 输出 bundle v2：Sigma proof、Spartan proof、cmPK 编码、leaf、CA 证书/签名根及绑定元数据；不包含私有 Merkle path。

**Verifier**：

1. 从包外配置读取 CA 指纹 pin，并验证 CA 根签名和有效期。
2. 重新加载并重新计算 Poseidon 参数文件指纹，核对签名根中的 profile、depth 和参数指纹。
3. 要求调用方独立提供 manifest digest，并验证 Sigma proof。
4. 从已验证 Sigma statement 重新导出 cmPK，重算 H_reg leaf。
5. 要求 bundle 中 cmPK/leaf 与上述派生结果一致。
6. 使用派生 leaf 和 CA 签名 Root 验证 Spartan proof。

因此，Sigma proof A 与 Spartan proof B 的跨设备拼接会在 leaf 绑定或 Spartan 公共输入验证处被拒绝。Verifier 不接收也不需要 Merkle path 或 device credential。

## 3. 关键文件变更

| 文件 | 变更 |
|---|---|
| `src/ecdsa/ca_registry.rs` | CA enrollment、PoP、cmPK opening、Merkle Tree、私有凭证、ES256 根签名与验证 |
| `src/ecdsa/pk_link.rs` | 加入实际 SEC1/P-256 点校验，保留原 H_reg 口径 |
| `src/ecdsa/registry_binding.rs` | Sigma cmPK 与 CA credential/leaf 的确定性绑定 |
| `src/ecdsa/mod.rs` | 导出新增模块 |
| `examples/ca_registry_demo.rs` | CA 注册、建树、签根 smoke demo；输出私有 credential |
| `examples/spartan_merkle_linked.rs` | 保留 v1 CLI；加入已验证 Poseidon 参数载入及显式参数对象的 R1CS synthesize helper |
| `examples/picproof_authenticated_registry.rs` | 新增 authenticated bundle v2 的 prove/verify CLI |
| `scripts/phase2_static_checks.py` | 新增静态集成检查 |
| `README.md` | 增加第二阶段设计边界和运行说明 |

## 4. 测试与验证结果

### 已完成的非 Rust 运行检查

- 静态集成检查：25/25 PASS。
- 修改的 7 个 Rust 文件括号/分隔符平衡检查：7/7 PASS。
- Poseidon 参数文件指纹独立复算：PASS。声明值与复算值均为 `fe39b46ac826db30c41db8bceda953a93e231ec10ca2b2e737995974f63c7d00`。
- 检查 Sigma 正式路径中不存在 `StdRng::from_seed([0u8; 32])`：PASS。
- 新增 Rust 单元测试：17 项，覆盖 enrollment opening、零开启值、PoP challenge/replay、CA pin/root tamper/expiry、重复注册、Merkle path 方向、credential 隐私字段、Sigma cmPK/leaf mismatch、Poseidon 参数指纹及 profile mismatch。

### 尚未完成的运行验证

当前执行环境没有 `cargo`、`rustc` 或 `rustfmt`，因此本阶段**没有声称 Rust 编译通过，也没有声称上述 Rust 单元测试已经运行通过**。静态检查不能替代 Rust 编译和密码学运行测试。

另外，上传的 `circ_picproof_project.zip`/第一阶段 ZIP 中，`src/lib.rs` 声明了 `pub mod target;`，但归档内没有对应的 `src/target.rs` 或 `src/target/mod.rs`。源码其他位置还引用 `crate::target::r1cs::proof` 和 `crate::target::smt`。这是输入归档已有的缺项，不是本阶段删除或修改造成的；在补齐该模块前，无法对整个 Circ crate 做完整构建验证。

拿到完整 `src/target` 后，建议依次运行：

```bash
cargo test --lib ecdsa::ca_registry
cargo test --lib ecdsa::registry_binding
cargo test --lib ecdsa::pk_link
cargo test --example picproof_authenticated_registry
cargo test --example spartan_merkle_linked
cargo build --release --example ca_registry_demo
cargo build --release --example picproof_authenticated_registry
```

随后再用同一设备、同一 opening 生成的 Sigma proof 和 CA credential 做真实端到端 prove/verify；不能用不同设备或不同 opening 的材料拼接测试。

## 5. 历史实验数据保护

- 原始 `circ_picproof_project.zip` 未覆盖。
- 第一阶段 Sigma 安全修复作为本阶段基线保留。
- 旧 `spartan_merkle_linked` v1 CLI 和 `SpartanMerklePackage` v1 结构未改成 v2。
- 原有 Sonobe 工作区、64 KiB/1 MiB 数据、fullchain 结果、负例 fixture、clean-build 日志及历史统计归档均保留。
- 新版 CA statement v2 和 authenticated bundle v2 单独编号，不覆盖历史证明包或实验数据。
- 本阶段没有重新运行历史性能实验，也没有生成可用于论文性能表格的新数据。
- 完整工作区打包前后校验：`source/sigpop-927baae9` 以外的 184 个文件 SHA-256 全部一致；该源码目录内历史 `results/` 的 1 个文件也保持逐字节一致。

## 6. 仍需明确的部署边界

1. CA 在注册时会看到 `PK_D` 和 `v`；普通 verifier 只看到随机化 cmPK、Sigma proof 和 CA 认证的 Merkle Root。本方案不声称对 CA 隐藏设备公钥。
2. EnrollmentChallenge 的 consumed 状态目前只在进程内存中维护。生产 CA 必须把 nonce 的签发、消费和注册记录放入持久化事务存储，防止重启后重放。
3. 当前 CA certificate 是自定义 trust-anchor，不是 X.509；正式部署若改用 X.509，应保留包外指纹/信任根验证语义。
4. 设备撤销、根版本回滚保护和在线 CA 服务尚未实现。
5. CA demo 使用临时 CA 和临时设备密钥，仅作 smoke demo；其私有 credential 不能与其他设备生成的 Sigma proof 混用。
