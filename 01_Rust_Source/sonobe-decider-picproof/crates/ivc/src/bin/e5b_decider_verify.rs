//! E5-B Decider 独立验证器（验证者侧）。
//!
//! 只读取公开材料：
//!   - decider_vk.bin            验证密钥
//!   - pi_decider.bin            Decider 证明
//!   - decider_public_inputs.json 公开语句（初态/终态/步数/摘要）
//!
//! **不读取**：原始 JPEG、bound_bytes.bin、opening_v.txt、Merkle 路径、
//!             fold-only 日志。
//!
//! 验证逻辑
//! --------
//!   1. 从公开输入重建 IVC 公开语句 (i, initial_state, current_state, binding)
//!   2. 独立核对 current_state 拼接 == 外部给定的认证 C2PA 摘要
//!   3. 独立核对 initial_state == SHA-256 标准 IV
//!   4. 核对步数与块数一致
//!   5. 调用 Decider::verify 验证证明
//!
//! 关键：第 2 步使用的认证摘要来自命令行 `--expect-sha256`，
//! 而不是 public_inputs.json 里自称的值。若两者不一致直接拒绝。

use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use ark_bn254::{Bn254, Fr, G1Projective as C1};
use ark_grumpkin::Projective as C2;

use sonobe_fs::nova::{CycleFoldNova, Nova};
use sonobe_ivc::compilers::cyclefold::CycleFoldBasedIVCDecider;
use sonobe_ivc::sha256_step::Sha256PaddedCircuit;
use sonobe_ivc::IVCProofCompressor;
use sonobe_primitives::circuits::FCircuit;
use sonobe_primitives::commitments::pedersen::Pedersen;
use sonobe_primitives::transcripts::griffin::sponge::GriffinSponge;
use sonobe_snarks::cp::legogroth16::LegoGroth16;

type FC = Sha256PaddedCircuit<Fr>;
type Decider = CycleFoldBasedIVCDecider<
    Nova<Pedersen<C1, true>>,
    CycleFoldNova<Pedersen<C2, true>>,
    GriffinSponge<Fr>,
    LegoGroth16<Bn254>,
>;

/// SHA-256 标准初始向量
const SHA256_IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

fn main() -> Result<(), Box<dyn Error>> {
    let av: Vec<String> = std::env::args().collect();
    let mut vk_path: Option<PathBuf> = None;
    let mut proof_path: Option<PathBuf> = None;
    let mut pub_path: Option<PathBuf> = None;
    let mut expect: Option<String> = None;

    let mut i = 1;
    while i < av.len() {
        match av[i].as_str() {
            "--vk" => {
                i += 1;
                vk_path = Some(PathBuf::from(&av[i]));
            }
            "--proof" => {
                i += 1;
                proof_path = Some(PathBuf::from(&av[i]));
            }
            "--public-inputs" => {
                i += 1;
                pub_path = Some(PathBuf::from(&av[i]));
            }
            "--expect-sha256" => {
                i += 1;
                expect = Some(av[i].to_lowercase());
            }
            other => {
                eprintln!("unknown argument: {other}");
                eprintln!(
                    "usage: e5b_decider_verify --vk <f> --proof <f> --public-inputs <f> \
                     --expect-sha256 <hex>"
                );
                std::process::exit(2);
            }
        }
        i += 1;
    }

    let vk_path = vk_path.ok_or("--vk required")?;
    let proof_path = proof_path.ok_or("--proof required")?;
    let pub_path = pub_path.ok_or("--public-inputs required")?;
    let expect = expect.ok_or("--expect-sha256 required (authenticated C2PA digest)")?;

    if expect.len() != 64 {
        return Err("--expect-sha256 must be 64 hex chars".into());
    }

    println!("============================================================");
    println!(" E5-B Decider 独立验证（公开材料 only）");
    println!("============================================================");

    let doc: serde_json::Value = serde_json::from_slice(&fs::read(&pub_path)?)?;

    // ---------- [1] 独立核对终态摘要 == 外部认证摘要 ----------
    // 不采信 public_inputs 里的 sha256_authenticated，用命令行值
    let declared = doc["sha256_authenticated"].as_str().unwrap_or("");
    if declared != expect {
        return Err(format!(
            "REJECT: public-inputs declares authenticated digest {declared}, \
             but verifier was given {expect}"
        )
        .into());
    }
    println!("[1] authenticated digest : {expect}");

    let current_state_hex: Vec<String> = doc["current_state"]
        .as_array()
        .ok_or("current_state missing")?
        .iter()
        .map(|v| v.as_str().unwrap_or("").to_string())
        .collect();
    if current_state_hex.len() != 8 {
        return Err(format!("current_state must have 8 words, got {}", current_state_hex.len()).into());
    }
    // 每个 word 取低 8 hex（32-bit）
    let joined: String = current_state_hex
        .iter()
        .map(|w| {
            let n = w.len();
            w[n.saturating_sub(8)..].to_string()
        })
        .collect();
    if joined != expect {
        return Err(format!(
            "REJECT: current_state reconstructs to {joined}, expected {expect}"
        )
        .into());
    }
    println!("[2] terminal state        : {joined}  (reconstructed from 8 words)");
    println!("    == authenticated      : PASS");

    // ---------- [2] 初态必须是 SHA-256 IV ----------
    let initial_state_hex: Vec<String> = doc["initial_state"]
        .as_array()
        .ok_or("initial_state missing")?
        .iter()
        .map(|v| v.as_str().unwrap_or("").to_string())
        .collect();
    if initial_state_hex.len() != 8 {
        return Err("initial_state must have 8 words".into());
    }
    let mut iv_ok = true;
    let mut initial_state = [Fr::from(0u64); 8];
    for (idx, w) in initial_state_hex.iter().enumerate() {
        let n = w.len();
        let low = &w[n.saturating_sub(8)..];
        let val = u32::from_str_radix(low, 16)?;
        if val != SHA256_IV[idx] {
            iv_ok = false;
        }
        initial_state[idx] = Fr::from(val as u64);
    }
    if !iv_ok {
        return Err("REJECT: initial_state is not the SHA-256 IV".into());
    }
    println!("[3] initial state         : SHA-256 IV  PASS");

    // ---------- [3] 步数 / 块数 ----------
    let steps = doc["folding_steps"].as_u64().ok_or("folding_steps missing")? as usize;
    let media_bytes = doc["media_bytes"].as_u64().ok_or("media_bytes missing")? as usize;
    let expected_blocks = (media_bytes + 1 + 8).div_ceil(64);
    if steps != expected_blocks {
        return Err(format!(
            "REJECT: declared steps {steps} != block count {expected_blocks} for {media_bytes} bytes"
        )
        .into());
    }
    let sig_blocks = doc["sigmabus_num_blocks"].as_u64().unwrap_or(0) as usize;
    if sig_blocks != steps {
        return Err(format!(
            "REJECT: Sigmabus num_blocks {sig_blocks} != steps {steps}"
        )
        .into());
    }
    println!(
        "[4] steps / media         : {steps} blocks for {media_bytes} B  PASS"
    );

    // ---------- [4] 重建 current_state 为 Fr ----------
    let mut current_state = [Fr::from(0u64); 8];
    for (idx, w) in current_state_hex.iter().enumerate() {
        let n = w.len();
        let low = &w[n.saturating_sub(8)..];
        let val = u32::from_str_radix(low, 16)?;
        current_state[idx] = Fr::from(val as u64);
    }

    // ---------- [5] Sigmabus binding ----------
    let h_hi_hex = doc["h_hi_hex"].as_str().ok_or("h_hi_hex missing")?;
    let h_lo_hex = doc["h_lo_hex"].as_str().ok_or("h_lo_hex missing")?;
    // 与终态一致性
    if !expect.starts_with(h_hi_hex) || !expect[32..].starts_with(h_lo_hex) {
        return Err(format!(
            "REJECT: h_hi/h_lo ({h_hi_hex}/{h_lo_hex}) do not match authenticated digest"
        )
        .into());
    }
    let h_hi = u128::from_str_radix(h_hi_hex, 16)?;
    let h_lo = u128::from_str_radix(h_lo_hex, 16)?;

    let binding = <FC as FCircuit>::sigmabus_final_binding(steps, &current_state)
        .ok_or("FC must publish a Sigmabus binding")?;
    if binding.h_hi != Fr::from(h_hi) || binding.h_lo != Fr::from(h_lo) {
        return Err("REJECT: circuit-derived Sigmabus binding != declared binding".into());
    }
    println!("[5] Sigmabus binding      : PASS (derived from state == declared)");

    // ---------- [6] 加载 vk / proof 并验证 ----------
    let dvk_bytes = fs::read(&vk_path)?;
    let dvk = Decider::deserialize_verifier_key::<FC>(&dvk_bytes)
        .map_err(|e| format!("dvk deserialization failed: {e:?}"))?;
    println!("[6] verifier key          : {} B", dvk_bytes.len());

    let pi_bytes = fs::read(&proof_path)?;
    let compressed = Decider::deserialize_compressed_proof::<FC>(&pi_bytes)
        .map_err(|e| format!("proof deserialization failed: {e:?}"))?;
    println!("[7] decider proof         : {} B", pi_bytes.len());

    let t = Instant::now();
    match <Decider as IVCProofCompressor>::verify::<FC>(
        &dvk,
        steps,
        &initial_state,
        &current_state,
        &compressed,
        Some(binding),
    ) {
        Ok(()) => {
            let ms = t.elapsed().as_millis();
            println!("[8] Decider::verify       : PASS ({ms} ms)");
        }
        Err(e) => {
            return Err(format!("REJECT: Decider::verify failed: {e:?}").into());
        }
    }

    println!();
    println!("============================================================");
    println!(" STATUS: ACCEPT");
    println!("============================================================");
    println!(" verified: Decider proof over authenticated C2PA digest {expect}");
    println!(" inputs  : public materials only (no JPEG, no private witness)");
    Ok(())
}
