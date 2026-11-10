//! E5-B HashFold fold-only entrypoint.
//!
//! 复用 E4/sonobe 现有的 SHA-256 HashFold 折叠逻辑，只执行：
//!   1. 读取媒体字节
//!   2. 初始化 SHA-256 电路与 IVC 参数
//!   3. 逐块折叠
//!   4. 输出折叠终态（Sigmabus h_hi/h_lo 绑定）
//!
//! 明确 **不执行** Decider（preprocess_and_generate_keys / prove），
//! 因为 Decider 电路合成在 2 GiB 内存下会被 OOM kill。
//!
//! 关键约束：公开摘要必须是外部传入、已由 C2PA Claim 认证的值，
//! 绝不能用本程序自己算出的摘要回填。

use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use ark_bn254::{Fr, G1Projective as C1};
use ark_ff::PrimeField;
use ark_grumpkin::Projective as C2;
use ark_std::rand::thread_rng;
use sha2::{Digest, Sha256};

use sonobe_fs::nova::{CycleFoldNova, Nova};
use sonobe_ivc::compilers::cyclefold::CycleFoldBasedIVC;
use sonobe_ivc::sha256_step::{sha256_padded_blocks, Sha256PaddedCircuit};
use sonobe_ivc::{IVCKeyGenerator, IVCPreprocessor, IVCStatefulProver, IVCVerifier};
use sonobe_primitives::algebra::field::SonobeField;
use sonobe_primitives::circuits::FCircuit;
use sonobe_primitives::commitments::pedersen::Pedersen;
use sonobe_primitives::transcripts::griffin::{GriffinParams, sponge::GriffinSponge};

type FC = Sha256PaddedCircuit<Fr>;
type IVCType = CycleFoldBasedIVC<
    Nova<Pedersen<C1, true>>,
    CycleFoldNova<Pedersen<C2, true>>,
    GriffinSponge<Fr>,
>;

fn read_status_kb(key: &str) -> u64 {
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with(key))
                .and_then(|l| l.split_whitespace().nth(1).and_then(|v| v.parse().ok()))
        })
        .unwrap_or(0)
}

fn peak_rss_kb() -> u64 {
    read_status_kb("VmHWM:")
}
fn cur_rss_kb() -> u64 {
    read_status_kb("VmRSS:")
}

/// 把 bound 在 Fr 里的 u128 还原成 16 字节大端。
fn fr_to_u128(f: &Fr) -> Option<u128> {
    let big = f.into_bigint();
    let limbs = big.as_ref();
    // 低 128 位 = limb[0] | limb[1] << 64；更高位必须为 0
    if limbs.iter().skip(2).any(|&l| l != 0) {
        return None;
    }
    let lo = limbs[0] as u128;
    let hi = (limbs[1] as u128) << 64;
    Some(hi | lo)
}

fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    let mut input: Option<PathBuf> = None;
    let mut expected_hex: Option<String> = None;
    let mut out_json: Option<PathBuf> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--input" => {
                i += 1;
                input = Some(PathBuf::from(&args[i]));
            }
            "--expect-sha256" => {
                i += 1;
                expected_hex = Some(args[i].to_lowercase());
            }
            "--out" => {
                i += 1;
                out_json = Some(PathBuf::from(&args[i]));
            }
            other => {
                eprintln!("unknown argument: {other}");
                eprintln!("usage: fold_only --input <media> --expect-sha256 <hex> [--out <json>]");
                std::process::exit(2);
            }
        }
        i += 1;
    }

    let input = input.ok_or("--input is required")?;
    let expected_hex =
        expected_hex.ok_or("--expect-sha256 is required (authenticated C2PA digest)")?;
    if expected_hex.len() != 64 {
        return Err(format!(
            "--expect-sha256 must be 64 hex chars, got {}",
            expected_hex.len()
        )
        .into());
    }

    let raw = fs::read(&input)?;
    println!("============================================================");
    println!(" E5-B HashFold FOLD-ONLY (no Decider)");
    println!("============================================================");
    println!(" input file      : {}", input.display());
    println!(" input bytes     : {}", raw.len());
    println!(" expected sha256 : {expected_hex}");

    // 独立计算真实 SHA-256，仅用于与认证摘要比对
    let real_digest = Sha256::digest(&raw);
    let mut real_arr = [0u8; 32];
    real_arr.copy_from_slice(&real_digest);
    let real_hex = hex32(&real_arr);
    println!(" computed sha256 : {real_hex}");
    if real_hex != expected_hex {
        return Err(format!(
            "SHA-256 mismatch: witness hashes to {real_hex} but authenticated C2PA digest is {expected_hex}"
        )
        .into());
    }
    println!(" digest match    : OK (witness matches authenticated C2PA hard binding)");

    let blocks = sha256_padded_blocks(&raw);
    let nblocks = blocks.len();
    println!(" sha256 blocks   : {nblocks}");
    println!(
        " memory at start : {} MiB (peak {} MiB)",
        cur_rss_kb() / 1024,
        peak_rss_kb() / 1024
    );

    let circuit = Sha256PaddedCircuit::<Fr>::new(raw.len());
    assert_eq!(
        circuit.num_blocks(),
        nblocks,
        "block count mismatch vs circuit"
    );

    let mut rng = thread_rng();

    // ---- 2. 初始化（IVC 预处理 + 密钥；非 Decider）----
    let t_setup = Instant::now();
    let pp = <IVCType as IVCPreprocessor>::preprocess(
        (131072, 16384, Arc::new(GriffinParams::new(16, 5, 9))),
        &mut rng,
    )?;
    let (pk, vk) = <IVCType as IVCKeyGenerator>::generate_keys(pp, &circuit)?;
    let setup_ms = t_setup.elapsed().as_millis() as u64;
    println!(
        " IVC setup       : {} ms, RSS={} MiB, peak={} MiB",
        setup_ms,
        cur_rss_kb() / 1024,
        peak_rss_kb() / 1024
    );

    let initial_state = circuit.dummy_state();
    let mut prover = IVCStatefulProver::<_, IVCType>::new(&pk, &circuit, initial_state.clone())?;

    // ---- 3. 逐块折叠 ----
    let t_fold = Instant::now();
    for (idx, block) in blocks.iter().enumerate() {
        prover.prove_step(*block, &mut rng)?;
        if (idx + 1) % 50 == 0 || idx + 1 == nblocks {
            println!(
                "   step {}/{}  elapsed={} ms  RSS={} MiB  peak={} MiB",
                idx + 1,
                nblocks,
                t_fold.elapsed().as_millis(),
                cur_rss_kb() / 1024,
                peak_rss_kb() / 1024
            );
        }
    }
    let fold_ms = t_fold.elapsed().as_millis() as u64;
    let peak_after_fold = peak_rss_kb();
    println!(
        " folding done    : {} ms total, {:.2} ms/step, peak={} MiB",
        fold_ms,
        fold_ms as f64 / nblocks as f64,
        peak_after_fold / 1024
    );

    // ---- 4. 输出折叠终态 ----
    let t_verify = Instant::now();
    IVCType::verify::<FC>(
        &vk,
        prover.i,
        &prover.initial_state,
        &prover.current_state,
        &prover.current_proof,
    )?;
    let verify_ms = t_verify.elapsed().as_millis() as u64;
    println!(" IVC verify      : {} ms (final accumulated proof verifies)", verify_ms);

    let state = prover.current_state.clone();
    let binding = <FC as FCircuit>::sigmabus_final_binding(nblocks, &state)
        .expect("SHA-256 circuit must publish a Sigmabus binding");

    let h_hi_u = fr_to_u128(&binding.h_hi).ok_or("h_hi exceeds u128")?;
    let h_lo_u = fr_to_u128(&binding.h_lo).ok_or("h_lo exceeds u128")?;

    let mut folded_digest = [0u8; 32];
    folded_digest[0..16].copy_from_slice(&h_hi_u.to_be_bytes());
    folded_digest[16..32].copy_from_slice(&h_lo_u.to_be_bytes());
    let folded_hex = hex32(&folded_digest);

    println!();
    println!(" === folded terminal state ===");
    println!(" blocks folded   : {}", binding.num_blocks);
    println!(" h_hi            : {:032x}", h_hi_u);
    println!(" h_lo            : {:032x}", h_lo_u);
    println!(" folded digest   : {folded_hex}");
    println!(" expected digest : {expected_hex}");
    println!(" BINDING MATCH   : {}", folded_hex == expected_hex);
    println!(" peak RSS        : {} MiB", peak_rss_kb() / 1024);
    println!(" Decider         : NOT EXECUTED");

    if folded_hex != expected_hex {
        return Err(format!(
            "folded digest {folded_hex} != authenticated C2PA digest {expected_hex}"
        )
        .into());
    }

    // 附带：确认 h_hi/h_lo 与 σ/签名用的 u128 拆分口径一致
    if let Some(out) = out_json {
        let doc = serde_json::json!({
            "input_file": input.display().to_string(),
            "input_bytes": raw.len(),
            "sha256_expected": expected_hex,
            "sha256_witness": real_hex,
            "sha256_folded": folded_hex,
            "blocks": nblocks,
            "folding_steps": prover.i,
            "setup_ms": setup_ms,
            "folding_ms": fold_ms,
            "mean_ms_per_step": fold_ms as f64 / nblocks as f64,
            "verify_ms": verify_ms,
            "peak_rss_kib_after_fold": peak_after_fold,
            "peak_rss_kib_total": peak_rss_kb(),
            "h_hi": format!("{:032x}", h_hi_u),
            "h_lo": format!("{:032x}", h_lo_u),
            "binding_match": folded_hex == expected_hex,
            "decider_executed": false,
            "ivc_final_proof_verified": true,
        });
        if let Some(p) = out.parent() {
            if !p.as_os_str().is_empty() {
                fs::create_dir_all(p)?;
            }
        }
        fs::write(&out, serde_json::to_string_pretty(&doc)?)?;
        println!(" result written  : {}", out.display());
    }

    Ok(())
}
