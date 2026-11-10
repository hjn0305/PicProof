//! E5-B Decider 完整证明流程（独立入口）。
//!
//! 与 E4 的 `jisa_unified_e2e.rs` 完全独立，不修改任何已有实验代码。
//!
//! 流程
//! ----
//!   1. 读入私有媒体 `private/bound_bytes.bin`
//!   2. **独立校验** SHA256(media) == 认证的 C2PA Hard Binding 摘要
//!   3. HashFold：444 步折叠，保留完整 IVC 状态
//!   4. 校验折叠终态 Sigmabus 绑定 == 认证摘要拆分出的 (h_hi, h_lo)
//!   5. Decider preprocess_and_generate_keys（合成 + 密钥生成，分段探针）
//!   6. Decider prove（对第 3 步的完整 IVC 状态）
//!   7. Decider verify（独立复核公开语句）
//!   8. 落盘 proof / vk / 公开输入清单，供 Python 联合验证器独立验证
//!
//! 关键安全约束
//! ------------
//! 公开目标摘要只来自外部传入的**认证值**，绝不用程序自算值回填。
//! 折叠终态必须与认证摘要逐字节一致，否则直接失败。
//!
//! 内存探针
//! --------
//! 按固定间隔采样 VmRSS，按阶段时间戳切分，得到各阶段真实峰值
//! （VmHWM 是历史峰值，不能相减）。

use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use ark_bn254::{Bn254, Fr, G1Projective as C1};
use ark_grumpkin::Projective as C2;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::thread_rng;
use sha2::{Digest, Sha256};

use sonobe_fs::nova::{CycleFoldNova, Nova};
use sonobe_ivc::compilers::cyclefold::{CycleFoldBasedIVC, CycleFoldBasedIVCDecider};
use sonobe_ivc::sha256_step::{sha256_padded_blocks, Sha256PaddedCircuit};
use sonobe_ivc::{
    IVCKeyGenerator, IVCPreprocessor, IVCProofCompressor, IVCStatefulProver, IVCVerifier,
};
use sonobe_primitives::circuits::FCircuit;
use sonobe_primitives::commitments::pedersen::Pedersen;
use sonobe_primitives::transcripts::griffin::{sponge::GriffinSponge, GriffinParams};
use sonobe_snarks::cp::legogroth16::LegoGroth16;

type FC = Sha256PaddedCircuit<Fr>;
type IVCType = CycleFoldBasedIVC<
    Nova<Pedersen<C1, true>>,
    CycleFoldNova<Pedersen<C2, true>>,
    GriffinSponge<Fr>,
>;
type Decider = CycleFoldBasedIVCDecider<
    Nova<Pedersen<C1, true>>,
    CycleFoldNova<Pedersen<C2, true>>,
    GriffinSponge<Fr>,
    LegoGroth16<Bn254>,
>;

// ============================================================
// 内存采样器
// ============================================================

static SAMPLER_RUNNING: AtomicBool = AtomicBool::new(false);
static SAMPLER_INTERVAL_US: AtomicU64 = AtomicU64::new(20_000);

/// 一条采样记录：相对进程启动的微秒数 + VmRSS(KiB)
#[derive(Clone, Copy, Debug)]
struct Sample {
    t_us: u64,
    rss_kib: u64,
}

fn read_vm_kib(key: &str) -> u64 {
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with(key))
                .and_then(|l| l.split_whitespace().nth(1).and_then(|v| v.parse().ok()))
        })
        .unwrap_or(0)
}

fn peak_rss_kib() -> u64 {
    read_vm_kib("VmHWM:")
}

struct Sampler {
    t0: Instant,
    samples: Arc<Mutex<Vec<Sample>>>,
    handle: Option<thread::JoinHandle<()>>,
    phases: Vec<(String, u64, u64, u64, u64)>, // label, t_start_us, t_end_us, rss_start, rss_end
}

impl Sampler {
    fn start() -> Self {
        let t0 = Instant::now();
        let samples = Arc::new(Mutex::new(Vec::with_capacity(200_000)));
        let s2 = samples.clone();
        let t0_thread = t0; // Instant 是 Copy，直接移入线程

        let handle = thread::spawn(move || {
            SAMPLER_RUNNING.store(true, Ordering::SeqCst);
            while SAMPLER_RUNNING.load(Ordering::SeqCst) {
                let t = t0_thread.elapsed().as_micros() as u64;
                let rss = read_vm_kib("VmRSS:");
                if let Ok(mut g) = s2.lock() {
                    g.push(Sample { t_us: t, rss_kib: rss });
                }
                thread::sleep(Duration::from_micros(
                    SAMPLER_INTERVAL_US.load(Ordering::SeqCst),
                ));
            }
        });

        Sampler {
            t0,
            samples,
            handle: Some(handle),
            phases: Vec::new(),
        }
    }

    fn now_us(&self) -> u64 {
        self.t0.elapsed().as_micros() as u64
    }

    /// 记录一个阶段的边界；返回 (start_us, start_rss)
    fn mark(&self) -> (u64, u64) {
        (self.now_us(), read_vm_kib("VmRSS:"))
    }

    fn close_phase(&mut self, label: &str, start: (u64, u64)) {
        let end = (self.now_us(), read_vm_kib("VmRSS:"));
        self.phases
            .push((label.to_string(), start.0, end.0, start.1, end.1));
    }

    fn stop(mut self) -> Self {
        SAMPLER_RUNNING.store(false, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        self
    }

    /// 阶段内峰值 RSS（KiB），基于采样点
    fn phase_peak_kib(&self, label: &str) -> Option<u64> {
        let (_l, s, e, _rs, _re) = self.phases.iter().find(|p| p.0 == label)?;
        let g = self.samples.lock().ok()?;
        let mut peak = 0u64;
        for smp in g.iter() {
            if smp.t_us >= *s && smp.t_us <= *e {
                peak = peak.max(smp.rss_kib);
            }
        }
        if peak == 0 {
            None
        } else {
            Some(peak)
        }
    }

    fn dump_phases(&self) -> Vec<serde_json::Value> {
        self.phases
            .iter()
            .map(|(label, s, e, rs, re)| {
                let sampled = self.phase_peak_kib(label).unwrap_or(0);
                // 极短阶段可能没有任何采样点落入区间（如 4ms 的 verify）。
                // 此时退化为阶段边界 RSS 的较小上界：max(start, end)。
                // 明确标注来源，避免把边界值误当采样峰值。
                let (peak, source) = if sampled > 0 {
                    (sampled, "sampled")
                } else {
                    ((*rs).max(*re), "boundary")
                };
                serde_json::json!({
                    "phase": label,
                    "duration_ms": (e - s) / 1000,
                    "duration_us": e - s,
                    "rss_start_kib": rs,
                    "rss_end_kib": re,
                    "rss_peak_kib": peak,
                    "rss_peak_mib": (peak as f64 / 1024.0 * 100.0).round() / 100.0,
                    "peak_source": source,
                })
            })
            .collect()
    }

    fn sample_count(&self) -> usize {
        self.samples.lock().map(|g| g.len()).unwrap_or(0)
    }
}

/// 简易探针：打印当前 RSS / 历史峰值
fn mem_probe(label: &str) {
    eprintln!(
        "[E5B_MEM] {:28} VmRSS={} KiB  VmHWM={} KiB",
        label,
        read_vm_kib("VmRSS:"),
        peak_rss_kib()
    );
}

// ============================================================
// 参数
// ============================================================

struct Args {
    media: PathBuf,
    expect_sha256: String,
    h_sig_sha256: Option<String>,
    out_dir: PathBuf,
}

fn parse_args() -> Result<Args, Box<dyn Error>> {
    let av: Vec<String> = std::env::args().collect();
    let mut media: Option<PathBuf> = None;
    let mut expect: Option<String> = None;
    let mut h_sig: Option<String> = None;
    let mut out = PathBuf::from(".");

    let mut i = 1;
    while i < av.len() {
        match av[i].as_str() {
            "--media" => {
                i += 1;
                media = Some(PathBuf::from(&av[i]));
            }
            "--expect-sha256" => {
                i += 1;
                expect = Some(av[i].to_lowercase());
            }
            "--expect-h-sig" => {
                i += 1;
                h_sig = Some(av[i].to_lowercase());
            }
            "--out-dir" => {
                i += 1;
                out = PathBuf::from(&av[i]);
            }
            other => {
                eprintln!("unknown argument: {other}");
                eprintln!(
                    "usage: e5b_decider --media <file> --expect-sha256 <hex> \
                     [--expect-h-sig <hex>] [--out-dir <dir>]"
                );
                std::process::exit(2);
            }
        }
        i += 1;
    }

    let media = media.ok_or("--media is required")?;
    let expect_sha256 = expect.ok_or("--expect-sha256 is required (authenticated C2PA digest)")?;
    if expect_sha256.len() != 64 {
        return Err(format!("--expect-sha256 must be 64 hex chars, got {}", expect_sha256.len()).into());
    }
    if let Some(h) = &h_sig {
        if h.len() != 64 {
            return Err(format!("--expect-h-sig must be 64 hex chars, got {}", h.len()).into());
        }
    }

    Ok(Args {
        media,
        expect_sha256,
        h_sig_sha256: h_sig,
        out_dir: out,
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = parse_args()?;
    let started = Instant::now();

    fs::create_dir_all(&args.out_dir)?;

    println!("============================================================");
    println!(" E5-B Decider 完整证明流程（独立入口）");
    println!("============================================================");

    // ---------------- [1] 读入私有媒体 ----------------
    let raw = fs::read(&args.media)
        .map_err(|e| format!("failed to read media {}: {e}", args.media.display()))?;
    let img_len = raw.len();
    mem_probe("after_load_media");
    println!("[1] media           : {} ({} B)", args.media.display(), img_len);
    println!("    expect sha256   : {}", args.expect_sha256);

    // ---------------- [2] 独立校验：见证摘要 == 认证摘要 ----------------
    let witness_digest: [u8; 32] = Sha256::digest(&raw).into();
    let witness_hex = hex(&witness_digest);
    println!("    witness sha256  : {witness_hex}");
    if witness_hex != args.expect_sha256 {
        return Err(format!(
            "SECURITY FAILURE: media hashes to {witness_hex} but authenticated C2PA digest is {}",
            args.expect_sha256
        )
        .into());
    }
    println!("[2] digest check    : PASS (witness matches authenticated C2PA Hard Binding)");

    // 认证摘要拆分为 (h_hi, h_lo)，作为**公开目标**
    let auth_digest = hex_to_32(&args.expect_sha256)?;
    let target_h_hi = u128::from_be_bytes(auth_digest[0..16].try_into().unwrap());
    let target_h_lo = u128::from_be_bytes(auth_digest[16..32].try_into().unwrap());
    println!(
        "    target h_hi     : {target_h_hi:032x}\n    target h_lo     : {target_h_lo:032x}"
    );

    let mut sampler = Sampler::start();
    let mut rng = thread_rng();

    // ---------------- [3] HashFold：444 步，保留完整 IVC 状态 ----------------
    println!();
    println!("[3] HashFold");
    let blocks = sha256_padded_blocks(&raw);
    let nblocks = blocks.len();
    let circuit = Sha256PaddedCircuit::<Fr>::new(img_len);
    assert_eq!(
        circuit.num_blocks(),
        nblocks,
        "circuit block count mismatch"
    );
    println!("    blocks          : {nblocks}");

    let ph_setup = sampler.mark();
    let pp = <IVCType as IVCPreprocessor>::preprocess(
        (131072, 16384, Arc::new(GriffinParams::new(16, 5, 9))),
        &mut rng,
    )?;
    let (pk, vk) = <IVCType as IVCKeyGenerator>::generate_keys(pp, &circuit)?;
    sampler.close_phase("ivc_preprocess", ph_setup);
    println!(
        "    IVC setup       : {} ms",
        sampler.phases.last().unwrap().2 - sampler.phases.last().unwrap().1
    );

    let initial_state = circuit.dummy_state();
    let mut prover = IVCStatefulProver::<_, IVCType>::new(&pk, &circuit, initial_state.clone())?;

    let ph_fold = sampler.mark();
    mem_probe("before_folding");
    for (idx, block) in blocks.iter().enumerate() {
        prover.prove_step(*block, &mut rng)?;
        if (idx + 1) % 100 == 0 {
            eprintln!(
                "[E5B_FOLD] step {}/{} RSS={} KiB peak={} KiB",
                idx + 1,
                nblocks,
                read_vm_kib("VmRSS:"),
                peak_rss_kib()
            );
        }
    }
    sampler.close_phase("hashfold_folding", ph_fold);
    mem_probe("after_folding");

    let fold_ms = {
        let p = sampler.phases.last().unwrap();
        (p.2 - p.1) / 1000
    };
    println!("    folding         : {fold_ms} ms ({nblocks} steps)");

    // IVC 终态自验证
    let ph_ivcv = sampler.mark();
    IVCType::verify::<FC>(
        &vk,
        prover.i,
        &prover.initial_state,
        &prover.current_state,
        &prover.current_proof,
    )?;
    sampler.close_phase("ivc_verify", ph_ivcv);
    println!("    IVC verify      : PASS");

    // ---------------- [4] 校验折叠终态 == 认证摘要 ----------------
    let current_state = prover.current_state.clone();
    let binding = <FC as FCircuit>::sigmabus_final_binding(nblocks, &current_state)
        .ok_or("SHA-256 circuit must publish a Sigmabus binding")?;

    // 从 binding 的 Fr 还原 u128
    let got_h_hi = fr_to_u128(&binding.h_hi).ok_or("h_hi exceeds u128")?;
    let got_h_lo = fr_to_u128(&binding.h_lo).ok_or("h_lo exceeds u128")?;

    let mut folded_digest = [0u8; 32];
    folded_digest[0..16].copy_from_slice(&got_h_hi.to_be_bytes());
    folded_digest[16..32].copy_from_slice(&got_h_lo.to_be_bytes());
    let folded_hex = hex(&folded_digest);

    println!();
    println!("[4] folded terminal state binding");
    println!("    folded digest   : {folded_hex}");
    println!("    authenticated   : {}", args.expect_sha256);
    println!("    blocks bound    : {}", binding.num_blocks);

    if got_h_hi != target_h_hi || got_h_lo != target_h_lo {
        return Err(format!(
            "SECURITY FAILURE: folded terminal digest {folded_hex} != authenticated {}",
            args.expect_sha256
        )
        .into());
    }
    if binding.num_blocks != nblocks {
        return Err(format!(
            "block count mismatch: binding says {} vs actual {nblocks}",
            binding.num_blocks
        )
        .into());
    }
    println!("    BINDING MATCH   : PASS (folded terminal state == authenticated C2PA digest)");

    // ---------------- [5] Decider 预处理 + 密钥生成 ----------------
    println!();
    println!("[5] Decider preprocess + keygen");
    mem_probe("before_decider_synthesis");

    let ph_dec = sampler.mark();
    let (dpk, dvk) =
        <Decider as IVCProofCompressor>::preprocess_and_generate_keys(&circuit, vk, &mut rng)?;
    sampler.close_phase("decider_synthesis_and_keygen", ph_dec);
    mem_probe("after_generate_keys");

    {
        let p = sampler.phases.last().unwrap();
        let peak = sampler.phase_peak_kib("decider_synthesis_and_keygen").unwrap_or(0);
        println!(
            "    preprocess+keygen: {} ms, phase peak RSS = {} MiB",
            (p.2 - p.1) / 1000,
            peak / 1024
        );
    }

    let dvk_bytes = Decider::serialize_verifier_key::<FC>(&dvk)?;
    let dvk_sha = hex(&Sha256::digest(&dvk_bytes));
    println!("    dvk             : {} B, sha256={}", dvk_bytes.len(), dvk_sha);
    fs::write(args.out_dir.join("decider_vk.bin"), &dvk_bytes)?;

    // ---------------- [6] Decider 证明生成 ----------------
    println!();
    println!("[6] Decider prove");
    mem_probe("before_decider_prove");

    let ph_prove = sampler.mark();
    let compressed = <Decider as IVCProofCompressor>::prove::<FC>(
        &dpk,
        nblocks,
        &initial_state,
        &current_state,
        &prover.current_proof,
        Some(binding.clone()),
        &mut rng,
    )?;
    sampler.close_phase("decider_prove", ph_prove);
    mem_probe("after_decider_prove");

    let pi_bytes = Decider::serialize_compressed_proof::<FC>(&compressed)?;
    let pi_sha = hex(&Sha256::digest(&pi_bytes));
    {
        let p = sampler.phases.last().unwrap();
        let peak = sampler.phase_peak_kib("decider_prove").unwrap_or(0);
        println!(
            "    prove           : {} ms, {} B, sha256={}, phase peak = {} MiB",
            (p.2 - p.1) / 1000,
            pi_bytes.len(),
            pi_sha,
            peak / 1024
        );
    }
    fs::write(args.out_dir.join("pi_decider.bin"), &pi_bytes)?;

    // ---------------- [7] Decider 验证 ----------------
    println!();
    println!("[7] Decider verify");
    mem_probe("before_decider_verify");

    let ph_verify = sampler.mark();
    <Decider as IVCProofCompressor>::verify::<FC>(
        &dvk,
        nblocks,
        &initial_state,
        &current_state,
        &compressed,
        Some(binding.clone()),
    )?;
    sampler.close_phase("decider_verify", ph_verify);
    mem_probe("after_decider_verify");

    let verify_ms = {
        let p = sampler.phases.last().unwrap();
        (p.2 - p.1) / 1000
    };
    println!("    verify          : PASS ({verify_ms} ms)");

    // ---------------- [8] 落盘公开输入清单 ----------------
    let sampler = sampler.stop();
    let total_ms = started.elapsed().as_millis() as u64;

    let initial_state_json: Vec<String> = initial_state.iter().map(fr_to_hex).collect();
    let current_state_json: Vec<String> = current_state.iter().map(fr_to_hex).collect();

    let public_inputs = serde_json::json!({
        "profile": "E5B-Decider-v1",
        "media_bytes": img_len,
        "sha256_authenticated": args.expect_sha256,
        "sha256_witness": witness_hex,
        "sha256_folded": folded_hex,
        "h_sig_sha256": args.h_sig_sha256,
        "folding_steps": nblocks,
        "sigmabus_num_blocks": binding.num_blocks,
        "h_hi_hex": format!("{got_h_hi:032x}"),
        "h_lo_hex": format!("{got_h_lo:032x}"),
        "initial_state": initial_state_json,
        "current_state": current_state_json,
        "decider_vk_sha256": dvk_sha,
        "decider_vk_bytes": dvk_bytes.len(),
        "decider_proof_sha256": pi_sha,
        "decider_proof_bytes": pi_bytes.len(),
        "ivc_preprocess": "(131072, 16384, GriffinParams::new(16, 5, 9))",
        "hash_type": "sha256",
        "decider_verify_passed": true,
        "ivc_verify_passed": true,
        "binding_match": true,
    });
    fs::write(
        args.out_dir.join("decider_public_inputs.json"),
        serde_json::to_string_pretty(&public_inputs)?,
    )?;

    println!();
    println!("============================================================");
    println!(" 各阶段计时与峰值 RSS");
    println!("============================================================");
    for p in sampler.dump_phases() {
        println!(
            "  {:32} {:>8} ms  peak {:>8.2} MiB",
            p["phase"].as_str().unwrap_or("?"),
            p["duration_ms"],
            p["rss_peak_mib"]
        );
    }
    println!(
        "  {:32} {:>8} ms  peak {:>8.2} MiB",
        "TOTAL",
        total_ms,
        peak_rss_kib() as f64 / 1024.0
    );

    let timing = serde_json::json!({
        "phases": sampler.dump_phases(),
        "total_ms": total_ms,
        "process_peak_rss_kib": peak_rss_kib(),
        "process_peak_rss_mib": (peak_rss_kib() as f64 / 1024.0 * 100.0).round() / 100.0,
        "media_bytes": img_len,
        "blocks": nblocks,
        "decider_vk_bytes": dvk_bytes.len(),
        "decider_proof_bytes": pi_bytes.len(),
    });
    fs::write(
        args.out_dir.join("decider_timing.json"),
        serde_json::to_string_pretty(&timing)?,
    )?;

    println!();
    println!(" outputs:");
    for f in [
        "decider_vk.bin",
        "pi_decider.bin",
        "decider_public_inputs.json",
        "decider_timing.json",
    ] {
        let p = args.out_dir.join(f);
        println!("   {}  ({} B)", p.display(), fs::metadata(&p).map(|m| m.len()).unwrap_or(0));
    }
    println!();
    println!(" E5B_DECIDER_OK");
    Ok(())
}

fn hex_to_32(s: &str) -> Result<[u8; 32], Box<dyn Error>> {
    let mut out = [0u8; 32];
    if s.len() != 64 {
        return Err(format!("hex digest must be 64 chars, got {}", s.len()).into());
    }
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)?;
    }
    Ok(out)
}

fn fr_to_u128(f: &Fr) -> Option<u128> {
    let big = f.into_bigint();
    let limbs = big.as_ref();
    if limbs.iter().skip(2).any(|&l| l != 0) {
        return None;
    }
    Some(((limbs[1] as u128) << 64) | (limbs[0] as u128))
}

/// Fr -> 64 位十六进制（大端，左补零）。
/// BigInt 未实现 LowerHex，改为取 limbs 手工拼字节。
fn fr_to_hex(f: &Fr) -> String {
    let big = f.into_bigint();
    let limbs = big.as_ref(); // [u64; 4]，小端
    let mut bytes = [0u8; 32];
    for (i, &limb) in limbs.iter().enumerate() {
        let start = 32 - (i + 1) * 8;
        bytes[start..start + 8].copy_from_slice(&limb.to_be_bytes());
    }
    hex(&bytes)
}
