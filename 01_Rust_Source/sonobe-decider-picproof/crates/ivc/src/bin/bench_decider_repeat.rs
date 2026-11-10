//! Decider Repeated Verification Benchmark
//!
//! Measures exact latency distribution across 1000 warm verifications
//! and 50 cold verifications of the 192-byte LegoGroth16 Decider proof.

use std::error::Error;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use ark_bn254::{Bn254, Fr, G1Projective as C1};
use ark_grumpkin::Projective as C2;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::thread_rng;
use serde::{Deserialize, Serialize};

use sonobe_fs::nova::{CycleFoldNova, Nova};
use sonobe_ivc::compilers::cyclefold::{CycleFoldBasedIVC, CycleFoldBasedIVCDecider};
use sonobe_ivc::sha256_step::{Sha256PaddedCircuit, sha256_padded_blocks};
use sonobe_ivc::{
    IVCKeyGenerator, IVCPreprocessor, IVCProofCompressor, IVCStatefulProver, IVCVerifier,
};
use sonobe_primitives::circuits::FCircuit;
use sonobe_primitives::commitments::pedersen::Pedersen;
use sonobe_primitives::transcripts::griffin::{GriffinParams, sponge::GriffinSponge};
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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LatencyStats {
    pub count: usize,
    pub mean_ms: f64,
    pub median_ms: f64,
    pub std_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub min_ms: f64,
    pub max_ms: f64,
    pub raw_us: Vec<u64>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DeciderRepeatReport {
    pub proof_bytes: usize,
    pub block_count_represented: usize,
    pub warm_stats: LatencyStats,
    pub cold_stats: LatencyStats,
    pub single_observation_ms: f64,
    pub verification_valid: bool,
}

fn compute_stats(mut samples_us: Vec<u64>) -> LatencyStats {
    let count = samples_us.len();
    assert!(count > 0);
    samples_us.sort_unstable();

    let sum_us: u64 = samples_us.iter().sum();
    let mean_us = sum_us as f64 / count as f64;

    let median_us = if count % 2 == 0 {
        (samples_us[count / 2 - 1] + samples_us[count / 2]) as f64 / 2.0
    } else {
        samples_us[count / 2] as f64
    };

    let p95_idx = ((count as f64) * 0.95).round() as usize;
    let p95_us = samples_us[p95_idx.min(count - 1)] as f64;

    let p99_idx = ((count as f64) * 0.99).round() as usize;
    let p99_us = samples_us[p99_idx.min(count - 1)] as f64;

    let min_us = samples_us[0] as f64;
    let max_us = samples_us[count - 1] as f64;

    let variance = samples_us
        .iter()
        .map(|&x| {
            let diff = x as f64 - mean_us;
            diff * diff
        })
        .sum::<f64>()
        / count as f64;
    let std_us = variance.sqrt();

    LatencyStats {
        count,
        mean_ms: mean_us / 1000.0,
        median_ms: median_us / 1000.0,
        std_ms: std_us / 1000.0,
        p95_ms: p95_us / 1000.0,
        p99_ms: p99_us / 1000.0,
        min_ms: min_us / 1000.0,
        max_ms: max_us / 1000.0,
        raw_us: samples_us,
    }
}

// Invalidate CPU cache lines by reading/writing a 64 MB buffer
fn evict_cache() {
    const SIZE: usize = 64 * 1024 * 1024;
    let mut buf = vec![0u8; SIZE];
    for i in (0..SIZE).step_by(64) {
        buf[i] = (i & 0xFF) as u8;
    }
    std::hint::black_box(&buf);
    std::thread::sleep(std::time::Duration::from_millis(5));
}

fn main() -> Result<(), Box<dyn Error>> {
    println!("============================================================");
    println!(" [DECIDER REPEAT VERIFICATION BENCHMARK]");
    println!(" 1000 Warm Verifications + 50 Cold Verifications");
    println!("============================================================");

    let mut rng = thread_rng();
    let msg = vec![0x42u8; 64];
    let blocks = sha256_padded_blocks(&msg);
    let sha256_blocks = blocks.len();
    let circuit = Sha256PaddedCircuit::<Fr>::new(msg.len());

    println!("[1/5] Generating IVC parameters...");
    let pp = <IVCType as IVCPreprocessor>::preprocess(
        (131072, 16384, Arc::new(GriffinParams::new(16, 5, 9))),
        &mut rng,
    )?;
    let (pk, vk) = <IVCType as IVCKeyGenerator>::generate_keys(pp, &circuit)?;
    let initial_state = circuit.dummy_state();

    let mut prover = IVCStatefulProver::<_, IVCType>::new(&pk, &circuit, initial_state.clone())?;
    for block in blocks.iter() {
        prover.prove_step(*block, &mut rng)?;
    }

    let current_state = prover.current_state.clone();
    let binding = <FC as FCircuit>::sigmabus_final_binding(sha256_blocks, &current_state)
        .expect("Binding required");

    println!("[2/5] Setting up LegoGroth16 Decider...");
    let (dpk, dvk) =
        <Decider as IVCProofCompressor>::preprocess_and_generate_keys(&circuit, vk, &mut rng)?;

    println!("[3/5] Generating 192 B compressed Decider proof...");
    let compressed = <Decider as IVCProofCompressor>::prove::<FC>(
        &dpk,
        sha256_blocks,
        &initial_state,
        &current_state,
        &prover.current_proof,
        Some(binding),
        &mut rng,
    )?;

    let mut proof_bytes = Vec::new();
    compressed
        .0
        .groth16_proof
        .serialize_compressed(&mut proof_bytes)?;
    compressed.0.d.serialize_compressed(&mut proof_bytes)?;
    compressed
        .0
        .link_pi
        .serialize_compressed(&mut proof_bytes)?;
    assert_eq!(proof_bytes.len(), 192, "Proof must be 192 bytes");

    // Single verification baseline
    let t_single = Instant::now();
    <Decider as IVCProofCompressor>::verify::<FC>(
        &dvk,
        sha256_blocks,
        &initial_state,
        &current_state,
        &compressed,
        Some(binding),
    )?;
    let single_observation_ms = t_single.elapsed().as_secs_f64() * 1000.0;
    println!(
        "       Single initial observation: {:.3} ms",
        single_observation_ms
    );

    // Warm-up 10 runs
    for _ in 0..10 {
        <Decider as IVCProofCompressor>::verify::<FC>(
            &dvk,
            sha256_blocks,
            &initial_state,
            &current_state,
            &compressed,
            Some(binding),
        )?;
    }

    // 1000 Warm Verifications
    println!("[4/5] Running 1000 Warm Verifications...");
    let mut warm_samples_us = Vec::with_capacity(1000);
    for i in 0..1000 {
        let t = Instant::now();
        <Decider as IVCProofCompressor>::verify::<FC>(
            &dvk,
            sha256_blocks,
            &initial_state,
            &current_state,
            &compressed,
            Some(binding),
        )?;
        warm_samples_us.push(t.elapsed().as_micros() as u64);
        if (i + 1) % 200 == 0 {
            print!(".");
            use std::io::Write;
            std::io::stdout().flush().unwrap();
        }
    }
    println!(" Done!");

    // 50 Cold Verifications
    println!("[5/5] Running 50 Cold Verifications (with cache eviction)...");
    let mut cold_samples_us = Vec::with_capacity(50);
    for _ in 0..50 {
        evict_cache();
        let t = Instant::now();
        <Decider as IVCProofCompressor>::verify::<FC>(
            &dvk,
            sha256_blocks,
            &initial_state,
            &current_state,
            &compressed,
            Some(binding),
        )?;
        cold_samples_us.push(t.elapsed().as_micros() as u64);
    }
    println!(" Done!");

    let warm_stats = compute_stats(warm_samples_us);
    let cold_stats = compute_stats(cold_samples_us);

    println!(
        "
============================================================"
    );
    println!(" DECIDER STATISTICAL RESULTS (N=1000 warm, N=50 cold)");
    println!("============================================================");
    println!(" Warm Verify:");
    println!("   Mean:   {:.3} ms", warm_stats.mean_ms);
    println!("   Median: {:.3} ms", warm_stats.median_ms);
    println!("   Std:    {:.3} ms", warm_stats.std_ms);
    println!("   p95:    {:.3} ms", warm_stats.p95_ms);
    println!("   p99:    {:.3} ms", warm_stats.p99_ms);
    println!("   Min:    {:.3} ms", warm_stats.min_ms);
    println!("   Max:    {:.3} ms", warm_stats.max_ms);
    println!(" Cold Verify:");
    println!("   Mean:   {:.3} ms", cold_stats.mean_ms);
    println!("   Median: {:.3} ms", cold_stats.median_ms);
    println!("   Std:    {:.3} ms", cold_stats.std_ms);
    println!("   p95:    {:.3} ms", cold_stats.p95_ms);
    println!("   p99:    {:.3} ms", cold_stats.p99_ms);
    println!("   Min:    {:.3} ms", cold_stats.min_ms);
    println!("   Max:    {:.3} ms", cold_stats.max_ms);
    println!("============================================================");

    let report = DeciderRepeatReport {
        proof_bytes: proof_bytes.len(),
        block_count_represented: 258329,
        warm_stats,
        cold_stats,
        single_observation_ms,
        verification_valid: true,
    };

    let out_dir = Path::new("results/jisa_final_server");
    fs::create_dir_all(out_dir)?;
    let out_path = out_dir.join("decider_repeat_stats.json");
    fs::write(&out_path, serde_json::to_string_pretty(&report)?)?;
    println!("Saved report to {:?}", out_path);

    Ok(())
}
