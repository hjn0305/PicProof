//! Image-size scaling benchmark for the Sigmabus SHA-256 IVC pipeline.
//!
//! Driven by environment variables so one binary serves the whole curve:
//!   SIGMABUS_MSG_BYTES    message length in bytes (default 64)
//!   SIGMABUS_MSG_FILE     path to real image bytes; length must equal MSG_BYTES
//!   SIGMABUS_RUN_DECIDER  "1" also runs LegoGroth16 setup + prove (default off)
//!   SIGMABUS_PROGRESS_EVERY  print a step/ETA line every N folding steps (0 = off)
//!
//! Emits one `SIGMABUS_SCALING {...}` line per run for a wrapper to scrape.
//! Proof size is measured off the serialized Groth16 triple plus the two
//! LegoGroth16 linkability elements; the enclosing tuple itself is not
//! `CanonicalSerialize`, so the parts are summed explicitly.
//!
//! Peak RSS is read from `/proc/self/status` (`VmHWM`) so the "memory is
//! independent of image size" claim is measured rather than asserted.

use std::error::Error;
use std::sync::Arc;
use std::time::Instant;

use ark_bn254::{Bn254, Fr, G1Projective as C1};
use ark_grumpkin::Projective as C2;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::thread_rng;
use sha2::{Digest, Sha256};

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

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_flag(key: &str) -> bool {
    std::env::var(key)
        .map(|v| v == "1" || v == "true")
        .unwrap_or(false)
}

/// Peak resident set size in kB as reported by the kernel (`VmHWM`).
fn peak_rss_kb() -> u64 {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return 0;
    };
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            if let Some(value) = rest.split_whitespace().next() {
                return value.parse().unwrap_or(0);
            }
        }
    }
    0
}

/// Deterministic stand-in for image bytes: a SHA-256 counter stream so every
/// run on every machine absorbs the same payload.
fn synthetic_payload(len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut counter: u64 = 0;
    while out.len() < len {
        let mut h = Sha256::new();
        h.update(counter.to_le_bytes());
        out.extend_from_slice(&h.finalize());
        counter += 1;
    }
    out.truncate(len);
    out
}

/// Real image bytes when `SIGMABUS_MSG_FILE` is set, otherwise the synthetic
/// stream. Both paths absorb exactly `len` bytes so the folding step count,
/// and therefore the runtime, is identical.
fn payload(len: usize) -> Vec<u8> {
    if let Ok(path) = std::env::var("SIGMABUS_MSG_FILE") {
        let bytes = std::fs::read(&path).expect("SIGMABUS_MSG_FILE must be readable");
        assert_eq!(
            bytes.len(),
            len,
            "SIGMABUS_MSG_FILE must hold exactly SIGMABUS_MSG_BYTES bytes"
        );
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let digest: String = hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        eprintln!("PAYLOAD file={path} sha256={digest}");
        return bytes;
    }
    synthetic_payload(len)
}

#[test]
fn test_scaling() -> Result<(), Box<dyn Error>> {
    let msg_bytes = env_usize("SIGMABUS_MSG_BYTES", 64);
    let run_decider = env_flag("SIGMABUS_RUN_DECIDER");
    let progress_every = env_usize("SIGMABUS_PROGRESS_EVERY", 0);

    let payload = payload(msg_bytes);
    let blocks = sha256_padded_blocks(&payload);
    let circuit = FC::new(msg_bytes);
    let n = circuit.num_blocks();
    assert_eq!(n, blocks.len());

    let mut rng = thread_rng();

    // ---- IVC public parameters -------------------------------------------
    let t = Instant::now();
    let pp = <IVCType as IVCPreprocessor>::preprocess(
        (131072, 16384, Arc::new(GriffinParams::new(16, 5, 9))),
        &mut rng,
    )?;
    let preprocess_ms = t.elapsed().as_millis();

    // ---- IVC keys ---------------------------------------------------------
    let t = Instant::now();
    let (pk, vk) = <IVCType as IVCKeyGenerator>::generate_keys(pp, &circuit)?;
    let ivc_keys_ms = t.elapsed().as_millis();

    // ---- Folding: exactly one prove step per SHA-256 block ----------------
    //
    // The IVC proof is verified once at the end rather than after every step.
    // Nova verification is O(i) in the step count, so per-step verification
    // would make the whole sweep O(n^2) and swamp the per-step cost that this
    // benchmark exists to measure.
    let initial_state = circuit.dummy_state();
    let mut prover = IVCStatefulProver::<_, IVCType>::new(&pk, &circuit, initial_state.clone())?;

    let mut step_sum_ms: u128 = 0;
    let mut first_step_ms: u128 = 0;
    let mut last_step_ms: u128 = 0;
    let t_fold_all = Instant::now();
    for (idx, block) in blocks.iter().enumerate() {
        let t = Instant::now();
        prover.prove_step(*block, &mut rng)?;
        last_step_ms = t.elapsed().as_millis();
        if idx == 0 {
            first_step_ms = last_step_ms;
        }
        step_sum_ms += last_step_ms;

        // Long runs need external visibility; the ETA uses the running mean.
        if progress_every > 0 && (idx + 1) % progress_every == 0 {
            let done = idx + 1;
            let elapsed = t_fold_all.elapsed().as_secs_f64();
            let rate = elapsed / done as f64;
            eprintln!(
                "PROGRESS i={done}/{} elapsed_s={elapsed:.0} ms_per_step={:.1} eta_s={:.0} peak_rss_kb={}",
                n,
                rate * 1000.0,
                rate * (n - done) as f64,
                peak_rss_kb(),
            );
        }
    }
    let folding_ms = t_fold_all.elapsed().as_millis();
    assert_eq!(prover.i, n);
    let current_state = prover.current_state.clone();
    let rss_after_folding_kb = peak_rss_kb();

    let mean_step_ms = step_sum_ms / n as u128;

    let t = Instant::now();
    IVCType::verify::<FC>(
        &vk,
        prover.i,
        &prover.initial_state,
        &prover.current_state,
        &prover.current_proof,
    )?;
    let ivc_verify_ms = t.elapsed().as_millis();

    let mut decider_setup_ms: u128 = 0;
    let mut decider_prove_ms: u128 = 0;
    let mut decider_verify_ms: u128 = 0;
    let mut decider_proof_bytes: usize = 0;

    if run_decider {
        let binding = <FC as FCircuit>::sigmabus_final_binding(n, &current_state)
            .expect("SHA-256 circuit must publish a Sigmabus binding");

        // `vk` moves into the decider keys, so the verify above must have
        // finished borrowing it by now.
        let t = Instant::now();
        let (dpk, dvk) =
            <Decider as IVCProofCompressor>::preprocess_and_generate_keys(&circuit, vk, &mut rng)?;
        decider_setup_ms = t.elapsed().as_millis();

        let t = Instant::now();
        let pi_final = <Decider as IVCProofCompressor>::prove::<FC>(
            &dpk,
            n,
            &initial_state,
            &current_state,
            &prover.current_proof,
            Some(binding),
            &mut rng,
        )?;
        decider_prove_ms = t.elapsed().as_millis();

        let mut proof_bytes = Vec::new();
        pi_final
            .0
            .groth16_proof
            .serialize_compressed(&mut proof_bytes)?;
        pi_final.0.d.serialize_compressed(&mut proof_bytes)?;
        pi_final.0.link_pi.serialize_compressed(&mut proof_bytes)?;
        decider_proof_bytes = proof_bytes.len();

        let t = Instant::now();
        assert!(
            <Decider as IVCProofCompressor>::verify::<FC>(
                &dvk,
                n,
                &initial_state,
                &current_state,
                &pi_final,
                Some(binding),
            )
            .is_ok()
        );
        decider_verify_ms = t.elapsed().as_millis();
    }

    println!(
        "SIGMABUS_SCALING {{\"msg_bytes\":{msg_bytes},\"num_blocks\":{n},\
         \"preprocess_ms\":{preprocess_ms},\"ivc_keys_ms\":{ivc_keys_ms},\
         \"folding_ms\":{folding_ms},\"mean_step_ms\":{mean_step_ms},\
         \"first_step_ms\":{first_step_ms},\"last_step_ms\":{last_step_ms},\
         \"ivc_verify_ms\":{ivc_verify_ms},\"decider_setup_ms\":{decider_setup_ms},\
         \"decider_prove_ms\":{decider_prove_ms},\"decider_verify_ms\":{decider_verify_ms},\
         \"decider_proof_bytes\":{decider_proof_bytes},\
         \"peak_rss_kb_after_folding\":{rss_after_folding_kb}}}"
    );

    Ok(())
}
