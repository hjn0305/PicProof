//! Multi-block HashFold Benchmark (k in {1, 2, 4, 8})
//!
//! Benchmarks parameterizing the IVC step circuit to absorb k SHA-256 blocks per step.
//! Compares constraints/step, setup time, total folding time T_total(k), mean ms/step,
//! and throughput (MiB/s).

use std::error::Error;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use ark_bn254::{Fr, G1Projective as C1};
use ark_grumpkin::Projective as C2;
use ark_r1cs_std::GR1CSVar;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::uint32::UInt32;
use ark_relations::gr1cs::{ConstraintSystem, SynthesisError};
use ark_std::rand::thread_rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use sonobe_fs::nova::{CycleFoldNova, Nova};
use sonobe_ivc::compilers::cyclefold::CycleFoldBasedIVC;
use sonobe_ivc::sha256_step::{compress_vars, sha256_padded_blocks};
use sonobe_ivc::{IVCKeyGenerator, IVCPreprocessor, IVCStatefulProver, IVCVerifier};
use sonobe_primitives::algebra::field::SonobeField;
use sonobe_primitives::circuits::FCircuit;
use sonobe_primitives::commitments::pedersen::Pedersen;
use sonobe_primitives::transcripts::griffin::{GriffinParams, sponge::GriffinSponge};

const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

#[derive(Clone)]
pub struct Sha256MultiBlockCircuit<F: SonobeField> {
    pub k: usize,
    _field: core::marker::PhantomData<F>,
}

impl<F: SonobeField> Sha256MultiBlockCircuit<F> {
    pub fn new(k: usize) -> Self {
        Self {
            k,
            _field: core::marker::PhantomData,
        }
    }
}

impl<F: SonobeField> FCircuit for Sha256MultiBlockCircuit<F> {
    type Field = F;
    type State = [F; 8];
    type StateVar = [FpVar<F>; 8];
    type ExternalInputs = Vec<[u32; 16]>;
    type ExternalOutputs = ();

    fn same_state_shape(_a: &Self::State, _b: &Self::State) -> bool {
        true
    }

    fn dummy_state(&self) -> Self::State {
        IV.map(F::from)
    }

    fn dummy_external_inputs(&self) -> Self::ExternalInputs {
        vec![[0u32; 16]; self.k]
    }

    fn synthesize_step(
        &self,
        _i: FpVar<F>,
        z_i: Self::StateVar,
        blocks: Self::ExternalInputs,
    ) -> Result<(Self::StateVar, Self::ExternalOutputs), SynthesisError> {
        let mut state = z_i;
        for block in blocks.iter() {
            let cs = state[0].cs();
            let words: [UInt32<F>; 16] = UInt32::new_witness_vec(cs, block)?.try_into().unwrap();
            let state_u32: [UInt32<F>; 8] = state
                .map(|word| UInt32::from_fp(&word).map(|(u, _)| u))
                .into_iter()
                .collect::<Result<Vec<_>, _>>()?
                .try_into()
                .unwrap();
            let output = compress_vars(words, state_u32)?;
            state = output
                .map(|word| word.to_fp())
                .into_iter()
                .collect::<Result<Vec<_>, _>>()?
                .try_into()
                .unwrap();
        }
        Ok((state, ()))
    }
}

type IVCType<F> = CycleFoldBasedIVC<
    Nova<Pedersen<C1, true>>,
    CycleFoldNova<Pedersen<C2, true>>,
    GriffinSponge<F>,
>;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MultiBlockResult {
    pub k: usize,
    pub payload_bytes: usize,
    pub total_blocks: usize,
    pub folding_steps: usize,
    pub constraints_per_step: usize,
    pub setup_ms: u64,
    pub folding_ms: u64,
    pub mean_ms_per_step: f64,
    pub throughput_mib_s: f64,
    pub peak_rss_kib: u64,
    pub rc: i32,
}

fn count_step_constraints(k: usize) -> Result<usize, Box<dyn Error>> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    let circuit = Sha256MultiBlockCircuit::<Fr>::new(k);
    let state_var = [
        FpVar::new_witness(cs.clone(), || Ok(Fr::from(IV[0])))?,
        FpVar::new_witness(cs.clone(), || Ok(Fr::from(IV[1])))?,
        FpVar::new_witness(cs.clone(), || Ok(Fr::from(IV[2])))?,
        FpVar::new_witness(cs.clone(), || Ok(Fr::from(IV[3])))?,
        FpVar::new_witness(cs.clone(), || Ok(Fr::from(IV[4])))?,
        FpVar::new_witness(cs.clone(), || Ok(Fr::from(IV[5])))?,
        FpVar::new_witness(cs.clone(), || Ok(Fr::from(IV[6])))?,
        FpVar::new_witness(cs.clone(), || Ok(Fr::from(IV[7])))?,
    ];
    let i_var = FpVar::new_witness(cs.clone(), || Ok(Fr::from(0u64)))?;
    let inputs = vec![[0u32; 16]; k];
    circuit.synthesize_step(i_var, state_var, inputs)?;
    Ok(cs.num_constraints())
}

fn run_multiblock_test(k: usize, payload_bytes: usize) -> Result<MultiBlockResult, Box<dyn Error>> {
    println!("------------------------------------------------------------");
    println!(
        " Running Multi-Block Benchmark: k={}, payload={} bytes",
        k, payload_bytes
    );
    println!("------------------------------------------------------------");

    let payload = vec![0xABu8; payload_bytes];
    let blocks = sha256_padded_blocks(&payload);
    let total_blocks = blocks.len();

    let mut step_blocks: Vec<Vec<[u32; 16]>> = Vec::new();
    for chunk in blocks.chunks(k) {
        let mut step = chunk.to_vec();
        while step.len() < k {
            step.push([0u32; 16]);
        }
        step_blocks.push(step);
    }
    let folding_steps = step_blocks.len();

    let constraints = count_step_constraints(k)?;
    println!("  k={}: constraints/step = {}", k, constraints);

    let mut rng = thread_rng();
    let circuit = Sha256MultiBlockCircuit::<Fr>::new(k);

    let t_setup = Instant::now();
    let pp_size = 131072.max(constraints * 2).next_power_of_two();
    let pp = <IVCType<Fr> as IVCPreprocessor>::preprocess(
        (pp_size, 16384, Arc::new(GriffinParams::new(16, 5, 9))),
        &mut rng,
    )?;
    let (pk, vk) = <IVCType<Fr> as IVCKeyGenerator>::generate_keys(pp, &circuit)?;
    let setup_ms = t_setup.elapsed().as_millis() as u64;

    let initial_state = circuit.dummy_state();
    let mut prover =
        IVCStatefulProver::<_, IVCType<Fr>>::new(&pk, &circuit, initial_state.clone())?;

    let t_fold = Instant::now();
    for (idx, step) in step_blocks.into_iter().enumerate() {
        prover.prove_step(step, &mut rng)?;
        if (idx + 1) % 100 == 0 || idx + 1 == folding_steps {
            println!("    Step {}/{} done", idx + 1, folding_steps);
        }
    }
    let folding_ms = t_fold.elapsed().as_millis() as u64;

    IVCType::<Fr>::verify::<Sha256MultiBlockCircuit<Fr>>(
        &vk,
        prover.i,
        &prover.initial_state,
        &prover.current_state,
        &prover.current_proof,
    )?;

    let mean_ms_per_step = folding_ms as f64 / folding_steps as f64;
    let throughput_mib_s =
        (payload_bytes as f64 / (1024.0 * 1024.0)) / (folding_ms as f64 / 1000.0);

    println!(
        "  k={}: total_folding={} ms, steps={}, mean={:.2} ms/step, throughput={:.3} MiB/s",
        k, folding_ms, folding_steps, mean_ms_per_step, throughput_mib_s
    );

    Ok(MultiBlockResult {
        k,
        payload_bytes,
        total_blocks,
        folding_steps,
        constraints_per_step: constraints,
        setup_ms,
        folding_ms,
        mean_ms_per_step,
        throughput_mib_s,
        peak_rss_kib: 0,
        rc: 0,
    })
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    let mut bytes = 65536usize;
    let mut k_vals = vec![1, 2, 4, 8];
    let mut out_json = "results/jisa_final_server/hashfold_multiblock_64k.json".to_string();
    let mut out_csv = "results/jisa_final_server/hashfold_multiblock_64k.csv".to_string();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--bytes" => {
                i += 1;
                bytes = args[i].parse()?;
            }
            "--k-values" => {
                i += 1;
                k_vals = args[i].split(',').map(|s| s.parse().unwrap()).collect();
            }
            "--output" => {
                i += 1;
                out_json = args[i].clone();
            }
            "--csv" => {
                i += 1;
                out_csv = args[i].clone();
            }
            _ => {}
        }
        i += 1;
    }

    println!("============================================================");
    println!(" MULTI-BLOCK HASHFOLD BENCHMARK (k in {:?})", k_vals);
    println!(
        " Payload: {} bytes, JSON: {}, CSV: {}",
        bytes, out_json, out_csv
    );
    println!("============================================================");

    let mut results = Vec::new();
    for &k in &k_vals {
        let res = run_multiblock_test(k, bytes)?;
        results.push(res);
    }

    if let Some(p) = Path::new(&out_json).parent() {
        fs::create_dir_all(p)?;
    }
    fs::write(&out_json, serde_json::to_string_pretty(&results)?)?;

    let mut csv_file = File::create(&out_csv)?;
    writeln!(
        csv_file,
        "k,payload_bytes,total_blocks,folding_steps,constraints_per_step,setup_ms,folding_ms,mean_ms_per_step,throughput_mib_s"
    )?;
    for r in &results {
        writeln!(
            csv_file,
            "{},{},{},{},{},{},{},{:.3},{:.4}",
            r.k,
            r.payload_bytes,
            r.total_blocks,
            r.folding_steps,
            r.constraints_per_step,
            r.setup_ms,
            r.folding_ms,
            r.mean_ms_per_step,
            r.throughput_mib_s
        )?;
    }
    println!(
        "Results successfully written to {} and {}",
        out_json, out_csv
    );

    Ok(())
}
