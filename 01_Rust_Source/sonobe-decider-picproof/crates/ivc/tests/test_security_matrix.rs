//! Security negative matrix for the decoupled Sigmabus pipeline.
//!
//! The expensive part (IVC folding + LegoGroth16 compression) runs once on a
//! 64-byte payload; every case below is then a ~10 ms verify, so the whole
//! matrix costs about the same as a single honest proof.
//!
//! Each case asserts that the verifier REJECTS. Every case is run, and the test
//! fails at the end listing all acceptances, so one early bug cannot hide the
//! rest.

use std::error::Error;
use std::sync::Arc;

use ark_bn254::{Bn254, Fr, G1Projective as C1};
use ark_grumpkin::Projective as C2;
use ark_std::rand::thread_rng;
use sha2::{Digest, Sha256};

use sonobe_fs::nova::{CycleFoldNova, Nova};
use sonobe_ivc::compilers::cyclefold::{CycleFoldBasedIVC, CycleFoldBasedIVCDecider};
use sonobe_ivc::sha256_step::{Sha256PaddedCircuit, sha256_padded_blocks};
use sonobe_ivc::{
    IVCKeyGenerator, IVCPreprocessor, IVCProofCompressor, IVCStatefulProver, IVCVerifier,
};
use sonobe_primitives::circuits::{FCircuit, SigmabusFinalBinding};
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

type State = [Fr; 8];
type Binding = Option<SigmabusFinalBinding<Fr>>;

fn split_digest(bytes: &[u8]) -> (Fr, Fr) {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    (
        Fr::from(u128::from_be_bytes(digest[0..16].try_into().unwrap())),
        Fr::from(u128::from_be_bytes(digest[16..32].try_into().unwrap())),
    )
}

fn make_binding(num_blocks: usize, h_hi: Fr, h_lo: Fr) -> Binding {
    Some(SigmabusFinalBinding {
        num_blocks,
        h_hi,
        h_lo,
    })
}

#[test]
fn test_security_matrix() -> Result<(), Box<dyn Error>> {
    let m_salt: &[u8; 64] = b"Sigmabus-Test-Image-0123456789abcdef-Camera-Salt-Padding-Fixed!!";
    let blocks = sha256_padded_blocks(m_salt);
    let circuit = FC::new(64);
    let n = circuit.num_blocks();
    assert_eq!(n, blocks.len());

    let (h_hi, h_lo) = split_digest(m_salt);

    // The binding is consumed by `prove` and the tuple is not Copy, so each
    // call site rebuilds an equivalent one instead of moving a shared value.
    let hb = || make_binding(n, h_hi, h_lo);

    let mut rng = thread_rng();
    let pp = <IVCType as IVCPreprocessor>::preprocess(
        (131072, 16384, Arc::new(GriffinParams::new(16, 5, 9))),
        &mut rng,
    )?;
    let (pk, vk) = <IVCType as IVCKeyGenerator>::generate_keys(pp, &circuit)?;

    let initial_state: State = circuit.dummy_state();
    let mut prover = IVCStatefulProver::<_, IVCType>::new(&pk, &circuit, initial_state.clone())?;

    for block in blocks.iter() {
        prover.prove_step(*block, &mut rng)?;
    }
    let current_state: State = prover.current_state.clone();

    let honest_binding = <FC as FCircuit>::sigmabus_final_binding(n, &current_state)
        .expect("SHA-256 circuit must publish a Sigmabus binding");
    assert_eq!(
        honest_binding.h_hi, h_hi,
        "in-circuit h_hi must match SHA-256(M)"
    );
    assert_eq!(
        honest_binding.h_lo, h_lo,
        "in-circuit h_lo must match SHA-256(M)"
    );

    let (dpk, dvk) =
        <Decider as IVCProofCompressor>::preprocess_and_generate_keys(&circuit, vk, &mut rng)?;
    let pi_final = <Decider as IVCProofCompressor>::prove::<FC>(
        &dpk,
        n,
        &initial_state,
        &current_state,
        &prover.current_proof,
        hb(),
        &mut rng,
    )?;

    let verify = |i: usize, ist: &State, cst: &State, pf: &_, b: Binding| -> bool {
        <Decider as IVCProofCompressor>::verify::<FC>(&dvk, i, ist, cst, pf, b).is_ok()
    };

    // Without a passing honest case every rejection below would be vacuous.
    assert!(
        verify(n, &initial_state, &current_state, &pi_final, hb()),
        "H-0: the honest proof must verify"
    );
    println!("H-0 honest LegoVerify -> PASSED (this is what makes the negatives meaningful)");

    let one = Fr::from(1u64);
    let zero = Fr::from(0u64);
    // A genuine 1-of-n transcript, used by the early-state cases. The proof
    // type is not Clone, so this prover stays alive and is borrowed.
    let mut early = IVCStatefulProver::<_, IVCType>::new(&pk, &circuit, initial_state.clone())?;
    early.prove_step(blocks[0], &mut rng)?;
    let i1 = early.i;
    let s1: State = early.current_state.clone();
    assert_eq!(i1, 1);

    let mut bad_initial = initial_state.clone();
    bad_initial[0] += one;

    let cases: Vec<(&str, &str, Box<dyn Fn() -> bool>)> = vec![
        (
            "N-1",
            "h_hi flipped by +1",
            Box::new(|| {
                verify(
                    n,
                    &initial_state,
                    &current_state,
                    &pi_final,
                    make_binding(n, h_hi + one, h_lo),
                )
            }),
        ),
        (
            "N-2",
            "h_lo flipped by +1",
            Box::new(|| {
                verify(
                    n,
                    &initial_state,
                    &current_state,
                    &pi_final,
                    make_binding(n, h_hi, h_lo + one),
                )
            }),
        ),
        (
            "N-3",
            "h_hi and h_lo swapped",
            Box::new(|| {
                verify(
                    n,
                    &initial_state,
                    &current_state,
                    &pi_final,
                    make_binding(n, h_lo, h_hi),
                )
            }),
        ),
        (
            "N-4",
            "binding zeroed out",
            Box::new(|| {
                verify(
                    n,
                    &initial_state,
                    &current_state,
                    &pi_final,
                    make_binding(n, zero, zero),
                )
            }),
        ),
        (
            "N-5",
            "state after 1 of 2 steps passed off as final",
            Box::new(|| {
                let b = <FC as FCircuit>::sigmabus_final_binding(i1, &s1);
                verify(i1, &initial_state, &s1, &pi_final, b)
            }),
        ),
        (
            "N-6",
            "claimed block count reduced to n-1",
            Box::new(|| verify(n - 1, &initial_state, &current_state, &pi_final, hb())),
        ),
        (
            "N-7",
            "claimed block count inflated to n+1",
            Box::new(|| verify(n + 1, &initial_state, &current_state, &pi_final, hb())),
        ),
        (
            "N-8",
            "different initial state (salt substitution)",
            Box::new(|| verify(n, &bad_initial, &current_state, &pi_final, hb())),
        ),
        (
            "N-9",
            "binding taken from an unrelated message",
            Box::new(|| {
                let (oh, ol) = split_digest(b"a completely different camera payload");
                verify(
                    n,
                    &initial_state,
                    &current_state,
                    &pi_final,
                    make_binding(n, oh, ol),
                )
            }),
        ),
        (
            "N-10",
            "step-1 proof re-compressed then bound to the final hash",
            Box::new(|| {
                let early_binding = <FC as FCircuit>::sigmabus_final_binding(i1, &s1);
                let rebuilt = <Decider as IVCProofCompressor>::prove::<FC>(
                    &dpk,
                    i1,
                    &initial_state,
                    &s1,
                    &early.current_proof,
                    early_binding,
                    &mut thread_rng(),
                );
                match rebuilt {
                    Ok(pf) => verify(i1, &initial_state, &s1, &pf, hb()),
                    // Proving itself refused: that is also a rejection.
                    Err(_) => false,
                }
            }),
        ),
    ];

    let mut failures = Vec::new();
    println!("\n=============== security negative matrix ===============");
    for (id, claim, check) in &cases {
        let accepted = check();
        println!(
            "{id}: {claim} -> {}",
            if accepted {
                "FAILED (verifier ACCEPTED a forged statement)"
            } else {
                "PASSED (rejected)"
            }
        );
        if accepted {
            failures.push(*id);
        }
    }
    println!("========================================================");

    assert!(
        failures.is_empty(),
        "soundness regressions, verifier accepted forged statements: {failures:?}"
    );
    println!(
        ">>> all {} negative cases rejected as expected <<<",
        cases.len()
    );
    Ok(())
}
