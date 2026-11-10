use std::error::Error;
use std::path::Path;
use std::process::Command;
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

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn lego_verify(
    dvk: &<Decider as IVCProofCompressor>::VerifierKey<FC>,
    n: usize,
    initial_state: &<FC as FCircuit>::State,
    current_state: &<FC as FCircuit>::State,
    proof: &<Decider as IVCProofCompressor>::CompressedProof<FC>,
    h_hi: Fr,
    h_lo: Fr,
) -> bool {
    let binding = SigmabusFinalBinding {
        num_blocks: n,
        h_hi,
        h_lo,
    };
    <Decider as IVCProofCompressor>::verify::<FC>(
        dvk,
        n,
        initial_state,
        current_state,
        proof,
        Some(binding),
    )
    .is_ok()
}

fn dorian_prove(
    h_hi: u128,
    h_lo: u128,
    privkey_path: &str,
    proof_path: &str,
) -> Result<(), Box<dyn Error>> {
    let sigpop_dir = Path::new("/root/autodl-tmp/sigpop");
    let bin = sigpop_dir.join("target/release/examples/ecdsa_sigma");
    let status = Command::new(bin)
        .current_dir(sigpop_dir)
        .arg("--action")
        .arg("prove")
        .arg("--h-hi")
        .arg(h_hi.to_string())
        .arg("--h-lo")
        .arg(h_lo.to_string())
        .arg("--privkey")
        .arg(privkey_path)
        .arg("--proof")
        .arg(proof_path)
        .status()?;
    if !status.success() {
        return Err(format!("Dorian prove failed with status: {:?}", status).into());
    }
    Ok(())
}

fn dorian_verify(h_hi: u128, h_lo: u128, proof_path: &str) -> bool {
    let sigpop_dir = Path::new("/root/autodl-tmp/sigpop");
    let bin = sigpop_dir.join("target/release/examples/ecdsa_sigma");
    let output = Command::new(bin)
        .current_dir(sigpop_dir)
        .arg("--action")
        .arg("verify")
        .arg("--h-hi")
        .arg(h_hi.to_string())
        .arg("--h-lo")
        .arg(h_lo.to_string())
        .arg("--proof")
        .arg(proof_path)
        .output();
    match output {
        Ok(out) => out.status.success(),
        Err(_) => false,
    }
}

#[test]
fn test_e2e_minimal() -> Result<(), Box<dyn Error>> {
    println!("\n=======================================================");
    println!(" 1. Input: 64-byte fixed input string M || salt");
    println!("=======================================================");
    let m_salt: &[u8; 64] = b"Sigmabus-Test-Image-0123456789abcdef-Camera-Salt-Padding-Fixed!!";
    assert_eq!(m_salt.len(), 64);
    println!("Fixed input (64 bytes): {:?}", std::str::from_utf8(m_salt)?);

    println!("\n=======================================================");
    println!(" 2. Compute real SHA-256 hash and split into (h_hi, h_lo)");
    println!("=======================================================");
    let digest: [u8; 32] = Sha256::digest(m_salt).into();
    println!("Real SHA-256 digest: {}", hex_string(&digest));
    let h_hi_u128 = u128::from_be_bytes(digest[0..16].try_into().unwrap());
    let h_lo_u128 = u128::from_be_bytes(digest[16..32].try_into().unwrap());
    let h_hi_A = Fr::from(h_hi_u128);
    let h_lo_A = Fr::from(h_lo_u128);
    let h_hi_B = h_hi_u128;
    let h_lo_B = h_lo_u128;
    println!("Split h_hi = {}", h_hi_u128);
    println!("Split h_lo = {}", h_lo_u128);

    println!("\n=======================================================");
    println!(" 3. Call local Dorian logic to generate signature proof pi_sigma");
    println!("=======================================================");
    let privkey_path = "/root/autodl-tmp/camera_privkey.pem";
    let pi_sigma_path = "/tmp/pi_sigma_minimal.bin";
    dorian_prove(h_hi_B, h_lo_B, privkey_path, pi_sigma_path)?;
    println!(
        "Dorian pi_sigma generated successfully at {}",
        pi_sigma_path
    );

    println!("\n=======================================================");
    println!(" 4. Run ProtoGalaxy folding (2 steps) and Decider for pi_final");
    println!("=======================================================");
    let blocks = sha256_padded_blocks(m_salt);
    assert_eq!(
        blocks.len(),
        2,
        "64-byte input must produce exactly 2 SHA-256 blocks"
    );
    let circuit = Sha256PaddedCircuit::<Fr>::new(64);
    let n = circuit.num_blocks();
    assert_eq!(n, 2);

    let mut rng = thread_rng();
    let pp = <IVCType as IVCPreprocessor>::preprocess(
        (131072, 16384, Arc::new(GriffinParams::new(16, 5, 9))),
        &mut rng,
    )?;
    let (pk, vk) = <IVCType as IVCKeyGenerator>::generate_keys(pp, &circuit)?;
    let initial_state = circuit.dummy_state();

    let mut prover = IVCStatefulProver::<_, IVCType>::new(&pk, &circuit, initial_state.clone())?;
    for (i, block) in blocks.iter().enumerate() {
        println!("Folding step {}/{}...", i + 1, n);
        prover.prove_step(*block, &mut rng)?;
        IVCType::verify::<FC>(
            &vk,
            prover.i,
            &prover.initial_state,
            &prover.current_state,
            &prover.current_proof,
        )?;
    }
    assert_eq!(prover.i, n);
    let current_state = prover.current_state.clone();

    let binding = <FC as FCircuit>::sigmabus_final_binding(n, &current_state)
        .expect("SHA-256 circuit must publish a Sigmabus binding");
    assert_eq!(binding.h_hi, h_hi_A);
    assert_eq!(binding.h_lo, h_lo_A);

    println!("Generating LegoGroth16 decider compressed proof pi_final...");
    let (dpk, dvk) =
        <Decider as IVCProofCompressor>::preprocess_and_generate_keys(&circuit, vk, &mut rng)?;
    let pi_final = <Decider as IVCProofCompressor>::prove::<FC>(
        &dpk,
        n,
        &initial_state,
        &current_state,
        &prover.current_proof,
        Some(binding),
        &mut rng,
    )?;
    println!("pi_final generated successfully!");

    println!("\n=======================================================");
    println!(" 5. Verifier assertions & anti-tampering tests");
    println!("=======================================================");

    // Assertion 1: LegoVerify(pi_final, h_hi^A, h_lo^A) == true
    let lego_ok = lego_verify(
        &dvk,
        n,
        &initial_state,
        &current_state,
        &pi_final,
        h_hi_A,
        h_lo_A,
    );
    println!(
        "Assertion 1: LegoVerify(pi_final, h_hi^A, h_lo^A) == true -> {}",
        lego_ok
    );
    assert!(lego_ok, "LegoVerify(pi_final, h_hi^A, h_lo^A) must be true");

    // Assertion 2: DorianVerify(pi_sigma, h_hi^B, h_lo^B) == true
    let dorian_ok = dorian_verify(h_hi_B, h_lo_B, pi_sigma_path);
    println!(
        "Assertion 2: DorianVerify(pi_sigma, h_hi^B, h_lo^B) == true -> {}",
        dorian_ok
    );
    assert!(
        dorian_ok,
        "DorianVerify(pi_sigma, h_hi^B, h_lo^B) must be true"
    );

    // Assertion 3: h_hi^A == h_hi^B && h_lo^A == h_lo^B
    assert_eq!(h_hi_A, Fr::from(h_hi_B), "h_hi^A must match h_hi^B");
    assert_eq!(h_lo_A, Fr::from(h_lo_B), "h_lo^A must match h_lo^B");
    println!("Assertion 3: h_hi^A == h_hi^B && h_lo^A == h_lo^B -> PASSED");

    // Anti-tampering 1: Tampered h_hi^A in LegoVerify
    let lego_tampered = lego_verify(
        &dvk,
        n,
        &initial_state,
        &current_state,
        &pi_final,
        h_hi_A + Fr::from(1u64),
        h_lo_A,
    );
    assert!(!lego_tampered, "LegoVerify must reject tampered h_hi^A");
    println!("Anti-Tampering 1: LegoVerify rejected tampered h_hi^A (+1) -> PASSED");

    // Anti-tampering 2: Tampered h_hi^B in DorianVerify
    let dorian_tampered = dorian_verify(h_hi_B + 1, h_lo_B, pi_sigma_path);
    assert!(!dorian_tampered, "DorianVerify must reject tampered h_hi^B");
    println!("Anti-Tampering 2: DorianVerify rejected tampered h_hi^B (+1) -> PASSED");

    println!("\n>>> ALL TESTS PASSED: E2E minimal pipeline verified successfully! <<<\n");
    Ok(())
}
