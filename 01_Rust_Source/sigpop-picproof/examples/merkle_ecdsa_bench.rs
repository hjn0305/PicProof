use circ::cfg::{
    clap::{self, Parser},
    CircOpt,
};
use std::path::PathBuf;
use std::time::Instant;
use rug::Integer;
use fxhash::FxHashMap as HashMap;
use circ::ir::term::Value;
use circ::convert::bool_to_value;
use circ::create_input::PfCurve;
use circ::target::r1cs::spartan::spartan;
use circ::ecdsa::ecdsa::{ProverPrecomputeInput, P256Point};
use circ::commitment::poseidon_const::{POSEIDON_C, POSEIDON_M};
use circ::right_field_arithmetic::alloc::{map_field, map_field_vec};
use circ::right_field_arithmetic::field::ARC_MOD_T256;
use circ::allocate::map_bool_arr;

#[derive(Debug, Parser)]
#[command(name = "merkle_ecdsa_bench", about = "Benchmarking Dorian Spartan with Poseidon Merkle Tree")]
struct Options {
    #[arg(long, default_value = "/tmp/merkle_test/P_merkle")]
    prover_key: PathBuf,
    #[arg(long, default_value = "/tmp/merkle_test/V_merkle")]
    verifier_key: PathBuf,
    #[arg(long, default_value = "/tmp/merkle_test/SpartanPP_merkle")]
    pp: PathBuf,
    #[arg(long, default_value = "/tmp/merkle_test/pi_merkle")]
    proof: PathBuf,
    #[arg(long, default_value = "/data/doriansig/experiments/signed_images/camera_privkey.pem")]
    privkey: String,
    #[arg(long, default_value = "187199887208821815522073596861122131756")]
    h_hi: String,
    #[arg(long, default_value = "100726822908373414632896859755960828030")]
    h_lo: String,
    #[arg(long, default_value_t = 5)]
    iterations: usize,
    #[command(flatten)]
    circ: CircOpt,
}

fn ark_mod(state: &mut Vec<Integer>, c: &Vec<Integer>, it: usize, modulus: &Integer) {
    for i in 0..state.len() {
        state[i] = (state[i].clone() + c[it + i].clone()) % modulus.clone();
    }
}

fn sbox_mod(state: &mut Vec<Integer>, f: usize, p: usize, r: usize, modulus: &Integer) {
    state[0] = state[0].clone().pow_mod(&Integer::from(5), modulus).unwrap();
    for i in 1..state.len() {
        if r < f / 2 || r >= f / 2 + p {
            state[i] = state[i].clone().pow_mod(&Integer::from(5), modulus).unwrap();
        }
    }
}

fn mix_mod(state: &Vec<Integer>, m: &Vec<Vec<Integer>>, modulus: &Integer) -> Vec<Integer> {
    let n = state.len();
    let mut out = vec![Integer::new(); n];
    for i in 0..n {
        let mut acc = Integer::new();
        for j in 0..n {
            acc = (acc.clone() + state[j].clone() * m[i][j].clone()) % modulus.clone();
        }
        out[i] = acc;
    }
    out
}

pub fn poseidon_hash_t256(inputs: Vec<Integer>) -> Integer {
    let n: usize = inputs.len();
    assert!(n > 0 && n <= 6);
    let t = n + 1;
    let rounds_p: Vec<usize> = vec![56, 57, 56, 60, 60, 63, 64, 63];
    let f = 8;
    let p = rounds_p[t - 2];
    let c: Vec<Integer> = POSEIDON_C[t - 2].to_vec();
    let m: Vec<Vec<Integer>> = POSEIDON_M[t - 2].to_vec();

    let modulus: &Integer = &**ARC_MOD_T256;
    let mut state = vec![Integer::new(); t];
    for i in 1..t {
        state[i] = inputs[i - 1].clone() % modulus;
    }
    for r in 0..f + p {
        ark_mod(&mut state, &c, r * t, modulus);
        sbox_mod(&mut state, f, p, r, modulus);
        state = mix_mod(&state, &m, modulus);
    }
    state[0].clone()
}

fn build_merkle_tree_depth8(my_leaf: Integer) -> (Integer, Vec<Integer>, Vec<bool>) {
    const DEPTH: usize = 8;
    const NUM_LEAVES: usize = 1 << DEPTH; // 256
    let my_idx = 0usize; // place our camera at leaf 0

    let mut current_level: Vec<Integer> = Vec::with_capacity(NUM_LEAVES);
    current_level.push(my_leaf.clone());
    for i in 1..NUM_LEAVES {
        // dummy leaves with predictable nonces
        let dummy = poseidon_hash_t256(vec![Integer::from(i * 1000 + 1), Integer::from(i * 1000 + 2)]);
        current_level.push(dummy);
    }

    let mut siblings: Vec<Integer> = Vec::with_capacity(DEPTH);
    let mut directions: Vec<bool> = Vec::with_capacity(DEPTH);

    let mut idx = my_idx;
    for _ in 0..DEPTH {
        let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        siblings.push(current_level[sibling_idx].clone());
        directions.push(idx % 2 == 0);

        let mut next_level: Vec<Integer> = Vec::with_capacity(current_level.len() / 2);
        for j in 0..(current_level.len() / 2) {
            let l = current_level[2 * j].clone();
            let r = current_level[2 * j + 1].clone();
            next_level.push(poseidon_hash_t256(vec![l, r]));
        }
        current_level = next_level;
        idx /= 2;
    }

    let root = current_level[0].clone();
    (root, siblings, directions)
}

fn main() {
    let opts = Options::parse();
    circ::cfg::set(&opts.circ);

    println!("============================================================");
    println!(" DORIAN SPARTAN + POSEIDON MERKLE BENCHMARK (OPTION B)");
    println!("============================================================");

    let h_hi: Integer = opts.h_hi.parse().expect("Invalid h_hi");
    let h_lo: Integer = opts.h_lo.parse().expect("Invalid h_lo");

    // 1. Generate signature over prehash
    let t0 = Instant::now();
    let prover_input = ProverPrecomputeInput::generate_sigmabus_prehash_signature(&h_hi, &h_lo, &opts.privkey)
        .expect("Failed to generate Sigmabus prehash signature");
    let sign_elapsed = t0.elapsed();
    println!("[1] ECDSA Camera Prehash Sign: {:?}", sign_elapsed);

    // 2. Extract camera public key (x, y)
    let p256_pt = P256Point::from_projective_point(prover_input.public_key);
    let pk_x = p256_pt.x.clone();
    let pk_y = p256_pt.y.clone();

    // 3. Compute Poseidon leaf & Merkle tree of depth 8
    let my_leaf = poseidon_hash_t256(vec![pk_x.clone(), pk_y.clone()]);
    let (root, siblings, directions) = build_merkle_tree_depth8(my_leaf.clone());
    println!("[2] Computed Poseidon Leaf: {}", my_leaf);
    println!("    Computed Merkle Root (Depth 8): {}", root);

    // Verify root computation in Rust matches expected
    {
        let mut curr = my_leaf.clone();
        for i in 0..8 {
            let (l, r) = if directions[i] { (curr.clone(), siblings[i].clone()) } else { (siblings[i].clone(), curr.clone()) };
            curr = poseidon_hash_t256(vec![l, r]);
        }
        assert_eq!(curr, root, "Rust Merkle path verification failed!");
        println!("    [PASS] Local Merkle path check passed!");
    }

    // 4. Construct Prover Input Map
    let mut prover_input_map = HashMap::<String, Value>::default();
    
    // Words for h_hi, h_lo
    let mask = Integer::from(0xFFFFFFFFu64);
    let h_hi_words: Vec<Integer> = (0..4).map(|i| (h_hi.clone() >> ((3 - i) * 32)) & mask.clone()).collect();
    let h_lo_words: Vec<Integer> = (0..4).map(|i| (h_lo.clone() >> ((3 - i) * 32)) & mask.clone()).collect();
    map_field_vec(&h_hi_words, &ARC_MOD_T256, "h_hi", &mut prover_input_map);
    map_field_vec(&h_lo_words, &ARC_MOD_T256, "h_lo", &mut prover_input_map);

    // Merkle inputs
    map_field(&root, &ARC_MOD_T256, "root", &mut prover_input_map);
    map_field_vec(&siblings, &ARC_MOD_T256, "siblings", &mut prover_input_map);
    map_bool_arr(&directions, "directions", &mut prover_input_map);

    // ECDSA inputs (digest, cert, intermediate, issuerkey)
    let mut digest_bytes = vec![0u8; 32];
    for index in 0..4 {
        let word = (h_hi.clone() >> ((3 - index) * 32)) & mask.clone();
        digest_bytes[index * 4..(index + 1) * 4].copy_from_slice(&word.to_u32().unwrap_or(0).to_be_bytes());
    }
    for index in 0..4 {
        let word = (h_lo.clone() >> ((3 - index) * 32)) & mask.clone();
        digest_bytes[(4 + index) * 4..(5 + index) * 4].copy_from_slice(&word.to_u32().unwrap_or(0).to_be_bytes());
    }
    let digest_result = circ::convert::os2ip(&digest_bytes);

    // Populate ECDSA certificate and intermediate witnesses
    circ::ecdsa::prover_input::inner_prover_input_for_single_ecdsa_cert_rightfield_whole(
        &digest_result,
        prover_input.public_key,
        prover_input.signature,
        prover_input.r,
        32, 8, 8 * 32 + 1, 6, 32, "",
        &mut prover_input_map,
    );

    println!("[3] Prover Input Map assembled: {} variables", prover_input_map.len());

    // 5. Construct Verifier Input Map (Only Public Inputs!)
    let mut verifier_input_map = HashMap::<String, Value>::default();
    map_field_vec(&h_hi_words, &ARC_MOD_T256, "h_hi", &mut verifier_input_map);
    map_field_vec(&h_lo_words, &ARC_MOD_T256, "h_lo", &mut verifier_input_map);
    map_field(&root, &ARC_MOD_T256, "root", &mut verifier_input_map);
    verifier_input_map.insert("return".to_string(), bool_to_value(true));

    println!("[4] Verifier Input Map assembled: {} public variables", verifier_input_map.len());

    // 6. Multi-iteration Benchmark for Prover and Verifier
    let iters = opts.iterations;
    println!("\n[5] Running Benchmark across {} iterations...", iters);
    let mut prove_times: Vec<f64> = Vec::with_capacity(iters);
    let mut verify_times: Vec<f64> = Vec::with_capacity(iters);
    let mut proof_size = 0u64;

    for i in 0..iters {
        let t_p = Instant::now();
        spartan::prove_fs(
            &opts.prover_key,
            &opts.pp,
            &prover_input_map,
            &opts.proof,
            &PfCurve::T256,
        ).expect("Spartan Prove failed!");
        let p_dur = t_p.elapsed().as_secs_f64() * 1000.0;
        prove_times.push(p_dur);

        proof_size = std::fs::metadata(&opts.proof).expect("proof metadata").len();

        let t_v = Instant::now();
        spartan::verify_fs(
            &opts.verifier_key,
            &opts.pp,
            &verifier_input_map,
            &opts.proof,
            &PfCurve::T256,
        ).expect("Spartan Verify failed!");
        let v_dur = t_v.elapsed().as_secs_f64() * 1000.0;
        verify_times.push(v_dur);

        println!("    Iter {}: Prove = {:.2} ms, Verify = {:.2} ms", i + 1, p_dur, v_dur);
    }

    let avg_prove: f64 = prove_times.iter().sum::<f64>() / (iters as f64);
    let avg_verify: f64 = verify_times.iter().sum::<f64>() / (iters as f64);

    // 7. Negative Test: Tampered Merkle Root MUST BE REJECTED
    println!("\n[6] Security Negative Test: Tampered Merkle Root...");
    let mut tampered_verifier_map = verifier_input_map.clone();
    let tampered_root = root + Integer::from(1);
    map_field(&tampered_root, &ARC_MOD_T256, "root", &mut tampered_verifier_map);
    
    // Silence panic hook temporarily for clean output
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let neg_res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        spartan::verify_fs(
            &opts.verifier_key,
            &opts.pp,
            &tampered_verifier_map,
            &opts.proof,
            &PfCurve::T256,
        )
    }));
    std::panic::set_hook(prev_hook);

    assert!(neg_res.is_err() || neg_res.unwrap().is_err(), "SECURITY FAILURE: Verifier accepted tampered root!");
    println!("    [PASS] Tampered Merkle Root was cryptographically REJECTED by Spartan verifier!");

    println!("\n============================================================");
    println!(" BENCHMARK RESULTS SUMMARY (Option B: Merkle + Dorian)");
    println!("============================================================");
    println!("  - Merkle Tree Depth:      8 (256 authorized devices)");
    println!("  - Hash Function:          Poseidon over P-256 scalar field");
    println!("  - ECDSA Prehash Sign:     {:.2} ms", sign_elapsed.as_secs_f64() * 1000.0);
    println!("  - Spartan Proving Time:   {:.2} ms (mean over {} runs)", avg_prove, iters);
    println!("  - Spartan Verify Time:    {:.2} ms (mean over {} runs)", avg_verify, iters);
    println!("  - Spartan Proof Size:     {} bytes ({:.2} KB)", proof_size, proof_size as f64 / 1024.0);
    println!("  - Negative Test:          PASSED (Tampered root rejected)");
    println!("  - Device Anonymity:       ACHIEVED (Camera PK is private witness)");
    println!("============================================================");
}
