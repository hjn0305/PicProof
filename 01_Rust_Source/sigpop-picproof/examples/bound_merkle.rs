use circ::cfg::clap::{self, Parser, ValueEnum};
use p256::{ProjectivePoint, Scalar, EncodedPoint};
use p256::elliptic_curve::PrimeField;
use p256::elliptic_curve::Field;
use p256::elliptic_curve::sec1::{ToEncodedPoint, FromEncodedPoint};
use rand::SeedableRng;
use rug::Integer;
use sha2::{Digest, Sha256};
use std::time::Instant;
use std::fs;
use std::path::{Path, PathBuf};
use serde::{Serialize, Deserialize};

use circ::ecdsa::pure_sigma::{
    ECDSASigmaSetupParamsPrior, ECDSASigmaPublicPrior,
    prover_sigmabus
};
use circ::target::r1cs::proof::{serialize_into_file, deserialize_from_file};
use circ::commitment::poseidon_const::{POSEIDON_C, POSEIDON_M};
use circ::right_field_arithmetic::field::ARC_MOD_T256;
use circ::ecdsa::ecdsa::{ProverPrecomputeInput, P256Point};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BoundMerkleProof {
    pub a_0: Vec<u8>,           // SEC1 compressed point A_0 (33 bytes)
    pub a_1: Vec<u8>,           // SEC1 compressed point A_1 (33 bytes)
    pub z_v: Vec<u8>,           // Scalar response z_v (32 bytes)
    pub pk_bytes: Vec<u8>,      // SEC1 compressed camera public key PK (33 bytes)
    pub leaf: String,           // Poseidon2(PK.x, PK.y)
    pub siblings: Vec<String>,  // Merkle siblings
    pub directions: Vec<bool>,  // Merkle path directions
    pub root: String,           // Merkle root
    pub depth: usize,
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

pub fn build_merkle_tree(depth: usize, my_leaf: Integer) -> (Integer, Vec<Integer>, Vec<bool>) {
    let num_leaves = 1 << depth.min(10);
    let mut current_level: Vec<Integer> = Vec::with_capacity(num_leaves);
    current_level.push(my_leaf.clone());
    for i in 1..num_leaves {
        let dummy = poseidon_hash_t256(vec![Integer::from(i * 1000 + 1), Integer::from(i * 1000 + 2)]);
        current_level.push(dummy);
    }

    let mut siblings: Vec<Integer> = Vec::with_capacity(depth);
    let mut directions: Vec<bool> = Vec::with_capacity(depth);

    let mut idx = 0usize;
    for d in 0..depth {
        if d < 10 {
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
        } else {
            let sib = poseidon_hash_t256(vec![Integer::from(d * 7919 + 1), Integer::from(d * 7919 + 2)]);
            siblings.push(sib.clone());
            let dir = (d % 2) == 0;
            directions.push(dir);
            let (l, r) = if dir { (current_level[0].clone(), sib) } else { (sib, current_level[0].clone()) };
            current_level[0] = poseidon_hash_t256(vec![l, r]);
        }
    }
    (current_level[0].clone(), siblings, directions)
}

pub fn prove_merkle_membership_bound(
    pk_point: &ProjectivePoint,
    opening_int: &Integer,
    cm_pk: &[ProjectivePoint; 2],
    depth: usize,
    rng_seed: u64,
) -> BoundMerkleProof {
    let params = ECDSASigmaSetupParamsPrior::new();
    let pt_l = params.hash_hash_g;
    let pt_k = params.hash_g;

    let p256_pt = P256Point::from_projective_point(*pk_point);
    let pk_x = p256_pt.x.clone();
    let pk_y = p256_pt.y.clone();

    // 1. Leaf and Tree
    let my_leaf = poseidon_hash_t256(vec![pk_x, pk_y]);
    let (root, siblings, directions) = build_merkle_tree(depth, my_leaf.clone());

    // 2. ZK Proof of Opening & PK Binding
    let mut rng = rand::rngs::StdRng::seed_from_u64(rng_seed);
    let r_v = Scalar::random(&mut rng);

    // Commitments A_0 = r_v * L, A_1 = r_v * K
    let a_0 = pt_l * r_v;
    let a_1 = pt_k * r_v;

    let pk_encoded = pk_point.to_encoded_point(true);
    let pk_bytes = pk_encoded.as_bytes().to_vec();

    // Challenge c = Hash(L, K, C_0, C_1, A_0, A_1, PK, leaf, root)
    let mut hasher = Sha256::new();
    hasher.update(pt_l.to_encoded_point(true).as_bytes());
    hasher.update(pt_k.to_encoded_point(true).as_bytes());
    hasher.update(cm_pk[0].to_encoded_point(true).as_bytes());
    hasher.update(cm_pk[1].to_encoded_point(true).as_bytes());
    hasher.update(a_0.to_encoded_point(true).as_bytes());
    hasher.update(a_1.to_encoded_point(true).as_bytes());
    hasher.update(&pk_bytes);
    hasher.update(my_leaf.to_string().as_bytes());
    hasher.update(root.to_string().as_bytes());
    let c_bytes = hasher.finalize();
    let challenge = Scalar::from_repr(c_bytes.into()).unwrap();

    // Opening scalar v
    let v_bytes = opening_int.to_digits::<u8>(rug::integer::Order::MsfBe);
    let mut v_arr = [0u8; 32];
    let start = 32usize.saturating_sub(v_bytes.len());
    v_arr[start..].copy_from_slice(&v_bytes);
    let v_scalar = Scalar::from_repr(v_arr.into()).unwrap();

    // Response
    let z_v = r_v + challenge * v_scalar;

    BoundMerkleProof {
        a_0: a_0.to_encoded_point(true).as_bytes().to_vec(),
        a_1: a_1.to_encoded_point(true).as_bytes().to_vec(),
        z_v: z_v.to_repr().as_slice().to_vec(),
        pk_bytes,
        leaf: my_leaf.to_string(),
        siblings: siblings.iter().map(|s| s.to_string()).collect(),
        directions,
        root: root.to_string(),
        depth,
    }
}

pub fn verify_merkle_bound(
    proof: &BoundMerkleProof,
    cm_pk: &[ProjectivePoint; 2],
    expected_root_str: &str,
) -> bool {
    let params = ECDSASigmaSetupParamsPrior::new();
    let pt_l = params.hash_hash_g;
    let pt_k = params.hash_g;

    // 1. Root match check
    if proof.root != expected_root_str {
        return false;
    }

    // 2. Decode points and scalars
    let a_0_enc = EncodedPoint::from_bytes(&proof.a_0);
    let a_1_enc = EncodedPoint::from_bytes(&proof.a_1);
    let pk_enc = EncodedPoint::from_bytes(&proof.pk_bytes);
    if a_0_enc.is_err() || a_1_enc.is_err() || pk_enc.is_err() {
        return false;
    }
    let a_0 = ProjectivePoint::from_encoded_point(&a_0_enc.unwrap());
    let a_1 = ProjectivePoint::from_encoded_point(&a_1_enc.unwrap());
    let pk_point = ProjectivePoint::from_encoded_point(&pk_enc.unwrap());
    if a_0.is_none().into() || a_1.is_none().into() || pk_point.is_none().into() {
        return false;
    }
    let a_0 = a_0.unwrap();
    let a_1 = a_1.unwrap();
    let pk_point = pk_point.unwrap();

    let mut z_v_arr = [0u8; 32];
    if proof.z_v.len() != 32 {
        return false;
    }
    z_v_arr.copy_from_slice(&proof.z_v);
    let z_v_opt = Scalar::from_repr(z_v_arr.into());
    if z_v_opt.is_none().into() {
        return false;
    }
    let z_v = z_v_opt.unwrap();

    // 3. Verify Leaf Hash equals Poseidon2(PK.x, PK.y)
    let p256_pt = P256Point::from_projective_point(pk_point);
    let computed_leaf = poseidon_hash_t256(vec![p256_pt.x, p256_pt.y]);
    if computed_leaf.to_string() != proof.leaf {
        return false;
    }

    // 4. Recompute Fiat-Shamir challenge
    let mut hasher = Sha256::new();
    hasher.update(pt_l.to_encoded_point(true).as_bytes());
    hasher.update(pt_k.to_encoded_point(true).as_bytes());
    hasher.update(cm_pk[0].to_encoded_point(true).as_bytes());
    hasher.update(cm_pk[1].to_encoded_point(true).as_bytes());
    hasher.update(&proof.a_0);
    hasher.update(&proof.a_1);
    hasher.update(&proof.pk_bytes);
    hasher.update(proof.leaf.as_bytes());
    hasher.update(proof.root.as_bytes());
    let c_bytes = hasher.finalize();
    let challenge = Scalar::from_repr(c_bytes.into()).unwrap();

    // 5. Check Commitment Opening Equations
    // Eq 1: z_v * L == A_0 + c * C_0
    if pt_l * z_v != a_0 + cm_pk[0] * challenge {
        return false;
    }
    // Eq 2: z_v * K + c * PK == A_1 + c * C_1
    if pt_k * z_v + pk_point * challenge != a_1 + cm_pk[1] * challenge {
        return false;
    }

    // 6. Verify Merkle Path
    let mut curr = match Integer::from_str_radix(&proof.leaf, 10) {
        Ok(v) => v,
        Err(_) => return false,
    };
    if proof.siblings.len() != proof.depth || proof.directions.len() != proof.depth {
        return false;
    }
    for i in 0..proof.depth {
        let sib = match Integer::from_str_radix(&proof.siblings[i], 10) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let (l, r) = if proof.directions[i] { (curr, sib) } else { (sib, curr) };
        curr = poseidon_hash_t256(vec![l, r]);
    }

    let expected_root = match Integer::from_str_radix(&proof.root, 10) {
        Ok(v) => v,
        Err(_) => return false,
    };
    if curr != expected_root {
        return false;
    }

    true
}

#[derive(Parser, Debug)]
#[command(name = "bound_merkle")]
struct Cli {
    #[arg(long)]
    action: Action,
    #[arg(long)]
    h_hi: String,
    #[arg(long)]
    h_lo: String,
    #[arg(long, default_value = "/root/autodl-tmp/camera_privkey.pem")]
    privkey: String,
    #[arg(long, default_value_t = 128)]
    depth: usize,
    #[arg(long, default_value = "/tmp/pi_sigma.bin")]
    proof_sigma: PathBuf,
    #[arg(long, default_value = "/tmp/pi_merkle.bin")]
    proof_merkle: PathBuf,
    #[arg(long)]
    merkle_root: Option<String>,
    #[arg(long)]
    root_out: Option<PathBuf>,
}

#[derive(Clone, Debug, ValueEnum, PartialEq)]
enum Action {
    Prove,
    Verify,
    TestNegatives,
}

fn main() {
    let cli = Cli::parse();
    let h_hi = Integer::from_str_radix(&cli.h_hi, 10).expect("Invalid h_hi");
    let h_lo = Integer::from_str_radix(&cli.h_lo, 10).expect("Invalid h_lo");

    match cli.action {
        Action::Prove => {
            let t0 = Instant::now();
            let (sigma_proof, opening) = prover_sigmabus(&h_hi, &h_lo, &cli.privkey, &cli.proof_sigma);
            let cm_pk = [sigma_proof.cm_pk[0].0, sigma_proof.cm_pk[1].0];

            let prover_input = ProverPrecomputeInput::generate_sigmabus_prehash_signature(&h_hi, &h_lo, &cli.privkey).unwrap();
            let pk = prover_input.public_key;

            let merkle_proof = prove_merkle_membership_bound(&pk, &opening, &cm_pk, cli.depth, 42);
            let root = merkle_proof.root.clone();

            let merkle_bytes = bincode::serialize(&merkle_proof).unwrap();
            fs::write(&cli.proof_merkle, &merkle_bytes).unwrap();

            if let Some(ref r_path) = cli.root_out {
                fs::write(r_path, &root).unwrap();
            }

            println!("BOUND_MERKLE_PROVE_OK elapsed_ms={} root={} merkle_bytes={}", t0.elapsed().as_millis(), root, merkle_bytes.len());
        }
        Action::Verify => {
            let t0 = Instant::now();
            // 1. Verify Sigma
            let sigma_pf: ECDSASigmaPublicPrior = deserialize_from_file(&cli.proof_sigma)
                .expect("Failed to read pi_sigma");
            let params = ECDSASigmaSetupParamsPrior::new();
            let digest_result = (h_hi.clone() << 128) | h_lo.clone();
            sigma_pf.verify(&digest_result, params);
            let cm_pk = [sigma_pf.cm_pk[0].0, sigma_pf.cm_pk[1].0];

            // 2. Verify Merkle
            let root = cli.merkle_root.expect("--merkle-root required for verify");
            let merkle_bytes = fs::read(&cli.proof_merkle).expect("Failed to read pi_merkle");
            let merkle_pf: BoundMerkleProof = bincode::deserialize(&merkle_bytes).expect("Failed to deserialize pi_merkle");

            let ok = verify_merkle_bound(&merkle_pf, &cm_pk, &root);
            if !ok {
                eprintln!("BOUND_MERKLE_VERIFY_FAIL: Merkle binding verification failed");
                std::process::exit(1);
            }
            println!("BOUND_MERKLE_VERIFY_OK elapsed_ms={}", t0.elapsed().as_millis());
        }
        Action::TestNegatives => {
            println!("Running test negatives for bound merkle...");
            // Run full audit suite
            let t0 = Instant::now();
            let (sigma_proof_a, opening_a) = prover_sigmabus(&h_hi, &h_lo, &cli.privkey, "/tmp/pi_sigma_a.bin");
            let cm_pk_a = [sigma_proof_a.cm_pk[0].0, sigma_proof_a.cm_pk[1].0];
            let prover_input_a = ProverPrecomputeInput::generate_sigmabus_prehash_signature(&h_hi, &h_lo, &cli.privkey).unwrap();
            let pk_a = prover_input_a.public_key;

            let merkle_proof_a = prove_merkle_membership_bound(&pk_a, &opening_a, &cm_pk_a, cli.depth, 42);
            let root_a = merkle_proof_a.root.clone();
            let serialized_merkle = bincode::serialize(&merkle_proof_a).unwrap();

            // Honest Verify
            let ok_honest = verify_merkle_bound(&merkle_proof_a, &cm_pk_a, &root_a);
            assert!(ok_honest, "Honest MUST accept");
            println!("[NEG_AUDIT] HONEST: ACCEPT");

            // Test A: root 1 bit
            let tampered_root = format!("{}1", &root_a[..root_a.len().saturating_sub(1)]);
            assert!(!verify_merkle_bound(&merkle_proof_a, &cm_pk_a, &tampered_root), "Test A MUST reject");
            println!("[NEG_AUDIT] TEST_A (tampered root): PASS (REJECTED)");

            // Test B: PK_A sig + PK_B Merkle
            let mut rng_b = rand::rngs::StdRng::seed_from_u64(999);
            let sk_b = Scalar::random(&mut rng_b);
            let pk_b = ProjectivePoint::GENERATOR * sk_b;
            let opening_b = Integer::from(123456789u64);
            let params = ECDSASigmaSetupParamsPrior::new();
            let cm_pk_b = [
                params.hash_hash_g * Scalar::from(123456789u64),
                params.hash_g * Scalar::from(123456789u64) + pk_b,
            ];
            let merkle_proof_b = prove_merkle_membership_bound(&pk_b, &opening_b, &cm_pk_b, cli.depth, 999);
            assert!(!verify_merkle_bound(&merkle_proof_b, &cm_pk_a, &merkle_proof_b.root), "Test B MUST reject");
            println!("[NEG_AUDIT] TEST_B (mismatched PK): PASS (REJECTED)");

            // Test B2: Spliced leaf
            let mut spliced_proof = merkle_proof_a.clone();
            spliced_proof.leaf = merkle_proof_b.leaf.clone();
            spliced_proof.siblings = merkle_proof_b.siblings.clone();
            spliced_proof.root = merkle_proof_b.root.clone();
            assert!(!verify_merkle_bound(&spliced_proof, &cm_pk_a, &spliced_proof.root), "Test B2 MUST reject");
            println!("[NEG_AUDIT] TEST_B2 (spliced leaf): PASS (REJECTED)");

            // Test C: Bad path
            let mut bad_path_proof = merkle_proof_a.clone();
            bad_path_proof.siblings[0] = "99999999999999999999999999".to_string();
            assert!(!verify_merkle_bound(&bad_path_proof, &cm_pk_a, &root_a), "Test C MUST reject");
            println!("[NEG_AUDIT] TEST_C (corrupt path): PASS (REJECTED)");

            // Test D: Digest flip 1 bit
            let tampered_h_hi = h_hi.clone() ^ Integer::from(1);
            let digest_tampered = (tampered_h_hi << 128) | h_lo.clone();
            let mut neg_d_failed = false;
            let prev_hook = std::panic::take_hook();
            std::panic::set_hook(Box::new(|_| {}));
            let d_res = std::panic::catch_unwind(|| {
                sigma_proof_a.verify(&digest_tampered, params);
            });
            std::panic::set_hook(prev_hook);
            assert!(d_res.is_err(), "Test D MUST reject");
            println!("[NEG_AUDIT] TEST_D (tampered digest): PASS (REJECTED)");

            // Test E: Corrupt proof byte
            let mut tampered_bytes = serialized_merkle.clone();
            tampered_bytes[100] ^= 0x55;
            let deser_res: Result<BoundMerkleProof, _> = bincode::deserialize(&tampered_bytes);
            let ok_e = match deser_res {
                Ok(tampered_pf) => verify_merkle_bound(&tampered_pf, &cm_pk_a, &root_a),
                Err(_) => false,
            };
            assert!(!ok_e, "Test E MUST reject");
            println!("[NEG_AUDIT] TEST_E (corrupt byte): PASS (REJECTED)");

            println!("ALL_NEGATIVES_PASSED_100% total_ms={}", t0.elapsed().as_millis());
        }
    }
}
