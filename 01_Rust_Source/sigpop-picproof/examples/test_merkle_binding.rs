use p256::{ProjectivePoint, Scalar, EncodedPoint};
use p256::elliptic_curve::PrimeField;
use p256::elliptic_curve::Field;
use p256::elliptic_curve::sec1::{ToEncodedPoint, FromEncodedPoint};
use rand::SeedableRng;
use rug::Integer;
use sha2::{Digest, Sha256};
use std::time::Instant;
use serde::{Serialize, Deserialize};

use circ::ecdsa::pure_sigma::{
    ECDSASigmaSetupParamsPrior,
    prover_sigmabus
};
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
    let num_leaves = 1 << depth.min(10); // cap simulation at depth 10 for speed, virtualize rest
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

fn main() {
    println!("============================================================");
    println!(" AUDIT SUITE: BOUND MERKLE PROOF & 5 NEGATIVE CONTROLS");
    println!("============================================================");

    let h_hi = Integer::from_str_radix("299632729380388324093288566627275573104", 10).unwrap();
    let h_lo = Integer::from_str_radix("107405792424698788680040687698419521117", 10).unwrap();
    let privkey_a = "/root/autodl-tmp/camera_privkey.pem";

    // 1. Honest Prover Run (PK_A)
    println!("[1/7] Running honest prove_sigmabus & prove_merkle_membership_bound...");
    let t0 = Instant::now();
    let (sigma_proof_a, opening_a) = prover_sigmabus(&h_hi, &h_lo, privkey_a, "/tmp/pi_sigma_a.bin");
    let cm_pk_a = [sigma_proof_a.cm_pk[0].0, sigma_proof_a.cm_pk[1].0];

    // Extract PK_A point
    let prover_input_a = ProverPrecomputeInput::generate_sigmabus_prehash_signature(&h_hi, &h_lo, privkey_a).unwrap();
    let pk_a = prover_input_a.public_key;

    let merkle_depth = 128;
    let merkle_proof_a = prove_merkle_membership_bound(&pk_a, &opening_a, &cm_pk_a, merkle_depth, 42);
    let root_a = merkle_proof_a.root.clone();
    let prove_elapsed = t0.elapsed();
    println!("      Honest prove SUCCESS in {:?} (Root: {})", prove_elapsed, root_a);

    // Serialize proof
    let serialized_merkle = bincode::serialize(&merkle_proof_a).unwrap();
    println!("      Bound Merkle Proof Size: {} bytes ({:.2} KB)", serialized_merkle.len(), serialized_merkle.len() as f64 / 1024.0);

    // 2. Honest Verification
    println!("[2/7] Verifying honest package...");
    let t_v = Instant::now();
    let ok_honest = verify_merkle_bound(&merkle_proof_a, &cm_pk_a, &root_a);
    println!("      Honest Verify: {} (in {:?})", if ok_honest { "ACCEPT" } else { "REJECT" }, t_v.elapsed());
    assert!(ok_honest, "Honest package MUST ACCEPT");

    // =========================================================================
    // NEGATIVE TEST A: merkle_root flip 1 bit
    // =========================================================================
    println!("\n[3/7] NEGATIVE TEST A: merkle_root flipped by 1 bit...");
    let tampered_root = format!("{}1", &root_a[..root_a.len().saturating_sub(1)]);
    let ok_a = verify_merkle_bound(&merkle_proof_a, &cm_pk_a, &tampered_root);
    println!("      Test A Result: {}", if ok_a { "FAIL: ACCEPTED" } else { "PASS: REJECTED" });
    assert!(!ok_a, "Test A MUST REJECT");

    // =========================================================================
    // NEGATIVE TEST B: PK_A 签名 + PK_B Merkle membership (CRITICAL PK LINK TEST)
    // =========================================================================
    println!("\n[4/7] NEGATIVE TEST B: PK_A signature + PK_B Merkle membership (PK Link)...");
    // Generate a distinct second key pair PK_B
    let mut rng_b = rand::rngs::StdRng::seed_from_u64(999);
    let sk_b = Scalar::random(&mut rng_b);
    let pk_b = ProjectivePoint::GENERATOR * sk_b;
    let opening_b = Integer::from(123456789u64);
    let params = ECDSASigmaSetupParamsPrior::new();
    let cm_pk_b = [
        params.hash_hash_g * Scalar::from(123456789u64),
        params.hash_g * Scalar::from(123456789u64) + pk_b,
    ];
    // Attacker generates Merkle proof for PK_B
    let merkle_proof_b = prove_merkle_membership_bound(&pk_b, &opening_b, &cm_pk_b, merkle_depth, 999);
    // Verifier checks PK_B Merkle proof against PK_A commitment cm_pk_a!
    let ok_b = verify_merkle_bound(&merkle_proof_b, &cm_pk_a, &merkle_proof_b.root);
    println!("      Test B Result: {}", if ok_b { "FAIL: ACCEPTED (PK LINK BROKEN!)" } else { "PASS: REJECTED (PK LINK VERIFIED!)" });
    assert!(!ok_b, "Test B MUST REJECT: Attacker cannot mix PK_A signature with PK_B membership!");

    // =========================================================================
    // NEGATIVE TEST B2: Adversarial Splicing (PK_A signature with Bob's leaf injected)
    // =========================================================================
    println!("\n[5/7] NEGATIVE TEST B2: Adversarial Splicing (PK_A proof with PK_B leaf)...");
    let mut spliced_proof = merkle_proof_a.clone();
    spliced_proof.leaf = merkle_proof_b.leaf.clone();
    spliced_proof.siblings = merkle_proof_b.siblings.clone();
    spliced_proof.root = merkle_proof_b.root.clone();
    let ok_b2 = verify_merkle_bound(&spliced_proof, &cm_pk_a, &spliced_proof.root);
    println!("      Test B2 Result: {}", if ok_b2 { "FAIL: ACCEPTED (LEAF SPLICED!)" } else { "PASS: REJECTED (LEAF BINDING VERIFIED!)" });
    assert!(!ok_b2, "Test B2 MUST REJECT: Leaf must strictly match Poseidon2(PK)!");

    // =========================================================================
    // NEGATIVE TEST C: Correct PK + wrong Merkle path
    // =========================================================================
    println!("\n[6/7] NEGATIVE TEST C: Correct PK + wrong Merkle path...");
    let mut bad_path_proof = merkle_proof_a.clone();
    bad_path_proof.siblings[0] = "99999999999999999999999999".to_string(); // corrupt sibling
    let ok_c = verify_merkle_bound(&bad_path_proof, &cm_pk_a, &root_a);
    println!("      Test C Result: {}", if ok_c { "FAIL: ACCEPTED" } else { "PASS: REJECTED" });
    assert!(!ok_c, "Test C MUST REJECT");

    // =========================================================================
    // NEGATIVE TEST E: pi_merkle 任意翻转 1 byte
    // =========================================================================
    println!("\n[7/7] NEGATIVE TEST E: pi_merkle flip 1 byte in serialized proof...");
    let mut tampered_bytes = serialized_merkle.clone();
    tampered_bytes[100] ^= 0x55;
    let deser_res: Result<BoundMerkleProof, _> = bincode::deserialize(&tampered_bytes);
    let ok_e = match deser_res {
        Ok(tampered_pf) => verify_merkle_bound(&tampered_pf, &cm_pk_a, &root_a),
        Err(_) => false,
    };
    println!("      Test E Result: {}", if ok_e { "FAIL: ACCEPTED" } else { "PASS: REJECTED" });
    assert!(!ok_e, "Test E MUST REJECT");

    println!("\n============================================================");
    println!(" ALL NEGATIVE SECURITY CONTROLS PASSED 100%!");
    println!(" Cryptographic PK binding and Merkle membership verified.");
    println!("============================================================");
}
