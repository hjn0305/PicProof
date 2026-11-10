//! Standalone Spartan NIZK Poseidon Merkle Membership Prover and Verifier
//!
//! Public Inputs: (leaf, root, depth)
//! Private Witness: (siblings, directions)
//! Proof Object: SpartanMerklePackage (only contains NIZK proof, depth, version, profile)

use libdoriant256::{Instance, NIZKGens, NIZK, VarsAssignment, InputsAssignment};
use merlin::Transcript;
use rug::Integer;
use circ::commitment::poseidon_const::{POSEIDON_C, POSEIDON_M};
use circ::right_field_arithmetic::field::ARC_MOD_T256;
use serde::{Serialize, Deserialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::time::Instant;

pub const VERSION: &str = "1.0.0";
pub const PROFILE: &str = "PicProof-P256Fp-Poseidon-t3-v1";
pub const DOMAIN_TAG: &[u8] = b"picproof_spartan_merkle_membership_v1";
pub const MAX_MERKLE_DEPTH: usize = 32;

#[derive(Serialize, Deserialize, Debug)]
pub struct SpartanMerklePackage {
    pub proof: NIZK,
    pub depth: usize,
    pub version: String,
    pub profile: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MerklePathInput {
    pub siblings: Vec<String>,
    pub directions: Vec<bool>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MerkleStatement {
    pub leaf: String,
    pub root: String,
    pub depth: usize,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TimingReport {
    pub action: String,
    pub depth: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub num_constraints: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub num_variables: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prove_time_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify_time_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_bytes: Option<usize>,
    pub success: bool,
}

pub fn parse_integer(s: &str) -> Result<Integer, String> {
    let clean = s.trim();
    if clean.starts_with("0x") || clean.starts_with("0X") {
        Integer::from_str_radix(&clean[2..], 16)
            .map_err(|e| format!("Invalid hex integer '{}': {:?}", clean, e))
    } else {
        Integer::from_str_radix(clean, 10)
            .map_err(|e| format!("Invalid decimal integer '{}': {:?}", clean, e))
    }
}

pub fn integer_to_bytes32(val: &Integer) -> [u8; 32] {
    let modulus = &**ARC_MOD_T256;
    let mut v = val.clone() % modulus;
    if v < 0 {
        v += modulus;
    }
    let digits = v.to_digits::<u8>(rug::integer::Order::LsfLe);
    let mut bytes = [0u8; 32];
    bytes[..digits.len()].copy_from_slice(&digits);
    bytes
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
        for i in 0..state.len() {
            state[i] = (state[i].clone() + c[r * t + i].clone()) % modulus;
        }
        state[0] = state[0].clone().pow_mod(&Integer::from(5), modulus).unwrap();
        for i in 1..state.len() {
            if r < f / 2 || r >= f / 2 + p {
                state[i] = state[i].clone().pow_mod(&Integer::from(5), modulus).unwrap();
            }
        }
        let mut out = vec![Integer::new(); t];
        for i in 0..t {
            let mut acc = Integer::new();
            for j in 0..t {
                acc = (acc + state[j].clone() * m[i][j].clone()) % modulus;
            }
            out[i] = acc;
        }
        state = out;
    }
    state[0].clone()
}


#[derive(Clone, Debug)]
pub struct P256PoseidonParams {
    pub name: String,
    pub modulus: Integer,
    pub alpha: u64,
    pub t: usize,
    pub input_rate: usize,
    pub full_rounds: usize,
    pub partial_rounds: usize,
    pub round_constants: Vec<Integer>,
    pub mds: Vec<Vec<Integer>>,
    pub parameter_sha256: String,
}

pub fn json_integer(v: &Value) -> Result<Integer, String> {
    match v {
        Value::String(s) => parse_integer(s),
        Value::Number(n) => Integer::from_str_radix(&n.to_string(), 10)
            .map_err(|e| format!("Invalid number {}: {:?}", n, e)),
        _ => Err(format!("Expected string or number for Integer, got {:?}", v)),
    }
}

pub fn load_p256_poseidon_params(path_opt: Option<&str>) -> Result<P256PoseidonParams, String> {
    let candidate_paths = [
        path_opt.unwrap_or(""),
        "/root/autodl-tmp/sigpop/p256_poseidon_t3_params.json",
        "p256_poseidon_t3_params.json",
        "params/p256_poseidon/p256_poseidon_t3_params.json",
        "/data/zk-tools/sigpop/params/p256_poseidon/p256_poseidon_t3_params.json",
    ];

    let mut content = None;
    let mut resolved_path = String::new();
    for p in &candidate_paths {
        if !p.is_empty() && Path::new(p).exists() {
            if let Ok(c) = std::fs::read_to_string(p) {
                content = Some(c);
                resolved_path = p.to_string();
                break;
            }
        }
    }

    let c = content.ok_or_else(|| {
        "Could not find p256_poseidon_t3_params.json in any candidate path".to_string()
    })?;

    let v: Value = serde_json::from_str(&c)
        .map_err(|e| format!("JSON parse error in {}: {:?}", resolved_path, e))?;

    let name = v["name"].as_str().unwrap_or("unknown").to_string();
    let modulus = json_integer(&v["modulus"])?;
    let alpha = v["alpha"].as_u64().ok_or("Missing or invalid alpha")?;
    let t = v["t"].as_u64().ok_or("Missing or invalid t")? as usize;
    let input_rate = v["input_rate"].as_u64().ok_or("Missing or invalid input_rate")? as usize;
    let full_rounds = v["full_rounds"].as_u64().ok_or("Missing or invalid full_rounds")? as usize;
    let partial_rounds = v["partial_rounds"].as_u64().ok_or("Missing or invalid partial_rounds")? as usize;

    let rc_arr = v["round_constants"].as_array().ok_or("Missing round_constants")?;
    let mut round_constants = Vec::with_capacity(rc_arr.len());
    for rc in rc_arr {
        round_constants.push(json_integer(rc)?);
    }

    let mds_arr = v["mds"].as_array().ok_or("Missing mds")?;
    let mut mds = Vec::with_capacity(mds_arr.len());
    for row in mds_arr {
        let r_arr = row.as_array().ok_or("MDS row is not an array")?;
        let mut row_vec = Vec::with_capacity(r_arr.len());
        for elem in r_arr {
            row_vec.push(json_integer(elem)?);
        }
        mds.push(row_vec);
    }

    let parameter_sha256 = v["parameter_sha256"].as_str().unwrap_or("").to_string();
    if parameter_sha256.len() != 64 || !parameter_sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("Poseidon parameter_sha256 must be 32-byte hexadecimal".into());
    }
    let mut fingerprint_value = v.clone();
    fingerprint_value.as_object_mut()
        .ok_or("Poseidon parameter file root must be a JSON object")?
        .remove("parameter_sha256");
    let canonical_parameters = serde_json::to_vec(&fingerprint_value)
        .map_err(|e| format!("Cannot canonicalize Poseidon parameters: {e}"))?;
    let computed_fingerprint = hex::encode(Sha256::digest(&canonical_parameters));
    if !computed_fingerprint.eq_ignore_ascii_case(&parameter_sha256) {
        return Err(format!("Poseidon parameter fingerprint mismatch: declared {}, computed {}", parameter_sha256, computed_fingerprint));
    }
    let expected_modulus = Integer::from_str_radix(
        "115792089210356248762697446949407573530086143415290314195533631308867097853951", 10,
    ).map_err(|e| format!("Cannot parse expected P-256 base-field modulus: {e}"))?;
    if name != PROFILE || modulus != expected_modulus || alpha != 7 || t != 3
        || input_rate != 2 || full_rounds != 8 || partial_rounds != 46
        || round_constants.len() != 162 || mds.len() != 3
        || mds.iter().any(|row| row.len() != 3) {
        return Err("Poseidon parameters do not match the pinned PicProof P-256 t=3 profile".into());
    }

    Ok(P256PoseidonParams {
        name,
        modulus,
        alpha,
        t,
        input_rate,
        full_rounds,
        partial_rounds,
        round_constants,
        mds,
        parameter_sha256,
    })
}

pub fn pow7_mod(x: &Integer, p: &Integer) -> Integer {
    let mut val = x.clone() % p;
    if val < 0 {
        val += p;
    }
    val.pow_mod(&Integer::from(7), p).unwrap()
}

pub fn poseidon_p256_hash(left: &Integer, right: &Integer, params: &P256PoseidonParams) -> Integer {
    let p = &params.modulus;
    let t = params.t;
    let rf = params.full_rounds;
    let rp = params.partial_rounds;
    let half = rf / 2;

    let mut state = vec![Integer::new(); t];
    state[0] = Integer::new();
    state[1] = {
        let mut v = left.clone() % p;
        if v < 0 { v += p; }
        v
    };
    state[2] = {
        let mut v = right.clone() % p;
        if v < 0 { v += p; }
        v
    };

    let mut ci = 0;
    for r in 0..(rf + rp) {
        // 1. Add Round Constants (ARK)
        for i in 0..t {
            state[i] = (state[i].clone() + params.round_constants[ci].clone()) % p;
            if state[i] < 0 {
                state[i] += p;
            }
            ci += 1;
        }

        // 2. Hades S-box layer: alpha = 7
        let is_full = (r < half) || (r >= half + rp);
        state[0] = pow7_mod(&state[0], p);
        if is_full {
            for i in 1..t {
                state[i] = pow7_mod(&state[i], p);
            }
        }

        // 3. Dense MDS mix
        let old = state.clone();
        for i in 0..t {
            let mut acc = Integer::new();
            for j in 0..t {
                acc += old[j].clone() * params.mds[i][j].clone();
            }
            acc %= p;
            if acc < 0 {
                acc += p;
            }
            state[i] = acc;
        }
    }
    assert_eq!(ci, params.round_constants.len(), "All round constants must be consumed");
    state[0].clone()
}

pub fn run_poseidon_kat() -> bool {
    println!("[KAT] Loading P-256 Poseidon parameters...");
    let params = match load_p256_poseidon_params(None) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[KAT] ERROR loading parameters: {}", e);
            return false;
        }
    };
    println!("[KAT] Parameter profile: {}", params.name);
    println!("[KAT] Parameter SHA256: {}", params.parameter_sha256);
    println!("[KAT] Field modulus: {}", params.modulus);
    println!("[KAT] alpha={}, t={}, RF={}, RP={}", params.alpha, params.t, params.full_rounds, params.partial_rounds);

    // Also load raw json to test all test_vectors if present
    let json_val: Option<Value> = (|| {
        let p = "/root/autodl-tmp/sigpop/p256_poseidon_t3_params.json";
        if Path::new(p).exists() {
            let c = std::fs::read_to_string(p).ok()?;
            serde_json::from_str(&c).ok()
        } else if Path::new("p256_poseidon_t3_params.json").exists() {
            let c = std::fs::read_to_string("p256_poseidon_t3_params.json").ok()?;
            serde_json::from_str(&c).ok()
        } else {
            None
        }
    })();

    let mut all_pass = true;
    if let Some(jv) = json_val {
        if let Some(tvecs) = jv["test_vectors"].as_array() {
            println!("[KAT] Found {} test vectors in parameter file:", tvecs.len());
            for (idx, tv) in tvecs.iter().enumerate() {
                let l_int = json_integer(&tv["left"]).unwrap();
                let r_int = json_integer(&tv["right"]).unwrap();
                let exp_int = json_integer(&tv["out"]).unwrap();
                let evaluated = poseidon_p256_hash(&l_int, &r_int, &params);
                if evaluated == exp_int {
                    println!("[KAT] Vector {}: ({}, {}) -> PASS", idx, l_int, r_int);
                } else {
                    eprintln!("[KAT] Vector {}: ({}, {}) -> FAIL: got {}, expected {}", idx, l_int, r_int, evaluated, exp_int);
                    all_pass = false;
                }
            }
        }
    }

    // Explicit test vector H(1, 2)
    let l1 = Integer::from(1);
    let r1 = Integer::from(2);
    let expected_h12 = Integer::from_str_radix("36467780161211596468984493607115583606898651699366728417584141181844989207865", 10).unwrap();
    let out1 = poseidon_p256_hash(&l1, &r1, &params);
    println!("[KAT] Evaluated H(1, 2) = {}", out1);
    println!("[KAT] Expected  H(1, 2) = {}", expected_h12);

    if out1 == expected_h12 {
        println!("KAT H(1,2): PASS");
    } else {
        eprintln!("KAT H(1,2): FAIL");
        all_pass = false;
    }

    if all_pass {
        println!("[KAT] All test vectors passed successfully.");
    }
    all_pass
}

pub struct MerkleCircuitBuilder {
    pub depth: usize,
    pub num_cons: usize,
    pub num_vars: usize,
    pub num_inputs: usize,
    pub a_triples: Vec<(usize, usize, [u8; 32])>,
    pub b_triples: Vec<(usize, usize, [u8; 32])>,
    pub c_triples: Vec<(usize, usize, [u8; 32])>,
    pub witness_values: Vec<[u8; 32]>,
}

impl MerkleCircuitBuilder {
    pub fn new(depth: usize) -> Self {
        Self {
            depth,
            num_cons: 0,
            num_vars: 0,
            num_inputs: 2,
            a_triples: Vec::new(),
            b_triples: Vec::new(),
            c_triples: Vec::new(),
            witness_values: Vec::new(),
        }
    }

    pub fn alloc_var(&mut self, val: &Integer) -> usize {
        let id = self.num_vars;
        self.num_vars += 1;
        self.witness_values.push(integer_to_bytes32(val));
        id
    }

    pub fn add_constraint(
        &mut self,
        a_terms: &[(usize, Integer)],
        b_terms: &[(usize, Integer)],
        c_terms: &[(usize, Integer)],
    ) {
        let row = self.num_cons;
        self.num_cons += 1;
        for &(var_id, ref coeff) in a_terms {
            self.a_triples.push((row, var_id, integer_to_bytes32(coeff)));
        }
        for &(var_id, ref coeff) in b_terms {
            self.b_triples.push((row, var_id, integer_to_bytes32(coeff)));
        }
        for &(var_id, ref coeff) in c_terms {
            self.c_triples.push((row, var_id, integer_to_bytes32(coeff)));
        }
    }
}

type LC = Vec<(usize, Integer)>;

fn lc_normalize(lc: LC, modulus: &Integer) -> LC {
    let mut map: BTreeMap<usize, Integer> = BTreeMap::new();

    for (var, coeff) in lc {
        let entry = map.entry(var).or_insert_with(|| Integer::from(0));
        *entry += coeff;
        *entry %= modulus;
        if *entry < 0 {
            *entry += modulus;
        }
    }

    map.into_iter()
        .filter(|(_, c)| *c != 0)
        .collect()
}

fn lc_add(a: &LC, b: &LC, modulus: &Integer) -> LC {
    let mut out = a.clone();
    out.extend(b.iter().cloned());
    lc_normalize(out, modulus)
}

fn lc_scale(a: &LC, k: &Integer, modulus: &Integer) -> LC {
    let out: LC = a
        .iter()
        .map(|(v, c)| {
            let mut coeff = (c.clone() * k.clone()) % modulus;
            if coeff < 0 {
                coeff += modulus;
            }
            (*v, coeff)
        })
        .collect();

    lc_normalize(out, modulus)
}

fn lc_add_const(
    a: &LC,
    v_one: usize,
    c: &Integer,
    modulus: &Integer,
) -> LC {
    let mut out = a.clone();
    out.push((v_one, c.clone()));
    lc_normalize(out, modulus)
}

fn lc_is_constant(lc: &LC, v_one: usize) -> bool {
    lc.iter().all(|(v, _)| *v == v_one)
}

fn lc_constant_value(
    lc: &LC,
    v_one: usize,
    modulus: &Integer,
) -> Option<Integer> {
    if !lc_is_constant(lc, v_one) {
        return None;
    }

    let mut acc = Integer::from(0);

    for (v, c) in lc {
        assert_eq!(*v, v_one);
        acc += c.clone();
    }

    acc %= modulus;

    if acc < 0 {
        acc += modulus;
    }

    Some(acc)
}

pub fn synthesize_merkle_circuit(
    depth: usize,
    leaf: &Integer,
    siblings: &[Integer],
    directions: &[bool],
    root: &Integer,
) -> (Instance, VarsAssignment, InputsAssignment, usize, usize, usize) {
    let params = load_p256_poseidon_params(None)
        .expect("Failed to load and authenticate p256_poseidon_t3_params.json");
    synthesize_merkle_circuit_with_params(depth, leaf, siblings, directions, root, &params)
}

pub fn synthesize_merkle_circuit_with_params(
    depth: usize,
    leaf: &Integer,
    siblings: &[Integer],
    directions: &[bool],
    root: &Integer,
    params: &P256PoseidonParams,
) -> (Instance, VarsAssignment, InputsAssignment, usize, usize, usize) {
    let mut builder = MerkleCircuitBuilder::new(depth);
    let modulus = &params.modulus;

    let t = params.t;
    let f = params.full_rounds;
    let p_rounds = params.partial_rounds;

    assert_eq!(t, 3);
    assert_eq!(f, 8);
    assert_eq!(p_rounds, 46);
    assert_eq!(params.alpha, 7);
    assert_eq!(params.round_constants.len(), 162);

    let c_consts = &params.round_constants;
    let m_matrix = &params.mds;

    let v_one = usize::MAX - 2;
    let v_leaf = usize::MAX - 1;
    let v_root = usize::MAX;

    let mut curr_val = leaf.clone();
    let mut curr_lc: LC = vec![
        (v_leaf, Integer::from(1)),
    ];

    for d in 0..depth {
        let sib_val = siblings[d].clone();
        let dir_val = directions[d];
        let dir_int = if dir_val { Integer::from(1) } else { Integer::from(0) };

        // 1. Witness for sibling and direction
        let w_sib = builder.alloc_var(&sib_val);
        let w_dir = builder.alloc_var(&dir_int);

        // Constraint: dir * dir = dir (boolean check)
        builder.add_constraint(
            &[(w_dir, Integer::from(1))],
            &[(w_dir, Integer::from(1))],
            &[(w_dir, Integer::from(1))],
        );

        // 2. Multiplexer:
        // When dir == true: curr is left, sib is right => left = curr, right = sib
        // When dir == false: sib is left, curr is right => left = sib, right = curr
        // left = sib + dir * (curr - sib) => dir * (curr - sib) = left - sib
        // right = curr + sib - left => 1 * (curr + sib - left) = right
        let left_val = if dir_val { curr_val.clone() } else { sib_val.clone() };
        let right_val = if dir_val { sib_val.clone() } else { curr_val.clone() };

        let w_left = builder.alloc_var(&left_val);
        let w_right = builder.alloc_var(&right_val);

        // Constraint for left: d * (curr - sib) = left - sib
        let mut curr_minus_sib = curr_lc.clone();
        curr_minus_sib.push((
            w_sib,
            modulus.clone() - 1,
        ));
        let curr_minus_sib = lc_normalize(
            curr_minus_sib,
            modulus,
        );

        builder.add_constraint(
            &[(w_dir, Integer::from(1))],
            &curr_minus_sib,
            &[
                (w_left, Integer::from(1)),
                (w_sib, modulus.clone() - 1),
            ],
        );

        // Constraint for right: 1 * (curr + sib - left) = right
        let mut right_expr = curr_lc.clone();
        right_expr.push((
            w_sib,
            Integer::from(1),
        ));
        right_expr.push((
            w_left,
            modulus.clone() - 1,
        ));
        let right_expr = lc_normalize(right_expr, modulus);

        builder.add_constraint(
            &[(v_one, Integer::from(1))],
            &right_expr,
            &[(w_right, Integer::from(1))],
        );

        // 3. Poseidon rounds: state size = 3
        let mut state_vals = vec![
            Integer::from(0),
            left_val,
            right_val,
        ];

        let mut state_lcs: Vec<LC> = vec![
            vec![], // state[0] = 0
            vec![(w_left, Integer::from(1))],
            vec![(w_right, Integer::from(1))],
        ];

        for r in 0..(f + p_rounds) {
            let mut sp_vals = Vec::with_capacity(t);
            let mut sp_lcs = Vec::with_capacity(t);

            for i in 0..t {
                let rc = c_consts[r * t + i].clone();
                let mut sp_val = (state_vals[i].clone() + rc.clone()) % modulus;
                if sp_val < 0 {
                    sp_val += modulus;
                }
                let sp_lc = lc_add_const(
                    &state_lcs[i],
                    v_one,
                    &rc,
                    modulus,
                );
                sp_vals.push(sp_val);
                sp_lcs.push(sp_lc);
            }

            // S-box x^7
            let mut sbox_out_vals = vec![Integer::new(); t];
            let mut sbox_out_lcs: Vec<LC> = vec![Vec::new(); t];

            for i in 0..t {
                if r < f / 2 || r >= f / 2 + p_rounds || i == 0 {
                    let x_val = sp_vals[i].clone();
                    let x_lc = sp_lcs[i].clone();

                    // Constant folding:
                    // If this S-box input is purely constant, compute x^7 natively
                    // and emit no witness variables / R1CS constraints.
                    if lc_is_constant(&x_lc, v_one) {
                        let x7_val = pow7_mod(&x_val, modulus);

                        sbox_out_vals[i] = x7_val.clone();

                        sbox_out_lcs[i] = vec![
                            (v_one, x7_val)
                        ];
                    } else {
                        // x2 = x*x
                        let mut x2_val = (x_val.clone() * x_val.clone()) % modulus;
                        if x2_val < 0 { x2_val += modulus; }
                        let x2_var = builder.alloc_var(&x2_val);

                        builder.add_constraint(
                            &x_lc,
                            &x_lc,
                            &[(x2_var, Integer::from(1))],
                        );

                        // x3 = x2*x
                        let mut x3_val = (x2_val.clone() * x_val.clone()) % modulus;
                        if x3_val < 0 { x3_val += modulus; }
                        let x3_var = builder.alloc_var(&x3_val);

                        builder.add_constraint(
                            &[(x2_var, Integer::from(1))],
                            &x_lc,
                            &[(x3_var, Integer::from(1))],
                        );

                        // x6 = x3*x3
                        let mut x6_val = (x3_val.clone() * x3_val.clone()) % modulus;
                        if x6_val < 0 { x6_val += modulus; }
                        let x6_var = builder.alloc_var(&x6_val);

                        builder.add_constraint(
                            &[(x3_var, Integer::from(1))],
                            &[(x3_var, Integer::from(1))],
                            &[(x6_var, Integer::from(1))],
                        );

                        // x7 = x6*x
                        let mut x7_val = (x6_val.clone() * x_val.clone()) % modulus;
                        if x7_val < 0 { x7_val += modulus; }
                        let x7_var = builder.alloc_var(&x7_val);

                        builder.add_constraint(
                            &[(x6_var, Integer::from(1))],
                            &x_lc,
                            &[(x7_var, Integer::from(1))],
                        );

                        sbox_out_vals[i] = x7_val;
                        sbox_out_lcs[i] =
                            vec![(x7_var, Integer::from(1))];
                    }
                } else {
                    sbox_out_vals[i] = sp_vals[i].clone();
                    sbox_out_lcs[i] = sp_lcs[i].clone();
                }
            }

            // MDS matrix mix - pure linear combination, no constraints, no witness
            let mut next_state_vals = vec![Integer::from(0); t];
            let mut next_state_lcs: Vec<LC> = vec![Vec::new(); t];

            for i in 0..t {
                // Native value
                let mut acc = Integer::from(0);
                for j in 0..t {
                    acc += sbox_out_vals[j].clone() * m_matrix[i][j].clone();
                }
                acc %= modulus;
                if acc < 0 {
                    acc += modulus;
                }
                next_state_vals[i] = acc;

                // R1CS linear combination
                let mut acc_lc: LC = Vec::new();
                for j in 0..t {
                    let term = lc_scale(
                        &sbox_out_lcs[j],
                        &m_matrix[i][j],
                        modulus,
                    );
                    acc_lc = lc_add(&acc_lc, &term, modulus);
                }
                next_state_lcs[i] = acc_lc;
            }

            state_vals = next_state_vals;
            state_lcs = next_state_lcs;
        }

        curr_val = state_vals[0].clone();
        curr_lc = state_lcs[0].clone();
    }

    // Final constraint: 1 * curr_lc = root
    builder.add_constraint(
        &[(v_one, Integer::from(1))],
        &curr_lc,
        &[(v_root, Integer::from(1))],
    );

    let num_cons = builder.num_cons;
    let num_vars = builder.num_vars;
    let num_inputs = 2;

    let actual_one = num_vars;
    let actual_leaf = num_vars + 1;
    let actual_root = num_vars + 2;

    let remap = |v: usize| -> usize {
        if v == v_one { actual_one }
        else if v == v_leaf { actual_leaf }
        else if v == v_root { actual_root }
        else { v }
    };

    let remap_triples = |triples: &[(usize, usize, [u8; 32])]| -> Vec<(usize, usize, [u8; 32])> {
        triples.iter().map(|&(r, c, val)| (r, remap(c), val)).collect()
    };

    let a = remap_triples(&builder.a_triples);
    let b = remap_triples(&builder.b_triples);
    let c = remap_triples(&builder.c_triples);

    let inst = Instance::new(
        num_cons,
        num_vars,
        num_inputs,
        &a,
        &b,
        &c,
    ).expect("Failed to construct Spartan Instance");

    let vars = VarsAssignment::new(&builder.witness_values).expect("Failed to build VarsAssignment");

    let inputs_raw = vec![
        integer_to_bytes32(leaf),
        integer_to_bytes32(root),
    ];
    let inputs = InputsAssignment::new(&inputs_raw).expect("Failed to build InputsAssignment");

    (inst, vars, inputs, num_cons, num_vars, num_inputs)
}

pub fn synthesize_merkle_instance(depth: usize) -> (Instance, NIZKGens, usize, usize, usize) {
    let params = load_p256_poseidon_params(None)
        .expect("Failed to load and authenticate p256_poseidon_t3_params.json");
    synthesize_merkle_instance_with_params(depth, &params)
}

pub fn synthesize_merkle_instance_with_params(
    depth: usize,
    params: &P256PoseidonParams,
) -> (Instance, NIZKGens, usize, usize, usize) {
    let dummy_leaf = Integer::from(0);
    let dummy_sibs = vec![Integer::from(0); depth];
    let dummy_dirs = vec![false; depth];
    let dummy_root = Integer::from(0);
    let (inst, _, _, num_cons, num_vars, num_inputs) =
        synthesize_merkle_circuit_with_params(depth, &dummy_leaf, &dummy_sibs, &dummy_dirs, &dummy_root, params);
    let gens = NIZKGens::new(num_cons, num_vars, num_inputs);
    (inst, gens, num_cons, num_vars, num_inputs)
}

fn print_usage() {
    eprintln!(
        r#"spartan_merkle_linked - Spartan NIZK Merkle Membership Tool

USAGE:
    spartan_merkle_linked <SUBCOMMAND> [OPTIONS]

SUBCOMMANDS:
    prove               Generate a Spartan NIZK membership proof
    verify              Verify a Spartan NIZK membership proof
    generate-test-vector Generate a self-consistent deterministic test vector
    kat                 Run Poseidon P-256 KAT test vectors

PROVE OPTIONS:
    --leaf <VAL>        Public leaf integer (decimal or 0x-hex) [required]
    --root <VAL>        Public root integer (decimal or 0x-hex) [required]
    --depth <INT>       Merkle tree depth (default: 16)
    --path-file <PATH>  Private witness JSON file containing siblings & directions [required]
    --proof-out <PATH>  Output path for serialized proof package [required]
    --timing-out <PATH> Optional output path for timing JSON report

VERIFY OPTIONS:
    --leaf <VAL>        Public leaf integer (decimal or 0x-hex) [required]
    --root <VAL>        Public root integer (decimal or 0x-hex) [required]
    --depth <INT>       Merkle tree depth (default: 16)
    --proof-in <PATH>   Input path for serialized proof package [required]
    --timing-out <PATH> Optional output path for timing JSON report

GENERATE-TEST-VECTOR OPTIONS:
    --depth <INT>       Merkle tree depth (default: 16)
    --out-dir <DIR>     Output directory for generated files (default: .)
"#
    );
}

fn get_arg(args: &[String], flag: &str) -> Option<String> {
    for i in 0..args.len() {
        if args[i] == flag {
            if i + 1 < args.len() {
                return Some(args[i + 1].clone());
            }
        }
    }
    None
}

fn run_prove(args: &[String]) -> Result<(), String> {
    let leaf_str = get_arg(args, "--leaf").ok_or("Missing required argument --leaf")?;
    let root_str = get_arg(args, "--root").ok_or("Missing required argument --root")?;
    let path_file = get_arg(args, "--path-file").ok_or("Missing required argument --path-file")?;
    let proof_out = get_arg(args, "--proof-out").ok_or("Missing required argument --proof-out")?;
    let depth: usize = get_arg(args, "--depth")
        .map(|d| d.parse::<usize>().map_err(|e| format!("Invalid depth: {}", e)))
        .unwrap_or(Ok(16))?;
    let timing_out = get_arg(args, "--timing-out");

    let leaf = parse_integer(&leaf_str)?;
    let root = parse_integer(&root_str)?;

    // Read path file
    let mut file = File::open(&path_file).map_err(|e| format!("Cannot open path-file '{}': {}", path_file, e))?;
    let mut content = String::new();
    file.read_to_string(&mut content).map_err(|e| format!("Failed to read path-file: {}", e))?;
    let path_input: MerklePathInput = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse path-file JSON: {}", e))?;

    if path_input.siblings.len() != depth {
        return Err(format!(
            "Path siblings count ({}) does not match depth ({})",
            path_input.siblings.len(),
            depth
        ));
    }
    if path_input.directions.len() != depth {
        return Err(format!(
            "Path directions count ({}) does not match depth ({})",
            path_input.directions.len(),
            depth
        ));
    }

    let mut siblings = Vec::with_capacity(depth);
    for s_str in &path_input.siblings {
        siblings.push(parse_integer(s_str)?);
    }
    let directions = path_input.directions;

    println!("[PROVER] Synthesizing Merkle R1CS Circuit (Depth = {})...", depth);
    let t_synth = Instant::now();
    let (inst, vars, inputs, num_cons, num_vars, num_inputs) =
        synthesize_merkle_circuit(depth, &leaf, &siblings, &directions, &root);
    println!(
        "[PROVER] Circuit synthesized in {:.2?}: {} constraints, {} witness vars, {} public inputs",
        t_synth.elapsed(),
        num_cons,
        num_vars,
        num_inputs
    );

    let is_sat = inst.is_sat(&vars, &inputs).map_err(|e| format!("is_sat error: {:?}", e))?;
    if !is_sat {
        return Err("R1CS instance is NOT satisfied by witness! Check leaf, root, or path.".into());
    }

    let gens = NIZKGens::new(num_cons, num_vars, num_inputs);

    println!("[PROVER] Generating Spartan NIZK Proof...");
    let t_prove = Instant::now();
    let mut transcript = Transcript::new(DOMAIN_TAG);
    let proof = NIZK::prove(&inst, vars, &inputs, &gens, &mut transcript);
    let prove_duration = t_prove.elapsed();
    let prove_ms = prove_duration.as_secs_f64() * 1000.0;
    println!("[PROVER] Proof generated successfully in {:.2} ms!", prove_ms);

    let package = SpartanMerklePackage {
        proof,
        depth,
        version: VERSION.to_string(),
        profile: PROFILE.to_string(),
    };

    let serialized = bincode::serialize(&package)
        .map_err(|e| format!("Failed to serialize SpartanMerklePackage: {}", e))?;
    let proof_bytes_len = serialized.len();
    println!(
        "[PROVER] Serialized proof package: {} bytes ({:.2} KB)",
        proof_bytes_len,
        proof_bytes_len as f64 / 1024.0
    );

    if let Some(parent) = Path::new(&proof_out).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| format!("Failed to create output dir: {}", e))?;
        }
    }
    let mut out_file = File::create(&proof_out)
        .map_err(|e| format!("Failed to create proof-out file '{}': {}", proof_out, e))?;
    out_file.write_all(&serialized)
        .map_err(|e| format!("Failed to write proof package: {}", e))?;
    println!("[PROVER] Proof saved to {}", proof_out);

    if let Some(tout) = timing_out {
        let report = TimingReport {
            action: "prove".to_string(),
            depth,
            num_constraints: Some(num_cons),
            num_variables: Some(num_vars),
            prove_time_ms: Some(prove_ms),
            verify_time_ms: None,
            proof_bytes: Some(proof_bytes_len),
            success: true,
        };
        let mut tf = File::create(&tout).map_err(|e| format!("Cannot create timing file: {}", e))?;
        tf.write_all(serde_json::to_string_pretty(&report).unwrap().as_bytes())
            .map_err(|e| format!("Cannot write timing file: {}", e))?;
        println!("[PROVER] Timing report written to {}", tout);
    }

    Ok(())
}

fn run_verify(args: &[String]) -> Result<(), String> {
    if get_arg(args, "--path-file").is_some() {
        return Err("CRITICAL SECURITY ERROR: Verifier MUST NOT accept or require --path-file!".into());
    }

    let leaf_str = get_arg(args, "--leaf").ok_or("Missing required argument --leaf")?;
    let root_str = get_arg(args, "--root").ok_or("Missing required argument --root")?;
    let proof_in = get_arg(args, "--proof-in").ok_or("Missing required argument --proof-in")?;
    let depth: usize = get_arg(args, "--depth")
        .map(|d| d.parse::<usize>().map_err(|e| format!("Invalid depth: {}", e)))
        .unwrap_or(Ok(16))?;
    validate_expected_depth(depth)?;
    let timing_out = get_arg(args, "--timing-out");

    let leaf = parse_integer(&leaf_str)?;
    let root = parse_integer(&root_str)?;

    let mut file = File::open(&proof_in).map_err(|e| format!("Cannot open proof-in '{}': {}", proof_in, e))?;
    let mut serialized = Vec::new();
    file.read_to_end(&mut serialized).map_err(|e| format!("Failed to read proof-in: {}", e))?;

    let package: SpartanMerklePackage = bincode::deserialize(&serialized)
        .map_err(|e| format!("Failed to deserialize SpartanMerklePackage: {}", e))?;

    validate_package_metadata(
        &package.version,
        &package.profile,
        package.depth,
        depth,
    )?;

    println!("[VERIFIER] Synthesizing verification instance (depth = {})...", depth);
    let t_v_inst = Instant::now();
    let (v_inst, v_gens, num_cons, num_vars, num_inputs) = synthesize_merkle_instance(depth);
    println!(
        "[VERIFIER] Instance synthesized in {:.2?}: {} cons, {} vars, {} inputs",
        t_v_inst.elapsed(),
        num_cons,
        num_vars,
        num_inputs
    );

    let inputs_raw = vec![
        integer_to_bytes32(&leaf),
        integer_to_bytes32(&root),
    ];
    let inputs = InputsAssignment::new(&inputs_raw)
        .map_err(|e| format!("Failed to build InputsAssignment: {:?}", e))?;

    println!("[VERIFIER] Verifying Spartan NIZK Proof against public statement (leaf, root)...");
    let t_verify = Instant::now();
    let mut transcript = Transcript::new(DOMAIN_TAG);
    let ver_res = package.proof.verify(&v_inst, &inputs, &mut transcript, &v_gens);
    let verify_duration = t_verify.elapsed();
    let verify_ms = verify_duration.as_secs_f64() * 1000.0;

    if ver_res.is_ok() {
        println!("[VERIFIER] PROOF VERIFICATION SUCCEEDED in {:.2} ms!", verify_ms);
        println!("[VERIFIER] Cryptographic membership of leaf in Merkle tree (root) is PROVEN.");
        if let Some(tout) = timing_out {
            let report = TimingReport {
                action: "verify".to_string(),
                depth,
                num_constraints: Some(num_cons),
                num_variables: Some(num_vars),
                prove_time_ms: None,
                verify_time_ms: Some(verify_ms),
                proof_bytes: Some(serialized.len()),
                success: true,
            };
            let mut tf = File::create(&tout).map_err(|e| format!("Cannot create timing file: {}", e))?;
            tf.write_all(serde_json::to_string_pretty(&report).unwrap().as_bytes())
                .map_err(|e| format!("Cannot write timing file: {}", e))?;
        }
        Ok(())
    } else {
        eprintln!("[VERIFIER] PROOF VERIFICATION REJECTED in {:.2} ms: {:?}", verify_ms, ver_res);
        if let Some(tout) = timing_out {
            let report = TimingReport {
                action: "verify".to_string(),
                depth,
                num_constraints: Some(num_cons),
                num_variables: Some(num_vars),
                prove_time_ms: None,
                verify_time_ms: Some(verify_ms),
                proof_bytes: Some(serialized.len()),
                success: false,
            };
            let _ = File::create(&tout).and_then(|mut f| f.write_all(serde_json::to_string_pretty(&report).unwrap().as_bytes()));
        }
        Err("Verification failed: cryptographic proof is invalid for statement (leaf, root)".into())
    }
}

fn validate_expected_depth(depth: usize) -> Result<(), String> {
    if depth > MAX_MERKLE_DEPTH {
        return Err(format!(
            "Expected Merkle depth ({}) exceeds the supported maximum ({})",
            depth, MAX_MERKLE_DEPTH
        ));
    }
    Ok(())
}

fn validate_package_metadata(
    version: &str,
    profile: &str,
    package_depth: usize,
    expected_depth: usize,
) -> Result<(), String> {
    if version != VERSION {
        return Err(format!(
            "Unsupported Spartan package version '{}' (expected '{}')",
            version, VERSION
        ));
    }
    if profile != PROFILE {
        return Err(format!(
            "Unsupported Spartan package profile '{}' (expected '{}')",
            profile, PROFILE
        ));
    }
    if package_depth != expected_depth {
        return Err(format!(
            "Package depth ({}) does not match expected depth ({})",
            package_depth, expected_depth
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_metadata_accepts_matching_header() {
        assert!(validate_package_metadata(VERSION, PROFILE, 16, 16).is_ok());
    }

    #[test]
    fn package_metadata_rejects_wrong_version() {
        assert!(validate_package_metadata("2.0.0", PROFILE, 16, 16).is_err());
    }

    #[test]
    fn package_metadata_rejects_wrong_profile() {
        assert!(validate_package_metadata(VERSION, "wrong-profile", 16, 16).is_err());
    }

    #[test]
    fn package_metadata_rejects_depth_mismatch() {
        assert!(validate_package_metadata(VERSION, PROFILE, 17, 16).is_err());
    }

    #[test]
    fn expected_depth_rejects_excessive_workload() {
        assert!(validate_expected_depth(MAX_MERKLE_DEPTH).is_ok());
        assert!(validate_expected_depth(MAX_MERKLE_DEPTH + 1).is_err());
    }
}

fn run_generate_test_vector(args: &[String]) -> Result<(), String> {
    let depth: usize = get_arg(args, "--depth")
        .map(|d| d.parse::<usize>().map_err(|e| format!("Invalid depth: {}", e)))
        .unwrap_or(Ok(16))?;
    let out_dir = get_arg(args, "--out-dir").unwrap_or(".".to_string());

    let params = load_p256_poseidon_params(None)
        .map_err(|e| format!("Failed to load params: {}", e))?;

    let leaf = if let Some(s) = get_arg(args, "--leaf") {
        parse_integer(&s)?
    } else {
        Integer::from(9876543210123456789u64)
    };
    let mut siblings = Vec::with_capacity(depth);
    let mut directions = Vec::with_capacity(depth);

    let mut curr = leaf.clone();
    for d in 0..depth {
        let sib = Integer::from(1000000007u64 + (d as u64) * 7919);
        let dir = (d % 2) == 0;
        siblings.push(sib.clone());
        directions.push(dir);
        let (l, r) = if dir { (curr.clone(), sib) } else { (sib, curr.clone()) };
        curr = poseidon_p256_hash(&l, &r, &params);
    }
    let honest_root = curr;

    std::fs::create_dir_all(&out_dir).map_err(|e| format!("Cannot create out-dir: {}", e))?;

    let path_input = MerklePathInput {
        siblings: siblings.iter().map(|s| s.to_string()).collect(),
        directions,
    };
    let priv_path = format!("{}/private_path_{}.json", out_dir, depth);
    let _ = File::create(&priv_path).and_then(|mut f| f.write_all(serde_json::to_string_pretty(&path_input).unwrap().as_bytes()));
    let priv_path = format!("{}/private_path_{}.json", out_dir, depth);
    let _ = File::create(&priv_path).and_then(|mut f| f.write_all(serde_json::to_string_pretty(&path_input).unwrap().as_bytes()));
    let path_path = format!("{}/test_path_{}.json", out_dir, depth);
    let mut pf = File::create(&path_path).map_err(|e| format!("Cannot create path file: {}", e))?;
    pf.write_all(serde_json::to_string_pretty(&path_input).unwrap().as_bytes())
        .map_err(|e| format!("Cannot write path file: {}", e))?;

    let stmt = MerkleStatement {
        leaf: leaf.to_string(),
        root: honest_root.to_string(),
        depth,
    };
    let trust_path = format!("{}/trusted_statement_{}.json", out_dir, depth);
    let _ = File::create(&trust_path).and_then(|mut f| f.write_all(serde_json::to_string_pretty(&stmt).unwrap().as_bytes()));
    let trust_path = format!("{}/trusted_statement_{}.json", out_dir, depth);
    let _ = File::create(&trust_path).and_then(|mut f| f.write_all(serde_json::to_string_pretty(&stmt).unwrap().as_bytes()));
    let stmt_path = format!("{}/test_statement_{}.json", out_dir, depth);
    let mut sf = File::create(&stmt_path).map_err(|e| format!("Cannot create stmt file: {}", e))?;
    sf.write_all(serde_json::to_string_pretty(&stmt).unwrap().as_bytes())
        .map_err(|e| format!("Cannot write stmt file: {}", e))?;

    println!("[TEST-VECTOR] Generated test vector for depth = {}:", depth);
    println!("  Leaf: {}", leaf);
    println!("  Root: {}", honest_root);
    println!("  Saved path to: {}", path_path);
    println!("  Saved statement to: {}", stmt_path);

    Ok(())
}

fn main() {
    // Ensure Poseidon constants can be loaded even if invoked from outside repo
    let zok_rel = "./third_party/ZoKrates/zokrates_stdlib/stdlib/hashes/poseidon/constants.zok";
    if !std::path::Path::new(zok_rel).exists() {
        if let Ok(exe_path) = std::env::current_exe() {
            let mut curr = exe_path.clone();
            for _ in 0..5 {
                if curr.join("third_party/ZoKrates").exists() {
                    let _ = std::env::set_current_dir(&curr);
                    break;
                }
                if !curr.pop() { break; }
            }
        }
        if !std::path::Path::new(zok_rel).exists() && std::path::Path::new("/root/autodl-tmp/sigpop").exists() {
            let _ = std::env::set_current_dir("/root/autodl-tmp/sigpop");
        }
    }

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage();
        std::process::exit(1);
    }

    let subcommand = args[1].as_str();
    let sub_args = &args[2..];

    let result = match subcommand {
        "prove" => run_prove(sub_args),
        "verify" => run_verify(sub_args),
        "generate-test-vector" => run_generate_test_vector(sub_args),
        "kat" => {
            if run_poseidon_kat() {
                std::process::exit(0);
            } else {
                std::process::exit(1);
            }
        },
        "-h" | "--help" | "help" => {
            print_usage();
            std::process::exit(0);
        }
        other => Err(format!("Unknown subcommand: '{}'. Run --help for usage.", other)),
    };

    if let Err(e) = result {
        eprintln!("ERROR: {}", e);
        std::process::exit(1);
    }
}

#[cfg(test)]
mod authenticated_parameter_tests {
    use super::*;

    #[test]
    fn poseidon_parameter_file_fingerprint_is_recomputed_and_matches() {
        let params = load_p256_poseidon_params(None).unwrap();
        assert_eq!(params.name, PROFILE);
        assert_eq!(params.parameter_sha256, "fe39b46ac826db30c41db8bceda953a93e231ec10ca2b2e737995974f63c7d00");
    }
}
