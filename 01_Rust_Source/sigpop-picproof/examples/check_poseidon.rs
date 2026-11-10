use circ::target::r1cs::spartan::t256::MOD_T256;
use rug::Integer;
use circ::commitment::poseidon_const::{POSEIDON_C, POSEIDON_M};

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

pub fn poseidon_hash_mod(inputs: Vec<Integer>, modulus: &Integer) -> Integer {
    let n: usize = inputs.len();
    let t = n + 1;
    let rounds_p: Vec<usize> = vec![56, 57, 56, 60, 60, 63, 64, 63];
    let f = 8;
    let p = rounds_p[t - 2];
    let c: Vec<Integer> = POSEIDON_C[t - 2].to_vec();
    let m: Vec<Vec<Integer>> = POSEIDON_M[t - 2].to_vec();

    let mut state = vec![Integer::new(); t];
    for i in 1..t {
        state[i] = inputs[i - 1].clone() % modulus.clone();
    }
    for r in 0..f + p {
        ark_mod(&mut state, &c, r * t, modulus);
        sbox_mod(&mut state, f, p, r, modulus);
        state = mix_mod(&state, &m, modulus);
    }
    state[0].clone()
}

fn main() {
    let a = Integer::from(12345);
    let b = Integer::from(67890);
    let hash_t256 = poseidon_hash_mod(vec![a.clone(), b.clone()], &MOD_T256);
    println!("Rust Poseidon mod T256: {}", hash_t256);

    use circ::target::r1cs::spartan::utils::read_simpl_prover_data;
    use fxhash::FxHashMap as HashMap;
    use circ::ir::term::Value;
    use circ::right_field_arithmetic::alloc::map_field;
    use circ::right_field_arithmetic::field::ARC_MOD_T256;

    let pd = read_simpl_prover_data("/tmp/P_test").expect("load P_test");
    let mut map = HashMap::<String, Value>::default();
    map_field(&a, &ARC_MOD_T256, "a", &mut map);
    map_field(&b, &ARC_MOD_T256, "b", &mut map);
    let vals = pd.extend_r1cs_witness(&map);
    println!("Witness extended, total values: {}", vals.len());
    for (i, v) in vals.iter().enumerate() {
        if i < 5 {
            println!("Val[{}]: {:?}", i, v);
        }
    }
}
