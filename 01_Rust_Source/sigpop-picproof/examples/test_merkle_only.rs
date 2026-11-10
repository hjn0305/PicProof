use circ::cfg::{clap::{self, Parser}, CircOpt};
use std::time::Instant;
use rug::Integer;
use fxhash::FxHashMap as HashMap;
use circ::ir::term::Value;
use circ::convert::bool_to_value;
use circ::create_input::PfCurve;
use circ::target::r1cs::spartan::spartan;
use circ::commitment::commitment::poseidon_hash;
use circ::right_field_arithmetic::alloc::{map_field, map_field_vec};
use circ::right_field_arithmetic::field::ARC_MOD_T256;
use circ::allocate::map_bool_arr;

#[derive(Debug, Parser)]
struct Opts {
    #[command(flatten)]
    circ: CircOpt,
}

fn main() {
    let opts = Opts::parse();
    circ::cfg::set(&opts.circ);

    println!(Testing Poseidon Merkle Alone...);
    let leaf = poseidon_hash(vec![Integer::from(12345), Integer::from(67890)]);
    println!(Leaf: {}, leaf);

    let mut curr = leaf.clone();
    let mut siblings = vec![];
    let mut directions = vec![];
    for i in 0..4 {
        let sib = poseidon_hash(vec![Integer::from(i*100+1), Integer::from(i*100+2)]);
        siblings.push(sib.clone());
        let dir = true; // left
        directions.push(dir);
        curr = poseidon_hash(vec![curr, sib]);
    }
    let root = curr;
    println!(Root: {}, root);

    let mut p_map = HashMap::<String, Value>::default();
    map_field(&root, &ARC_MOD_T256, expected_root, &mut p_map);
    map_field(&leaf, &ARC_MOD_T256, leaf, &mut p_map);
    map_field_vec(&siblings, &ARC_MOD_T256, siblings, &mut p_map);
    map_bool_arr(&directions, directions, &mut p_map);
    p_map.insert(return.to_string(), bool_to_value(true));

    let mut v_map = HashMap::<String, Value>::default();
    map_field(&root, &ARC_MOD_T256, expected_root, &mut v_map);
    v_map.insert(return.to_string(), bool_to_value(true));

    println!(Inputs mapped: {} prover, {} verifier, p_map.len(), v_map.len());
}
