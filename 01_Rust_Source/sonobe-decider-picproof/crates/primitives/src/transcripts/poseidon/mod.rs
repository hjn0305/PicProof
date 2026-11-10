//! Poseidon-based transcript configurations and implementations.

use ark_crypto_primitives::sponge::poseidon::{PoseidonConfig, find_poseidon_ark_and_mds};
use ark_ff::{One, PrimeField};
use num_bigint::BigUint;
use num_integer::Integer;

pub mod sponge;

fn log2_order<F: PrimeField>() -> f64 {
    let x = F::MODULUS.into();
    let bits = x.bits(); // bit length
    if bits <= 53 {
        // Fits in f64 mantissa exactly
        let val: u64 = x.try_into().unwrap();
        return (val as f64).log2();
    }
    // Shift right so only top ~53 bits remain
    let shift = bits - 53;
    let top = x >> shift;
    let top_u64: u64 = top.try_into().unwrap();
    (top_u64 as f64).log2() + shift as f64
}

fn sat_inequiv_alpha<F: PrimeField>(t: usize, r_f: u64, r_p: u64, alpha: u64, m: usize) -> bool {
    let log2_p = log2_order::<F>();
    let n = log2_p.ceil() as usize;
    let m_f = m as f64;
    let n_f = n as f64;
    let t_f = t as f64;
    let r_p_f = r_p as f64;
    let r_f_f = r_f as f64;
    let alpha_f = alpha as f64;
    let log2_alpha = 2.0f64.ln() / alpha_f.ln();

    let r_f_1: f64 = if m_f <= (log2_p - (alpha_f - 1.0) / 2.0).floor() * (t_f + 1.0) {
        6.0
    } else {
        10.0
    };

    let r_f_2 = 1.0 + log2_alpha * m_f.min(n_f) + (t_f.ln() / alpha_f.ln()).ceil() - r_p_f;

    let r_f_3 = 1.0 + log2_alpha * (m_f / 3.0).min(log2_p / 2.0) - r_p_f;

    let r_f_4 = t_f - 1.0 + (log2_alpha * m_f / (t_f + 1.0)).min(log2_alpha * log2_p / 2.0) - r_p_f;

    let r_f_max = r_f_1
        .ceil()
        .max(r_f_2.ceil())
        .max(r_f_3.ceil())
        .max(r_f_4.ceil());

    r_f_f >= r_f_max
}

fn get_sbox_cost(r_f: u64, r_p: u64, _n: usize, t: usize) -> usize {
    t * r_f as usize + r_p as usize
}

fn find_fd_round_numbers<F: PrimeField>(
    t: usize,
    alpha: u64,
    m: usize,
    cost_function: fn(u64, u64, usize, usize) -> usize,
    security_margin: bool,
) -> (u64, u64) {
    let n = log2_order::<F>().ceil() as usize;
    let n_total = n * t;

    let mut r_p: u64 = 0;
    let mut r_f: u64 = 0;
    let mut min_cost = usize::MAX;
    let mut max_cost_rf: u64 = 0;

    for r_p_t in 1u64..500 {
        for r_f_t in (4u64..100).step_by(2) {
            if !sat_inequiv_alpha::<F>(t, r_f_t, r_p_t, alpha, m) {
                continue;
            }

            let (r_f_eff, r_p_eff) = if security_margin {
                (r_f_t + 2, (r_p_t as f64 * 1.075).ceil() as u64)
            } else {
                (r_f_t, r_p_t)
            };

            let cost = cost_function(r_f_eff, r_p_eff, n_total, t);
            if cost < min_cost || (cost == min_cost && r_f_eff < max_cost_rf) {
                r_p = r_p_eff;
                r_f = r_f_eff;
                min_cost = cost;
                max_cost_rf = r_f;
            }
        }
    }

    assert_ne!(min_cost, usize::MAX);

    (r_f, r_p)
}

/// [`poseidon_paper_config`] produces a Poseidon configuration which agrees
/// with the paper's reference implementation.
///
/// TODO(@winderica): alpha = -1 is not supported yet.
pub fn poseidon_paper_config<F: PrimeField, const SECURITY_BITS: usize>(
    alpha: u64,
    rate: usize,
) -> PoseidonConfig<F> {
    assert_ne!(alpha, 1);
    assert_eq!(
        BigUint::from(alpha).gcd(&(-F::one()).into()),
        BigUint::one()
    );
    let (full_rounds, partial_rounds) =
        find_fd_round_numbers::<F>(rate + 1, alpha, SECURITY_BITS, get_sbox_cost, true);
    let (ark, mds) = find_poseidon_ark_and_mds(
        F::MODULUS_BIT_SIZE as u64,
        rate,
        full_rounds,
        partial_rounds,
        0,
    );

    PoseidonConfig::new(
        full_rounds as usize,
        partial_rounds as usize,
        alpha,
        mds,
        ark,
        rate,
        1,
    )
}

/// [`poseidon_circom_config`] produces a Poseidon configuration for BN254's
/// scalar field that agrees with Circom's Poseidon(4).
pub fn poseidon_circom_config() -> PoseidonConfig<ark_bn254::Fr> {
    // 120 bit security target as in
    // https://eprint.iacr.org/2019/458.pdf
    // t = rate + 1

    let full_rounds = 8;
    let partial_rounds = 60;
    let alpha = 5;
    let rate = 4;

    let (ark, mds) = find_poseidon_ark_and_mds(
        ark_bn254::Fr::MODULUS_BIT_SIZE as u64,
        rate,
        full_rounds as u64,
        partial_rounds as u64,
        0,
    );

    PoseidonConfig::new(full_rounds, partial_rounds, alpha, mds, ark, rate, 1)
}
