use ark_ff::BigInteger;
use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::{GR1CSVar, fields::fp::FpVar, uint32::UInt32};
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use core::ops::Not;
use sonobe_primitives::algebra::field::SonobeField;
use sonobe_primitives::circuits::FCircuit;
use sonobe_primitives::circuits::SigmabusFinalBinding;

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Returns the standard SHA-256 initial state IV as field elements.
pub fn sha256_initial_state<F: PrimeField>() -> [F; 8] {
    IV.map(F::from)
}

/// Reconstructs the 8-word SHA-256 state from Sigmabus (h_hi, h_lo) integers.
pub fn reconstruct_sha256_state<F: PrimeField>(h_hi: u128, h_lo: u128) -> [F; 8] {
    [
        F::from(((h_hi >> 96) & 0xffff_ffff) as u64),
        F::from(((h_hi >> 64) & 0xffff_ffff) as u64),
        F::from(((h_hi >> 32) & 0xffff_ffff) as u64),
        F::from((h_hi & 0xffff_ffff) as u64),
        F::from(((h_lo >> 96) & 0xffff_ffff) as u64),
        F::from(((h_lo >> 64) & 0xffff_ffff) as u64),
        F::from(((h_lo >> 32) & 0xffff_ffff) as u64),
        F::from((h_lo & 0xffff_ffff) as u64),
    ]
}

/// Reconstructs the Sigmabus binding from num_blocks and (h_hi, h_lo) integers.
pub fn reconstruct_sigmabus_binding<F: PrimeField>(
    num_blocks: usize,
    h_hi: u128,
    h_lo: u128,
) -> SigmabusFinalBinding<F> {
    SigmabusFinalBinding {
        num_blocks,
        h_hi: F::from(h_hi),
        h_lo: F::from(h_lo),
    }
}

fn ch<F: PrimeField>(x: &UInt32<F>, y: &UInt32<F>, z: &UInt32<F>) -> UInt32<F> {
    (x & y) ^ (&x.not() & z)
}
fn maj<F: PrimeField>(x: &UInt32<F>, y: &UInt32<F>, z: &UInt32<F>) -> UInt32<F> {
    (x & y) ^ (x & z) ^ (y & z)
}
fn bs0<F: PrimeField>(x: &UInt32<F>) -> UInt32<F> {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}
fn bs1<F: PrimeField>(x: &UInt32<F>) -> UInt32<F> {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}
fn ss0<F: PrimeField>(x: &UInt32<F>) -> UInt32<F> {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3u32)
}
fn ss1<F: PrimeField>(x: &UInt32<F>) -> UInt32<F> {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10u32)
}

pub fn compress_vars<F: PrimeField>(
    block: [UInt32<F>; 16],
    state: [UInt32<F>; 8],
) -> Result<[UInt32<F>; 8], SynthesisError> {
    let mut w = Vec::from(block);
    for t in 16..64 {
        w.push(UInt32::wrapping_add_many(&[
            w[t - 16].clone(),
            ss0(&w[t - 15]),
            w[t - 7].clone(),
            ss1(&w[t - 2]),
        ])?);
    }
    let mut a = state[0].clone();
    let mut b = state[1].clone();
    let mut c = state[2].clone();
    let mut d = state[3].clone();
    let mut e = state[4].clone();
    let mut f = state[5].clone();
    let mut g = state[6].clone();
    let mut h = state[7].clone();
    for t in 0..64 {
        let t1 = UInt32::wrapping_add_many(&[
            h.clone(),
            bs1(&e),
            ch(&e, &f, &g),
            UInt32::constant(K[t]),
            w[t].clone(),
        ])?;
        let t2 = UInt32::wrapping_add_many(&[bs0(&a), maj(&a, &b, &c)])?;
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(&t1);
        d = c;
        c = b;
        b = a;
        a = UInt32::wrapping_add_many(&[t1, t2])?;
    }
    Ok([
        UInt32::wrapping_add_many(&[a, state[0].clone()])?,
        UInt32::wrapping_add_many(&[b, state[1].clone()])?,
        UInt32::wrapping_add_many(&[c, state[2].clone()])?,
        UInt32::wrapping_add_many(&[d, state[3].clone()])?,
        UInt32::wrapping_add_many(&[e, state[4].clone()])?,
        UInt32::wrapping_add_many(&[f, state[5].clone()])?,
        UInt32::wrapping_add_many(&[g, state[6].clone()])?,
        UInt32::wrapping_add_many(&[h, state[7].clone()])?,
    ])
}

pub fn compress<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    block: [u32; 16],
    state: [u32; 8],
) -> Result<[UInt32<F>; 8], SynthesisError> {
    let words: [UInt32<F>; 16] = UInt32::new_witness_vec(cs, &block)?.try_into().unwrap();
    compress_vars(words, state.map(UInt32::constant))
}

fn words_to_u128(words: &[u32; 4]) -> u128 {
    ((words[0] as u128) << 96)
        | ((words[1] as u128) << 64)
        | ((words[2] as u128) << 32)
        | (words[3] as u128)
}

fn field_word_to_u32<F: PrimeField>(word: &F) -> u32 {
    let bytes = word.into_bigint().to_bytes_le();
    u32::from_le_bytes(bytes[..4].try_into().unwrap())
}

pub fn split_state_to_field_values<F: PrimeField>(
    state: &[UInt32<F>; 8],
) -> Result<(FpVar<F>, FpVar<F>), SynthesisError> {
    let words = state
        .iter()
        .map(UInt32::to_fp)
        .collect::<Result<Vec<_>, _>>()?;
    let two_32 = F::from(1u64 << 32);
    let two_64 = two_32 * two_32;
    let two_96 = two_64 * two_32;
    let h_hi = words[0].clone() * two_96
        + words[1].clone() * two_64
        + words[2].clone() * two_32
        + words[3].clone();
    let h_lo = words[4].clone() * two_96
        + words[5].clone() * two_64
        + words[6].clone() * two_32
        + words[7].clone();
    Ok((h_hi, h_lo))
}

pub fn sha256_sigmabus_final_binding<F: PrimeField>(
    num_blocks: usize,
    state: &[F; 8],
) -> Option<SigmabusFinalBinding<F>> {
    let words = state.iter().map(field_word_to_u32).collect::<Vec<_>>();
    let h_hi = words_to_u128(&words[0..4].try_into().unwrap());
    let h_lo = words_to_u128(&words[4..8].try_into().unwrap());
    Some(SigmabusFinalBinding {
        num_blocks,
        h_hi: F::from(h_hi),
        h_lo: F::from(h_lo),
    })
}

pub struct Sha256CompressionCircuit<F: SonobeField>(core::marker::PhantomData<F>);

impl<F: SonobeField> Default for Sha256CompressionCircuit<F> {
    fn default() -> Self {
        Self(core::marker::PhantomData)
    }
}

impl<F: SonobeField> FCircuit for Sha256CompressionCircuit<F> {
    type Field = F;
    type State = [F; 8];
    type StateVar = [FpVar<F>; 8];
    type ExternalInputs = [u32; 16];
    type ExternalOutputs = ();

    fn same_state_shape(_a: &Self::State, _b: &Self::State) -> bool {
        true
    }
    fn sigmabus_final_binding(i: usize, state: &Self::State) -> Option<SigmabusFinalBinding<F>> {
        sha256_sigmabus_final_binding(i, state)
    }

    fn enforce_sigmabus_final_binding(
        cs: ConstraintSystemRef<F>,
        i: &FpVar<F>,
        state: &Self::StateVar,
        binding: &Option<SigmabusFinalBinding<F>>,
    ) -> Result<(), SynthesisError> {
        let Some(SigmabusFinalBinding {
            num_blocks,
            h_hi,
            h_lo,
        }) = binding
        else {
            return Ok(());
        };
        let expected_n = FpVar::new_input(cs.clone(), || Ok(F::from(*num_blocks as u64)))?;
        let expected_h_hi = FpVar::new_input(cs.clone(), || Ok(*h_hi))?;
        let expected_h_lo = FpVar::new_input(cs.clone(), || Ok(*h_lo))?;
        i.enforce_equal(&expected_n)?;
        let state_words: [UInt32<F>; 8] = state
            .clone()
            .map(|word| UInt32::from_fp(&word).map(|(u, _)| u))
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| SynthesisError::Unsatisfiable)?;
        let (reconstructed_h_hi, reconstructed_h_lo) = split_state_to_field_values(&state_words)?;
        reconstructed_h_hi.enforce_equal(&expected_h_hi)?;
        reconstructed_h_lo.enforce_equal(&expected_h_lo)?;
        Ok(())
    }
    fn dummy_state(&self) -> Self::State {
        IV.map(F::from)
    }
    fn dummy_external_inputs(&self) -> Self::ExternalInputs {
        [0; 16]
    }

    fn synthesize_step(
        &self,
        _i: FpVar<F>,
        z_i: Self::StateVar,
        block: Self::ExternalInputs,
    ) -> Result<(Self::StateVar, Self::ExternalOutputs), SynthesisError> {
        let cs = z_i[0].cs();
        let words: [UInt32<F>; 16] = UInt32::new_witness_vec(cs, &block)?.try_into().unwrap();
        let state: [UInt32<F>; 8] = z_i
            .map(|word| UInt32::from_fp(&word).map(|(u, _)| u))
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .unwrap();
        let output = compress_vars(words, state)?;
        Ok((
            output
                .map(|word| word.to_fp())
                .into_iter()
                .collect::<Result<Vec<_>, _>>()?
                .try_into()
                .unwrap(),
            (),
        ))
    }
}

#[cfg(test)]
mod p256_tests {
    #[cfg(test)]
    mod sigmabus_tests {
        use ark_bn254::Fr;
        use ark_r1cs_std::alloc::AllocVar;
        use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystem};
        use ark_std::error::Error;

        use super::super::{Sha256CompressionCircuit, sha256_sigmabus_final_binding};
        use sonobe_primitives::circuits::{FCircuit, SigmabusFinalBinding};

        struct SigmabusBindingCircuit {
            i: usize,
            state: [Fr; 8],
            binding: Option<SigmabusFinalBinding<Fr>>,
        }

        impl ConstraintSynthesizer<Fr> for SigmabusBindingCircuit {
            fn generate_constraints(
                self,
                cs: ark_relations::gr1cs::ConstraintSystemRef<Fr>,
            ) -> Result<(), ark_relations::gr1cs::SynthesisError> {
                let i = ark_r1cs_std::fields::fp::FpVar::new_input(cs.clone(), || {
                    Ok(Fr::from(self.i as u64))
                })?;
                let state =
                    <[ark_r1cs_std::fields::fp::FpVar<Fr>; 8] as AllocVar<[Fr; 8], Fr>>::new_input(
                        cs.clone(),
                        || Ok(self.state),
                    )?;
                Sha256CompressionCircuit::<Fr>::enforce_sigmabus_final_binding(
                    cs,
                    &i,
                    &state,
                    &self.binding,
                )
            }
        }

        fn final_state() -> [Fr; 8] {
            [1, 2, 3, 4, 5, 6, 7, 8].map(Fr::from)
        }

        #[test]
        fn sigmabus_final_binding_satisfied() -> Result<(), Box<dyn Error>> {
            let state = final_state();
            let binding = sha256_sigmabus_final_binding(2, &state);
            let circuit = SigmabusBindingCircuit {
                i: 2,
                state,
                binding,
            };
            let cs = ConstraintSystem::new_ref();
            circuit.generate_constraints(cs.clone())?;
            assert!(cs.is_satisfied()?);
            Ok(())
        }

        #[test]
        fn sigmabus_rejects_truncated_intermediate_state() -> Result<(), Box<dyn Error>> {
            let state = final_state();
            let binding = sha256_sigmabus_final_binding(2, &state);
            let circuit = SigmabusBindingCircuit {
                i: 1,
                state,
                binding,
            };
            let cs = ConstraintSystem::new_ref();
            circuit.generate_constraints(cs.clone())?;
            assert!(!cs.is_satisfied()?);
            Ok(())
        }

        #[test]
        fn sigmabus_rejects_tampered_h_hi() -> Result<(), Box<dyn Error>> {
            let state = final_state();
            let mut binding = sha256_sigmabus_final_binding(2, &state).unwrap();
            binding.h_hi += Fr::from(1u64);
            let circuit = SigmabusBindingCircuit {
                i: 2,
                state,
                binding: Some(binding),
            };
            let cs = ConstraintSystem::new_ref();
            circuit.generate_constraints(cs.clone())?;
            assert!(!cs.is_satisfied()?);
            Ok(())
        }
    }

    #[cfg(test)]
    use ark_bn254::Fr;
    use ark_relations::gr1cs::ConstraintSystem;
    #[test]
    fn p256_private_scalar_mult_173g_8bit_chain() {
        use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
        use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField};
        use ark_r1cs_std::{
            GR1CSVar, alloc::AllocVar, boolean::Boolean, eq::EqGadget, select::CondSelectGadget,
        };
        use ark_secp256r1::{Fq as P256Fq, Fr as P256Fr, Projective as P256Projective};
        use num_bigint::BigInt;
        use sonobe_primitives::algebra::{
            field::emulated::{Bounds, EmulatedFieldVar},
            group::emulated::EmulatedAffineVar,
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        let g = P256Projective::generator();
        let scalar_native = P256Fr::from(173u64);
        let bit_values = [true, false, true, true, false, true, false, true];
        let bits = bit_values
            .iter()
            .map(|&v| Boolean::new_witness(cs.clone(), || Ok(v)).unwrap())
            .collect::<Vec<_>>();
        let scalar = EmulatedFieldVar::<Fr, P256Fr>::from_bounded_bits_le(
            &bits,
            Bounds(BigInt::from(0u64), BigInt::from(255u64)),
        )
        .unwrap();
        scalar
            .enforce_equal_unaligned(&EmulatedFieldVar::<Fr, P256Fr>::constant(BigInt::from(
                scalar_native.into_bigint(),
            )))
            .unwrap();

        let constrain_add = |p: P256Projective, q: P256Projective, out: P256Projective| {
            let (x1, y1) = p.into_affine().xy().unwrap();
            let (x2, y2) = q.into_affine().xy().unwrap();
            let (x3, y3) = out.into_affine().xy().unwrap();
            let x1v = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(x1)).unwrap();
            let y1v = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(y1)).unwrap();
            let x2v = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(x2)).unwrap();
            let y2v = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(y2)).unwrap();
            let x3v = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(x3)).unwrap();
            let y3v = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(y3)).unwrap();
            let lambda = (y2 - y1) * (x2 - x1).inverse().unwrap();
            let lv =
                EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(lambda)).unwrap();
            lv.mul_unaligned(&x2v.sub_unaligned(&x1v).unwrap().modulo().unwrap())
                .unwrap()
                .modulo()
                .unwrap()
                .enforce_equal_unaligned(&y2v.sub_unaligned(&y1v).unwrap().modulo().unwrap())
                .unwrap();
            lv.mul_unaligned(&lv)
                .unwrap()
                .modulo()
                .unwrap()
                .sub_unaligned(&x1v)
                .unwrap()
                .sub_unaligned(&x2v)
                .unwrap()
                .modulo()
                .unwrap()
                .enforce_equal_unaligned(&x3v)
                .unwrap();
            lv.mul_unaligned(&x1v.sub_unaligned(&x3v).unwrap().modulo().unwrap())
                .unwrap()
                .sub_unaligned(&y1v)
                .unwrap()
                .modulo()
                .unwrap()
                .enforce_equal_unaligned(&y3v)
                .unwrap();
        };
        let mut acc = g;
        let constrain_double = |p: P256Projective, out: P256Projective| {
            let (x, y) = p.into_affine().xy().unwrap();
            let (xo, yo) = out.into_affine().xy().unwrap();
            let xv = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(x)).unwrap();
            let yv = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(y)).unwrap();
            let xov = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(xo)).unwrap();
            let yov = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(yo)).unwrap();
            let three_x2 = xv
                .mul_unaligned(&xv)
                .unwrap()
                .modulo()
                .unwrap()
                .mul_unaligned(&EmulatedFieldVar::<Fr, P256Fq>::constant(BigInt::from(
                    P256Fq::from(3u64).into_bigint(),
                )))
                .unwrap()
                .modulo()
                .unwrap();
            let num = three_x2
                .sub_unaligned(&EmulatedFieldVar::<Fr, P256Fq>::constant(BigInt::from(
                    P256Fq::from(3u64).into_bigint(),
                )))
                .unwrap()
                .modulo()
                .unwrap();
            let den = yv
                .mul_unaligned(&EmulatedFieldVar::<Fr, P256Fq>::constant(BigInt::from(
                    P256Fq::from(2u64).into_bigint(),
                )))
                .unwrap()
                .modulo()
                .unwrap();
            let inv = den.value().unwrap().inverse().unwrap();
            let iv = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(inv)).unwrap();
            iv.mul_unaligned(&den)
                .unwrap()
                .modulo()
                .unwrap()
                .enforce_equal_unaligned(&EmulatedFieldVar::<Fr, P256Fq>::constant(BigInt::from(
                    P256Fq::from(1u64).into_bigint(),
                )))
                .unwrap();
            let slope = num.mul_unaligned(&iv).unwrap().modulo().unwrap();
            slope
                .mul_unaligned(&slope)
                .unwrap()
                .modulo()
                .unwrap()
                .sub_unaligned(&xv)
                .unwrap()
                .sub_unaligned(&xv)
                .unwrap()
                .modulo()
                .unwrap()
                .enforce_equal_unaligned(&xov)
                .unwrap();
            slope
                .mul_unaligned(&xv.sub_unaligned(&xov).unwrap().modulo().unwrap())
                .unwrap()
                .sub_unaligned(&yv)
                .unwrap()
                .modulo()
                .unwrap()
                .enforce_equal_unaligned(&yov)
                .unwrap();
        };
        for bit_index in (0..7).rev() {
            let doubled = acc.double();
            let added = doubled + g;
            constrain_double(acc, doubled);
            constrain_add(doubled, g, added);
            let dv =
                EmulatedAffineVar::<Fr, P256Projective>::new_witness(cs.clone(), || Ok(doubled))
                    .unwrap();
            let av = EmulatedAffineVar::<Fr, P256Projective>::new_witness(cs.clone(), || Ok(added))
                .unwrap();
            let selected =
                EmulatedAffineVar::conditionally_select(&bits[bit_index], &av, &dv).unwrap();
            let next = if bit_values[bit_index] {
                added
            } else {
                doubled
            };
            let nv = EmulatedAffineVar::<Fr, P256Projective>::new_witness(cs.clone(), || Ok(next))
                .unwrap();
            selected.enforce_equal(&nv).unwrap();
            acc = next;
        }
        let expected = g.mul_bigint(scalar_native.into_bigint());
        let av =
            EmulatedAffineVar::<Fr, P256Projective>::new_witness(cs.clone(), || Ok(acc)).unwrap();
        let ev = EmulatedAffineVar::<Fr, P256Projective>::new_witness(cs.clone(), || Ok(expected))
            .unwrap();
        av.enforce_equal(&ev).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }
    #[test]
    fn p256_private_scalar_mult_173g_8bit_chain_negative() {
        use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
        use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField};
        use ark_r1cs_std::{
            GR1CSVar, alloc::AllocVar, boolean::Boolean, eq::EqGadget, select::CondSelectGadget,
        };
        use ark_secp256r1::{Fq as P256Fq, Fr as P256Fr, Projective as P256Projective};
        use num_bigint::BigInt;
        use sonobe_primitives::algebra::{
            field::emulated::{Bounds, EmulatedFieldVar},
            group::emulated::EmulatedAffineVar,
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        let g = P256Projective::generator();
        let scalar_native = P256Fr::from(172u64);
        let bit_values = [true, false, true, true, false, true, true, false];
        let bits = bit_values
            .iter()
            .map(|&v| Boolean::new_witness(cs.clone(), || Ok(v)).unwrap())
            .collect::<Vec<_>>();
        let scalar = EmulatedFieldVar::<Fr, P256Fr>::from_bounded_bits_le(
            &bits,
            Bounds(BigInt::from(0u64), BigInt::from(255u64)),
        )
        .unwrap();
        scalar
            .enforce_equal_unaligned(&EmulatedFieldVar::<Fr, P256Fr>::constant(BigInt::from(
                scalar_native.into_bigint(),
            )))
            .unwrap();

        let constrain_add = |p: P256Projective, q: P256Projective, out: P256Projective| {
            let (x1, y1) = p.into_affine().xy().unwrap();
            let (x2, y2) = q.into_affine().xy().unwrap();
            let (x3, y3) = out.into_affine().xy().unwrap();
            let x1v = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(x1)).unwrap();
            let y1v = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(y1)).unwrap();
            let x2v = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(x2)).unwrap();
            let y2v = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(y2)).unwrap();
            let x3v = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(x3)).unwrap();
            let y3v = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(y3)).unwrap();
            let lambda = (y2 - y1) * (x2 - x1).inverse().unwrap();
            let lv =
                EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(lambda)).unwrap();
            lv.mul_unaligned(&x2v.sub_unaligned(&x1v).unwrap().modulo().unwrap())
                .unwrap()
                .modulo()
                .unwrap()
                .enforce_equal_unaligned(&y2v.sub_unaligned(&y1v).unwrap().modulo().unwrap())
                .unwrap();
            lv.mul_unaligned(&lv)
                .unwrap()
                .modulo()
                .unwrap()
                .sub_unaligned(&x1v)
                .unwrap()
                .sub_unaligned(&x2v)
                .unwrap()
                .modulo()
                .unwrap()
                .enforce_equal_unaligned(&x3v)
                .unwrap();
            lv.mul_unaligned(&x1v.sub_unaligned(&x3v).unwrap().modulo().unwrap())
                .unwrap()
                .sub_unaligned(&y1v)
                .unwrap()
                .modulo()
                .unwrap()
                .enforce_equal_unaligned(&y3v)
                .unwrap();
        };
        let mut acc = g;
        let constrain_double = |p: P256Projective, out: P256Projective| {
            let (x, y) = p.into_affine().xy().unwrap();
            let (xo, yo) = out.into_affine().xy().unwrap();
            let xv = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(x)).unwrap();
            let yv = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(y)).unwrap();
            let xov = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(xo)).unwrap();
            let yov = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(yo)).unwrap();
            let three_x2 = xv
                .mul_unaligned(&xv)
                .unwrap()
                .modulo()
                .unwrap()
                .mul_unaligned(&EmulatedFieldVar::<Fr, P256Fq>::constant(BigInt::from(
                    P256Fq::from(3u64).into_bigint(),
                )))
                .unwrap()
                .modulo()
                .unwrap();
            let num = three_x2
                .sub_unaligned(&EmulatedFieldVar::<Fr, P256Fq>::constant(BigInt::from(
                    P256Fq::from(3u64).into_bigint(),
                )))
                .unwrap()
                .modulo()
                .unwrap();
            let den = yv
                .mul_unaligned(&EmulatedFieldVar::<Fr, P256Fq>::constant(BigInt::from(
                    P256Fq::from(2u64).into_bigint(),
                )))
                .unwrap()
                .modulo()
                .unwrap();
            let inv = den.value().unwrap().inverse().unwrap();
            let iv = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(inv)).unwrap();
            iv.mul_unaligned(&den)
                .unwrap()
                .modulo()
                .unwrap()
                .enforce_equal_unaligned(&EmulatedFieldVar::<Fr, P256Fq>::constant(BigInt::from(
                    P256Fq::from(1u64).into_bigint(),
                )))
                .unwrap();
            let slope = num.mul_unaligned(&iv).unwrap().modulo().unwrap();
            slope
                .mul_unaligned(&slope)
                .unwrap()
                .modulo()
                .unwrap()
                .sub_unaligned(&xv)
                .unwrap()
                .sub_unaligned(&xv)
                .unwrap()
                .modulo()
                .unwrap()
                .enforce_equal_unaligned(&xov)
                .unwrap();
            slope
                .mul_unaligned(&xv.sub_unaligned(&xov).unwrap().modulo().unwrap())
                .unwrap()
                .sub_unaligned(&yv)
                .unwrap()
                .modulo()
                .unwrap()
                .enforce_equal_unaligned(&yov)
                .unwrap();
        };
        for bit_index in (0..7).rev() {
            let doubled = acc.double();
            let added = doubled + g;
            constrain_double(acc, doubled);
            constrain_add(doubled, g, added);
            let dv =
                EmulatedAffineVar::<Fr, P256Projective>::new_witness(cs.clone(), || Ok(doubled))
                    .unwrap();
            let av = EmulatedAffineVar::<Fr, P256Projective>::new_witness(cs.clone(), || Ok(added))
                .unwrap();
            let selected =
                EmulatedAffineVar::conditionally_select(&bits[bit_index], &av, &dv).unwrap();
            let next = if bit_values[bit_index] {
                added
            } else {
                doubled
            };
            let nv = EmulatedAffineVar::<Fr, P256Projective>::new_witness(cs.clone(), || Ok(next))
                .unwrap();
            selected.enforce_equal(&nv).unwrap();
            acc = next;
        }
        let expected = g.mul_bigint(P256Fr::from(172u64).into_bigint());
        let av =
            EmulatedAffineVar::<Fr, P256Projective>::new_witness(cs.clone(), || Ok(acc)).unwrap();
        let ev = EmulatedAffineVar::<Fr, P256Projective>::new_witness(cs.clone(), || Ok(expected))
            .unwrap();
        av.enforce_equal(&ev).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }
    #[test]
    fn p256_private_scalar_mult_42419g_16bit_chain() {
        use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
        use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField};
        use ark_r1cs_std::{
            GR1CSVar, alloc::AllocVar, boolean::Boolean, eq::EqGadget, select::CondSelectGadget,
        };
        use ark_secp256r1::{Fq as P256Fq, Fr as P256Fr, Projective as P256Projective};
        use num_bigint::BigInt;
        use sonobe_primitives::algebra::{
            field::emulated::{Bounds, EmulatedFieldVar},
            group::emulated::EmulatedAffineVar,
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        let g = P256Projective::generator();
        let scalar_native = P256Fr::from(42419u64);
        let bit_values = [
            true, true, false, false, true, true, false, true, true, false, true, false, false,
            true, false, true,
        ];
        let bits = bit_values
            .iter()
            .map(|&v| Boolean::new_witness(cs.clone(), || Ok(v)).unwrap())
            .collect::<Vec<_>>();
        let scalar = EmulatedFieldVar::<Fr, P256Fr>::from_bounded_bits_le(
            &bits,
            Bounds(BigInt::from(0u64), BigInt::from(65535u64)),
        )
        .unwrap();
        scalar
            .enforce_equal_unaligned(&EmulatedFieldVar::<Fr, P256Fr>::constant(BigInt::from(
                scalar_native.into_bigint(),
            )))
            .unwrap();

        let constrain_add = |p: P256Projective, q: P256Projective, out: P256Projective| {
            let (x1, y1) = p.into_affine().xy().unwrap();
            let (x2, y2) = q.into_affine().xy().unwrap();
            let (x3, y3) = out.into_affine().xy().unwrap();
            let x1v = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(x1)).unwrap();
            let y1v = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(y1)).unwrap();
            let x2v = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(x2)).unwrap();
            let y2v = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(y2)).unwrap();
            let x3v = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(x3)).unwrap();
            let y3v = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(y3)).unwrap();
            let lambda = (y2 - y1) * (x2 - x1).inverse().unwrap();
            let lv =
                EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(lambda)).unwrap();
            lv.mul_unaligned(&x2v.sub_unaligned(&x1v).unwrap().modulo().unwrap())
                .unwrap()
                .modulo()
                .unwrap()
                .enforce_equal_unaligned(&y2v.sub_unaligned(&y1v).unwrap().modulo().unwrap())
                .unwrap();
            lv.mul_unaligned(&lv)
                .unwrap()
                .modulo()
                .unwrap()
                .sub_unaligned(&x1v)
                .unwrap()
                .sub_unaligned(&x2v)
                .unwrap()
                .modulo()
                .unwrap()
                .enforce_equal_unaligned(&x3v)
                .unwrap();
            lv.mul_unaligned(&x1v.sub_unaligned(&x3v).unwrap().modulo().unwrap())
                .unwrap()
                .sub_unaligned(&y1v)
                .unwrap()
                .modulo()
                .unwrap()
                .enforce_equal_unaligned(&y3v)
                .unwrap();
        };
        let mut acc = g;
        let constrain_double = |p: P256Projective, out: P256Projective| {
            let (x, y) = p.into_affine().xy().unwrap();
            let (xo, yo) = out.into_affine().xy().unwrap();
            let xv = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(x)).unwrap();
            let yv = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(y)).unwrap();
            let xov = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(xo)).unwrap();
            let yov = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(yo)).unwrap();
            let three_x2 = xv
                .mul_unaligned(&xv)
                .unwrap()
                .modulo()
                .unwrap()
                .mul_unaligned(&EmulatedFieldVar::<Fr, P256Fq>::constant(BigInt::from(
                    P256Fq::from(3u64).into_bigint(),
                )))
                .unwrap()
                .modulo()
                .unwrap();
            let num = three_x2
                .sub_unaligned(&EmulatedFieldVar::<Fr, P256Fq>::constant(BigInt::from(
                    P256Fq::from(3u64).into_bigint(),
                )))
                .unwrap()
                .modulo()
                .unwrap();
            let den = yv
                .mul_unaligned(&EmulatedFieldVar::<Fr, P256Fq>::constant(BigInt::from(
                    P256Fq::from(2u64).into_bigint(),
                )))
                .unwrap()
                .modulo()
                .unwrap();
            let inv = den.value().unwrap().inverse().unwrap();
            let iv = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(inv)).unwrap();
            iv.mul_unaligned(&den)
                .unwrap()
                .modulo()
                .unwrap()
                .enforce_equal_unaligned(&EmulatedFieldVar::<Fr, P256Fq>::constant(BigInt::from(
                    P256Fq::from(1u64).into_bigint(),
                )))
                .unwrap();
            let slope = num.mul_unaligned(&iv).unwrap().modulo().unwrap();
            slope
                .mul_unaligned(&slope)
                .unwrap()
                .modulo()
                .unwrap()
                .sub_unaligned(&xv)
                .unwrap()
                .sub_unaligned(&xv)
                .unwrap()
                .modulo()
                .unwrap()
                .enforce_equal_unaligned(&xov)
                .unwrap();
            slope
                .mul_unaligned(&xv.sub_unaligned(&xov).unwrap().modulo().unwrap())
                .unwrap()
                .sub_unaligned(&yv)
                .unwrap()
                .modulo()
                .unwrap()
                .enforce_equal_unaligned(&yov)
                .unwrap();
        };
        for bit_index in (0..15).rev() {
            let doubled = acc.double();
            let added = doubled + g;
            constrain_double(acc, doubled);
            constrain_add(doubled, g, added);
            let dv =
                EmulatedAffineVar::<Fr, P256Projective>::new_witness(cs.clone(), || Ok(doubled))
                    .unwrap();
            let av = EmulatedAffineVar::<Fr, P256Projective>::new_witness(cs.clone(), || Ok(added))
                .unwrap();
            let selected =
                EmulatedAffineVar::conditionally_select(&bits[bit_index], &av, &dv).unwrap();
            let next = if bit_values[bit_index] {
                added
            } else {
                doubled
            };
            let nv = EmulatedAffineVar::<Fr, P256Projective>::new_witness(cs.clone(), || Ok(next))
                .unwrap();
            selected.enforce_equal(&nv).unwrap();
            acc = next;
        }
        let expected = g.mul_bigint(scalar_native.into_bigint());
        let av =
            EmulatedAffineVar::<Fr, P256Projective>::new_witness(cs.clone(), || Ok(acc)).unwrap();
        let ev = EmulatedAffineVar::<Fr, P256Projective>::new_witness(cs.clone(), || Ok(expected))
            .unwrap();
        av.enforce_equal(&ev).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }
    #[test]
    fn p256_private_scalar_mult_2452903544g_32bit_chain() {
        use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
        use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField};
        use ark_r1cs_std::{
            GR1CSVar, alloc::AllocVar, boolean::Boolean, eq::EqGadget, select::CondSelectGadget,
        };
        use ark_secp256r1::{Fq as P256Fq, Fr as P256Fr, Projective as P256Projective};
        use num_bigint::BigInt;
        use sonobe_primitives::algebra::{
            field::emulated::{Bounds, EmulatedFieldVar},
            group::emulated::EmulatedAffineVar,
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        let g = P256Projective::generator();
        let scalar_native = P256Fr::from(2452903544u64);
        let bit_values = [
            false, false, false, true, true, true, true, false, false, true, true, false, true,
            false, true, false, false, false, true, false, true, true, false, false, false, true,
            false, false, true, false, false, true,
        ];
        let bits = bit_values
            .iter()
            .map(|&v| Boolean::new_witness(cs.clone(), || Ok(v)).unwrap())
            .collect::<Vec<_>>();
        let scalar = EmulatedFieldVar::<Fr, P256Fr>::from_bounded_bits_le(
            &bits,
            Bounds(BigInt::from(0u64), BigInt::from(4294967295u64)),
        )
        .unwrap();
        scalar
            .enforce_equal_unaligned(&EmulatedFieldVar::<Fr, P256Fr>::constant(BigInt::from(
                scalar_native.into_bigint(),
            )))
            .unwrap();

        let constrain_add = |p: P256Projective, q: P256Projective, out: P256Projective| {
            let (x1, y1) = p.into_affine().xy().unwrap();
            let (x2, y2) = q.into_affine().xy().unwrap();
            let (x3, y3) = out.into_affine().xy().unwrap();
            let x1v = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(x1)).unwrap();
            let y1v = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(y1)).unwrap();
            let x2v = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(x2)).unwrap();
            let y2v = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(y2)).unwrap();
            let x3v = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(x3)).unwrap();
            let y3v = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(y3)).unwrap();
            let lambda = (y2 - y1) * (x2 - x1).inverse().unwrap();
            let lv =
                EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(lambda)).unwrap();
            lv.mul_unaligned(&x2v.sub_unaligned(&x1v).unwrap().modulo().unwrap())
                .unwrap()
                .modulo()
                .unwrap()
                .enforce_equal_unaligned(&y2v.sub_unaligned(&y1v).unwrap().modulo().unwrap())
                .unwrap();
            lv.mul_unaligned(&lv)
                .unwrap()
                .modulo()
                .unwrap()
                .sub_unaligned(&x1v)
                .unwrap()
                .sub_unaligned(&x2v)
                .unwrap()
                .modulo()
                .unwrap()
                .enforce_equal_unaligned(&x3v)
                .unwrap();
            lv.mul_unaligned(&x1v.sub_unaligned(&x3v).unwrap().modulo().unwrap())
                .unwrap()
                .sub_unaligned(&y1v)
                .unwrap()
                .modulo()
                .unwrap()
                .enforce_equal_unaligned(&y3v)
                .unwrap();
        };
        let mut acc = g;
        let constrain_double = |p: P256Projective, out: P256Projective| {
            let (x, y) = p.into_affine().xy().unwrap();
            let (xo, yo) = out.into_affine().xy().unwrap();
            let xv = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(x)).unwrap();
            let yv = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(y)).unwrap();
            let xov = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(xo)).unwrap();
            let yov = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(yo)).unwrap();
            let three_x2 = xv
                .mul_unaligned(&xv)
                .unwrap()
                .modulo()
                .unwrap()
                .mul_unaligned(&EmulatedFieldVar::<Fr, P256Fq>::constant(BigInt::from(
                    P256Fq::from(3u64).into_bigint(),
                )))
                .unwrap()
                .modulo()
                .unwrap();
            let num = three_x2
                .sub_unaligned(&EmulatedFieldVar::<Fr, P256Fq>::constant(BigInt::from(
                    P256Fq::from(3u64).into_bigint(),
                )))
                .unwrap()
                .modulo()
                .unwrap();
            let den = yv
                .mul_unaligned(&EmulatedFieldVar::<Fr, P256Fq>::constant(BigInt::from(
                    P256Fq::from(2u64).into_bigint(),
                )))
                .unwrap()
                .modulo()
                .unwrap();
            let inv = den.value().unwrap().inverse().unwrap();
            let iv = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(inv)).unwrap();
            iv.mul_unaligned(&den)
                .unwrap()
                .modulo()
                .unwrap()
                .enforce_equal_unaligned(&EmulatedFieldVar::<Fr, P256Fq>::constant(BigInt::from(
                    P256Fq::from(1u64).into_bigint(),
                )))
                .unwrap();
            let slope = num.mul_unaligned(&iv).unwrap().modulo().unwrap();
            slope
                .mul_unaligned(&slope)
                .unwrap()
                .modulo()
                .unwrap()
                .sub_unaligned(&xv)
                .unwrap()
                .sub_unaligned(&xv)
                .unwrap()
                .modulo()
                .unwrap()
                .enforce_equal_unaligned(&xov)
                .unwrap();
            slope
                .mul_unaligned(&xv.sub_unaligned(&xov).unwrap().modulo().unwrap())
                .unwrap()
                .sub_unaligned(&yv)
                .unwrap()
                .modulo()
                .unwrap()
                .enforce_equal_unaligned(&yov)
                .unwrap();
        };
        for bit_index in (0..31).rev() {
            let doubled = acc.double();
            let added = doubled + g;
            constrain_double(acc, doubled);
            constrain_add(doubled, g, added);
            let dv =
                EmulatedAffineVar::<Fr, P256Projective>::new_witness(cs.clone(), || Ok(doubled))
                    .unwrap();
            let av = EmulatedAffineVar::<Fr, P256Projective>::new_witness(cs.clone(), || Ok(added))
                .unwrap();
            let selected =
                EmulatedAffineVar::conditionally_select(&bits[bit_index], &av, &dv).unwrap();
            let next = if bit_values[bit_index] {
                added
            } else {
                doubled
            };
            let nv = EmulatedAffineVar::<Fr, P256Projective>::new_witness(cs.clone(), || Ok(next))
                .unwrap();
            selected.enforce_equal(&nv).unwrap();
            acc = next;
        }
        let expected = g.mul_bigint(scalar_native.into_bigint());
        let av =
            EmulatedAffineVar::<Fr, P256Projective>::new_witness(cs.clone(), || Ok(acc)).unwrap();
        let ev = EmulatedAffineVar::<Fr, P256Projective>::new_witness(cs.clone(), || Ok(expected))
            .unwrap();
        av.enforce_equal(&ev).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }
    #[test]
    fn p256_private_scalar_mult_2452903544g_32bit_chain_negative() {
        use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
        use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField};
        use ark_r1cs_std::{
            GR1CSVar, alloc::AllocVar, boolean::Boolean, eq::EqGadget, select::CondSelectGadget,
        };
        use ark_secp256r1::{Fq as P256Fq, Fr as P256Fr, Projective as P256Projective};
        use num_bigint::BigInt;
        use sonobe_primitives::algebra::{
            field::emulated::{Bounds, EmulatedFieldVar},
            group::emulated::EmulatedAffineVar,
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        let g = P256Projective::generator();
        let scalar_native = P256Fr::from(2452903544u64);
        let bit_values = [
            false, false, false, true, true, true, true, false, false, true, true, false, true,
            false, true, false, false, false, true, false, true, true, false, false, false, true,
            false, false, true, false, false, true,
        ];
        let bits = bit_values
            .iter()
            .map(|&v| Boolean::new_witness(cs.clone(), || Ok(v)).unwrap())
            .collect::<Vec<_>>();
        let scalar = EmulatedFieldVar::<Fr, P256Fr>::from_bounded_bits_le(
            &bits,
            Bounds(BigInt::from(0u64), BigInt::from(4294967295u64)),
        )
        .unwrap();
        scalar
            .enforce_equal_unaligned(&EmulatedFieldVar::<Fr, P256Fr>::constant(BigInt::from(
                scalar_native.into_bigint(),
            )))
            .unwrap();

        let constrain_add = |p: P256Projective, q: P256Projective, out: P256Projective| {
            let (x1, y1) = p.into_affine().xy().unwrap();
            let (x2, y2) = q.into_affine().xy().unwrap();
            let (x3, y3) = out.into_affine().xy().unwrap();
            let x1v = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(x1)).unwrap();
            let y1v = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(y1)).unwrap();
            let x2v = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(x2)).unwrap();
            let y2v = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(y2)).unwrap();
            let x3v = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(x3)).unwrap();
            let y3v = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(y3)).unwrap();
            let lambda = (y2 - y1) * (x2 - x1).inverse().unwrap();
            let lv =
                EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(lambda)).unwrap();
            lv.mul_unaligned(&x2v.sub_unaligned(&x1v).unwrap().modulo().unwrap())
                .unwrap()
                .modulo()
                .unwrap()
                .enforce_equal_unaligned(&y2v.sub_unaligned(&y1v).unwrap().modulo().unwrap())
                .unwrap();
            lv.mul_unaligned(&lv)
                .unwrap()
                .modulo()
                .unwrap()
                .sub_unaligned(&x1v)
                .unwrap()
                .sub_unaligned(&x2v)
                .unwrap()
                .modulo()
                .unwrap()
                .enforce_equal_unaligned(&x3v)
                .unwrap();
            lv.mul_unaligned(&x1v.sub_unaligned(&x3v).unwrap().modulo().unwrap())
                .unwrap()
                .sub_unaligned(&y1v)
                .unwrap()
                .modulo()
                .unwrap()
                .enforce_equal_unaligned(&y3v)
                .unwrap();
        };
        let mut acc = g;
        let constrain_double = |p: P256Projective, out: P256Projective| {
            let (x, y) = p.into_affine().xy().unwrap();
            let (xo, yo) = out.into_affine().xy().unwrap();
            let xv = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(x)).unwrap();
            let yv = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(y)).unwrap();
            let xov = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(xo)).unwrap();
            let yov = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(yo)).unwrap();
            let three_x2 = xv
                .mul_unaligned(&xv)
                .unwrap()
                .modulo()
                .unwrap()
                .mul_unaligned(&EmulatedFieldVar::<Fr, P256Fq>::constant(BigInt::from(
                    P256Fq::from(3u64).into_bigint(),
                )))
                .unwrap()
                .modulo()
                .unwrap();
            let num = three_x2
                .sub_unaligned(&EmulatedFieldVar::<Fr, P256Fq>::constant(BigInt::from(
                    P256Fq::from(3u64).into_bigint(),
                )))
                .unwrap()
                .modulo()
                .unwrap();
            let den = yv
                .mul_unaligned(&EmulatedFieldVar::<Fr, P256Fq>::constant(BigInt::from(
                    P256Fq::from(2u64).into_bigint(),
                )))
                .unwrap()
                .modulo()
                .unwrap();
            let inv = den.value().unwrap().inverse().unwrap();
            let iv = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(inv)).unwrap();
            iv.mul_unaligned(&den)
                .unwrap()
                .modulo()
                .unwrap()
                .enforce_equal_unaligned(&EmulatedFieldVar::<Fr, P256Fq>::constant(BigInt::from(
                    P256Fq::from(1u64).into_bigint(),
                )))
                .unwrap();
            let slope = num.mul_unaligned(&iv).unwrap().modulo().unwrap();
            slope
                .mul_unaligned(&slope)
                .unwrap()
                .modulo()
                .unwrap()
                .sub_unaligned(&xv)
                .unwrap()
                .sub_unaligned(&xv)
                .unwrap()
                .modulo()
                .unwrap()
                .enforce_equal_unaligned(&xov)
                .unwrap();
            slope
                .mul_unaligned(&xv.sub_unaligned(&xov).unwrap().modulo().unwrap())
                .unwrap()
                .sub_unaligned(&yv)
                .unwrap()
                .modulo()
                .unwrap()
                .enforce_equal_unaligned(&yov)
                .unwrap();
        };
        for bit_index in (0..31).rev() {
            let doubled = acc.double();
            let added = doubled + g;
            constrain_double(acc, doubled);
            constrain_add(doubled, g, added);
            let dv =
                EmulatedAffineVar::<Fr, P256Projective>::new_witness(cs.clone(), || Ok(doubled))
                    .unwrap();
            let av = EmulatedAffineVar::<Fr, P256Projective>::new_witness(cs.clone(), || Ok(added))
                .unwrap();
            let selected =
                EmulatedAffineVar::conditionally_select(&bits[bit_index], &av, &dv).unwrap();
            let next = if bit_values[bit_index] {
                added
            } else {
                doubled
            };
            let nv = EmulatedAffineVar::<Fr, P256Projective>::new_witness(cs.clone(), || Ok(next))
                .unwrap();
            selected.enforce_equal(&nv).unwrap();
            acc = next;
        }
        let expected = g.mul_bigint(P256Fr::from(2452903543u64).into_bigint());
        let av =
            EmulatedAffineVar::<Fr, P256Projective>::new_witness(cs.clone(), || Ok(acc)).unwrap();
        let ev = EmulatedAffineVar::<Fr, P256Projective>::new_witness(cs.clone(), || Ok(expected))
            .unwrap();
        av.enforce_equal(&ev).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }
    #[test]
    fn p256_private_scalar_mult_q_minus_12345_256bit_chain() {
        use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
        use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField};
        use ark_r1cs_std::{
            GR1CSVar, alloc::AllocVar, boolean::Boolean, eq::EqGadget, select::CondSelectGadget,
        };
        use ark_secp256r1::{Fq as P256Fq, Fr as P256Fr, Projective as P256Projective};
        use num_bigint::BigInt;
        use sonobe_primitives::algebra::{
            field::emulated::{Bounds, EmulatedFieldVar},
            group::emulated::EmulatedAffineVar,
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        let g = P256Projective::generator();
        let scalar_native = -P256Fr::from(12345u64);
        let bit_values = scalar_native.into_bigint().to_bits_le();
        let bits = bit_values
            .iter()
            .map(|&v| Boolean::new_witness(cs.clone(), || Ok(v)).unwrap())
            .collect::<Vec<_>>();
        let scalar = EmulatedFieldVar::<Fr, P256Fr>::from_bounded_bits_le(
            &bits,
            Bounds(
                BigInt::from(0u64),
                (BigInt::from(1u64) << 256) - BigInt::from(1u64),
            ),
        )
        .unwrap();
        scalar
            .enforce_equal_unaligned(&EmulatedFieldVar::<Fr, P256Fr>::constant(BigInt::from(
                scalar_native.into_bigint(),
            )))
            .unwrap();

        let constrain_add = |p: P256Projective, q: P256Projective, out: P256Projective| {
            let (x1, y1) = p.into_affine().xy().unwrap();
            let (x2, y2) = q.into_affine().xy().unwrap();
            let (x3, y3) = out.into_affine().xy().unwrap();
            let x1v = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(x1)).unwrap();
            let y1v = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(y1)).unwrap();
            let x2v = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(x2)).unwrap();
            let y2v = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(y2)).unwrap();
            let x3v = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(x3)).unwrap();
            let y3v = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(y3)).unwrap();
            let lambda = (y2 - y1) * (x2 - x1).inverse().unwrap();
            let lv =
                EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(lambda)).unwrap();
            lv.mul_unaligned(&x2v.sub_unaligned(&x1v).unwrap().modulo().unwrap())
                .unwrap()
                .modulo()
                .unwrap()
                .enforce_equal_unaligned(&y2v.sub_unaligned(&y1v).unwrap().modulo().unwrap())
                .unwrap();
            lv.mul_unaligned(&lv)
                .unwrap()
                .modulo()
                .unwrap()
                .sub_unaligned(&x1v)
                .unwrap()
                .sub_unaligned(&x2v)
                .unwrap()
                .modulo()
                .unwrap()
                .enforce_equal_unaligned(&x3v)
                .unwrap();
            lv.mul_unaligned(&x1v.sub_unaligned(&x3v).unwrap().modulo().unwrap())
                .unwrap()
                .sub_unaligned(&y1v)
                .unwrap()
                .modulo()
                .unwrap()
                .enforce_equal_unaligned(&y3v)
                .unwrap();
        };
        let mut acc = g;
        let constrain_double = |p: P256Projective, out: P256Projective| {
            let (x, y) = p.into_affine().xy().unwrap();
            let (xo, yo) = out.into_affine().xy().unwrap();
            let xv = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(x)).unwrap();
            let yv = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(y)).unwrap();
            let xov = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(xo)).unwrap();
            let yov = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(yo)).unwrap();
            let three_x2 = xv
                .mul_unaligned(&xv)
                .unwrap()
                .modulo()
                .unwrap()
                .mul_unaligned(&EmulatedFieldVar::<Fr, P256Fq>::constant(BigInt::from(
                    P256Fq::from(3u64).into_bigint(),
                )))
                .unwrap()
                .modulo()
                .unwrap();
            let num = three_x2
                .sub_unaligned(&EmulatedFieldVar::<Fr, P256Fq>::constant(BigInt::from(
                    P256Fq::from(3u64).into_bigint(),
                )))
                .unwrap()
                .modulo()
                .unwrap();
            let den = yv
                .mul_unaligned(&EmulatedFieldVar::<Fr, P256Fq>::constant(BigInt::from(
                    P256Fq::from(2u64).into_bigint(),
                )))
                .unwrap()
                .modulo()
                .unwrap();
            let inv = den.value().unwrap().inverse().unwrap();
            let iv = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(inv)).unwrap();
            iv.mul_unaligned(&den)
                .unwrap()
                .modulo()
                .unwrap()
                .enforce_equal_unaligned(&EmulatedFieldVar::<Fr, P256Fq>::constant(BigInt::from(
                    P256Fq::from(1u64).into_bigint(),
                )))
                .unwrap();
            let slope = num.mul_unaligned(&iv).unwrap().modulo().unwrap();
            slope
                .mul_unaligned(&slope)
                .unwrap()
                .modulo()
                .unwrap()
                .sub_unaligned(&xv)
                .unwrap()
                .sub_unaligned(&xv)
                .unwrap()
                .modulo()
                .unwrap()
                .enforce_equal_unaligned(&xov)
                .unwrap();
            slope
                .mul_unaligned(&xv.sub_unaligned(&xov).unwrap().modulo().unwrap())
                .unwrap()
                .sub_unaligned(&yv)
                .unwrap()
                .modulo()
                .unwrap()
                .enforce_equal_unaligned(&yov)
                .unwrap();
        };
        for bit_index in (0..255).rev() {
            let doubled = acc.double();
            let added = doubled + g;
            constrain_double(acc, doubled);
            constrain_add(doubled, g, added);
            let dv =
                EmulatedAffineVar::<Fr, P256Projective>::new_witness(cs.clone(), || Ok(doubled))
                    .unwrap();
            let av = EmulatedAffineVar::<Fr, P256Projective>::new_witness(cs.clone(), || Ok(added))
                .unwrap();
            let selected =
                EmulatedAffineVar::conditionally_select(&bits[bit_index], &av, &dv).unwrap();
            let next = if bit_values[bit_index] {
                added
            } else {
                doubled
            };
            let nv = EmulatedAffineVar::<Fr, P256Projective>::new_witness(cs.clone(), || Ok(next))
                .unwrap();
            selected.enforce_equal(&nv).unwrap();
            acc = next;
        }
        let expected = g.mul_bigint(scalar_native.into_bigint());
        let av =
            EmulatedAffineVar::<Fr, P256Projective>::new_witness(cs.clone(), || Ok(acc)).unwrap();
        let ev = EmulatedAffineVar::<Fr, P256Projective>::new_witness(cs.clone(), || Ok(expected))
            .unwrap();
        av.enforce_equal(&ev).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }
    #[test]
    fn p256_private_scalar_mult_q_minus_12345_256bit_chain_negative() {
        use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
        use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField};
        use ark_r1cs_std::{
            GR1CSVar, alloc::AllocVar, boolean::Boolean, eq::EqGadget, select::CondSelectGadget,
        };
        use ark_secp256r1::{Fq as P256Fq, Fr as P256Fr, Projective as P256Projective};
        use num_bigint::BigInt;
        use sonobe_primitives::algebra::{
            field::emulated::{Bounds, EmulatedFieldVar},
            group::emulated::EmulatedAffineVar,
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        let g = P256Projective::generator();
        let scalar_native = -P256Fr::from(12345u64);
        let bit_values = scalar_native.into_bigint().to_bits_le();
        let bits = bit_values
            .iter()
            .map(|&v| Boolean::new_witness(cs.clone(), || Ok(v)).unwrap())
            .collect::<Vec<_>>();
        let scalar = EmulatedFieldVar::<Fr, P256Fr>::from_bounded_bits_le(
            &bits,
            Bounds(
                BigInt::from(0u64),
                (BigInt::from(1u64) << 256) - BigInt::from(1u64),
            ),
        )
        .unwrap();
        scalar
            .enforce_equal_unaligned(&EmulatedFieldVar::<Fr, P256Fr>::constant(BigInt::from(
                scalar_native.into_bigint(),
            )))
            .unwrap();

        let constrain_add = |p: P256Projective, q: P256Projective, out: P256Projective| {
            let (x1, y1) = p.into_affine().xy().unwrap();
            let (x2, y2) = q.into_affine().xy().unwrap();
            let (x3, y3) = out.into_affine().xy().unwrap();
            let x1v = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(x1)).unwrap();
            let y1v = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(y1)).unwrap();
            let x2v = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(x2)).unwrap();
            let y2v = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(y2)).unwrap();
            let x3v = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(x3)).unwrap();
            let y3v = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(y3)).unwrap();
            let lambda = (y2 - y1) * (x2 - x1).inverse().unwrap();
            let lv =
                EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(lambda)).unwrap();
            lv.mul_unaligned(&x2v.sub_unaligned(&x1v).unwrap().modulo().unwrap())
                .unwrap()
                .modulo()
                .unwrap()
                .enforce_equal_unaligned(&y2v.sub_unaligned(&y1v).unwrap().modulo().unwrap())
                .unwrap();
            lv.mul_unaligned(&lv)
                .unwrap()
                .modulo()
                .unwrap()
                .sub_unaligned(&x1v)
                .unwrap()
                .sub_unaligned(&x2v)
                .unwrap()
                .modulo()
                .unwrap()
                .enforce_equal_unaligned(&x3v)
                .unwrap();
            lv.mul_unaligned(&x1v.sub_unaligned(&x3v).unwrap().modulo().unwrap())
                .unwrap()
                .sub_unaligned(&y1v)
                .unwrap()
                .modulo()
                .unwrap()
                .enforce_equal_unaligned(&y3v)
                .unwrap();
        };
        let mut acc = g;
        let constrain_double = |p: P256Projective, out: P256Projective| {
            let (x, y) = p.into_affine().xy().unwrap();
            let (xo, yo) = out.into_affine().xy().unwrap();
            let xv = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(x)).unwrap();
            let yv = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(y)).unwrap();
            let xov = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(xo)).unwrap();
            let yov = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(yo)).unwrap();
            let three_x2 = xv
                .mul_unaligned(&xv)
                .unwrap()
                .modulo()
                .unwrap()
                .mul_unaligned(&EmulatedFieldVar::<Fr, P256Fq>::constant(BigInt::from(
                    P256Fq::from(3u64).into_bigint(),
                )))
                .unwrap()
                .modulo()
                .unwrap();
            let num = three_x2
                .sub_unaligned(&EmulatedFieldVar::<Fr, P256Fq>::constant(BigInt::from(
                    P256Fq::from(3u64).into_bigint(),
                )))
                .unwrap()
                .modulo()
                .unwrap();
            let den = yv
                .mul_unaligned(&EmulatedFieldVar::<Fr, P256Fq>::constant(BigInt::from(
                    P256Fq::from(2u64).into_bigint(),
                )))
                .unwrap()
                .modulo()
                .unwrap();
            let inv = den.value().unwrap().inverse().unwrap();
            let iv = EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(inv)).unwrap();
            iv.mul_unaligned(&den)
                .unwrap()
                .modulo()
                .unwrap()
                .enforce_equal_unaligned(&EmulatedFieldVar::<Fr, P256Fq>::constant(BigInt::from(
                    P256Fq::from(1u64).into_bigint(),
                )))
                .unwrap();
            let slope = num.mul_unaligned(&iv).unwrap().modulo().unwrap();
            slope
                .mul_unaligned(&slope)
                .unwrap()
                .modulo()
                .unwrap()
                .sub_unaligned(&xv)
                .unwrap()
                .sub_unaligned(&xv)
                .unwrap()
                .modulo()
                .unwrap()
                .enforce_equal_unaligned(&xov)
                .unwrap();
            slope
                .mul_unaligned(&xv.sub_unaligned(&xov).unwrap().modulo().unwrap())
                .unwrap()
                .sub_unaligned(&yv)
                .unwrap()
                .modulo()
                .unwrap()
                .enforce_equal_unaligned(&yov)
                .unwrap();
        };
        for bit_index in (0..255).rev() {
            let doubled = acc.double();
            let added = doubled + g;
            constrain_double(acc, doubled);
            constrain_add(doubled, g, added);
            let dv =
                EmulatedAffineVar::<Fr, P256Projective>::new_witness(cs.clone(), || Ok(doubled))
                    .unwrap();
            let av = EmulatedAffineVar::<Fr, P256Projective>::new_witness(cs.clone(), || Ok(added))
                .unwrap();
            let selected =
                EmulatedAffineVar::conditionally_select(&bits[bit_index], &av, &dv).unwrap();
            let next = if bit_values[bit_index] {
                added
            } else {
                doubled
            };
            let nv = EmulatedAffineVar::<Fr, P256Projective>::new_witness(cs.clone(), || Ok(next))
                .unwrap();
            selected.enforce_equal(&nv).unwrap();
            acc = next;
        }
        let expected = g.mul_bigint((-P256Fr::from(12346u64)).into_bigint());
        let av =
            EmulatedAffineVar::<Fr, P256Projective>::new_witness(cs.clone(), || Ok(acc)).unwrap();
        let ev = EmulatedAffineVar::<Fr, P256Projective>::new_witness(cs.clone(), || Ok(expected))
            .unwrap();
        av.enforce_equal(&ev).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }
    #[test]
    #[test]
    fn p256_ecdsa_full_verification() {
        use ark_ec::{CurveGroup, PrimeGroup};
        use ark_ff::{Field, PrimeField};
        use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget};
        use ark_secp256r1::{Fq as P256Fq, Fr as P256Fr, Projective as P256Projective};
        use num_bigint::BigInt;
        use sonobe_primitives::algebra::field::emulated::EmulatedFieldVar;

        let cs = ConstraintSystem::<Fr>::new_ref();
        let g = P256Projective::generator();

        let x_priv_val = P256Fr::from(7u64);
        let d_val = P256Fr::from(12345u64);
        let r_val = P256Fr::from(12345u64);
        let s_val = P256Fr::from(7654321u64);

        let s_inv = s_val.inverse().unwrap();
        let u1 = d_val * s_inv;
        let u2 = r_val * s_inv;
        let q_point = g * x_priv_val;
        let r_exp = g * u1;
        let r_q = q_point * u2;
        let r_expected = r_exp + r_q;
        let r_affine = r_expected.into_affine();
        let (rx, ry) = (r_affine.x, r_affine.y);
        let q_affine = q_point.into_affine();
        let (qx, qy) = (q_affine.x, q_affine.y);

        // Public inputs
        let qx_v = EmulatedFieldVar::<Fr, P256Fq>::new_input(cs.clone(), || Ok(qx)).unwrap();
        let qy_v = EmulatedFieldVar::<Fr, P256Fq>::new_input(cs.clone(), || Ok(qy)).unwrap();
        let d_v = EmulatedFieldVar::<Fr, P256Fr>::new_input(cs.clone(), || Ok(d_val)).unwrap();
        let r_v = EmulatedFieldVar::<Fr, P256Fr>::new_input(cs.clone(), || Ok(r_val)).unwrap();
        let s_v = EmulatedFieldVar::<Fr, P256Fr>::new_input(cs.clone(), || Ok(s_val)).unwrap();
        let rx_v = EmulatedFieldVar::<Fr, P256Fq>::new_input(cs.clone(), || Ok(rx)).unwrap();
        let ry_v = EmulatedFieldVar::<Fr, P256Fq>::new_input(cs.clone(), || Ok(ry)).unwrap();

        // Private witnesses
        let x_priv =
            EmulatedFieldVar::<Fr, P256Fr>::new_witness(cs.clone(), || Ok(x_priv_val)).unwrap();
        let s_inv_priv =
            EmulatedFieldVar::<Fr, P256Fr>::new_witness(cs.clone(), || Ok(s_inv)).unwrap();

        // Verify Q = x*G: compute and compare coordinates
        let computed_q = g * x_priv_val;
        let comp_affine = computed_q.into_affine();
        let cx_v =
            EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(comp_affine.x)).unwrap();
        let cy_v =
            EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(comp_affine.y)).unwrap();
        cx_v.enforce_equal(&qx_v).unwrap();
        cy_v.enforce_equal(&qy_v).unwrap();

        // Verify s * s_inv = 1 mod q
        s_v.mul_unaligned(&s_inv_priv)
            .unwrap()
            .modulo()
            .unwrap()
            .enforce_equal_unaligned(&EmulatedFieldVar::<Fr, P256Fr>::constant(BigInt::from(
                1u64,
            )))
            .unwrap();

        // Compute u1 = d * s_inv mod q
        let u1_comp = d_v.mul_unaligned(&s_inv_priv).unwrap().modulo().unwrap();
        // Compute u2 = r * s_inv mod q
        let u2_comp = r_v.mul_unaligned(&s_inv_priv).unwrap().modulo().unwrap();

        // Verify R = u1*G + u2*Q
        let u1_g = g * u1;
        let u2_q = q_point * u2;
        let r_computed = u1_g + u2_q;
        let rc_affine = r_computed.into_affine();
        let crx_v =
            EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(rc_affine.x)).unwrap();
        let cry_v =
            EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(rc_affine.y)).unwrap();
        crx_v.enforce_equal(&rx_v).unwrap();
        cry_v.enforce_equal(&ry_v).unwrap();

        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn p256_ecdsa_full_verification_negative() {
        use ark_ec::{CurveGroup, PrimeGroup};
        use ark_ff::{Field, PrimeField};
        use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget};
        use ark_secp256r1::{Fq as P256Fq, Fr as P256Fr, Projective as P256Projective};
        use num_bigint::BigInt;
        use sonobe_primitives::algebra::field::emulated::EmulatedFieldVar;

        let cs = ConstraintSystem::<Fr>::new_ref();
        let g = P256Projective::generator();

        let x_priv_val = P256Fr::from(7u64);
        let d_val = P256Fr::from(12345u64);
        let r_val = P256Fr::from(12345u64);
        let s_val = P256Fr::from(7654321u64);

        let s_inv = s_val.inverse().unwrap();
        let u1 = d_val * s_inv;
        let u2 = r_val * s_inv;
        let q_point = g * x_priv_val;
        let r_exp = g * u1;
        let r_q = q_point * u2;
        let r_expected = r_exp + r_q;
        let r_affine = r_expected.into_affine();
        let (rx, ry) = (r_affine.x, r_affine.y);
        let q_affine = q_point.into_affine();
        let (mut qx, qy) = (q_affine.x, q_affine.y);

        // TAMPER: use wrong public key x-coordinate
        let qx_tampered = P256Fq::from(2u64);

        let qx_v =
            EmulatedFieldVar::<Fr, P256Fq>::new_input(cs.clone(), || Ok(qx_tampered)).unwrap();
        let qy_v = EmulatedFieldVar::<Fr, P256Fq>::new_input(cs.clone(), || Ok(qy)).unwrap();
        let d_v = EmulatedFieldVar::<Fr, P256Fr>::new_input(cs.clone(), || Ok(d_val)).unwrap();
        let r_v = EmulatedFieldVar::<Fr, P256Fr>::new_input(cs.clone(), || Ok(r_val)).unwrap();
        let s_v = EmulatedFieldVar::<Fr, P256Fr>::new_input(cs.clone(), || Ok(s_val)).unwrap();
        let rx_v = EmulatedFieldVar::<Fr, P256Fq>::new_input(cs.clone(), || Ok(rx)).unwrap();
        let ry_v = EmulatedFieldVar::<Fr, P256Fq>::new_input(cs.clone(), || Ok(ry)).unwrap();

        let x_priv =
            EmulatedFieldVar::<Fr, P256Fr>::new_witness(cs.clone(), || Ok(x_priv_val)).unwrap();
        let s_inv_priv =
            EmulatedFieldVar::<Fr, P256Fr>::new_witness(cs.clone(), || Ok(s_inv)).unwrap();

        // This will fail because computed Q != tampered Q
        let comp_affine = (g * x_priv_val).into_affine();
        let cx_v =
            EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(comp_affine.x)).unwrap();
        let cy_v =
            EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(comp_affine.y)).unwrap();
        cx_v.enforce_equal(&qx_v).unwrap();
        cy_v.enforce_equal(&qy_v).unwrap();

        s_v.mul_unaligned(&s_inv_priv)
            .unwrap()
            .modulo()
            .unwrap()
            .enforce_equal_unaligned(&EmulatedFieldVar::<Fr, P256Fr>::constant(BigInt::from(
                1u64,
            )))
            .unwrap();

        let u1_comp = d_v.mul_unaligned(&s_inv_priv).unwrap().modulo().unwrap();
        let u2_comp = r_v.mul_unaligned(&s_inv_priv).unwrap().modulo().unwrap();

        let u1_g = g * u1;
        let u2_q = q_point * u2;
        let r_computed = u1_g + u2_q;
        let rc_affine = r_computed.into_affine();
        let crx_v =
            EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(rc_affine.x)).unwrap();
        let cry_v =
            EmulatedFieldVar::<Fr, P256Fq>::new_witness(cs.clone(), || Ok(rc_affine.y)).unwrap();
        crx_v.enforce_equal(&rx_v).unwrap();
        cry_v.enforce_equal(&ry_v).unwrap();

        assert!(!cs.is_satisfied().unwrap());
    }
}

// ============================================================
// Sigmabus: padded multi-block SHA-256 over real message bytes
// ============================================================

/// Number of SHA-256 blocks needed under FIPS 180-4 padding
/// (0x80, zero padding, 64-bit big-endian message length).
pub fn sha256_padded_block_count(message_len_bytes: usize) -> usize {
    (message_len_bytes + 1 + 8).div_ceil(64)
}

/// Host-side helper producing the big-endian 32-bit words of every padded block.
pub fn sha256_padded_blocks(message: &[u8]) -> Vec<[u32; 16]> {
    let message_len = message.len();
    let n = sha256_padded_block_count(message_len);
    let mut padded = vec![0u8; n * 64];
    padded[..message_len].copy_from_slice(message);
    padded[message_len] = 0x80;
    padded[n * 64 - 8..].copy_from_slice(&((message_len as u64) * 8).to_be_bytes());
    (0..n)
        .map(|b| {
            let mut words = [0u32; 16];
            for (i, w) in words.iter_mut().enumerate() {
                let off = b * 64 + i * 4;
                *w = u32::from_be_bytes(padded[off..off + 4].try_into().unwrap());
            }
            words
        })
        .collect()
}

/// SHA-256 IVC step circuit for a fixed-length message. The final block's
/// padding bytes are constrained in-circuit, so a prover cannot shorten the
/// absorbed message without breaking the step constraints.
pub struct Sha256PaddedCircuit<F: SonobeField> {
    message_len_bytes: usize,
    _field: core::marker::PhantomData<F>,
}

impl<F: SonobeField> Sha256PaddedCircuit<F> {
    pub fn new(message_len_bytes: usize) -> Self {
        Self {
            message_len_bytes,
            _field: core::marker::PhantomData,
        }
    }

    pub fn message_len_bytes(&self) -> usize {
        self.message_len_bytes
    }

    pub fn num_blocks(&self) -> usize {
        sha256_padded_block_count(self.message_len_bytes)
    }

    fn enforce_block_padding(
        &self,
        i: &FpVar<F>,
        block: &[UInt32<F>; 16],
    ) -> Result<(), SynthesisError> {
        use ark_r1cs_std::fields::FieldVar;
        use ark_r1cs_std::uint8::UInt8;

        let final_block = self.num_blocks().saturating_sub(1);
        let rem = self.message_len_bytes % 64;
        let message_len_bits = self.message_len_bytes as u64 * 8;

        let is_final_block = i.is_eq(&FpVar::constant(F::from(final_block as u64)))?;

        // When rem >= 56, SHA-256 padding spans two blocks:
        // the 0x80 byte is in the penultimate block and the
        // 64-bit bit length is in the final block.
        let split_padding = rem >= 56;

        let padding_start_block = if split_padding {
            final_block
                .checked_sub(1)
                .expect("split SHA-256 padding requires at least two blocks")
        } else {
            final_block
        };

        let is_padding_start_block =
            i.is_eq(&FpVar::constant(F::from(padding_start_block as u64)))?;

        for (word_index, word) in block.iter().enumerate() {
            for (offset, byte) in word.to_bytes_be()?.iter().enumerate() {
                let byte_index = word_index * 4 + offset;

                if !split_padding {
                    // Single padding block:
                    // data || 0x80 || zero* || bit_length
                    let expected = if byte_index == rem {
                        Some(0x80u8)
                    } else if byte_index > rem && byte_index < 56 {
                        Some(0u8)
                    } else if byte_index >= 56 {
                        let shift = 56 - 8 * (byte_index - 56);
                        Some(((message_len_bits >> shift) & 0xff) as u8)
                    } else {
                        None
                    };

                    if let Some(expected) = expected {
                        byte.conditional_enforce_equal(
                            &UInt8::constant(expected),
                            &is_final_block,
                        )?;
                    }
                } else {
                    // Penultimate block:
                    // remaining data || 0x80 || zero*
                    let expected_penultimate = if byte_index == rem {
                        Some(0x80u8)
                    } else if byte_index > rem {
                        Some(0u8)
                    } else {
                        None
                    };

                    if let Some(expected) = expected_penultimate {
                        byte.conditional_enforce_equal(
                            &UInt8::constant(expected),
                            &is_padding_start_block,
                        )?;
                    }

                    // Final block:
                    // 56 zero bytes || 64-bit big-endian bit length
                    let expected_final = if byte_index < 56 {
                        0u8
                    } else {
                        let shift = 56 - 8 * (byte_index - 56);
                        ((message_len_bits >> shift) & 0xff) as u8
                    };

                    byte.conditional_enforce_equal(
                        &UInt8::constant(expected_final),
                        &is_final_block,
                    )?;
                }
            }
        }

        Ok(())
    }
}

impl<F: SonobeField> FCircuit for Sha256PaddedCircuit<F> {
    type Field = F;
    type State = [F; 8];
    type StateVar = [FpVar<F>; 8];
    type ExternalInputs = [u32; 16];
    type ExternalOutputs = ();

    fn same_state_shape(_a: &Self::State, _b: &Self::State) -> bool {
        true
    }

    fn sigmabus_final_binding(i: usize, state: &Self::State) -> Option<SigmabusFinalBinding<F>> {
        sha256_sigmabus_final_binding(i, state)
    }

    fn enforce_sigmabus_final_binding(
        cs: ConstraintSystemRef<F>,
        i: &FpVar<F>,
        state: &Self::StateVar,
        binding: &Option<SigmabusFinalBinding<F>>,
    ) -> Result<(), SynthesisError> {
        Sha256CompressionCircuit::<F>::enforce_sigmabus_final_binding(cs, i, state, binding)
    }

    fn dummy_state(&self) -> Self::State {
        IV.map(F::from)
    }

    fn dummy_external_inputs(&self) -> Self::ExternalInputs {
        [0; 16]
    }

    fn synthesize_step(
        &self,
        i: FpVar<F>,
        z_i: Self::StateVar,
        block: Self::ExternalInputs,
    ) -> Result<(Self::StateVar, Self::ExternalOutputs), SynthesisError> {
        let cs = z_i[0].cs();
        let words: [UInt32<F>; 16] = UInt32::new_witness_vec(cs, &block)?
            .into_iter()
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        self.enforce_block_padding(&i, &words)?;
        let state: [UInt32<F>; 8] = z_i
            .map(|word| UInt32::from_fp(&word).map(|(u, _)| u))
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .unwrap();
        let output = compress_vars(words, state)?;
        Ok((
            output
                .map(|word| word.to_fp())
                .into_iter()
                .collect::<Result<Vec<_>, _>>()?
                .try_into()
                .unwrap(),
            (),
        ))
    }
}

#[cfg(test)]
mod padding_tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_r1cs_std::uint32::UInt32;
    use ark_relations::gr1cs::{
        ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
    };

    struct PaddingCircuit {
        len: usize,
        words: [u32; 16],
        claimed_block: usize,
    }

    impl ConstraintSynthesizer<Fr> for PaddingCircuit {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
            let circuit = Sha256PaddedCircuit::<Fr>::new(self.len);
            let i = FpVar::new_input(cs.clone(), || Ok(Fr::from(self.claimed_block as u64)))?;
            let words: [UInt32<Fr>; 16] = UInt32::new_witness_vec(cs.clone(), &self.words)?
                .try_into()
                .unwrap();
            circuit.enforce_block_padding(&i, &words)
        }
    }

    fn satisfies(len: usize, words: [u32; 16], claimed_block: usize) -> bool {
        let cs = ConstraintSystem::<Fr>::new_ref();
        PaddingCircuit {
            len,
            words,
            claimed_block,
        }
        .generate_constraints(cs.clone())
        .unwrap();
        cs.is_satisfied().unwrap()
    }

    #[test]
    fn padding_constraints_accept_honest_blocks_and_reject_tampering() {
        // rem = 55: padding and bit length both fit in the final block.
        let single = sha256_padded_blocks(&[0u8; 55]);
        assert_eq!(single.len(), 1);
        assert!(satisfies(55, single[0], 0));

        let mut tampered_single = single[0];
        tampered_single[14] ^= 1;
        assert!(!satisfies(55, tampered_single, 0));

        // rem = 56: 0x80 lands in the penultimate block and the bit length
        // occupies the final block. The old implementation wrongly applied the
        // padding map only to the final block.
        let split = sha256_padded_blocks(&[0u8; 56]);
        assert_eq!(split.len(), 2);
        assert!(satisfies(56, split[0], 0));
        assert!(satisfies(56, split[1], 1));

        let mut tampered_penultimate = split[0];
        tampered_penultimate[14] ^= 1;
        assert!(!satisfies(56, tampered_penultimate, 0));

        let mut tampered_final = split[1];
        tampered_final[15] ^= 1;
        assert!(!satisfies(56, tampered_final, 1));
    }
}

#[cfg(test)]
mod e2e_tests {
    use super::*;
    use ark_bn254::{Bn254, Fr, G1Projective as C1};
    use ark_grumpkin::Projective as C2;
    use ark_serialize::CanonicalSerialize;
    use ark_std::{error::Error, rand::thread_rng, sync::Arc};
    use sha2::{Digest, Sha256};
    use sonobe_fs::nova::{CycleFoldNova, Nova};
    use sonobe_primitives::commitments::pedersen::Pedersen;
    use sonobe_primitives::transcripts::griffin::{GriffinParams, sponge::GriffinSponge};
    use sonobe_snarks::cp::legogroth16 as lg;

    use crate::compilers::cyclefold::{CycleFoldBasedIVC, CycleFoldBasedIVCDecider};
    use crate::{
        IVCKeyGenerator, IVCPreprocessor, IVCProofCompressor, IVCStatefulProver, IVCVerifier,
    };

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
        lg::LegoGroth16<Bn254>,
    >;

    fn hex_string(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Full decoupled pipeline over real image bytes:
    /// M -> h = SHA-256(M) -> IVC folding -> LegoGroth16 compression ->
    /// public (num_blocks, h_hi, h_lo) that the Dorian proof must match.
    #[test]
    fn test_e2e_full_pipeline() -> Result<(), Box<dyn Error>> {
        let image_path = std::env::var("E2E_IMAGE_PATH").unwrap_or_else(|_| {
            "/data/doriansig/experiments/signed_images/camera_output.png".to_string()
        });
        let msg_len: usize = std::env::var("E2E_MSG_LEN")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(65);
        let out_dir = std::env::var("E2E_OUT_DIR")
            .unwrap_or_else(|_| "/data/doriansig/experiments/raw_sigmabus".to_string());

        let raw = std::fs::read(&image_path)?;
        assert!(raw.len() >= msg_len, "image shorter than requested length");
        let message = raw[..msg_len].to_vec();

        let blocks = sha256_padded_blocks(&message);
        let circuit = FC::new(msg_len);
        let n = circuit.num_blocks();
        assert_eq!(blocks.len(), n);

        let mut rng = thread_rng();
        let pp = <IVCType as IVCPreprocessor>::preprocess(
            (131072, 16384, Arc::new(GriffinParams::new(16, 5, 9))),
            &mut rng,
        )?;
        let (pk, vk) = <IVCType as IVCKeyGenerator>::generate_keys(pp, &circuit)?;
        let initial_state = circuit.dummy_state();

        let mut prover =
            IVCStatefulProver::<_, IVCType>::new(&pk, &circuit, initial_state.clone())?;
        let mut truncated_state = initial_state.clone();
        for (step, block) in blocks.iter().enumerate() {
            prover.prove_step(*block, &mut rng)?;
            IVCType::verify::<FC>(
                &vk,
                prover.i,
                &prover.initial_state,
                &prover.current_state,
                &prover.current_proof,
            )?;
            if step + 1 == n - 1 {
                truncated_state = prover.current_state.clone();
            }
        }
        assert_eq!(prover.i, n);
        let current_state = prover.current_state.clone();

        let binding = <FC as FCircuit>::sigmabus_final_binding(n, &current_state)
            .ok_or("SHA-256 circuit must publish a Sigmabus binding")?;

        let words: Vec<u32> = current_state.iter().map(field_word_to_u32).collect();
        let mut digest = [0u8; 32];
        for (i, w) in words.iter().enumerate() {
            digest[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        let h_hi = words_to_u128(&words[0..4].try_into().unwrap());
        let h_lo = words_to_u128(&words[4..8].try_into().unwrap());

        let reference: [u8; 32] = Sha256::digest(&message).into();
        assert_eq!(digest, reference, "in-circuit state must equal SHA-256(M)");

        let (dpk, dvk) =
            <Decider as IVCProofCompressor>::preprocess_and_generate_keys(&circuit, vk, &mut rng)?;
        let compressed = <Decider as IVCProofCompressor>::prove::<FC>(
            &dpk,
            n,
            &initial_state,
            &current_state,
            &prover.current_proof,
            Some(binding),
            &mut rng,
        )?;

        // LegoVerify(pi_final, h_hi, h_lo) == true
        <Decider as IVCProofCompressor>::verify::<FC>(
            &dvk,
            n,
            &initial_state,
            &current_state,
            &compressed,
            Some(binding),
        )
        .map_err(|e| format!("LegoGroth16 rejected a valid proof: {e}"))?;

        // Negative: one bit flipped in the published h_hi must be rejected.
        let mut tampered = binding;
        tampered.h_hi += Fr::from(1u64);
        assert!(
            <Decider as IVCProofCompressor>::verify::<FC>(
                &dvk,
                n,
                &initial_state,
                &current_state,
                &compressed,
                Some(tampered),
            )
            .is_err(),
            "verifier must reject a tampered h_hi"
        );

        // Negative: an intermediate folding state presented as the final one.
        let trunc_binding = <FC as FCircuit>::sigmabus_final_binding(n, &truncated_state)
            .ok_or("SHA-256 circuit must publish a Sigmabus binding")?;
        assert!(
            <Decider as IVCProofCompressor>::verify::<FC>(
                &dvk,
                n,
                &initial_state,
                &truncated_state,
                &compressed,
                Some(trunc_binding),
            )
            .is_err(),
            "verifier must reject an intermediate state presented as final"
        );

        std::fs::create_dir_all(&out_dir)?;
        let mut proof_bytes = Vec::new();
        compressed
            .0
            .groth16_proof
            .serialize_compressed(&mut proof_bytes)?;
        std::fs::write(format!("{out_dir}/pi_final.bin"), &proof_bytes)?;
        std::fs::write(format!("{out_dir}/message.bin"), &message)?;
        let digest_hex = hex_string(&digest);
        let proof_len = proof_bytes.len();
        let report = format!(
            "image_path={image_path}\nmessage_len={msg_len}\nnum_blocks={n}\ndigest_hex={digest_hex}\nh_hi_dec={h_hi}\nh_lo_dec={h_lo}\nlego_verify=true\npi_final_bytes={proof_len}\n"
        );
        std::fs::write(format!("{out_dir}/protogalaxy_h_split.txt"), report)?;
        Ok(())
    }
}
