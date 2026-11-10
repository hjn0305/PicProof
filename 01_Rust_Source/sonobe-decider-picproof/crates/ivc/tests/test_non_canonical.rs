//! N-11: non-canonical representation attacks on verifier-supplied inputs.
//!
//! The camera public key and the published digest binding both cross a byte
//! boundary before the verifier uses them. A non-canonical representation
//! attack hands the verifier an encoding whose integer value is >= the field
//! modulus (or a point whose x is not a canonical base-field element). If the
//! deserializer accepts such bytes without validating, one logical statement
//! gains several distinct byte encodings, which is the classic malleability
//! route into public-key and commitment equality checks.
//!
//! Two curves matter here:
//!   BN254 scalar field  -> transcript digests and the Sigmabus h_hi/h_lo pair
//!   P-256 (secp256r1)   -> the camera signing public key itself
//!
//! Emits one `N11_CASE {...}` line per probe. `safe` means the attack was
//! refused or normalised; `stage` records where.

use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

/// Little-endian, fixed-width encoding of `MODULUS + k` for a field `F`.
fn modulus_plus_k<F: PrimeField>(k: u64) -> Vec<u8> {
    let mut bytes = F::MODULUS.to_bytes_le();
    // pad to the serialized width of the modulus, then add k with carry
    let width = bytes.len().max(32);
    bytes.resize(width, 0u8);
    let mut carry = k;
    for b in bytes.iter_mut() {
        let sum = *b as u128 + carry as u128;
        *b = sum as u8;
        carry = (sum >> 8) as u64;
        if carry == 0 {
            break;
        }
    }
    bytes
}

fn emit(id: &str, curve: &str, attack: &str, safe: bool, stage: &str) {
    println!(
        "N11_CASE {{\"id\":\"{id}\",\"curve\":\"{curve}\",\"attack\":\"{attack}\",\
         \"safe\":{safe},\"stage\":\"{stage}\"}}"
    );
}

/// Probe one non-canonical integer encoding against a field's deserializer.
fn probe_field<F: PrimeField>(id: &str, curve: &str, label: &str, bytes: &[u8]) {
    // `deserialize_uncompressed` is the checked path in arkworks.
    let checked = <F as CanonicalDeserialize>::deserialize_uncompressed(bytes);
    // `deserialize_uncompressed_unchecked` is the path a careless caller takes.
    let unchecked = <F as CanonicalDeserialize>::deserialize_uncompressed_unchecked(bytes);

    let reduced_is_zero = match &checked {
        Ok(v) => v.into_bigint() < F::MODULUS,
        Err(_) => true,
    };
    let accepted_as_canonical = checked.is_ok();
    let refused_at_checked = checked.is_err();
    let unchecked_leaks = unchecked.is_ok() && !reduced_is_zero;

    // The attack only succeeds if some accepted encoding yields a value that
    // is not the canonical residue.
    let safe = !unchecked_leaks && (!accepted_as_canonical || reduced_is_zero);
    let stage = if refused_at_checked {
        "checked_deserialize_rejected"
    } else if unchecked_leaks {
        "UNCHECKED_ACCEPTED_NON_CANONICAL"
    } else {
        "normalised_to_canonical_residue"
    };

    emit(id, curve, label, safe, stage);
    println!(
        "  detail {id}: checked_ok={accepted_as_canonical} \
         checked_err={refused_at_checked} unchecked_ok={} residue_canonical={reduced_is_zero} \
         bytes_len={}",
        unchecked.is_ok(),
        bytes.len(),
    );
}

#[test]
fn test_non_canonical_representations() {
    println!("=== N-11 non-canonical representation probes ===");

    // ------------------------------------------------------------------ F1/Fq
    type BnFq = ark_bn254::Fq;
    type P256Fq = ark_secp256r1::Fq;

    probe_field::<ark_bn254::Fr>(
        "F-1",
        "bn254-fr",
        "value == p",
        &modulus_plus_k::<ark_bn254::Fr>(0),
    );
    probe_field::<ark_bn254::Fr>(
        "F-2",
        "bn254-fr",
        "value == p+1",
        &modulus_plus_k::<ark_bn254::Fr>(1),
    );
    probe_field::<ark_bn254::Fr>(
        "F-3",
        "bn254-fr",
        "value == p+7",
        &modulus_plus_k::<ark_bn254::Fr>(7),
    );
    probe_field::<BnFq>("F-4", "bn254-fq", "value == p", &modulus_plus_k::<BnFq>(0));
    probe_field::<BnFq>(
        "F-5",
        "bn254-fq",
        "value == p+1",
        &modulus_plus_k::<BnFq>(1),
    );
    probe_field::<P256Fq>("K-1", "p256-fq", "value == p", &modulus_plus_k::<P256Fq>(0));
    probe_field::<P256Fq>(
        "K-2",
        "p256-fq",
        "value == p+1",
        &modulus_plus_k::<P256Fq>(1),
    );
    probe_field::<P256Fq>(
        "K-3",
        "p256-fq",
        "value == p+7",
        &modulus_plus_k::<P256Fq>(7),
    );

    // ------------------------------------------------- point-level x for PK
    // A camera public key is a P-256 point. Confirm the checked deserializer
    // refuses a coordinate equal to the modulus, and record what the unchecked
    // path does with the same bytes.
    let p_bytes = modulus_plus_k::<P256Fq>(0);
    let checked_x = <P256Fq as CanonicalDeserialize>::deserialize_uncompressed(&p_bytes[..]);
    let unchecked_x =
        <P256Fq as CanonicalDeserialize>::deserialize_uncompressed_unchecked(&p_bytes[..]);
    emit(
        "K-6",
        "p256-fq",
        "x == p used as a public-key coordinate",
        checked_x.is_err(),
        if checked_x.is_err() {
            "checked_deserialize_rejected"
        } else {
            "ACCEPTED"
        },
    );
    println!(
        "  detail K-6: checked_err={} unchecked_ok={}",
        checked_x.is_err(),
        unchecked_x.is_ok(),
    );

    // generator must be on curve (sanity for the assertions below)
    let g = <ark_secp256r1::Affine as AffineRepr>::generator();
    assert!(g.is_on_curve(), "P-256 generator must be on curve");
    assert!(g.is_in_correct_subgroup_assuming_on_curve());
    emit(
        "K-0",
        "p256-g1",
        "generator baseline on-curve",
        true,
        "sanity_ok",
    );

    // Negation gives a second valid point with the SAME x. A consumer that
    // identifies keys by x alone therefore admits two distinct public keys;
    // compressed encodings must carry the sign bit to stay injective.
    let neg = -g;
    assert_eq!(g.x(), neg.x(), "P and -P must share x");
    assert!(neg.is_on_curve());
    let mut a = Vec::new();
    let mut b = Vec::new();
    g.serialize_compressed(&mut a).unwrap();
    neg.serialize_compressed(&mut b).unwrap();
    emit(
        "K-4",
        "p256-g1",
        "x-collision between P and -P under compressed encoding",
        a != b,
        if a != b {
            "sign_bit_distinguishes_encodings"
        } else {
            "SIGN_BIT_LOST"
        },
    );
    println!("  compressed(P)={a:02x?}");
    println!("  compressed(-P)={b:02x?}");

    // And the same pair under uncompressed encoding must stay distinct too.
    let mut ua = Vec::new();
    let mut ub = Vec::new();
    g.serialize_uncompressed(&mut ua).unwrap();
    neg.serialize_uncompressed(&mut ub).unwrap();
    emit(
        "K-5",
        "p256-g1",
        "x-collision between P and -P under uncompressed encoding",
        ua != ub,
        if ua != ub {
            "y_field_distinguishes_encodings"
        } else {
            "ENCODINGS_IDENTICAL"
        },
    );
}
