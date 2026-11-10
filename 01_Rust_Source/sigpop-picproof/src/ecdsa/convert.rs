//! Convert functions for EC operations
use p256::elliptic_curve::ops::Reduce;
use p256::elliptic_curve::group::ff::PrimeField;
use p256::Scalar;
use p256::ProjectivePoint;

use rug::Integer;
use std::convert::TryInto;

/// Convert bytes to p256::Scalar by reducing a big-endian integer mod q.
///
/// This is for digest and x-coordinate interpretation, not for proof scalar
/// encodings or Fiat-Shamir challenges.
pub fn bytes_to_scalar(input: &[u8]) -> Scalar {
    let mut bytes = input.to_vec();
    while bytes.len() < 32 {
        bytes.insert(0, 0);
    }
    let bytes_array: [u8; 32] = bytes
        .try_into()
        .expect("bytes_to_scalar accepts at most 32 bytes");
    scalar_from_be_bytes(&bytes_array)
}

/// Interpret a 32-byte scalar encoding in canonical form.
///
/// Returns `None` when the integer is not strictly less than the P-256 group
/// order.
pub fn canonical_bytes_to_scalar(input: &[u8; 32]) -> Option<Scalar> {
    Scalar::from_repr((*input).into()).into()
}

/// Convert a signed rug::Integer to p256::Scalar modulo the P-256 order.
pub fn integer_to_scalar(input: &Integer) -> Scalar {
    let magnitude = input.clone().abs();
    let magnitude_scalar = magnitude_to_scalar(&magnitude);
    if input.is_negative() {
        -magnitude_scalar
    } else {
        magnitude_scalar
    }
}

fn magnitude_to_scalar(input: &Integer) -> Scalar {
    let mut bytes = input.to_digits(rug::integer::Order::MsfBe);
    // The P-256 field size is 32 bytes. Pad the byte array if needed.
    while bytes.len() < 32 {
        bytes.insert(0, 0);
    }
    if bytes.len() == 32 {
        let bytes_array: [u8; 32] = bytes
            .try_into()
            .expect("integer_to_scalar byte length must be exactly 32");
        return scalar_from_be_bytes(&bytes_array);
    }
    reduce_big_endian_bytes(&bytes)
}

/// Interpret one 32-byte big-endian integer modulo the P-256 group order.
fn scalar_from_be_bytes(bytes: &[u8; 32]) -> Scalar {
    if let Some(scalar) = canonical_bytes_to_scalar(bytes) {
        return scalar;
    }
    Scalar::reduce_bytes(&(*bytes).into())
}

/// Reduce an arbitrary-length big-endian integer modulo the P-256 order.
fn reduce_big_endian_bytes(bytes: &[u8]) -> Scalar {
    let mut acc = Scalar::ZERO;
    for chunk in bytes.chunks(32) {
        for _ in 0..chunk.len() * 8 {
            acc += acc;
        }
        let mut padded = [0u8; 32];
        padded[32 - chunk.len()..].copy_from_slice(chunk);
        acc += scalar_from_be_bytes(&padded);
    }
    acc
}


/// Convert p256::Scalar to rug::Integer
pub fn scalar_to_integer(input: &Scalar) -> Integer {
    let bytes = input.to_repr();
    Integer::from_digits(&bytes, rug::integer::Order::MsfBe)
}

/// Input scalar of type rug::Integer; Output G^{scalar}
pub fn scalar_mult_on_point_g(scalar: &Integer) -> ProjectivePoint {
    let scalar_p256: Scalar = integer_to_scalar(&scalar);
    ProjectivePoint::GENERATOR * scalar_p256
}

/// Input scalar of type rug::Integer; Output P^{scalar}
pub fn scalar_mult_on_point_p(scalar: &Integer, point: ProjectivePoint) -> ProjectivePoint {
    let scalar_p256: Scalar = integer_to_scalar(&scalar);
    point * scalar_p256
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORDER_HEX: &str =
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
    const ORDER_MINUS_ONE_HEX: &str =
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550";
    const MAX_HEX: &str =
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

    fn decode_hex<const N: usize>(hex: &str) -> [u8; N] {
        let mut out = [0u8; N];
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn scalar_mapping_handles_order_boundaries() {
        let order_minus_one = decode_hex::<32>(ORDER_MINUS_ONE_HEX);
        let order = decode_hex::<32>(ORDER_HEX);
        let max = decode_hex::<32>(MAX_HEX);

        assert_eq!(
            bytes_to_scalar(&order_minus_one),
            Scalar::from_repr(order_minus_one.into()).unwrap()
        );
        assert_eq!(bytes_to_scalar(&order), Scalar::ZERO);
        assert_eq!(
            bytes_to_scalar(&max),
            Scalar::reduce_bytes(&max.into())
        );
    }

    #[test]
    fn integer_mapping_reduces_large_values() {
        let order = Integer::from_str_radix(ORDER_HEX, 16).unwrap();
        let order_minus_one = Integer::from_str_radix(ORDER_MINUS_ONE_HEX, 16).unwrap();
        let max = Integer::from_str_radix(MAX_HEX, 16).unwrap();
        let overflow = (Integer::from(1) << 256) + Integer::from(7);

        assert_eq!(integer_to_scalar(&Integer::from(-1)), -Scalar::ONE);
        assert_eq!(
            integer_to_scalar(&(-(order.clone() + Integer::from(1)))),
            -Scalar::ONE
        );
        assert_eq!(integer_to_scalar(&Integer::from(0)), Scalar::ZERO);
        assert_eq!(integer_to_scalar(&order), Scalar::ZERO);
        assert_eq!(
            integer_to_scalar(&(order.clone() + Integer::from(1))),
            Scalar::ONE
        );
        assert_eq!(
            integer_to_scalar(&order_minus_one),
            Scalar::from_repr(decode_hex::<32>(ORDER_MINUS_ONE_HEX).into()).unwrap()
        );
        assert_eq!(
            integer_to_scalar(&max),
            Scalar::reduce_bytes(&decode_hex::<32>(MAX_HEX).into())
        );

        let mut expected = Scalar::ONE;
        for _ in 0..256 {
            expected += expected;
        }
        expected += Scalar::from(7u64);
        assert_eq!(integer_to_scalar(&overflow), expected);
    }
}
