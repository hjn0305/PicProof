use rug::{integer::Order, Integer};
use sha2::{Digest, Sha256};
use p256::elliptic_curve::sec1::FromEncodedPoint;
use p256::elliptic_curve::group::Group;
use p256::{AffinePoint, EncodedPoint, ProjectivePoint};

pub const D_REG: &[u8] = b"PICPROOF-PKI-CMPK-v1";

pub const P256_BASE_FIELD_DEC: &str =
    "115792089210356248762697446949407573530086143415290314195533631308867097853951";

/// Normative encoding:
/// Encode(cmPK) = SEC1_compressed(C0) || SEC1_compressed(C1)
/// Each point must be exactly 33 bytes and must not be infinity.
pub fn encode_cmpk(c0: &[u8], c1: &[u8]) -> Result<[u8; 66], String> {
    if c0.len() != 33 {
        return Err(format!("C0 must be 33 bytes, got {}", c0.len()));
    }

    if c1.len() != 33 {
        return Err(format!("C1 must be 33 bytes, got {}", c1.len()));
    }

    if !matches!(c0[0], 0x02 | 0x03) {
        return Err(format!(
            "C0 must use compressed SEC1 prefix 0x02/0x03, got 0x{:02x}",
            c0[0]
        ));
    }

    if !matches!(c1[0], 0x02 | 0x03) {
        return Err(format!(
            "C1 must use compressed SEC1 prefix 0x02/0x03, got 0x{:02x}",
            c1[0]
        ));
    }

    // Length and prefix checks are not sufficient: reject non-curve SEC1 points.
    // This ensures the registered commitment encoding denotes actual P-256 points.
    for (label, bytes) in [("C0", c0), ("C1", c1)] {
        let encoded = EncodedPoint::from_bytes(bytes)
            .map_err(|e| format!("{} is not a valid SEC1 point: {}", label, e))?;
        let affine = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))
            .ok_or_else(|| format!("{} is not a valid P-256 curve point", label))?;
        if ProjectivePoint::from(affine) == ProjectivePoint::IDENTITY {
            return Err(format!("{} must not be the point at infinity", label));
        }
    }

    let mut out = [0u8; 66];
    out[..33].copy_from_slice(c0);
    out[33..].copy_from_slice(c1);

    Ok(out)
}

/// H_reg(cmPK):
///
/// digest_c = SHA256(
///     "PICPROOF-PKI-CMPK-v1"
///     || 0x00
///     || Encode(cmPK)
///     || I2OSP_4_BE(counter)
/// )
///
/// Interpret digest as a 256-bit unsigned big-endian integer.
/// Accept iff x < P-256 base-field modulus; otherwise increment counter.
pub fn h_reg_from_encoded_cmpk(
    encoded_cmpk: &[u8; 66],
) -> Result<(Integer, u32, [u8; 32]), String> {
    let modulus =
        Integer::from_str_radix(P256_BASE_FIELD_DEC, 10)
            .map_err(|_| "failed to parse P-256 base-field modulus")?;

    for counter in 0u32..=u32::MAX {
        let mut hasher = Sha256::new();

        hasher.update(D_REG);
        hasher.update([0x00]);
        hasher.update(encoded_cmpk);
        hasher.update(counter.to_be_bytes());

        let digest: [u8; 32] = hasher.finalize().into();

        let candidate =
            Integer::from_digits(&digest, Order::MsfBe);

        if candidate < modulus {
            return Ok((candidate, counter, digest));
        }
    }

    Err("H_reg rejection sampling exhausted u32 counter space".into())
}

pub fn h_reg(
    c0: &[u8],
    c1: &[u8],
) -> Result<(Integer, u32, [u8; 32], [u8; 66]), String> {
    let encoded = encode_cmpk(c0, c1)?;
    let (leaf, counter, digest) =
        h_reg_from_encoded_cmpk(&encoded)?;

    Ok((leaf, counter, digest, encoded))
}


#[cfg(test)]
mod point_validation_tests {
    use super::*;
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    #[test]
    fn rejects_invalid_curve_point_with_valid_length_and_prefix() {
        let valid = ProjectivePoint::GENERATOR.to_affine().to_encoded_point(true);
        let c0 = valid.as_bytes();
        let mut invalid = [0u8; 33];
        invalid[0] = 0x02;
        invalid[1..].fill(0xff);
        assert!(encode_cmpk(c0, &invalid).is_err());
    }

    #[test]
    fn accepts_valid_compressed_points() {
        let g = ProjectivePoint::GENERATOR.to_affine().to_encoded_point(true);
        assert!(encode_cmpk(g.as_bytes(), g.as_bytes()).is_ok());
    }
}
