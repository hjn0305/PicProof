//! This module includes implementations related to Elliptic curve points
use p256::{Scalar, ProjectivePoint};
use elliptic_curve::group::GroupEncoding; 
use core::ops::{Mul, Add};

use serde::{Serializer, Serialize}; // ser/de for sigma proof
use serde::{Deserialize, Deserializer}; // ser/de for sigma proof
use p256::elliptic_curve::generic_array::GenericArray;
use elliptic_curve::PrimeField;
use super::convert::canonical_bytes_to_scalar;

use std::borrow::Borrow;
use std::convert::TryInto;

use ark_secp256r1::{Projective, Affine, Fr};
use ark_serialize::SerializationError;
pub use ark_std::io::{Read, Write};

use ark_ec::CurveGroup;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};

/// Elliptic curve point over P256
#[derive(PartialEq, Clone, Copy)]
pub struct ArkECPoint(pub Projective);

/// Elliptic curve point over P256
#[derive(PartialEq, Clone, Copy)]
pub struct ECPoint(pub ProjectivePoint);

/// Elliptic curve scalar over P256
#[derive(Clone, Copy)]
pub struct ArkScalar(pub Fr);

/// Elliptic curve scalar over P256
#[derive(Clone, Copy)]
pub struct P256Scalar(pub Scalar);


impl ECPoint {
    /// Default
    pub fn default() -> ECPoint {
        ECPoint(ProjectivePoint::default())
    }
}
impl Mul<Scalar> for ECPoint {
    type Output = ECPoint;

    fn mul(self, scalar: Scalar) -> ECPoint { 
        ECPoint(self.0 * scalar)
    }
}

// implement Add for ECPoint
impl Add<ProjectivePoint> for ECPoint {
    type Output = ECPoint;
  
    fn add(self, other: ProjectivePoint) -> Self::Output {
        ECPoint(self.0 + other)
    }
}

impl Mul<P256Scalar> for ECPoint {
    type Output = ECPoint;

    fn mul(self, scalar: P256Scalar) -> ECPoint { 
        ECPoint(self.0 * scalar.0)
    }
}

// Implement Serialize for ECPoint
impl Serialize for ECPoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.0.to_bytes(); 
        bytes.serialize(serializer)
    }
}

// Implement Deserialize for ECPoint
impl<'de> Deserialize<'de> for ECPoint { // Size: 33 bytes
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        if bytes.len() != 33 {
            return Err(serde::de::Error::custom(format!("Expected 33 bytes for SEC1 point, got {}", bytes.len())));
        }
        let generic_bytes: &<ProjectivePoint as GroupEncoding>::Repr = GenericArray::from_slice(&bytes);

        let point = ProjectivePoint::from_bytes(generic_bytes);
        let affine = point.into_option().ok_or_else(|| serde::de::Error::custom("Invalid SEC1 P-256 curve point encoding"))?;
        Ok(ECPoint(affine.into()))
    }
}

// Implement Serialize for ArkECPoint
impl Serialize for ArkECPoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = Vec::new();
        self.0.serialize_compressed(&mut bytes).unwrap();
        bytes.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ArkECPoint { // Size: 33 Bytes
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        let point = Projective::deserialize_compressed(&bytes[..])
            .map_err(|e| serde::de::Error::custom(format!("Deserialization error: {:?}", e)))?;
        Ok(ArkECPoint(point))
    }
}

impl ArkECPoint {
    pub fn serialize_compressed<W: Write>(&self, writer: W) -> Result<(), SerializationError> {
        self.0.serialize_compressed(writer)
    }

    pub fn into_affine(&self) -> Affine {
        self.0.into_affine()
    }

    pub fn batch_to_projective(points: &[Self]) -> Vec<Projective> {
        points.iter().map(|p| p.0).collect()
    }

    pub fn batch_from_projective(points: &[Projective]) -> Vec<ArkECPoint> {
        points.iter().map(|p| ArkECPoint(*p)).collect()
    }
}


impl Borrow<Scalar> for P256Scalar {
    fn borrow(&self) -> &Scalar {
        &self.0
    }
}

impl P256Scalar {
    /// Default
    pub fn default() -> P256Scalar {
        P256Scalar(Scalar::default())
    }
}
// Implement Serialize for P256Scalar
impl Serialize for P256Scalar {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.0.to_repr(); 
        bytes.serialize(serializer)
    }
}

// Implement Deserialize for P256Scalar
impl<'de> Deserialize<'de> for P256Scalar { // Size: 32 Bytes
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        let bytes_array: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            serde::de::Error::custom(format!(
                "P256Scalar must be exactly 32 bytes, got {}",
                bytes.len()
            ))
        })?;
        let scalar = canonical_bytes_to_scalar(&bytes_array).ok_or_else(|| {
            serde::de::Error::custom("P256Scalar encoding is not canonical (>= q)")
        })?;
        Ok(P256Scalar(scalar))
    }
}

// Implement Serialize for ArkScalar
impl Serialize for ArkScalar {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use ark_ff::PrimeField;  
        use ark_ff::BigInteger;    
        let bytes = self.0.into_bigint().to_bytes_le(); // testing
        bytes.serialize(serializer)
    }
}

// Implement Deserialize for ArkScalar
impl<'de> Deserialize<'de> for ArkScalar { // Size: 32 Bytes
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        let scalar = Fr::deserialize_compressed(&bytes[..]).unwrap();
        Ok(ArkScalar(scalar))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::group::ff::PrimeField;

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

    fn deserialize_scalar(bytes: &[u8]) -> Result<P256Scalar, bincode::Error> {
        bincode::deserialize(bytes)
    }

    #[test]
    fn p256scalar_deserialization_is_canonical_only() {
        let order_minus_one = decode_hex::<32>(ORDER_MINUS_ONE_HEX);
        let order = decode_hex::<32>(ORDER_HEX);
        let max = decode_hex::<32>(MAX_HEX);

        assert_eq!(
            deserialize_scalar(&bincode::serialize(&order_minus_one.to_vec()).unwrap())
                .unwrap()
                .0,
            Scalar::from_repr(order_minus_one.into()).unwrap()
        );
        assert!(deserialize_scalar(&bincode::serialize(&order.to_vec()).unwrap()).is_err());
        assert!(deserialize_scalar(&bincode::serialize(&max.to_vec()).unwrap()).is_err());
        assert!(deserialize_scalar(&bincode::serialize(&vec![0u8; 31]).unwrap()).is_err());
        assert!(deserialize_scalar(&bincode::serialize(&vec![0u8; 33]).unwrap()).is_err());
    }
}

impl ArkScalar {
    pub fn batch_to_scalar(scalars: &[Self]) -> Vec<Fr> {
        scalars.iter().map(|s| s.0).collect()
    }
    pub fn batch_from_scalar(scalars: &[Fr]) -> Vec<ArkScalar> {
        scalars.iter().map(|s| ArkScalar(*s)).collect()
    }
}
