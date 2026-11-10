//! Strict binding between a committed-PK Sigma statement and a CA-issued Merkle credential.
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::ProjectivePoint;
use rug::Integer;

use super::ca_registry::DeviceRegistryCredential;
use super::pk_link::h_reg;

/// Recompute Encode(cmPK) and H_reg(cmPK) from the public Sigma statement.
pub fn derive_sigma_cm_pk_leaf(
    cm_pk: &[ProjectivePoint; 2],
) -> Result<(String, Integer), String> {
    let c0 = cm_pk[0].to_affine().to_encoded_point(true);
    let c1 = cm_pk[1].to_affine().to_encoded_point(true);
    let (leaf, _counter, _digest, encoded) = h_reg(c0.as_bytes(), c1.as_bytes())?;
    Ok((hex::encode(encoded), leaf))
}

/// Compare the Sigma statement against the CA-issued private enrollment credential.
pub fn verify_sigma_cm_pk_credential(
    cm_pk: &[ProjectivePoint; 2],
    credential: &DeviceRegistryCredential,
) -> Result<(String, Integer), String> {
    if credential.version != 1 {
        return Err("Unsupported device registry credential version".into());
    }
    let (encoded_hex, leaf) = derive_sigma_cm_pk_leaf(cm_pk)?;
    if !encoded_hex.eq_ignore_ascii_case(&credential.cm_pk_encoded_hex) {
        return Err("Sigma cmPK does not match the CA-issued enrollment credential".into());
    }
    if leaf.to_string() != credential.leaf_decimal {
        return Err("H_reg(Sigma cmPK) does not match the CA-issued leaf".into());
    }
    if credential.path.siblings.len() != credential.depth as usize
        || credential.path.directions.len() != credential.depth as usize {
        return Err("CA-issued Merkle path length does not match credential depth".into());
    }
    Ok((encoded_hex, leaf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecdsa::ca_registry::{DeviceRegistryCredential, MerklePath};
    use crate::ecdsa::picproof_k::picproof_commitment_generator_k;

    #[test]
    fn exact_cm_pk_and_leaf_are_required() {
        let pk = ProjectivePoint::GENERATOR * p256::Scalar::from(7u64);
        let v = p256::Scalar::from(11u64);
        let cm = [
            ProjectivePoint::GENERATOR * v,
            pk + picproof_commitment_generator_k() * v,
        ];
        let c0 = cm[0].to_affine().to_encoded_point(true);
        let c1 = cm[1].to_affine().to_encoded_point(true);
        let (leaf, _, _, encoded) = h_reg(c0.as_bytes(), c1.as_bytes()).unwrap();
        let credential = DeviceRegistryCredential {
            version: 1,
            registry_id: "registry-test".into(),
            depth: 0,
            cm_pk_encoded_hex: hex::encode(encoded),
            leaf_decimal: leaf.to_string(),
            path: MerklePath { siblings: vec![], directions: vec![] },
        };
        assert!(verify_sigma_cm_pk_credential(&cm, &credential).is_ok());
        let mut wrong_leaf = credential.clone();
        let mut incremented_leaf = leaf.clone();
        incremented_leaf += Integer::from(1);
        wrong_leaf.leaf_decimal = incremented_leaf.to_string();
        assert!(verify_sigma_cm_pk_credential(&cm, &wrong_leaf).is_err());
        let other_cm = [cm[0], cm[1] + ProjectivePoint::GENERATOR];
        assert!(verify_sigma_cm_pk_credential(&other_cm, &credential).is_err());
    }
}
