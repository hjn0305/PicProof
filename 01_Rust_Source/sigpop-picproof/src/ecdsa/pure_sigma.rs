//! This module includes implementations for ECDSA signature verification using sigma protocol
use crate::convert::os2ip;

use p256::ProjectivePoint;
use super::convert::{integer_to_scalar, bytes_to_scalar, scalar_to_integer};
use rug::Integer;
use p256::Scalar;

use super::ecdsa::{P256Point};

use crate::ecdsa::transcript::{challenge_scalar, SigmaTranscript};
use merlin::Transcript;

use elliptic_curve::PrimeField;
use super::ecdsa::{ECDSASignatureVar};
use super::random::gen_rand_scalars;

use std::path::Path;
use crate::target::r1cs::proof::{serialize_into_file, deserialize_from_file};
use serde::{Serialize, Deserialize};
use super::group::ECPoint;
use super::group::P256Scalar;
use crate::commitment::PointCommit;
use rand_core::RngCore;


use crate::hash::hash::DigestAlgorithm;
use crate::parse_cert::{X509Certificate, IssuerKey, Signature};
use super::ecdsa::EllipticCurveP256;
use elliptic_curve::point::AffineCoordinates;

use std::time::Instant;
use crate::util::timer::print_time;
use lazy_static::lazy_static;

use crate::conditional_print;

lazy_static! {
    static ref MODQ: Integer = Integer::from_str_radix("115792089210356248762697446949407573529996955224135760342422259061068512044369", 10).unwrap();
}
/// Prover for proof of possesion of ECDSA signatures in prior setting (committed pk, public R and public m)
pub fn prover<P: AsRef<Path>>(pf_path: P) {
    let signed_certificate_path = "./example_cert/cloudflare/www.cloudflare.com.cer";
    let issuer_certificate_path = "./example_cert/cloudflare/Cloudflare_Inc_ECC_CA-3.cer";   
    conditional_print!("Path of the signed certificate: {}", signed_certificate_path);
    conditional_print!("Path of the issuer certificate: {}", issuer_certificate_path);
    let cert: X509Certificate = X509Certificate::new(signed_certificate_path, issuer_certificate_path);
    cert.print_signature_algorithm();
    let params = ECDSASigmaSetupParamsPrior::new();
    if let IssuerKey::StructECDSA(ecdsa_key) = &cert.issuer_key {
        if let Signature::StructECDSA(ecdsa_signature) = cert.signature {
            // to do: extract (R, z)
            let digest_result: Integer = DigestAlgorithm::sha256(&(cert.body));
            let issuer_key_pt: ProjectivePoint = ecdsa_key
                                                    .to_p256point()
                                                    .to_projective_point(); // actually we only need projectivepoint
            let signature_var: ECDSASignatureVar = ECDSASignatureVar::from_ecdsasignature(&ecdsa_signature, digest_result.clone(), issuer_key_pt, EllipticCurveP256::new().q.clone());
            let print_msg = true;
            let start = Instant::now();
            inner_prover(
                issuer_key_pt,
                signature_var, 
                &cert.body,
                params,
                pf_path,
            );
            print_time("Time for Proving", start.elapsed(), print_msg); // verify-ecdsa: 10.522471ms
            conditional_print!("Proof has been written to file `pi_sigma`");
        } else { panic!("Didn't implement other signature algorithms");}
    } else {panic!("Didn't implement other signature algorithms");}
}

/// Verifier for proof of possesion of ECDSA signatures in prior setting (committed pk, public R and public m)
pub fn verifier<P: AsRef<Path>>(pf_path: P) {
    let signed_certificate_path = "./example_cert/cloudflare/www.cloudflare.com.cer";
    let issuer_certificate_path = "./example_cert/cloudflare/Cloudflare_Inc_ECC_CA-3.cer";   
    conditional_print!("Path of the signed certificate: {}", signed_certificate_path);
    conditional_print!("Path of the issuer certificate: {}", issuer_certificate_path);
    let cert: X509Certificate = X509Certificate::new(signed_certificate_path, issuer_certificate_path);
    cert.print_signature_algorithm();
    let params = ECDSASigmaSetupParamsPrior::new();
    let start = Instant::now();
    inner_verifier(
        &cert.body,
        params,
        pf_path,
    );
    print_time("Time for Verifying", start.elapsed(), true); // verify-ecdsa: 10.522471ms
    conditional_print!("Proof has been verified");
}
/// Inner Prover for proof of possesion of ECDSA signatures in prior setting (committed pk, public R and public m)
pub fn inner_prover<P: AsRef<Path>>(
    verify_key: ProjectivePoint,
    signature: ECDSASignatureVar, 
    message: &Vec<u8>,
    params: ECDSASigmaSetupParamsPrior,
    pf_path: P,
) {
    let (proof, opening) = create_proof(
        verify_key,
        signature, 
        message,
        params,
    );

    let _ = serialize_into_file(&proof, pf_path);
}

/// Create Proof

/// Create Proof directly from digest (256-bit integer)

pub fn create_proof_from_digest_with_opening(
    verify_key: ProjectivePoint,
    signature: ECDSASignatureVar,
    digest_result: &Integer,
    opening: Scalar,
    params: ECDSASigmaSetupParamsPrior,
) -> Result<(ECDSASigmaPublicPrior, Integer), String> {
    let comm_pk = PointCommit::try_from_opening(
        &verify_key,
        &[params.hash_hash_g, params.hash_g],
        opening,
    )?;

    let x = signature.point_r.to_affine().x();
    let r_scalar: Scalar = bytes_to_scalar(&x);

    // Fresh Sigma randomness for every proof.
    let mut rng = rand::rngs::OsRng;

    let sigma = ECDSASigmaPrior::new(
        &comm_pk,
        digest_result,
        &r_scalar,
        signature,
        params,
        &mut rng,
    );

    let opening_integer = scalar_to_integer(&comm_pk.opening);

    Ok((sigma.public_input, opening_integer))
}

pub fn prover_existing_signature<P: AsRef<Path>>(
    digest_bytes: &[u8; 32],
    signature_der: &[u8],
    verify_key: ProjectivePoint,
    opening: Scalar,
    pf_path: P,
) -> Result<(ECDSASigmaPublicPrior, Integer), String> {
    let params = ECDSASigmaSetupParamsPrior::new();

    let prover_input =
        super::ecdsa::ProverPrecomputeInput::from_existing_der_prehash(
            digest_bytes,
            signature_der,
            verify_key,
        )?;

    let digest_result = os2ip(digest_bytes);

    let (proof, opening_integer) =
        create_proof_from_digest_with_opening(
            prover_input.public_key,
            prover_input.signature,
            &digest_result,
            opening,
            params,
        )?;

    serialize_into_file(&proof, pf_path)
        .map_err(|e| format!("Failed to serialize pi_sigma: {:?}", e))?;

    Ok((proof, opening_integer))
}

/// Create a proof from a digest using fresh OS-backed randomness for both the
/// commitment opening and every Sigma first-message nonce.
pub fn create_proof_from_digest(
    verify_key: ProjectivePoint,
    signature: ECDSASignatureVar,
    digest_result: &Integer,
    params: ECDSASigmaSetupParamsPrior,
) -> (ECDSASigmaPublicPrior, Integer) {
    let mut rng_scalar = rand::rngs::OsRng;

    let comm_pk: PointCommit = PointCommit::new(
        &verify_key,
        &[params.hash_hash_g, params.hash_g],
        &mut rng_scalar,
    );

    let x = signature.point_r.to_affine().x();
    let r_scalar: Scalar = bytes_to_scalar(&x);
    let sigma: ECDSASigmaPrior = ECDSASigmaPrior::new(
        &comm_pk,
        digest_result,
        &r_scalar,
        signature,
        params,
        &mut rng_scalar,
    );
    let opening = scalar_to_integer(&comm_pk.opening);

    (sigma.public_input, opening)
}

/// Prover for proof of possession of ECDSA signatures in Sigmabus setting
pub fn prover_sigmabus<P: AsRef<Path>>(
    h_hi: &Integer,
    h_lo: &Integer,
    privkey_pem_path: &str,
    pf_path: P,
) -> (ECDSASigmaPublicPrior, Integer) {
    let params = ECDSASigmaSetupParamsPrior::new();
    let prover_input = super::ecdsa::ProverPrecomputeInput::generate_sigmabus_prehash_signature(
        h_hi,
        h_lo,
        privkey_pem_path,
    ).expect("Failed to generate Sigmabus prehash signature");

    let digest_result = (h_hi.clone() << 128) | h_lo.clone();
    let start = Instant::now();
    let (proof, opening) = create_proof_from_digest(
        prover_input.public_key,
        prover_input.signature,
        &digest_result,
        params,
    );
    let _ = serialize_into_file(&proof, pf_path);
    print_time("Time for Proving (Sigmabus)", start.elapsed(), true);
    conditional_print!("Proof has been written to file `pi_sigma`");
    (proof, opening)
}

/// Verifier for proof of possession of ECDSA signatures in Sigmabus setting
pub fn verifier_sigmabus<P: AsRef<Path>>(
    h_hi: &Integer,
    h_lo: &Integer,
    pf_path: P,
) {
    let params = ECDSASigmaSetupParamsPrior::new();
    let digest_result = (h_hi.clone() << 128) | h_lo.clone();
    let start = Instant::now();
    let sigma: ECDSASigmaPublicPrior = deserialize_from_file(pf_path)
        .expect("Failed to read file `pi_sigma`");
    sigma.verify(
        &digest_result,
        params,
    );
    print_time("Time for Verifying (Sigmabus)", start.elapsed(), true);
    conditional_print!("Proof has been verified for Sigmabus (h_hi, h_lo)");
}

pub fn create_proof (
    verify_key: ProjectivePoint,
    signature: ECDSASignatureVar, 
    message: &Vec<u8>,
    params: ECDSASigmaSetupParamsPrior,
) -> (ECDSASigmaPublicPrior, Integer) {
    let digest_result: Integer = DigestAlgorithm::sha256(message);
    let mut rng_scalar = rand::rngs::OsRng; // fresh CSPRNG for every proof

    let comm_pk: PointCommit = PointCommit::new(
        &verify_key,
        &[params.hash_hash_g, params.hash_g],  // L = params.hash_hash_g, K = params.hash_g
        &mut rng_scalar);

    // Obtain x-coordinate of R under truncation to Fq
    let x = signature.point_r.to_affine().x();
    let r_scalar: Scalar = bytes_to_scalar(&x); // scalar in Fq
    let sigma: ECDSASigmaPrior = ECDSASigmaPrior::new(
        &comm_pk, 
        &digest_result, 
        &r_scalar, 
        signature, 
        params, 
        &mut rng_scalar
    );
    let opening = scalar_to_integer(&comm_pk.opening);

    (sigma.public_input, opening)
}

/// Inner Verifier for proof of possesion of ECDSA signatures in prior setting (committed pk, public R and public m)
pub fn inner_verifier<P: AsRef<Path>>(
    message: &Vec<u8>,
    params: ECDSASigmaSetupParamsPrior,
    pf_path: P, 
) {
    let digest_result: Integer = DigestAlgorithm::sha256(message);
    let sigma: ECDSASigmaPublicPrior = deserialize_from_file(pf_path)
                                    .expect("Failed to read file `pi_sigma`");
    sigma.verify(
        &digest_result, 
        params); // abort if verification fails
}
/// Public parameters for the (partial) sigma proof for ECDSA signature verification
pub struct ECDSASigmaSetupParamsPrior {
    /// K: transparent H2C-derived commitment generator, in projective form
    pub hash_g: ProjectivePoint, // Corresponds to K in the paper
    /// L = G: standard P-256 generator, in projective form
    pub hash_hash_g: ProjectivePoint, // Corresponds to L in the paper
    /// generator of P256 in projective form
    pub g: ProjectivePoint,
}

impl ECDSASigmaSetupParamsPrior {
    /// Create an instance of ECDSASigmaSetupParams
    pub fn new() -> Self {
        let hash_g: P256Point = P256Point::picproof_commitment_generator_k();
        let hash_g_project: ProjectivePoint = hash_g.to_projective_point();
        Self {
            hash_g: hash_g_project,
            // L is the standard P-256 generator; no separate constant is needed.
            hash_hash_g: ProjectivePoint::GENERATOR,
            g: ProjectivePoint::GENERATOR,
        }
    }
}

#[derive(Serialize, Deserialize)]
/// Prover messages for the proof for ECDSA signature verification under prior setting (Commited public key, Public R and Public m)
pub struct ECDSASigmaPublic {
    /// Responses
    pub responses: [P256Scalar; 4],
    /// Commitments
    pub comm: [ECPoint; 4],
}

#[derive(Serialize, Deserialize)]
/// Public inputs for the proof for ECDSA signature verification under prior setting (Commited public key, Public R and Public m)
pub struct ECDSASigmaPublicPrior {
    /// Responses
    pub responses: [P256Scalar; 4],
    /// Commitments
    pub comm: [ECPoint; 4],
    /// Commitments to public key
    pub cm_pk: [ECPoint; 2],
    /// Partial Signature; The random elliptic curve point
    pub pt_r: ECPoint,
}

impl ECDSASigmaPublicPrior {
    /// Compute E_0 = `cm_pk[0]` and E_1 = `cm_pk[1] + (H(m)/r) * G` from commited public key, message and R
    pub fn precompute(
        cm_pk: [ProjectivePoint; 2],
        digest_result: &Integer,
        r: &Scalar,
    ) -> [ProjectivePoint; 2] {
        let digest_result_scalar = integer_to_scalar(digest_result);
        // let r_scalar = integer_to_scalar(r);
        let e_1 = cm_pk[1] + 
                    ProjectivePoint::GENERATOR * (digest_result_scalar * r.invert().expect("Cannot find multiplicative inverse of r"));
                    // ProjectivePoint::GENERATOR * (digest_result_scalar * r_scalar.invert().expect("Cannot find multiplicative inverse of r"));
        [cm_pk[0], e_1]
    }

    /// Compute the challenge for the sigma protocol
    pub fn compute_challenge(
        pts_e: &[ProjectivePoint; 2], 
        pt_r: &ProjectivePoint, 
        comm: &[ECPoint; 4]
    ) -> Scalar {
        let mut transcript = Transcript::new(b"ECDSA_Sigma_Prior");
        for (i, pt) in pts_e.iter().enumerate() {
            let label = match i {
                0 => b"E_0",
                1 => b"E_1",
                _ => panic!("Invalid index"),
            };
            transcript.append_point(label, pt);
        }
        transcript.append_point(b"R", pt_r);
        for (i, pt) in comm.iter().enumerate() {
            let label = match i {
                0 => b"comm_0",
                1 => b"comm_1",
                2 => b"comm_2",
                3 => b"comm_3",
                _ => panic!("Invalid index"),
            };
            transcript.append_point(label, &pt.0);
        }
        challenge_scalar(&mut transcript, b"challenge")
    }

    /// Verify the sigma proof; Abort if verification fails
    pub fn verify(&self, 
        digest_result: &Integer, 
        params: ECDSASigmaSetupParamsPrior
    ) {
        let x = self.pt_r.0.to_affine().x();
        let r: Scalar = bytes_to_scalar(&x);
        assert_ne!(r, Scalar::ZERO);

        let pts_e: [ProjectivePoint; 2] = ECDSASigmaPublicPrior::precompute(
                                                [self.cm_pk[0].0, self.cm_pk[1].0], 
                                                digest_result, 
                                                &r
                                            ); // Compute E_0 = `cm_pk[0]` and E_1 = `cm_pk[1] + (H(m)/r) * G`
        let challenge: Scalar = ECDSASigmaPublicPrior::compute_challenge(
                                    &pts_e,
                                    &self.pt_r.0,
                                    &self.comm,
                                );
        let pt_l: ProjectivePoint = params.hash_hash_g;
        let pt_k: ProjectivePoint = params.hash_g;
        assert_eq!(pt_l * self.responses[0],
                    self.comm[0].0 + pts_e[0] * challenge);
        assert_eq!(self.pt_r.0 * self.responses[1] + pt_k * self.responses[0],
                    self.comm[1].0 + pts_e[1] * challenge);
        assert_eq!(pts_e[0] * self.responses[2] + pt_l * self.responses[3],
                    self.comm[2].0);
        assert_eq!(pts_e[1] * self.responses[2] + pt_k * self.responses[3],
                    self.comm[3].0 + self.pt_r.0 * challenge);
    }
}
/// Params for the proof for ECDSA signature verification under prior setting (Commited public key, Public R and Public m)
pub struct ECDSASigmaPrior {
    /// Public inputs
    pub public_input: ECDSASigmaPublicPrior,
    /// Challenge
    pub challenge: Scalar,
}

impl ECDSASigmaPrior {
    /// Create variables needed for the sigma protocol; ** to do
    pub fn new( 
        cm_pk: &PointCommit, // Commitment to the public key with opening
        digest_result: &Integer,
        r: &Scalar,
        sign_var: ECDSASignatureVar,
        params: ECDSASigmaSetupParamsPrior,
        mut rng_scalar: impl RngCore
    ) -> Self {
        let pts_e: [ProjectivePoint; 2] = ECDSASigmaPublicPrior::precompute(
                                                cm_pk.comm, 
                                                digest_result, 
                                                r
                                            ); // Compute E_0 = `cm_pk[0]` and E_1 = `cm_pk[1] + (H(m)/r) * G`

        // Commitment phase in the sigma protocol
        let randexp_scalar: Vec<Scalar> = gen_rand_scalars(4, &mut rng_scalar);
        let mut comm: [ECPoint; 4] = [ECPoint::default(); 4];
        // L = params.hash_hash_g; K = params.hash_g
        comm[0] = ECPoint(params.hash_hash_g * randexp_scalar[0]);
        comm[1] = ECPoint(sign_var.point_r * randexp_scalar[1] + params.hash_g * randexp_scalar[0]);
        comm[2] = ECPoint(pts_e[0] * randexp_scalar[2] + params.hash_hash_g * randexp_scalar[3]);
        comm[3] = ECPoint(pts_e[1] * randexp_scalar[2] + params.hash_g * randexp_scalar[3]);

        // Challenge phase in the sigma protocol
        let challenge: Scalar = ECDSASigmaPublicPrior::compute_challenge(
                                    &pts_e,
                                    &sign_var.point_r,
                                    &comm,
                                );

        // Response phase in the sigma protocol
        let z_scalar: Scalar = integer_to_scalar(&sign_var.z);
        let z_inv: Scalar = z_scalar.invert().expect("Cannot find multiplicative inverse of z");
        let exp_scalar: [Scalar; 4] = [
            cm_pk.opening,
            z_scalar,
            z_inv,
            -cm_pk.opening * z_inv,
        ];
        let mut responses: [P256Scalar; 4] = [P256Scalar::default(), P256Scalar::default(), P256Scalar::default(), P256Scalar::default()];
        for (i, (exp, rexp)) in exp_scalar.iter().zip(randexp_scalar.iter()).enumerate() {
            responses[i] = P256Scalar((exp * &challenge) + rexp);
        }  

        let public_input: ECDSASigmaPublicPrior = ECDSASigmaPublicPrior {
            responses: responses,
            comm: comm,
            cm_pk: [ECPoint(cm_pk.comm[0]), ECPoint(cm_pk.comm[1])],
            pt_r: ECPoint(sign_var.point_r),
        };

        Self {
            public_input,
            challenge,
        }
    }
}

#[cfg(test)]
mod sigma_randomness_security_tests {
    use super::*;
    use crate::convert::{bignumref_to_integer, os2ip};
    use crate::ecdsa::convert::integer_to_scalar;
    use crate::ecdsa::ecdsa::{ECDSASignature, ECDSASignatureVar, EllipticCurveP256};
    use openssl::ec::{EcGroup, EcKey};
    use openssl::ecdsa::EcdsaSig;
    use openssl::nid::Nid;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use serde_json::Value as JsonValue;

    fn make_signed_fixture() -> (ProjectivePoint, Vec<u8>, [u8; 32]) {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = EcKey::generate(&group).unwrap();
        let digest_bytes = [0x5au8; 32];
        let signature = EcdsaSig::sign(&digest_bytes, &key).unwrap();
        let signature_der = signature.to_der().unwrap();

        // Derive the P-256 public point from the same OpenSSL private scalar.
        // This avoids writing fixture keys to the repository or filesystem.
        let private_scalar = bignumref_to_integer(key.private_key()).unwrap();
        let public_key = ProjectivePoint::GENERATOR * integer_to_scalar(&private_scalar);

        (public_key, signature_der, digest_bytes)
    }

    fn signature_var_from_der(
        signature_der: &[u8],
        digest_bytes: &[u8; 32],
        public_key: ProjectivePoint,
    ) -> ECDSASignatureVar {
        let signature = EcdsaSig::from_der(signature_der).unwrap();
        let r = bignumref_to_integer(signature.r()).unwrap();
        let s = bignumref_to_integer(signature.s()).unwrap();
        let signature = ECDSASignature { r, s, signature };
        ECDSASignatureVar::from_ecdsasignature(
            &signature,
            os2ip(digest_bytes),
            public_key,
            EllipticCurveP256::new().q,
        )
    }

    fn contains_exact_byte_array(value: &JsonValue, needle: &[u8]) -> bool {
        match value {
            JsonValue::Array(items) => {
                let is_match = items.len() == needle.len()
                    && items.iter().zip(needle.iter()).all(|(item, byte)| {
                        item.as_u64() == Some(*byte as u64)
                    });
                is_match || items.iter().any(|item| contains_exact_byte_array(item, needle))
            }
            JsonValue::Object(fields) => {
                fields.values().any(|item| contains_exact_byte_array(item, needle))
            }
            _ => false,
        }
    }

    #[test]
    fn repeated_proofs_with_same_signature_and_opening_use_fresh_sigma_nonces() {
        let (public_key, signature_der, digest_bytes) = make_signed_fixture();
        let digest = os2ip(&digest_bytes);
        let opening = Scalar::from(17u64);

        let proof_a = create_proof_from_digest_with_opening(
            public_key.clone(),
            signature_var_from_der(&signature_der, &digest_bytes, public_key.clone()),
            &digest,
            opening,
            ECDSASigmaSetupParamsPrior::new(),
        )
        .unwrap()
        .0;

        let proof_b = create_proof_from_digest_with_opening(
            public_key.clone(),
            signature_var_from_der(&signature_der, &digest_bytes, public_key.clone()),
            &digest,
            opening,
            ECDSASigmaSetupParamsPrior::new(),
        )
        .unwrap()
        .0;

        // The registration commitment and signature R are fixed, while the
        // Sigma first messages and responses must be fresh on every invocation.
        assert!(proof_a.cm_pk == proof_b.cm_pk);
        assert!(proof_a.pt_r == proof_b.pt_r);
        assert!(proof_a.comm != proof_b.comm);
        assert!(proof_a
            .responses
            .iter()
            .zip(proof_b.responses.iter())
            .any(|(left, right)| left.0 != right.0));

        proof_a.verify(&digest, ECDSASigmaSetupParamsPrior::new());
        proof_b.verify(&digest, ECDSASigmaSetupParamsPrior::new());
    }

    #[test]
    fn zero_commitment_opening_is_rejected() {
        let (public_key, signature_der, digest_bytes) = make_signed_fixture();
        let digest = os2ip(&digest_bytes);
        let result = create_proof_from_digest_with_opening(
            public_key.clone(),
            signature_var_from_der(&signature_der, &digest_bytes, public_key.clone()),
            &digest,
            Scalar::ZERO,
            ECDSASigmaSetupParamsPrior::new(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn fresh_random_openings_and_public_proof_do_not_encode_device_public_key() {
        let (public_key, signature_der, digest_bytes) = make_signed_fixture();
        let digest = os2ip(&digest_bytes);

        let (proof_a, opening_a) = create_proof_from_digest(
            public_key.clone(),
            signature_var_from_der(&signature_der, &digest_bytes, public_key.clone()),
            &digest,
            ECDSASigmaSetupParamsPrior::new(),
        );
        let (proof_b, opening_b) = create_proof_from_digest(
            public_key.clone(),
            signature_var_from_der(&signature_der, &digest_bytes, public_key.clone()),
            &digest,
            ECDSASigmaSetupParamsPrior::new(),
        );

        assert_ne!(opening_a, Integer::from(0));
        assert_ne!(opening_b, Integer::from(0));
        assert_ne!(opening_a, opening_b);
        assert!(proof_a.cm_pk != proof_b.cm_pk);
        assert!(proof_a.comm != proof_b.comm);

        proof_a.verify(&digest, ECDSASigmaSetupParamsPrior::new());
        proof_b.verify(&digest, ECDSASigmaSetupParamsPrior::new());

        let encoded_public_key = public_key.to_encoded_point(true);
        let public_json = serde_json::to_value(&proof_a).unwrap();
        assert!(public_json.get("pk_d").is_none());
        assert!(public_json.get("private_key").is_none());
        assert!(public_json.get("opening").is_none());
        assert!(public_json.get("opening_v").is_none());
        assert!(!contains_exact_byte_array(
            &public_json,
            encoded_public_key.as_bytes(),
        ));

        // The non-zero opening randomizes both commitment components; in
        // particular, C1 is not the raw device public key.
        assert!(&proof_a.cm_pk[1].0 != &public_key);
    }
}

