use std::env;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use p256::elliptic_curve::group::Group;
use p256::{ProjectivePoint, Scalar};

use circ::ecdsa::ca_registry::SignedRegistryRoot;
use circ::ecdsa::group::{ECPoint, P256Scalar};
use circ::ecdsa::pure_sigma::ECDSASigmaPublicPrior;

// Reuse the exact Spartan package definition used by the verifier example.
// This module also contains a nested main() function, which is harmless.
#[allow(dead_code)]
#[path = "spartan_merkle_linked.rs"]
mod spartan_merkle_linked;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthenticatedPicProofPackage {
    magic: String,
    version: u32,
    profile: String,
    registry_id: String,
    depth: usize,
    digest_sha256_hex: String,
    cm_pk_encoded_hex: String,
    leaf_decimal: String,
    signed_registry_root: SignedRegistryRoot,
    sigma_proof: ECDSASigmaPublicPrior,
    spartan_proof: spartan_merkle_linked::SpartanMerklePackage,
}

fn read_original(path: &Path) -> Vec<u8> {
    fs::read(path).expect("Cannot read original bundle")
}

fn decode_package(bytes: &[u8]) -> AuthenticatedPicProofPackage {
    bincode::deserialize(bytes).expect("Cannot deserialize original bundle")
}

fn write_mutant<F>(
    original: &[u8],
    output_dir: &Path,
    filename: &str,
    mutate: F,
)
where
    F: FnOnce(&mut AuthenticatedPicProofPackage),
{
    // Every mutant starts from independently deserialized original bytes.
    let mut package = decode_package(original);

    mutate(&mut package);

    let encoded =
        bincode::serialize(&package).expect("Cannot serialize mutant");

    let output = output_dir.join(filename);
    fs::write(&output, &encoded).expect("Cannot write mutant");

    println!(
        "[MUTATOR] {} bytes={}",
        output.display(),
        encoded.len()
    );
}

fn shifted_point(original: ProjectivePoint) -> ProjectivePoint {
    let generator = ProjectivePoint::GENERATOR;

    let mut replacement = original + generator;

    // Extremely defensive handling of the identity point.
    if bool::from(replacement.is_identity()) {
        replacement = original + generator + generator;
    }

    assert_ne!(replacement, original);
    assert!(!bool::from(replacement.is_identity()));

    replacement
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        eprintln!(
            "Usage: picproof_e2e03_c_mutator <original.bundle> <output_dir>"
        );
        std::process::exit(2);
    }

    let source_path = Path::new(&args[1]);
    let output_dir = Path::new(&args[2]);

    fs::create_dir_all(output_dir).expect("Cannot create output directory");

    let original = read_original(source_path);
    let original_package = decode_package(&original);

    println!("[MUTATOR] source_bytes={}", original.len());
    println!("[MUTATOR] digest={}", original_package.digest_sha256_hex);

    // Preserve the authentic digest for C09-C11 and the baseline.
    fs::write(
        output_dir.join("digest_sha256_hex.txt"),
        format!("{}\n", original_package.digest_sha256_hex),
    )
    .expect("Cannot save digest");

    // C09: modify one response scalar in F_n.
    // The result remains canonical and non-zero.
    write_mutant(
        &original,
        output_dir,
        "C09_mutated_response_0.bundle",
        |package| {
            let old = package.sigma_proof.responses[0].0;

            let mut replacement = old + Scalar::from(1u64);

            if replacement == Scalar::from(0u64) {
                replacement = old + Scalar::from(2u64);
            }

            assert_ne!(replacement, old);
            assert_ne!(replacement, Scalar::from(0u64));

            package.sigma_proof.responses[0] = P256Scalar(replacement);
        },
    );

    // C10: replace comm[0] with another valid P-256 point.
    write_mutant(
        &original,
        output_dir,
        "C10_mutated_comm_0.bundle",
        |package| {
            let old = package.sigma_proof.comm[0].0;
            let replacement = shifted_point(old);

            package.sigma_proof.comm[0] = ECPoint(replacement);
        },
    );

    // C11: replace pt_r with another valid P-256 point.
    write_mutant(
        &original,
        output_dir,
        "C11_mutated_pt_r.bundle",
        |package| {
            let old = package.sigma_proof.pt_r.0;
            let replacement = shifted_point(old);

            package.sigma_proof.pt_r = ECPoint(replacement);
        },
    );

    println!(
        "[MUTATOR] PASS: three independent, structurally valid Sigma mutants generated"
    );
}
