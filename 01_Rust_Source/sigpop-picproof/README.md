# Sig-PoP
This repository contains implementations of proofs of posession for ECDSA, Ed25519, RSA, as well as standalone implementations of SHA512 and SHA256.

For more information, see our [paper](https://eprint.iacr.org/2025/538).

## Transparent commitment generator `K`

The PicProof committed-public-key sigma protocol commits with

    cm_PK = (vG, PK + vK)

where `G` is the standard P-256 generator and `K` is a transparent,
nothing-up-my-sleeve point derived by RFC 9380 hash-to-curve:

    profile : PicProof-P256-CmPK-K-v1
    curve   : P-256
    suite   : P256_XMD:SHA-256_SSWU_RO_
    dst     : PICPROOF-P256-CMPK-K-v1
    message : PicProof commitment generator K

No party knows `k = log_G K`, so the second commitment component binds.
The fixed runtime point, the SEC1 encoding, and the parameter fingerprint are
recorded in `test_vectors/cmpk_generator_kat.json`; the derivation lives in
`src/ecdsa/picproof_k.rs` and is re-run by

    cargo run --release --example derive_cmpk_generator

The unit tests `commitment_generator_k_matches_kat`,
`parameter_fingerprint_matches_kat`, and `kat_file_matches_constants` lock the
transparent derivation, the hardcoded runtime point, and the KAT file together:

    cargo test --release --lib ecdsa::picproof_k

## Legacy ZoKrates paths

`zok_src/ecdsa/Fp-estimate` and `zok_src/test/ecdsa/advanced_incomplete` are
legacy experimental ZoKrates paths and are not compiled, invoked, or consumed by
the final PicProof v3 Sigma backend. Their historical constants do not define
the final protocol parameters. The final backend is the pure-Rust
`src/ecdsa/pure_sigma.rs` path used by `examples/sigma_prove.rs`,
`examples/sigma_extract_cmpk.rs`, and `examples/enroll_camera.rs`.


## Examples
#### SHA256 (|m| = 2KB)
    cargo run --release --example circ -- zok_src/test/hashes/sha256/test_sha256_adv32.zok r1cs --action setup --proof-impl mirage
    cargo run --release --example run_zk -- --compute sha256-adv --aux-input 32 --proof-impl mirage --action prove
    cargo run --release --example run_zk -- --compute sha256-adv --aux-input 32 --proof-impl mirage --action verify

#### RSA-PKCS1v1.5 PoP (dynamic modulus, |m| = 64B)
    cargo run --release --example circ -- zok_src/test/modexpon/test_rsa2048_w_hash_advanced1.zok  r1cs --action setup --proof-impl mirage
    cargo run --release --example run_zk -- --compute verify-rsa-adv-whole --aux-input 1 --proof-impl mirage --action prove
    cargo run --release --example run_zk -- --compute verify-rsa-adv-whole --aux-input 1 --proof-impl mirage --action verify

#### ECDSA-P256-SHA256 PoP, sidecar approach (|m| = 64B)
    cargo run --release --example circ -- zok_src/test/ecdsa/advanced_incomplete/test_sigma_32_6_w_hash1.zok r1cs --action setup --proof-impl mirage
    cargo run --release --example run_zk -- --compute verify-ecdsa-sigma-whole --aux-input 1 --proof-impl mirage --action prove
    cargo run --release --example run_zk -- --compute verify-ecdsa-sigma-whole --aux-input 1 --proof-impl mirage --action verify

#### ECDSA-P256-SHA256 PoP, right field approach (|m| = 64B)
    cargo run --release --example circ -- zok_src/test/ecdsa/Fp/test_naive_32_w_hash1.zok  r1cs --action setup --proof-impl dorian --pfcurve t256
    cargo run --release --example run_zk -- --compute verify-ecdsa-right-whole --aux-input 1 --proof-impl dorian --pfcurve t256 --action prove
    cargo run --release --example run_zk -- --compute verify-ecdsa-right-whole --aux-input 1 --proof-impl dorian --pfcurve t256 --action verify

#### Ed25519 PoP, sidecar approach (|m| = 64B)
    cargo run --release --example circ -- zok_src/ed25519/unsafe_witness/sidecar/verify1.zok  r1cs --action setup --proof-impl mirage
    cargo run --release --example run_zk -- --compute eddsa-sigma --aux-input 1 --proof-impl mirage --action prove
    cargo run --release --example run_zk -- --compute eddsa-sigma --aux-input 1 --proof-impl mirage --action verify

#### Ed25519 PoP, right field approach (|m| = 64B)
    cargo run --release --example circ -- zok_src/ed25519/right_field/verify1.zok r1cs --action setup --proof-impl dorian --pfcurve t25519
    cargo run --release --example zk -- --inputs zok_src/ed25519/right_field/test_verify_64.zok.pin --action prove --proof-impl dorian --pfcurve t25519
    cargo run --release --example zk -- --inputs zok_src/ed25519/right_field/test_verify_64.zok.vin --action verify --proof-impl dorian --pfcurve t25519

#### Profiling ECDSA Ring (Ring Size = $2^1$, $2^2$, ..., $2^{14}$)
    bash scripts/ecdsa_ring.sh # Results are written to ecdsa_ring_<current date>.csv

## NOTES:

Currently both the SHA256 and SHA512 implementations are restricted to certain message lengths. They each essentially currently require that the length of the message in bytes is a multiple of 4 and 8 respectively. Consequently, our proofs of posession have the same restriction at present. We plan on fixing this soon.


## PicProof Phase 2: CA-authenticated device registry and Sigma/Spartan binding

This phase adds `circ::ecdsa::ca_registry` and `circ::ecdsa::registry_binding`.
The CA validates a one-time device proof-of-possession challenge, canonical
P-256 points and the opening relation `cmPK=(vG, PK_D+vK)`, then computes
`H_reg(cmPK)`. It builds the same binary Poseidon Merkle tree used by the
Spartan circuit, issues a device-private credential containing the exact
66-byte `cmPK`, leaf and path, and signs a time-bounded registry-root statement
with P-256 ECDSA (ES256).

`examples/picproof_authenticated_registry.rs` provides `prove` and `verify`
subcommands. The v2 bundle includes the Sigma proof, Spartan membership proof,
CA-signed root statement and public cmPK encoding. The verifier recomputes
`Encode(cmPK)` and `H_reg(cmPK)` from the Sigma statement, checks the exact
CA-issued credential binding at proving time, authenticates the CA root using
an out-of-band SHA-256 certificate fingerprint pin, checks the Poseidon
parameter fingerprint and depth, verifies Sigma against the externally supplied
manifest digest, and only then verifies Spartan against the derived `(leaf,root)`.

The legacy `spartan_merkle_linked prove/verify` v1 CLI and historical fixtures
are retained unchanged. The compact CA certificate remains a prototype trust
anchor, not a complete X.509 implementation. Enrollment challenge consumption
is process-local in this prototype; a production CA service must persist issued
and consumed nonces transactionally. The CA sees `PK_D` and `v` at enrollment;
ordinary verifiers do not. Registry-root statements expire after one year and
must be re-issued by the CA before expiry.

### Phase 2 commands

Run the CA registration smoke demo (ephemeral demo device and ephemeral CA):

```bash
cargo run --release --example ca_registry_demo -- ca_registry_demo_out 16
```

It writes `signed_registry_root.json`, `trusted_ca_fingerprint.txt`, and the
private `private_credential_0.json`. The latter contains the public commitment,
leaf and Merkle path, but not `PK_D` or the opening scalar. Treat it as private
because the path is a witness.

For a real authenticated proof, use a Sigma proof and CA credential produced
for the **same registered cmPK and opening**:

```bash
cargo run --release --example picproof_authenticated_registry -- prove \
  --sigma-proof pi_sigma \
  --digest-hex <64-hex-manifest-digest> \
  --credential <device-private-credential.json> \
  --signed-root <ca-signed-root.json> \
  --trusted-ca-fingerprint <out-of-band-ca-pin.txt> \
  --proof-out picproof_v2.bundle

cargo run --release --example picproof_authenticated_registry -- verify \
  --proof-in picproof_v2.bundle \
  --digest-hex <64-hex-manifest-digest> \
  --trusted-ca-fingerprint <out-of-band-ca-pin.txt>
```

The registration smoke demo generates an ephemeral device key and opening for
its own CA tests; its credential is not interchangeable with a Sigma proof
from another device or another opening. The verifier takes neither the private
credential nor the Merkle path. It recomputes the leaf from the Sigma statement.

### Build note for this delivered archive

The supplied source archive declares `pub mod target;` in `src/lib.rs` but does
not contain `src/target.rs` or `src/target/mod.rs`; existing source files also
reference `target::r1cs::proof` and `target::smt`. This pre-existing omission
must be restored from the user's complete local Circ source before claiming a
full crate build or running the Rust test commands above. No placeholder target
implementation has been added.
