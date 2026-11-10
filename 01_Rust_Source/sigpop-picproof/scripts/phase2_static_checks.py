#!/usr/bin/env python3
"""Static integration checks for PicProof Phase 2 (not a substitute for cargo test)."""
from pathlib import Path
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
checks = []

def check(name, condition, detail=""):
    checks.append((name, bool(condition), detail))

ca = (ROOT / "src/ecdsa/ca_registry.rs").read_text()
binding = (ROOT / "src/ecdsa/registry_binding.rs").read_text()
spartan = (ROOT / "examples/spartan_merkle_linked.rs").read_text()
bundle = (ROOT / "examples/picproof_authenticated_registry.rs").read_text()
demo = (ROOT / "examples/ca_registry_demo.rs").read_text()
pure_sigma = (ROOT / "src/ecdsa/pure_sigma.rs").read_text()
sigma = (ROOT / "src/ecdsa/sigma.rs").read_text()

# Validate the Poseidon parameter file's canonical fingerprint exactly as Rust does.
param_path = ROOT / "p256_poseidon_t3_params.json"
params = json.loads(param_path.read_text())
claimed = params["parameter_sha256"]
preimage = dict(params)
preimage.pop("parameter_sha256", None)
canonical = json.dumps(preimage, sort_keys=True, separators=(",", ":")).encode()
computed = hashlib.sha256(canonical).hexdigest()
check("Poseidon parameter fingerprint", computed == claimed,
      f"declared={claimed}; computed={computed}")

check("CA root statement version/domain bumped", "REGISTRY_STATEMENT_VERSION: u32 = 2" in ca and "ROOT-v2" in ca)
check("CA root signature binds validity interval", "issued_at_unix" in ca and "expires_at_unix" in ca and "issued_at_unix.to_be_bytes()" in ca and "expires_at_unix.to_be_bytes()" in ca)
check("CA root signature binds algorithm and Poseidon profile", "signature_algorithm" in ca and "merkle_hash_algorithm" in ca and "merkle_parameters_sha256" in ca)
check("CA root validity interval is enforced", "CA registry root has expired" in ca and "CA registry root is not yet valid" in ca and "REGISTRY_DEFAULT_VALIDITY_SECS" in ca)
check("CA signatures reject non-canonical high-S", "signature.normalize_s().is_some()" in ca and "pop_signature.normalize_s().is_some()" in ca)
check("Duplicate commitments and leaves are rejected", "Duplicate cmPK commitment" in ca and "Duplicate H_reg leaf" in ca)
check("Merkle nodes are range-checked in the field", "Merkle hash output at level" in ca and "Merkle default hash output" in ca)
check("CA trust pin enforced", "trusted_fingerprint" in ca and "CA certificate is not the configured trust anchor" in ca)
check("CA enrollment checks cmPK opening", "cmPK C0 does not equal v*G" in ca and "cmPK C1 does not equal PK_D + v*K" in ca)
check("CA enrollment checks one-time PoP", "challenge.consumed" in ca and "proof-of-possession challenge verification failed" in ca)
check("CA Merkle path direction matches Spartan", "directions.push(index % 2 == 0)" in ca and "When dir == true: curr is left" in spartan)
check("CA credential excludes PK and opening", "pub struct DeviceRegistryCredential" in ca and "opening_scalar" not in ca.split("pub struct DeviceRegistryCredential",1)[1].split("}",1)[0] and "device_public_key_sec1" not in ca.split("pub struct DeviceRegistryCredential",1)[1].split("}",1)[0])
check("CA emits per-device private credential", "output.enrollment_credentials[0]" in demo and "private_credential_0.json" in demo)
check("Sigma cmPK is re-derived into H_reg leaf", "derive_sigma_cm_pk_leaf" in binding and "h_reg(c0.as_bytes(), c1.as_bytes())" in binding)
check("Credential binds exact cmPK and leaf", "Sigma cmPK does not match" in binding and "does not match the CA-issued leaf" in binding)
check("Authenticated package includes Sigma, Spartan and signed root", "sigma_proof: ECDSASigmaPublicPrior" in bundle and "spartan_proof:" in bundle and "signed_registry_root: SignedRegistryRoot" in bundle)
check("Verifier checks external digest and CA pin", "Externally supplied manifest digest" in bundle and "read_trust_pin" in bundle and "verify_signed_registry_root" in bundle)
check("Verifier derives leaf from Sigma and verifies Spartan", "derive_sigma_cm_pk_leaf(&cm_pk)" in bundle and "verify_spartan(&package.spartan_proof, &leaf, &root, params)" in bundle)
check("Verifier rejects private credential/path inputs", "verifier must not accept a private Merkle path or device credential" in bundle)
check("Authenticated public bundle does not serialize the private path", "path:" not in bundle.split("struct AuthenticatedPicProofPackage",1)[1].split("}",1)[0])
check("Root statement format is versioned separately from legacy Spartan v1", "REGISTRY_STATEMENT_VERSION: u32 = 2" in ca and "pub const VERSION: &str = \"1.0.0\"" in spartan)
check("Spartan v1 CLI remains present", "fn run_prove" in spartan and "fn run_verify" in spartan and "pub const VERSION: &str = \"1.0.0\"" in spartan)
check("Sigma fixed-seed RNG absent", "StdRng::from_seed([0u8; 32])" not in pure_sigma and "StdRng::from_seed([0u8; 32])" not in sigma)
check("Poseidon hash fingerprint is recomputed in Rust", "computed_fingerprint" in spartan and "Poseidon parameter fingerprint mismatch" in spartan)

failed = [item for item in checks if not item[1]]
for name, ok, detail in checks:
    print(("PASS" if ok else "FAIL") + " | " + name + (" | " + detail if detail else ""))
print(f"\nSTATIC_CHECKS={len(checks)} PASSED={len(checks)-len(failed)} FAILED={len(failed)}")
if failed:
    sys.exit(1)
