# PicProof E2E-03 B Group Kit

This kit adds one new Rust example and one isolated runner script. It does not edit the original verifier, CA registry implementation, Sigma implementation, historical bundles, or prior experiment folders.

## Contents

- `examples/picproof_e2e03_mutator.rs`: deserializes the original authenticated bundle and creates B05-B08 as four independent single-field mutants.
- `scripts/run_picproof_e2e03_b_group.sh`: builds the mutator, verifies the authentic baseline, tests the four mutants using the existing Release verifier, records exit codes/logs/hashes/cgroup memory events.

## Important technical expectations

| Case | Mutation | Expected rejection stage |
|---|---|---|
| B05 | Replace Sigma `cm_pk[0]` with another valid non-identity P-256 point | Sigma verification |
| B06 | Replace Sigma `cm_pk[1]` with another valid non-identity P-256 point | Sigma verification |
| B07 | Increment only top-level `leaf_decimal` | Sigma should pass, then cmPK/leaf binding should reject |
| B08 | Change only CA-signed `commitment_profile_id`, retain original signature | CA ECDSA signature verification |

B08 is intentionally classified as a cryptographic signature rejection in this single-field mutation design. It does not test the later explicit profile-policy branch; that requires a separately CA-signed wrong-profile test.

## Install

From the project root, extract the ZIP so the files land at:

- `examples/picproof_e2e03_mutator.rs`
- `scripts/run_picproof_e2e03_b_group.sh`

Then:

```bash
chmod +x scripts/run_picproof_e2e03_b_group.sh
export CARGO_BUILD_JOBS=1
export CARGO_INCREMENTAL=0
cargo check --example picproof_e2e03_mutator
```

Do not run `cargo clean`.

## Run

Use the exact Device 0 baseline bundle, its corresponding 64-character digest, the independently configured trusted CA fingerprint file, and the already-built original Release verifier:

```bash
bash scripts/run_picproof_e2e03_b_group.sh \
  "$PWD" \
  "/absolute/path/to/e2e_smoke_20261106T021511Z/bundles/device_0.bundle" \
  "PUT_THE_EXACT_64_HEX_DIGEST_HERE" \
  "/absolute/path/to/verifier_config/trusted_ca_fingerprint.txt" \
  "$PWD/target/release/examples/picproof_authenticated_registry" \
  "/absolute/path/to/e2e03_attack_matrix_20261106T023529Z/B_group_YYYYMMDDTHHMMSSZ"
```

The final output directory must not already exist. The script refuses to overwrite it.

## Review requirements

Do not treat a nonzero exit code alone as proof of the intended cryptographic rejection. Review each log and confirm:

- B05/B06: rejection text identifies the Sigma verification path.
- B07: rejection text identifies the leaf / `H_reg` / cmPK-leaf binding check.
- B08: rejection text is `CA registry-root signature verification failed`.
- Baseline: verifier prints `[PICPROOF V2 VERIFIER] ACCEPT`.

If a layer marker does not match, the script marks that case as unconfirmed and returns `B_GROUP_STATUS=REQUIRES_REVIEW`.

The script records source hashes before/after, baseline bundle hashes before/after, verifier binary hashes before/after, per-case logs, exit codes, artifact hashes, and cgroup `oom` / `oom_kill` counters.

## Validation caveat

The source and script are prepared from the structure excerpts supplied in the conversation. They have not been compiled or executed against the user's remote workspace in this session. Run `cargo check` first; if it reports an import/path or feature mismatch, preserve the compiler log and send it back before editing the original verifier.
