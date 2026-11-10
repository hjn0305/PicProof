#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'USAGE'
Usage:
  run_picproof_e2e03_b_group.sh \
    WORKSPACE BASE_BUNDLE DIGEST_HEX TRUSTED_CA_FINGERPRINT VERIFIER_BIN NEW_OUT_DIR

Example:
  bash scripts/run_picproof_e2e03_b_group.sh \
    "$PWD" \
    "/path/to/e2e_smoke/bundles/device_0.bundle" \
    "64_HEX_DIGEST" \
    "/path/to/verifier_config/trusted_ca_fingerprint.txt" \
    "$PWD/target/release/examples/picproof_authenticated_registry" \
    "/path/to/e2e03_attack_matrix/B_group_UTC_TIMESTAMP"

NEW_OUT_DIR must not already exist. No existing experiment directory is overwritten.
USAGE
}

if [[ $# -ne 6 ]]; then usage; exit 2; fi

WORKSPACE="$(cd "$1" && pwd)"
BASE_BUNDLE="$(readlink -f "$2")"
DIGEST_HEX="$3"
TRUSTED_FP="$(readlink -f "$4")"
VERIFIER_BIN="$(readlink -f "$5")"
OUT_DIR="$6"

if [[ ! -f "$BASE_BUNDLE" ]]; then echo "missing base bundle: $BASE_BUNDLE" >&2; exit 2; fi
if [[ ! -f "$TRUSTED_FP" ]]; then echo "missing trusted CA fingerprint: $TRUSTED_FP" >&2; exit 2; fi
if [[ ! -x "$VERIFIER_BIN" ]]; then echo "verifier is not executable: $VERIFIER_BIN" >&2; exit 2; fi
if [[ ! "$DIGEST_HEX" =~ ^[0-9a-fA-F]{64}$ ]]; then echo "DIGEST_HEX must be exactly 64 hex characters" >&2; exit 2; fi
if [[ -e "$OUT_DIR" ]]; then echo "refusing to overwrite existing OUT_DIR: $OUT_DIR" >&2; exit 2; fi

mkdir -p "$(dirname "$OUT_DIR")"
mkdir "$OUT_DIR"
mkdir -p "$OUT_DIR"/{logs,results,source_backup}

cd "$WORKSPACE"
export CARGO_BUILD_JOBS=1
export CARGO_INCREMENTAL=0

FAILURES=0
CSV="$OUT_DIR/results/B_group_results.csv"
printf 'case,expected,actual,exit_code,classification\n' > "$CSV"

capture_source_hashes() {
  local target="$1"
  {
    for f in \
      examples/picproof_authenticated_registry.rs \
      examples/spartan_merkle_linked.rs \
      src/ecdsa/ca_registry.rs \
      src/ecdsa/registry_binding.rs \
      src/ecdsa/pure_sigma.rs \
      src/ecdsa/group.rs
    do
      [[ -f "$f" ]] && sha256sum "$f"
    done
  } > "$target"
}

sha256sum "$BASE_BUNDLE" > "$OUT_DIR/results/base_bundle_before.sha256"
sha256sum "$TRUSTED_FP" > "$OUT_DIR/results/trusted_ca_pin_before.sha256"
sha256sum "$VERIFIER_BIN" > "$OUT_DIR/results/verifier_binary_before.sha256"
capture_source_hashes "$OUT_DIR/source_backup/source_sha256_before.txt"

if [[ -r /sys/fs/cgroup/memory.events ]]; then
  cp /sys/fs/cgroup/memory.events "$OUT_DIR/results/cgroup_memory_events_before.txt"
else
  echo "memory.events unavailable" > "$OUT_DIR/results/cgroup_memory_events_before.txt"
fi

echo "=== BUILD MUTATOR (no cargo clean) ==="
if ! cargo build --release --example picproof_e2e03_mutator \
    > "$OUT_DIR/logs/00_build_mutator.log" 2>&1; then
  cat "$OUT_DIR/logs/00_build_mutator.log"
  echo "MUTATOR_BUILD=FAIL" > "$OUT_DIR/results/status.txt"
  exit 1
fi
echo "MUTATOR_BUILD=PASS" | tee "$OUT_DIR/results/status.txt"

MUTATOR_BIN="$WORKSPACE/target/release/examples/picproof_e2e03_mutator"
if [[ ! -x "$MUTATOR_BIN" ]]; then
  echo "mutator binary missing after successful cargo build" >&2
  exit 1
fi

echo "=== GENERATE FOUR INDEPENDENT MUTANTS ==="
"$MUTATOR_BIN" "$BASE_BUNDLE" "$OUT_DIR/mutants" \
  > "$OUT_DIR/logs/01_mutator.log" 2>&1
cat "$OUT_DIR/logs/01_mutator.log"

verify_case() {
  local name="$1"
  local bundle="$2"
  local expected="$3"
  local pattern="$4"
  local log="$OUT_DIR/logs/${name}.log"
  local rc=0
  local actual="UNCONFIRMED"
  local classification="UNCONFIRMED"

  set +e
  "$VERIFIER_BIN" verify \
    --proof-in "$bundle" \
    --digest-hex "$DIGEST_HEX" \
    --trusted-ca-fingerprint "$TRUSTED_FP" \
    > "$log" 2>&1
  rc=$?
  set -e

  if [[ "$expected" == "ACCEPT" ]]; then
    if [[ $rc -eq 0 ]] && grep -Fq '[PICPROOF V2 VERIFIER] ACCEPT' "$log"; then
      actual="ACCEPT"
      classification="BASELINE"
    else
      actual="FAIL"
      classification="BASELINE_NOT_ACCEPTED"
      FAILURES=$((FAILURES + 1))
    fi
  else
    if [[ $rc -ne 0 ]] && grep -Eiq "$pattern" "$log"; then
      actual="REJECT"
      classification="$pattern"
    else
      actual="FAIL"
      classification="REJECTION_LAYER_NOT_CONFIRMED"
      FAILURES=$((FAILURES + 1))
    fi
  fi

  printf '%s,%s,%s,%s,%s\n' "$name" "$expected" "$actual" "$rc" "$classification" >> "$CSV"
  printf '[%s] expected=%s actual=%s exit=%s classification=%s\n' \
    "$name" "$expected" "$actual" "$rc" "$classification"
}

echo "=== VERIFY AUTHENTIC BASELINE ==="
verify_case "BASELINE_DEVICE0" "$BASE_BUNDLE" "ACCEPT" ""

echo "=== VERIFY B05-B08 MUTANTS ==="
verify_case "B05_MUTATED_C0" \
  "$OUT_DIR/mutants/B05_mutated_cm_pk_c0.bundle" \
  "REJECT" 'sigma'

verify_case "B06_MUTATED_C1" \
  "$OUT_DIR/mutants/B06_mutated_cm_pk_c1.bundle" \
  "REJECT" 'sigma'

verify_case "B07_MUTATED_LEAF" \
  "$OUT_DIR/mutants/B07_mutated_top_level_leaf.bundle" \
  "REJECT" 'leaf|H_reg|cmPK'

verify_case "B08_MUTATED_PROFILE" \
  "$OUT_DIR/mutants/B08_mutated_commitment_profile.bundle" \
  "REJECT" 'Unsupported commitment or registration leaf profile|CA registry-root signature verification failed'

echo "=== PRESERVATION AND RESOURCE AUDIT ==="
sha256sum "$BASE_BUNDLE" > "$OUT_DIR/results/base_bundle_after.sha256"
sha256sum "$TRUSTED_FP" > "$OUT_DIR/results/trusted_ca_pin_after.sha256"
sha256sum "$VERIFIER_BIN" > "$OUT_DIR/results/verifier_binary_after.sha256"
capture_source_hashes "$OUT_DIR/source_backup/source_sha256_after.txt"

if ! diff -u "$OUT_DIR/results/base_bundle_before.sha256" "$OUT_DIR/results/base_bundle_after.sha256" \
  > "$OUT_DIR/results/base_bundle_hash_diff.txt"; then
  echo "ERROR: original baseline bundle changed" >&2
  FAILURES=$((FAILURES + 1))
fi
if ! diff -u "$OUT_DIR/results/trusted_ca_pin_before.sha256" "$OUT_DIR/results/trusted_ca_pin_after.sha256" \
  > "$OUT_DIR/results/trusted_pin_hash_diff.txt"; then
  echo "ERROR: trusted CA pin changed" >&2
  FAILURES=$((FAILURES + 1))
fi
if ! diff -u "$OUT_DIR/results/verifier_binary_before.sha256" "$OUT_DIR/results/verifier_binary_after.sha256" \
  > "$OUT_DIR/results/verifier_hash_diff.txt"; then
  echo "ERROR: verifier binary changed" >&2
  FAILURES=$((FAILURES + 1))
fi
if ! diff -u "$OUT_DIR/source_backup/source_sha256_before.txt" "$OUT_DIR/source_backup/source_sha256_after.txt" \
  > "$OUT_DIR/results/source_hash_diff.txt"; then
  echo "ERROR: protected source files changed during B group" >&2
  FAILURES=$((FAILURES + 1))
fi

if [[ -r /sys/fs/cgroup/memory.events ]]; then
  cp /sys/fs/cgroup/memory.events "$OUT_DIR/results/cgroup_memory_events_after.txt"
else
  echo "memory.events unavailable" > "$OUT_DIR/results/cgroup_memory_events_after.txt"
fi

event_value() {
  local key="$1" file="$2"
  awk -v k="$key" '$1 == k {print $2; found=1} END {if (!found) print "NA"}' "$file"
}

OOM_OK="NOT_MEASURED"
BEFORE="$OUT_DIR/results/cgroup_memory_events_before.txt"
AFTER="$OUT_DIR/results/cgroup_memory_events_after.txt"
if grep -q '^oom ' "$BEFORE" && grep -q '^oom ' "$AFTER"; then
  oom_before="$(event_value oom "$BEFORE")"
  oom_after="$(event_value oom "$AFTER")"
  kill_before="$(event_value oom_kill "$BEFORE")"
  kill_after="$(event_value oom_kill "$AFTER")"
  if [[ "$oom_before" == "$oom_after" && "$kill_before" == "$kill_after" ]]; then
    OOM_OK="PASS"
  else
    OOM_OK="FAIL"
    FAILURES=$((FAILURES + 1))
  fi
fi

{
  echo "B_GROUP_EXPECTED_CASES=5"
  echo "B_GROUP_FAILURES=$FAILURES"
  echo "CGROUP_OOM_DELTA_CHECK=$OOM_OK"
  echo "BASE_BUNDLE_PRESERVED=$(cmp -s "$OUT_DIR/results/base_bundle_before.sha256" "$OUT_DIR/results/base_bundle_after.sha256" && echo YES || echo NO)"
  echo "VERIFIER_BINARY_PRESERVED=$(cmp -s "$OUT_DIR/results/verifier_binary_before.sha256" "$OUT_DIR/results/verifier_binary_after.sha256" && echo YES || echo NO)"
  echo "SOURCE_FILES_PRESERVED=$(cmp -s "$OUT_DIR/source_backup/source_sha256_before.txt" "$OUT_DIR/source_backup/source_sha256_after.txt" && echo YES || echo NO)"
} | tee "$OUT_DIR/results/B_group_summary.txt"

(
  cd "$OUT_DIR"
  find mutants logs results source_backup -type f \
    ! -name 'B_group_artifact_sha256.txt' -print0 \
    | sort -z \
    | xargs -0 -r sha256sum
) > "$OUT_DIR/results/B_group_artifact_sha256.txt"

echo "=== FINAL CSV ==="
cat "$CSV"

if [[ $FAILURES -eq 0 && "$OOM_OK" != "FAIL" ]]; then
  echo "B_GROUP_STATUS=PASS" | tee -a "$OUT_DIR/results/status.txt"
  exit 0
else
  echo "B_GROUP_STATUS=REQUIRES_REVIEW" | tee -a "$OUT_DIR/results/status.txt"
  exit 1
fi
