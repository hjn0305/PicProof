#!/usr/bin/env bash
# Real cross-device Sigma/Spartan swaps, verified by the UNMODIFIED Phase 2 verifier.
# Usage: bash scripts/run_picproof_e2e02_splice.sh /absolute/E2E01/output /absolute/new/E2E02/output
set -euo pipefail
umask 077
if (( $# != 2 )); then
  echo 'Usage: bash scripts/run_picproof_e2e02_splice.sh /absolute/E2E01/output /absolute/new/E2E02/output' >&2
  exit 2
fi
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$ROOT"
BASE="$1"; OUT="$2"
[[ "$BASE" == /* && "$OUT" == /* ]] || { echo 'ERROR: paths must be absolute' >&2; exit 2; }
[[ -d "$BASE" ]] || { echo "ERROR: E2E-01 directory missing: $BASE" >&2; exit 2; }
[[ ! -e "$OUT" ]] || { echo "ERROR: output exists, refusing to overwrite: $OUT" >&2; exit 2; }
[[ -f "$BASE/results/e2e_summary.txt" ]] || { echo 'ERROR: missing E2E-01 summary' >&2; exit 2; }
grep -Fxq 'E2E_BASELINE_STATUS=PASS' "$BASE/results/e2e_summary.txt" || { echo 'ERROR: baseline summary not PASS' >&2; exit 2; }
[[ -s "$BASE/bundles/device_0.bundle" && -s "$BASE/bundles/device_1.bundle" ]] || { echo 'ERROR: missing baseline bundles' >&2; exit 2; }
[[ -s "$BASE/fixture/manifest_digest.hex" && -s "$BASE/verifier_config/trusted_ca_fingerprint.txt" ]] || { echo 'ERROR: missing digest or CA trust pin' >&2; exit 2; }
[[ -x target/release/examples/picproof_authenticated_registry ]] || { echo 'ERROR: original verifier binary missing' >&2; exit 2; }
[[ -f scripts/make_e2e02_splice_example.py ]] || { echo 'ERROR: install the E2E-02 generator first' >&2; exit 2; }

export CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 RAYON_NUM_THREADS=1 OMP_NUM_THREADS=1
mkdir -p "$OUT"/{bundles,logs,results}
chmod 700 "$OUT" "$OUT"/*
DIGEST="$(tr -d '\r\n' < "$BASE/fixture/manifest_digest.hex")"
[[ "$DIGEST" =~ ^[a-fA-F0-9]{64}$ ]] || { echo 'ERROR: digest must be 64 hex chars' >&2; exit 2; }
PIN="$BASE/verifier_config/trusted_ca_fingerprint.txt"
VERIFIER="$ROOT/target/release/examples/picproof_authenticated_registry"
SPLICER="$ROOT/target/release/examples/picproof_e2e02_splice"
BASE_A="$BASE/bundles/device_0.bundle"
BASE_B="$BASE/bundles/device_1.bundle"
AB="$OUT/bundles/sigma_0_spartan_1.bundle"
BA="$OUT/bundles/sigma_1_spartan_0.bundle"

{
  date -u +'%Y-%m-%dT%H:%M:%SZ'
  echo "BASE=$BASE"; echo "OUT=$OUT"
  echo '=== cgroup memory ==='; cat /sys/fs/cgroup/memory.max /sys/fs/cgroup/memory.events 2>/dev/null || :
  echo '=== baseline and verifier SHA-256 ==='
  sha256sum "$BASE_A" "$BASE_B" "$VERIFIER"
} > "$OUT/logs/environment.txt"

# Check genuine E2E-01 baselines again, using the original, independently built verifier.
for index in 0 1; do
  echo "[E2E-02] Recheck baseline $index (must ACCEPT)"
  "$VERIFIER" verify \
    --proof-in "$BASE/bundles/device_${index}.bundle" \
    --digest-hex "$DIGEST" \
    --trusted-ca-fingerprint "$PIN" > "$OUT/logs/baseline_${index}.log" 2>&1
  grep -Fq '[PICPROOF V2 VERIFIER] ACCEPT' "$OUT/logs/baseline_${index}.log" || {
    echo "ERROR: baseline $index did not explicitly ACCEPT" >&2; exit 1;
  }
done

# Generate attack helper against the local, tested Phase 2 verifier source.
# Never overwrite an existing example or any core code.
if [[ ! -f examples/picproof_e2e02_splice.rs ]]; then
  python3 scripts/make_e2e02_splice_example.py "$ROOT" > "$OUT/logs/generate_splice_source.log" 2>&1
else
  echo '[E2E-02] Existing splice example found; no generator overwrite' > "$OUT/logs/generate_splice_source.log"
fi

set -o pipefail
cargo check --example picproof_e2e02_splice > "$OUT/logs/01_check_splice.log" 2>&1 || {
  echo '[E2E-02] cargo check failed:' >&2; tail -n 60 "$OUT/logs/01_check_splice.log" >&2; exit 1;
}
cargo build --release --example picproof_e2e02_splice > "$OUT/logs/02_build_splice.log" 2>&1 || {
  echo '[E2E-02] cargo release build failed:' >&2; tail -n 60 "$OUT/logs/02_build_splice.log" >&2; exit 1;
}
[[ -x "$SPLICER" ]] || { echo 'ERROR: splice binary not generated' >&2; exit 1; }

echo '[E2E-02] Create two authentic cross-device Spartan swaps'
"$SPLICER" splice \
  --proof-a "$BASE_A" --proof-b "$BASE_B" \
  --digest-hex "$DIGEST" --trusted-ca-fingerprint "$PIN" \
  --out-ab "$AB" --out-ba "$BA" \
  > "$OUT/logs/03_create_splices.log" 2>&1 || {
    echo '[E2E-02] cannot create valid-baseline cross-device splices:' >&2
    tail -n 60 "$OUT/logs/03_create_splices.log" >&2
    exit 1
  }

# Reject only if the ORIGINAL verifier explicitly fails at the Spartan proof relation.
check_reject_spartan() {
  local label="$1" path="$2" log="$OUT/logs/$3"
  echo "[E2E-02] Verify attack $label (expected: Spartan REJECT)"
  local status
  if "$VERIFIER" verify \
      --proof-in "$path" --digest-hex "$DIGEST" \
      --trusted-ca-fingerprint "$PIN" > "$log" 2>&1; then
    echo "[E2E-02] SECURITY FAILURE: $label was ACCEPTED" >&2
    exit 1
  else
    status=$?
  fi
  if [[ "$status" -eq 137 || "$status" -eq 139 ]]; then
    echo "[E2E-02] INVALID TEST: process killed/crashed (exit=$status), not a cryptographic REJECT" >&2
    exit 1
  fi
  if ! grep -Fq 'Spartan membership proof rejected' "$log"; then
    echo "[E2E-02] INVALID TEST: $label rejected at unexpected stage, inspect log:" >&2
    tail -n 60 "$log" >&2
    exit 1
  fi
  grep -F '[PICPROOF V2] REJECT/ERROR:' "$log" | tail -n 1
  echo "ATTACK=$label STATUS=REJECT CODE=$status REASON=Spartan_membership" >> "$OUT/results/rejections.txt"
}
check_reject_spartan Sigma0_Spartan1 "$AB" '04_verify_splice_ab.log'
check_reject_spartan Sigma1_Spartan0 "$BA" '05_verify_splice_ba.log'

sha256sum "$BASE_A" "$BASE_B" "$AB" "$BA" "$VERIFIER" "$SPLICER" \
    > "$OUT/results/sha256_artifacts.txt"
cat /sys/fs/cgroup/memory.events > "$OUT/logs/cgroup_memory_events_after.txt" 2>/dev/null || :
{
  echo 'E2E02_STATUS=PASS'
  echo 'BASELINE_0=ACCEPT'
  echo 'BASELINE_1=ACCEPT'
  echo 'SIGMA_0_PLUS_SPARTAN_1=REJECT'
  echo 'SIGMA_1_PLUS_SPARTAN_0=REJECT'
  echo 'ATTACKS_TESTED=2'
  echo 'CAUTION: synthetic, functional attack regression; not yet full 24-case matrix or performance benchmark'
} > "$OUT/results/e2e02_summary.txt"
echo '[E2E-02] PASS: 2 valid baseline ACCEPT; 2 cross-device splices rejected at Spartan membership check.'
echo "[E2E-02] Logs: $OUT"
