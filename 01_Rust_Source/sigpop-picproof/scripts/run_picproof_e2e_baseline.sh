#!/usr/bin/env bash
# PicProof Phase 2 E2E smoke: 2 registered devices, two independently verified v2 bundles.
# Usage: bash scripts/run_picproof_e2e_baseline.sh /absolute/new/output/directory [depth]
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$ROOT"

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo 'Usage: bash scripts/run_picproof_e2e_baseline.sh /absolute/new/output/directory [depth=1]' >&2
  exit 2
fi
OUT="$1"
DEPTH="${2:-1}"
[[ "$OUT" == /* ]] || { echo 'ERROR: output path must be absolute' >&2; exit 2; }
[[ "$DEPTH" =~ ^[1-9][0-9]*$ ]] || { echo 'ERROR: depth must be a positive integer' >&2; exit 2; }
(( DEPTH <= 8 )) || { echo 'ERROR: safety cap depth<=8 for this 2-GiB E2E smoke; start with depth=1' >&2; exit 2; }
[[ ! -e "$OUT" ]] || { echo "ERROR: output exists, refusing to overwrite: $OUT" >&2; exit 2; }
[[ -f examples/picproof_e2e_fixture.rs ]] || { echo 'ERROR: install examples/picproof_e2e_fixture.rs first' >&2; exit 2; }
[[ -x target/release/examples/picproof_authenticated_registry ]] || { echo 'ERROR: missing Phase 2 authenticated verifier binary' >&2; exit 2; }
[[ -f p256_poseidon_t3_params.json ]] || { echo 'ERROR: missing Poseidon parameter file' >&2; exit 2; }

export CARGO_BUILD_JOBS=1
export CARGO_INCREMENTAL=0
export RAYON_NUM_THREADS=1
export OMP_NUM_THREADS=1
mkdir -p "$OUT"/{fixture,bundles,verifier_config,logs,results}
chmod 700 "$OUT" "$OUT/fixture" "$OUT/bundles" "$OUT/verifier_config" "$OUT/logs" "$OUT/results"

{ date -u +'%Y-%m-%dT%H:%M:%SZ'; uname -a; rustc -Vv; cargo -V;
  echo 'CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0';
  echo '=== cgroup memory.max ==='; cat /sys/fs/cgroup/memory.max 2>/dev/null || :;
  echo '=== cgroup memory.events before ==='; cat /sys/fs/cgroup/memory.events 2>/dev/null || :;
  echo '=== disk ==='; df -h .;
} > "$OUT/logs/environment.txt" 2>&1

run_logged() {
  local name="$1"; shift
  echo "[E2E] $name"
  if [[ -x /usr/bin/time ]]; then
    if /usr/bin/time -v "$@" >"$OUT/logs/${name}.log" 2>&1; then
      :
    else
      local code=$?
      echo "[E2E] FAILED $name (exit=$code); log tail:" >&2
      tail -n 50 "$OUT/logs/${name}.log" >&2 || :
      return "$code"
    fi
  else
    if "$@" >"$OUT/logs/${name}.log" 2>&1; then
      :
    else
      local code=$?
      echo "[E2E] FAILED $name (exit=$code); log tail:" >&2
      tail -n 50 "$OUT/logs/${name}.log" >&2 || :
      return "$code"
    fi
  fi
  grep -E '(SIGMA_PROVE_OK|PHASE3 FIXTURE|PICPROOF V2|Finished `release`)' "$OUT/logs/${name}.log" | tail -n 12 || true
}

# Build ONLY the new fixture, reusing existing Phase 2 build cache/binaries.
run_logged 01_build_fixture cargo build --release --example picproof_e2e_fixture
FIXTURE_BIN="$ROOT/target/release/examples/picproof_e2e_fixture"
VERIFIER_BIN="$ROOT/target/release/examples/picproof_authenticated_registry"
[[ -x "$FIXTURE_BIN" ]] || { echo 'Fixture binary missing after successful build' >&2; exit 1; }

run_logged 02_generate_real_two_device_fixture "$FIXTURE_BIN" "$OUT/fixture" "$DEPTH"
DIGEST="$(tr -d '\r\n' < "$OUT/fixture/manifest_digest.hex")"
[[ "$DIGEST" =~ ^[0-9a-fA-F]{64}$ ]] || { echo 'Invalid generated fixture digest' >&2; exit 1; }
ROOT_JSON="$OUT/fixture/signed_registry_root.json"
PIN_SOURCE="$OUT/fixture/trusted_ca_fingerprint.txt"
[[ -s "$ROOT_JSON" && -s "$PIN_SOURCE" ]] || { echo 'Missing CA signed root or pin' >&2; exit 1; }
# Simulate a verifier's separately provisioned test trust anchor (not read from the bundle).
cp "$PIN_SOURCE" "$OUT/verifier_config/trusted_ca_fingerprint.txt"
PIN="$OUT/verifier_config/trusted_ca_fingerprint.txt"

for index in 0 1; do
  run_logged "03_prove_device_${index}" "$VERIFIER_BIN" prove \
    --sigma-proof "$OUT/fixture/device_${index}/pi_sigma" \
    --digest-hex "$DIGEST" \
    --credential "$OUT/fixture/device_${index}/private_credential.json" \
    --signed-root "$ROOT_JSON" \
    --trusted-ca-fingerprint "$PIN" \
    --proof-out "$OUT/bundles/device_${index}.bundle"
  run_logged "04_verify_device_${index}" "$VERIFIER_BIN" verify \
    --proof-in "$OUT/bundles/device_${index}.bundle" \
    --digest-hex "$DIGEST" \
    --trusted-ca-fingerprint "$PIN"
  grep -Fq '[PICPROOF V2 VERIFIER] ACCEPT' "$OUT/logs/04_verify_device_${index}.log" || {
    echo "ERROR: device $index verifier exited without explicit ACCEPT" >&2; exit 1;
  }
done

sha256sum "$FIXTURE_BIN" "$VERIFIER_BIN" > "$OUT/results/executable_sha256.txt"
find "$OUT/fixture" "$OUT/bundles" "$OUT/verifier_config" -type f -print0 | sort -z | xargs -0 sha256sum > "$OUT/results/input_and_output_sha256.txt"
{
  echo 'E2E_BASELINE_STATUS=PASS'
  echo 'REGISTERED_DEVICES=2'
  echo "MERKLE_DEPTH=$DEPTH"
  echo 'BASELINE_A=ACCEPT'
  echo 'BASELINE_B=ACCEPT'
  echo 'CAUTION: synthetic fixed digest, ephemeral CA/device keys; not production/benchmark data'
} > "$OUT/results/e2e_summary.txt"
cat /sys/fs/cgroup/memory.events > "$OUT/logs/cgroup_memory_events_after.txt" 2>/dev/null || :
echo '[E2E] PASS: two independently generated Sigma proofs + CA-signed root + two Spartan packages; both accepted.'
echo "[E2E] Outputs: $OUT"
