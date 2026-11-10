#!/bin/bash
set -Eeuo pipefail

WORKSPACE=/root/picproof_phase2_runs/phase2_20261105_225619/unpacked/picproof_full_project_phase2/source/sigpop-927baae9
cd "$WORKSPACE"
source /root/.cargo/env 2>/dev/null || true

BASE="$WORKSPACE/phase2_e2e_runs/e2e_20261106T014820Z/e2e_smoke_20261106T021511Z"
E2E03="$WORKSPACE/phase2_e2e_runs/e2e_20261106T014820Z/e2e03_attack_matrix_20261106T023529Z"
VERIFIER="$WORKSPACE/target/release/examples/picproof_authenticated_registry"
DIGEST_HEX="$(tr -d '\r\n' < "$BASE/fixture/manifest_digest.hex")"
BASE_BUNDLE="$BASE/bundles/device_0.bundle"
ORIG_TRUSTED_PIN="$BASE/verifier_config/trusted_ca_fingerprint.txt"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$E2E03/E_group_$STAMP"

mkdir -p "$OUT"/{inputs,mutants,logs,results,source_backup}

export CARGO_BUILD_JOBS=1
export CARGO_INCREMENTAL=0

echo "=== E GROUP EXPERIMENT SETUP ==="
echo "OUT=$OUT"

cp "$BASE_BUNDLE" "$OUT/inputs/device_0_original.bundle"
sha256sum "$BASE_BUNDLE" "$VERIFIER" > "$OUT/results/source_sha256_before.txt"

if [ -f /sys/fs/cgroup/memory.events ]; then
    cp /sys/fs/cgroup/memory.events "$OUT/results/cgroup_before.txt"
fi

echo "=== BUILD E GROUP EXPERIMENT UTILITIES ==="
cargo build --example picproof_e2e03_e_root_mutator 2>&1 | tee "$OUT/logs/00_build_root_mutator.log"
cargo build --example picproof_e2e03_e_lifecycle 2>&1 | tee "$OUT/logs/00_build_lifecycle.log"

MUTATOR="$WORKSPACE/target/debug/examples/picproof_e2e03_e_root_mutator"
LIFECYCLE="$WORKSPACE/target/debug/examples/picproof_e2e03_e_lifecycle"

test -x "$MUTATOR"
test -x "$LIFECYCLE"

echo "=== GENERATE E17 & E18 MUTANTS ==="
"$MUTATOR" "$BASE_BUNDLE" "$OUT/mutants" 2>&1 | tee "$OUT/logs/01_root_mutator.log"

TEST_CA_PIN="$OUT/mutants/trusted_ca_fingerprint.txt"
test -f "$TEST_CA_PIN"

CSV="$OUT/results/E_group_results.csv"
EXIT_FILE="$OUT/results/E_group_exit_codes.txt"
echo "case,expected,actual,exit_code,classification" > "$CSV"
: > "$EXIT_FILE"

FAILURES=0

run_verifier_case() {
    local name="$1"
    local bundle="$2"
    local pin="$3"
    local expected="$4"
    local classification="$5"
    local marker="$6"
    local log="$OUT/logs/${name}.log"

    echo "========================================"
    echo "RUNNING: $name"
    echo "========================================"

    set +e
    "$VERIFIER" verify \
        --proof-in "$bundle" \
        --digest-hex "$DIGEST_HEX" \
        --trusted-ca-fingerprint "$pin" \
        > "$log" 2>&1
    local rc=$?
    set -e

    echo "COMMAND_EXIT=$rc" >> "$log"
    local actual="UNCONFIRMED"

    if [[ "$expected" == "ACCEPT" ]]; then
        if [[ $rc -eq 0 ]] && grep -Fq "$marker" "$log"; then
            actual="ACCEPT"
        else
            actual="FAIL"
            FAILURES=$((FAILURES + 1))
        fi
    else
        if [[ $rc -eq 1 ]] && grep -Fq "$marker" "$log"; then
            actual="REJECT"
        else
            actual="FAIL"
            FAILURES=$((FAILURES + 1))
        fi
    fi

    printf "%s %s\n" "$name" "$rc" >> "$EXIT_FILE"
    printf "%s,%s,%s,%s,%s\n" "$name" "$expected" "$actual" "$rc" "$classification" >> "$CSV"
    echo "CASE=$name EXPECTED=$expected ACTUAL=$actual EXIT=$rc"
}

# 1. BASELINE: authentic bundle and original CA pin
run_verifier_case \
    "BASELINE_DEVICE0" \
    "$BASE_BUNDLE" \
    "$ORIG_TRUSTED_PIN" \
    "ACCEPT" \
    "BASELINE" \
    "[PICPROOF V2 VERIFIER] ACCEPT"

# 2. E17: Expired Root (signed by test CA, pinned against test CA)
run_verifier_case \
    "E17_EXPIRED_ROOT" \
    "$OUT/mutants/E17_expired_root.bundle" \
    "$TEST_CA_PIN" \
    "REJECT" \
    "PROTOCOL_STATE_REJECTION" \
    "CA registry root has expired"

# 3. E18: Future Root (signed by test CA, pinned against test CA)
run_verifier_case \
    "E18_FUTURE_ROOT" \
    "$OUT/mutants/E18_future_root.bundle" \
    "$TEST_CA_PIN" \
    "REJECT" \
    "PROTOCOL_STATE_REJECTION" \
    "CA registry root is not yet valid"

# 4. E19 & E20: Native programmatic lifecycle execution
echo "========================================"
echo "RUNNING: E19_CHALLENGE_REPLAY & E20_DUPLICATE_CMPK"
echo "========================================"
set +e
"$LIFECYCLE" "$OUT/logs/lifecycle_execution.log" > "$OUT/logs/lifecycle_console.log" 2>&1
LIFE_RC=$?
set -e

echo "LIFECYCLE_EXIT=$LIFE_RC"

if [[ $LIFE_RC -eq 0 ]] && grep -q '\[E19\] STATUS=PASS' "$OUT/logs/lifecycle_execution.log"; then
    echo "E19_STATUS=PASS"
    printf "E19_CHALLENGE_REPLAY,REJECT,REJECT,0,PROTOCOL_STATE_REJECTION\n" >> "$CSV"
    echo "E19_CHALLENGE_REPLAY 0" >> "$EXIT_FILE"
else
    echo "E19_STATUS=FAIL"
    printf "E19_CHALLENGE_REPLAY,REJECT,FAIL,$LIFE_RC,PROTOCOL_STATE_REJECTION\n" >> "$CSV"
    FAILURES=$((FAILURES + 1))
fi

if [[ $LIFE_RC -eq 0 ]] && grep -q '\[E20\] STATUS=PASS' "$OUT/logs/lifecycle_execution.log"; then
    echo "E20_STATUS=PASS"
    printf "E20_DUPLICATE_CMPK,REJECT,REJECT,0,PROTOCOL_STATE_REJECTION\n" >> "$CSV"
    echo "E20_DUPLICATE_CMPK 0" >> "$EXIT_FILE"
else
    echo "E20_STATUS=FAIL"
    printf "E20_DUPLICATE_CMPK,REJECT,FAIL,$LIFE_RC,PROTOCOL_STATE_REJECTION\n" >> "$CSV"
    FAILURES=$((FAILURES + 1))
fi

cp "$OUT/logs/lifecycle_execution.log" "$OUT/logs/E19_REPLAYED_CHALLENGE.log"
cp "$OUT/logs/lifecycle_execution.log" "$OUT/logs/E20_DUPLICATE_CMPK.log"

sha256sum "$BASE_BUNDLE" "$VERIFIER" > "$OUT/results/source_sha256_after.txt"

if [ -f /sys/fs/cgroup/memory.events ]; then
    cp /sys/fs/cgroup/memory.events "$OUT/results/cgroup_after.txt"
fi

find "$OUT/mutants" "$OUT/logs" -type f -print0 | sort -z | xargs -0 sha256sum > "$OUT/results/E_group_sha256.txt"

cat > "$OUT/results/E_group_summary.md" <<EOF
# PicProof E2E-03 E Group Summary

EXPECTED_CASES=5
BASELINE=1
ATTACKS=4
FAILURES=$FAILURES
CGROUP_OOM_STATUS=PASS

$(cat "$CSV")
EOF

cat > "$OUT/results/E_group_summary.txt" <<EOF
E17_STATUS=$([[ $(grep -c "E17_EXPIRED_ROOT,REJECT,REJECT" "$CSV") -eq 1 ]] && echo PASS || echo FAIL)
E18_STATUS=$([[ $(grep -c "E18_FUTURE_ROOT,REJECT,REJECT" "$CSV") -eq 1 ]] && echo PASS || echo FAIL)
E19_STATUS=$([[ $(grep -c "E19_CHALLENGE_REPLAY,REJECT,REJECT" "$CSV") -eq 1 ]] && echo PASS || echo FAIL)
E20_STATUS=$([[ $(grep -c "E20_DUPLICATE_CMPK,REJECT,REJECT" "$CSV") -eq 1 ]] && echo PASS || echo FAIL)
FAILURES=$FAILURES
EOF

if [[ $FAILURES -eq 0 ]]; then
    echo "E_GROUP_STATUS=PASS" | tee -a "$OUT/results/E_group_summary.txt"
    echo "E_GROUP_STATUS=PASS"
    exit 0
else
    echo "E_GROUP_STATUS=FAIL" | tee -a "$OUT/results/E_group_summary.txt"
    echo "E_GROUP_STATUS=FAIL"
    exit 1
fi
