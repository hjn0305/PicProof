#!/bin/bash
set -euo pipefail

WORKSPACE="$PWD"
BASE_DIR="$WORKSPACE/phase2_e2e_runs/e2e_20261106T014820Z/e2e_smoke_20261106T021511Z"
BASE_BUNDLE="$BASE_DIR/bundles/device_0.bundle"
TRUSTED_CA="$BASE_DIR/verifier_config/trusted_ca_fingerprint.txt"
VERIFIER="$WORKSPACE/target/release/examples/picproof_authenticated_registry"

OUT="${1:?Usage: run_picproof_e2e03_c_group.sh <C_GROUP_OUTPUT_DIR>}"

test -f "$BASE_BUNDLE"
test -f "$TRUSTED_CA"
test -x "$VERIFIER"
test -f "$OUT/results/source_sha256_before.txt"

mkdir -p "$OUT"/{logs,results,mutants}

CSV="$OUT/results/C_group_results.csv"
EXIT_FILE="$OUT/results/C_group_exit_codes.txt"

echo "case,expected,actual,exit_code,classification" > "$CSV"
: > "$EXIT_FILE"

FAILURES=0

DIGEST="$(tr -d '\r\n' < "$OUT/mutants/digest_sha256_hex.txt")"

if [[ ! "$DIGEST" =~ ^[0-9a-fA-F]{64}$ ]]; then
    echo "ERROR: invalid original SHA-256 digest"
    exit 2
fi

if [[ "${DIGEST:0:1}" == "0" ]]; then
    WRONG_DIGEST="1${DIGEST:1}"
else
    WRONG_DIGEST="0${DIGEST:1}"
fi

run_case() {
    local name="$1"
    local bundle="$2"
    local digest="$3"
    local expected="$4"
    local classification="$5"
    local marker="$6"

    local log="$OUT/logs/${name}.log"
    local rc
    local actual

    echo
    echo "========================================"
    echo "RUNNING: $name"
    echo "========================================"

    set +e
    "$VERIFIER" verify \
        --proof-in "$bundle" \
        --digest-hex "$digest" \
        --trusted-ca-fingerprint "$TRUSTED_CA" \
        > "$log" 2>&1
    rc=$?
    set -e

    echo "COMMAND_EXIT=$rc" >> "$log"

    if [[ "$expected" == "ACCEPT" ]]; then
        if [[ "$rc" -eq 0 ]] && grep -Fq "$marker" "$log"; then
            actual="ACCEPT"
        else
            actual="FAIL"
        fi
    else
        if [[ "$rc" -eq 1 ]] && grep -Fq "$marker" "$log"; then
            actual="REJECT"
        else
            actual="FAIL"
        fi
    fi

    printf "%s %s\n" "$name" "$rc" >> "$EXIT_FILE"
    printf "%s,%s,%s,%s,%s\n" "$name" "$expected" "$actual" "$rc" "$classification" >> "$CSV"
    echo "CASE=$name EXPECTED=$expected ACTUAL=$actual EXIT=$rc"

    if [[ "$actual" == "FAIL" ]]; then
        FAILURES=$((FAILURES + 1))
        echo "FAILED: inspect $log"
    fi
}

# BASELINE: authentic bundle and authentic digest.
run_case \
    "BASELINE_DEVICE0" \
    "$BASE_BUNDLE" \
    "$DIGEST" \
    "ACCEPT" \
    "BASELINE" \
    "[PICPROOF V2 VERIFIER] ACCEPT"

# C09: modified response scalar.
run_case \
    "C09_MUTATED_RESPONSE_0" \
    "$OUT/mutants/C09_mutated_response_0.bundle" \
    "$DIGEST" \
    "REJECT" \
    "CRYPTOGRAPHIC_SIGMA" \
    "Sigma proof verification rejected (invalid proof or digest)"

# C10: modified Sigma commitment point.
run_case \
    "C10_MUTATED_COMM_0" \
    "$OUT/mutants/C10_mutated_comm_0.bundle" \
    "$DIGEST" \
    "REJECT" \
    "CRYPTOGRAPHIC_SIGMA" \
    "Sigma proof verification rejected (invalid proof or digest)"

# C11: modified signature R point.
run_case \
    "C11_MUTATED_PT_R" \
    "$OUT/mutants/C11_mutated_pt_r.bundle" \
    "$DIGEST" \
    "REJECT" \
    "CRYPTOGRAPHIC_SIGMA" \
    "Sigma proof verification rejected (invalid proof or digest)"

# C12: original bundle, incorrect external digest.
run_case \
    "C12_WRONG_EXTERNAL_DIGEST" \
    "$BASE_BUNDLE" \
    "$WRONG_DIGEST" \
    "REJECT" \
    "PROTOCOL_STATE_DIGEST" \
    "Externally supplied manifest digest does not match the digest bound into this package"

# Record source fingerprints after execution.
sha256sum "$BASE_BUNDLE" "$VERIFIER" > "$OUT/results/source_sha256_after.txt"

SOURCE_HASH_STATUS="PASS"
if ! cmp -s "$OUT/results/source_sha256_before.txt" "$OUT/results/source_sha256_after.txt"; then
    SOURCE_HASH_STATUS="FAIL"
    FAILURES=$((FAILURES + 1))
fi

# Cgroup memory events.
OOM_STATUS="NOT_AVAILABLE"
if [[ -f /sys/fs/cgroup/memory.events ]]; then
    cp /sys/fs/cgroup/memory.events "$OUT/results/cgroup_after.txt"

    get_counter() {
        awk -v key="$1" '''$1 == key {print $2}''' "$2"
    }

    OOM_BEFORE="$(get_counter oom "$OUT/results/cgroup_before.txt")"
    OOM_AFTER="$(get_counter oom "$OUT/results/cgroup_after.txt")"
    KILL_BEFORE="$(get_counter oom_kill "$OUT/results/cgroup_before.txt")"
    KILL_AFTER="$(get_counter oom_kill "$OUT/results/cgroup_after.txt")"

    if [[ "$OOM_BEFORE" == "$OOM_AFTER" ]] && [[ "$KILL_BEFORE" == "$KILL_AFTER" ]]; then
        OOM_STATUS="PASS"
    else
        OOM_STATUS="FAIL"
        FAILURES=$((FAILURES + 1))
    fi
fi

# Hash all generated mutants and logs.
find "$OUT/mutants" "$OUT/logs" -type f -print0 | sort -z | xargs -0 sha256sum > "$OUT/results/C_group_sha256.txt"

# Summary.
{
    echo "# PicProof E2E-03 C Group"
    echo
    echo "EXPECTED_CASES=5"
    echo "BASELINE=1"
    echo "ATTACKS=4"
    echo "FAILURES=$FAILURES"
    echo "SOURCE_HASH_STATUS=$SOURCE_HASH_STATUS"
    echo "CGROUP_OOM_STATUS=$OOM_STATUS"
    echo
    cat "$CSV"
} > "$OUT/results/C_group_summary.md"

if [[ "$FAILURES" -eq 0 ]] && [[ "$SOURCE_HASH_STATUS" == "PASS" ]] && [[ "$OOM_STATUS" != "FAIL" ]]; then
    echo "C_GROUP_STATUS=PASS" | tee -a "$OUT/results/C_group_summary.md"
    echo "C_GROUP_STATUS=PASS"
    exit 0
else
    echo "C_GROUP_STATUS=FAIL" | tee -a "$OUT/results/C_group_summary.md"
    echo "C_GROUP_STATUS=FAIL"
    exit 1
fi
