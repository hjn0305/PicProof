#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

MUTATOR="$SCRIPT_DIR/picproof_e2e03_f_mutator.py"

VERIFIER="${PICPROOF_VERIFIER:-$ROOT/target/release/examples/picproof_authenticated_registry}"
VERIFY_WRAPPER="${VERIFY_WRAPPER:?Set VERIFY_WRAPPER first}"

EXPECTED_BASE_SHA="56a2ff77211f5945700aa818da551c2a7726281fe5c45947187f4810d89879ae"

if [[ ! -x "$VERIFIER" ]]; then
    echo "ERROR: Release verifier not found: $VERIFIER"
    exit 1
fi

if [[ ! -x "$VERIFY_WRAPPER" ]]; then
    echo "ERROR: Verify wrapper not executable"
    exit 1
fi

if [[ ! -f "$MUTATOR" ]]; then
    echo "ERROR: Mutator not found"
    exit 1
fi

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$ROOT/phase2_e2e_runs/f_group_$RUN_ID"

mkdir -p "$OUT"/{inputs,mutants,logs,results}

echo "========== F GROUP EXECUTION =========="
echo "ROOT=$ROOT"
echo "OUT=$OUT"
echo "VERIFIER=$VERIFIER"

# ------------------------------------------------
# 1. Locate original Device 0 bundle by SHA-256
# ------------------------------------------------

BASE_BUNDLE="${BASE_BUNDLE:-}"

if [[ -z "$BASE_BUNDLE" ]]; then
    while IFS= read -r -d '' file; do
        hash="$(sha256sum "$file" | awk '{print $1}')"

        if [[ "$hash" == "$EXPECTED_BASE_SHA" ]]; then
            BASE_BUNDLE="$file"
            break
        fi
    done < <(
        find "$ROOT/phase2_e2e_runs" \
            -type f \
            -name "device_0.bundle" \
            -print0
    )
fi

if [[ -z "$BASE_BUNDLE" || ! -f "$BASE_BUNDLE" ]]; then
    echo "ERROR: Original Device 0 bundle not found"
    exit 1
fi

BASE_HASH="$(sha256sum "$BASE_BUNDLE" | awk '{print $1}')"

if [[ "$BASE_HASH" != "$EXPECTED_BASE_SHA" ]]; then
    echo "ERROR: Original bundle SHA-256 mismatch"
    exit 1
fi

cp -p "$BASE_BUNDLE" "$OUT/inputs/device_0_original.bundle"

echo "$BASE_HASH  device_0_original.bundle" \
    > "$OUT/results/original_bundle_sha256.txt"

# ------------------------------------------------
# 2. Record source and verifier fingerprints
# ------------------------------------------------

SOURCE_FILES=(
    examples/picproof_authenticated_registry.rs
    examples/spartan_merkle_linked.rs
    src/ecdsa/ca_registry.rs
    src/ecdsa/registry_binding.rs
    src/ecdsa/pure_sigma.rs
    src/ecdsa/group.rs
    third_party/Dorian/src/lib.rs
    third_party/Dorian/src/errors.rs
    third_party/Dorian/src/sumcheck.rs
)

write_source_hashes() {
    local output="$1"

    (
        cd "$ROOT"

        for file in "${SOURCE_FILES[@]}"; do
            sha256sum "$file"
        done
    ) > "$output"
}

write_source_hashes "$OUT/results/source_sha256_before.txt"

sha256sum "$VERIFIER" \
    > "$OUT/results/verifier_sha256_before.txt"

# ------------------------------------------------
# 3. Cgroup memory snapshot before execution
# ------------------------------------------------

snapshot_memory() {
    local output="$1"

    if [[ -r /sys/fs/cgroup/memory.events ]]; then
        cp /sys/fs/cgroup/memory.events "$output"
    else
        echo "CGROUP_MEMORY_EVENTS_UNAVAILABLE" > "$output"
    fi
}

snapshot_memory "$OUT/results/cgroup_before.txt"

# ------------------------------------------------
# 4. Generate four independent mutants
# ------------------------------------------------

python3 "$MUTATOR" \
    --source "$BASE_BUNDLE" \
    --out-dir "$OUT/mutants" \
    | tee "$OUT/logs/mutator.log"

META="$OUT/mutants/mutation_metadata.json"

DIGEST_HEX="$(
python3 - "$META" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as f:
    obj = json.load(f)

print(obj["package_header"]["digest_sha256_hex"])
PY
)"

echo "DIGEST_HEX=$DIGEST_HEX" \
    > "$OUT/results/verification_parameters.txt"

# ------------------------------------------------
# 5. Prepare result CSV
# ------------------------------------------------

CSV="$OUT/results/F_group_results.csv"

echo "case,expected,actual,exit_code,classification,check" > "$CSV"

FAILURES=0
F23_ACTUAL="UNKNOWN"

run_case() {
    local name="$1"
    local bundle="$2"
    local expected_rc="$3"
    local expected_label="$4"
    local pattern="$5"
    local classification="$6"

    local log="$OUT/logs/${name}.log"
    local rc
    local actual
    local check="FAIL"

    echo
    echo "========== $name =========="

    set +e
    "$VERIFY_WRAPPER" "$bundle" "$DIGEST_HEX" \
        > "$log" 2>&1
    rc=$?
    set -e

    echo "COMMAND_EXIT=$rc" >> "$log"

    if grep -Fq "$pattern" "$log"; then
        if [[ "$rc" -eq 0 ]]; then
            actual="ACCEPT"
        else
            actual="REJECT"
        fi
    else
        actual="UNEXPECTED"
    fi

    if [[ "$rc" -eq "$expected_rc" ]] &&
       grep -Fq "$pattern" "$log"; then
        check="PASS"
    else
        FAILURES=$((FAILURES + 1))
    fi

    if [[ "$name" == "F23"* ]]; then
        F23_ACTUAL="$actual"
    fi

    printf '%s,%s,%s,%s,%s,%s\n' \
        "$name" \
        "$expected_label" \
        "$actual" \
        "$rc" \
        "$classification" \
        "$check" >> "$CSV"

    echo "EXPECTED=$expected_label"
    echo "ACTUAL=$actual"
    echo "EXIT_CODE=$rc"
    echo "CHECK=$check"
}

# ------------------------------------------------
# 6. BASELINE
# ------------------------------------------------

run_case \
    "BASELINE_DEVICE0" \
    "$OUT/inputs/device_0_original.bundle" \
    0 \
    "ACCEPT" \
    "[PICPROOF V2 VERIFIER] ACCEPT" \
    "BASELINE"

# ------------------------------------------------
# 7. F21: Version = 999
# ------------------------------------------------

run_case \
    "F21_VERSION_999" \
    "$OUT/mutants/F21_version_999.bundle" \
    1 \
    "REJECT" \
    "Unsupported authenticated PicProof bundle format/version/profile" \
    "PROTOCOL_STATE_REJECTION"

# ------------------------------------------------
# 8. F22: Truncated bundle
# ------------------------------------------------

run_case \
    "F22_TRUNCATED_100" \
    "$OUT/mutants/F22_truncated_100bytes.bundle" \
    1 \
    "REJECT" \
    "Cannot deserialize authenticated PicProof package" \
    "PARSER_REJECTION"

# ------------------------------------------------
# 9. F23: Trailing garbage
# ------------------------------------------------

run_case \
    "F23_TRAILING_GARBAGE" \
    "$OUT/mutants/F23_trailing_garbage.bundle" \
    0 \
    "ACCEPT" \
    "[PICPROOF V2 VERIFIER] ACCEPT" \
    "TRAILING_BYTES_TOLERATED_FINDING"

# ------------------------------------------------
# 10. F24: Invalid SEC1 point
# ------------------------------------------------

run_case \
    "F24_INVALID_SEC1" \
    "$OUT/mutants/F24_invalid_sec1_cm_pk0.bundle" \
    1 \
    "REJECT" \
    "Authenticated package deserialization panicked; malformed EC point encoding rejected" \
    "PARSER_REJECTION"

# ------------------------------------------------
# 11. After-execution integrity checks
# ------------------------------------------------

snapshot_memory "$OUT/results/cgroup_after.txt"

write_source_hashes "$OUT/results/source_sha256_after.txt"

sha256sum "$VERIFIER" \
    > "$OUT/results/verifier_sha256_after.txt"

if cmp -s \
    "$OUT/results/source_sha256_before.txt" \
    "$OUT/results/source_sha256_after.txt"; then
    SOURCE_STATUS="PASS"
else
    SOURCE_STATUS="FAIL"
fi

if cmp -s \
    "$OUT/results/verifier_sha256_before.txt" \
    "$OUT/results/verifier_sha256_after.txt"; then
    VERIFIER_STATUS="PASS"
else
    VERIFIER_STATUS="FAIL"
fi

if [[ "$(sha256sum "$BASE_BUNDLE" | awk '{print $1}')" == "$EXPECTED_BASE_SHA" ]]; then
    BASE_STATUS="PASS"
else
    BASE_STATUS="FAIL"
fi

# ------------------------------------------------
# 12. Cgroup OOM delta
# ------------------------------------------------

MEMORY_STATUS="UNKNOWN"

if grep -q "^oom " "$OUT/results/cgroup_before.txt" &&
   grep -q "^oom " "$OUT/results/cgroup_after.txt"; then

    OOM_BEFORE="$(awk '$1=="oom"{print $2}' "$OUT/results/cgroup_before.txt")"
    OOM_AFTER="$(awk '$1=="oom"{print $2}' "$OUT/results/cgroup_after.txt")"

    KILL_BEFORE="$(awk '$1=="oom_kill"{print $2}' "$OUT/results/cgroup_before.txt")"
    KILL_AFTER="$(awk '$1=="oom_kill"{print $2}' "$OUT/results/cgroup_after.txt")"

    if [[ "$OOM_BEFORE" == "$OOM_AFTER" &&
          "$KILL_BEFORE" == "$KILL_AFTER" ]]; then
        MEMORY_STATUS="PASS"
    else
        MEMORY_STATUS="FAIL"
    fi
fi

# ------------------------------------------------
# 13. Final summary
# ------------------------------------------------

if [[ "$FAILURES" -eq 0 &&
      "$F23_ACTUAL" == "ACCEPT" &&
      "$SOURCE_STATUS" == "PASS" &&
      "$VERIFIER_STATUS" == "PASS" &&
      "$BASE_STATUS" == "PASS" &&
      "$MEMORY_STATUS" == "PASS" ]]; then

    GROUP_STATUS="COMPLETED_WITH_SECURITY_FINDING"

else
    GROUP_STATUS="REVIEW_REQUIRED"
fi

REJECT_COUNT=0

for case_name in \
    F21_VERSION_999 \
    F22_TRUNCATED_100 \
    F23_TRAILING_GARBAGE \
    F24_INVALID_SEC1; do

    if grep -q "^${case_name},REJECT,REJECT," "$CSV"; then
        REJECT_COUNT=$((REJECT_COUNT + 1))
    fi
done

cat > "$OUT/results/F_group_summary.txt" <<EOF
PICPROOF E2E-03 F GROUP SUMMARY

F21_STATUS=$(grep '^F21_VERSION_999,' "$CSV" | cut -d, -f6)
F22_STATUS=$(grep '^F22_TRUNCATED_100,' "$CSV" | cut -d, -f6)
F23_STATUS=$(grep '^F23_TRAILING_GARBAGE,' "$CSV" | cut -d, -f6)
F24_STATUS=$(grep '^F24_INVALID_SEC1,' "$CSV" | cut -d, -f6)

ATTACKS_TESTED=4
ATTACKS_REJECTED=$REJECT_COUNT/4
ATTACKS_ACCEPTED=$((4 - REJECT_COUNT))/4

F23_TRAILING_BYTES_ACCEPTED=$([[ "$F23_ACTUAL" == "ACCEPT" ]] && echo YES || echo NO)

FAILURES=$FAILURES
SOURCE_HASH_STATUS=$SOURCE_STATUS
VERIFIER_HASH_STATUS=$VERIFIER_STATUS
BASE_BUNDLE_STATUS=$BASE_STATUS
CGROUP_OOM_STATUS=$MEMORY_STATUS

F_GROUP_STATUS=$GROUP_STATUS
EOF

cat "$OUT/results/F_group_summary.txt"

# Also generate full SHA256 of all artifacts in this run
find "$OUT" -type f ! -name F_group_sha256.txt -print0 | sort -z | xargs -0 -r sha256sum > "$OUT/results/F_group_sha256.txt"

echo
echo "========== F GROUP COMPLETED =========="
echo "OUTPUT=$OUT"
echo "F_GROUP_STATUS=$GROUP_STATUS"

if [[ "$GROUP_STATUS" == "REVIEW_REQUIRED" ]]; then
    exit 1
fi

exit 0
