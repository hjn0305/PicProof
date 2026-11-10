#!/bin/bash
set -Eeuo pipefail

ROOT="/root/picproof_phase2_runs/phase2_20261105_225619/unpacked/picproof_full_project_phase2/source/sigpop-927baae9"
BASE="$ROOT/phase2_e2e_runs/e2e_20261106T014820Z/e2e_smoke_20261106T021511Z"
OUT="${OUT:-$ROOT/phase2_e2e_runs/e2e_20261106T014820Z/e2e03_attack_matrix_20261106T023529Z/D_group_20261106T033506Z}"

cd "$ROOT"
source /root/.cargo/env 2>/dev/null || true

mkdir -p "$OUT"/{inputs,mutants,logs,results,backup}

VERIFIER="$ROOT/target/release/examples/picproof_authenticated_registry"
SPARTAN="$ROOT/target/release/examples/spartan_merkle_linked"
D13_BIN="$ROOT/target/debug/examples/picproof_e2e03_d13_mutator"
D15_BIN="$ROOT/target/debug/examples/picproof_e2e03_d15_d16"

DORIAN_LIB="$ROOT/third_party/Dorian/src/lib.rs"
DORIAN_CHECKOUT="/root/autodl-tmp/cargo/git/checkouts/dorian-821625206728e344/bc23b53/src/lib.rs"

SOURCE="$BASE/bundles/device_0.bundle"
TRUSTED_PIN="$BASE/verifier_config/trusted_ca_fingerprint.txt"
D13_MUTANT="$OUT/mutants/D13_mutated_spartan_proof.bundle"
SPARTAN_PROOF="$OUT/inputs/device_0_spartan.bin"
META="$OUT/results/spartan_metadata.env"

export CARGO_BUILD_JOBS=1
export CARGO_INCREMENTAL=0

test -f "$SOURCE"
test -f "$VERIFIER"
test -f "$SPARTAN"
test -f "$TRUSTED_PIN"
test -f "$DORIAN_LIB"
test -f "$DORIAN_CHECKOUT"

echo "=== D GROUP REMAINING EXPERIMENT ==="
echo "ROOT=$ROOT"
echo "OUT=$OUT"

sha256sum "$VERIFIER" "$SPARTAN" "$SOURCE" > "$OUT/results/original_binary_and_bundle_sha256.txt"
sha256sum "$DORIAN_LIB" "$DORIAN_CHECKOUT" > "$OUT/results/dorian_source_sha256_before.txt"

VERIFIER_HASH_BEFORE=$(sha256sum "$VERIFIER" | awk '{print $1}')
SPARTAN_HASH_BEFORE=$(sha256sum "$SPARTAN" | awk '{print $1}')
DORIAN_HASH_BEFORE=$(sha256sum "$DORIAN_LIB" | awk '{print $1}')
DORIAN_CK_HASH_BEFORE=$(sha256sum "$DORIAN_CHECKOUT" | awk '{print $1}')

cat /sys/fs/cgroup/memory.events > "$OUT/results/cgroup_before_remaining.txt"

# ------------------------------------------------------------
# 1. Temporarily patch Dorian with D13 test-only hook
# ------------------------------------------------------------
BACKUP_LIB="$OUT/backup/dorian_lib.rs.original"
BACKUP_CK="$OUT/backup/dorian_checkout_lib.rs.original"

cp "$DORIAN_LIB" "$BACKUP_LIB"
cp "$DORIAN_CHECKOUT" "$BACKUP_CK"

restore_dorian() {
    if [ -f "$BACKUP_LIB" ]; then cp "$BACKUP_LIB" "$DORIAN_LIB"; fi
    if [ -f "$BACKUP_CK" ]; then cp "$BACKUP_CK" "$DORIAN_CHECKOUT"; fi
    rm -rf target/debug/.fingerprint/dorian-t256* target/debug/deps/*doriant256*
}
trap restore_dorian EXIT INT TERM

python3 scripts/patch_dorian.py "$DORIAN_LIB" "$DORIAN_CHECKOUT"
rm -rf target/debug/.fingerprint/dorian-t256* target/debug/deps/*doriant256*

# ------------------------------------------------------------
# 2. Build two isolated experimental utilities
# ------------------------------------------------------------
cargo build --example picproof_e2e03_d13_mutator 2>&1 | tee "$OUT/logs/01_build_d13_mutator.log"
cargo build --example picproof_e2e03_d15_d16 2>&1 | tee "$OUT/logs/02_build_d15_d16.log"

test -x "$D13_BIN"
test -x "$D15_BIN"

echo "EXPERIMENT_UTILITIES_BUILD=PASS"

restore_dorian
trap - EXIT INT TERM

DORIAN_HASH_AFTER=$(sha256sum "$DORIAN_LIB" | awk '{print $1}')
DORIAN_CK_HASH_AFTER=$(sha256sum "$DORIAN_CHECKOUT" | awk '{print $1}')

if [ "$DORIAN_HASH_BEFORE" != "$DORIAN_HASH_AFTER" ] || [ "$DORIAN_CK_HASH_BEFORE" != "$DORIAN_CK_HASH_AFTER" ]; then
    echo "ERROR: Dorian source restoration failed"
    exit 1
fi
echo "DORIAN_SOURCE_RESTORATION=PASS"

# ------------------------------------------------------------
# 3. Extract original Spartan proof and public inputs
# ------------------------------------------------------------
"$D15_BIN" "$SOURCE" "$SPARTAN_PROOF" "$META" 2>&1 | tee "$OUT/logs/03_extract_spartan.log"

test -s "$SPARTAN_PROOF"
test -s "$META"

LEAF=$(sed -n 's/^LEAF=//p' "$META")
ROOT_VALUE=$(sed -n 's/^ROOT=//p' "$META")
DEPTH=$(sed -n 's/^DEPTH=//p' "$META")
LEAF_PLUS_ONE=$(sed -n 's/^LEAF_PLUS_ONE=//p' "$META")
ROOT_PLUS_ONE=$(sed -n 's/^ROOT_PLUS_ONE=//p' "$META")
DIGEST_HEX=$(sed -n 's/^DIGEST_HEX=//p' "$META")

if [ "${#DIGEST_HEX}" -ne 64 ]; then
    echo "ERROR: Invalid original media digest"
    exit 1
fi

echo "ORIGINAL_LEAF=$LEAF"
echo "ORIGINAL_ROOT=$ROOT_VALUE"
echo "DEPTH=$DEPTH"

# ------------------------------------------------------------
# 4. Verify original authenticated baseline
# ------------------------------------------------------------
set +e
"$VERIFIER" verify   --proof-in "$SOURCE"   --digest-hex "$DIGEST_HEX"   --trusted-ca-fingerprint "$TRUSTED_PIN"   > "$OUT/logs/04_baseline_authenticated.log" 2>&1
BASE_RC=$?
set -e

if [ "$BASE_RC" -ne 0 ] || ! grep -q 'ACCEPT' "$OUT/logs/04_baseline_authenticated.log"; then
    echo "ERROR: Original authenticated baseline failed"
    cat "$OUT/logs/04_baseline_authenticated.log"
    exit 1
fi
echo "BASELINE_AUTHENTICATED=ACCEPT"

# ------------------------------------------------------------
# 5. D13 - Mutate NIZK claimed rx
# ------------------------------------------------------------
"$D13_BIN" "$SOURCE" "$D13_MUTANT" 2>&1 | tee "$OUT/logs/05_generate_d13.log"
test -s "$D13_MUTANT"

ORIGINAL_SIZE=$(stat -c%s "$SOURCE")
MUTATED_SIZE=$(stat -c%s "$D13_MUTANT")

if [ "$ORIGINAL_SIZE" -ne "$MUTATED_SIZE" ]; then
    echo "ERROR: D13 serialization length changed"
    exit 1
fi

set +e
"$VERIFIER" verify   --proof-in "$D13_MUTANT"   --digest-hex "$DIGEST_HEX"   --trusted-ca-fingerprint "$TRUSTED_PIN"   > "$OUT/logs/06_verify_d13.log" 2>&1
D13_RC=$?
set -e

if [ "$D13_RC" -eq 1 ] && grep -Fq 'Spartan membership proof rejected: InternalError' "$OUT/logs/06_verify_d13.log"; then
    D13_STATUS=PASS
else
    D13_STATUS=FAIL
fi
echo "D13_EXIT_CODE=$D13_RC"
echo "D13_STATUS=$D13_STATUS"

# ------------------------------------------------------------
# 6. D15/D16 - Direct Spartan public-input verification
# ------------------------------------------------------------
run_spartan_case() {
    local name="$1"
    local leaf="$2"
    local root="$3"
    local logfile="$OUT/logs/${name}.log"

    set +e
    "$SPARTAN" verify       --leaf "$leaf"       --root "$root"       --depth "$DEPTH"       --proof-in "$SPARTAN_PROOF"       > "$logfile" 2>&1
    local rc=$?
    set -e
    echo "$rc"
}

BASE_SPARTAN_RC=$(run_spartan_case BASELINE_SPARTAN "$LEAF" "$ROOT_VALUE")
if [ "$BASE_SPARTAN_RC" -ne 0 ]; then
    echo "ERROR: Original Spartan proof failed direct verification"
    cat "$OUT/logs/BASELINE_SPARTAN.log"
    exit 1
fi
echo "BASELINE_SPARTAN=ACCEPT"

D15_RC=$(run_spartan_case D15_WRONG_LEAF "$LEAF_PLUS_ONE" "$ROOT_VALUE")
if [ "$D15_RC" -eq 1 ] && grep -Eqi 'InternalError|Proof verification failed|Verification failed' "$OUT/logs/D15_WRONG_LEAF.log"; then
    D15_STATUS=PASS
else
    D15_STATUS=FAIL
fi
echo "D15_EXIT_CODE=$D15_RC"
echo "D15_STATUS=$D15_STATUS"

D16_RC=$(run_spartan_case D16_WRONG_ROOT "$LEAF" "$ROOT_PLUS_ONE")
if [ "$D16_RC" -eq 1 ] && grep -Eqi 'InternalError|Proof verification failed|Verification failed' "$OUT/logs/D16_WRONG_ROOT.log"; then
    D16_STATUS=PASS
else
    D16_STATUS=FAIL
fi
echo "D16_EXIT_CODE=$D16_RC"
echo "D16_STATUS=$D16_STATUS"

# ------------------------------------------------------------
# 7. Final source/binary integrity checks
# ------------------------------------------------------------
VERIFIER_HASH_AFTER=$(sha256sum "$VERIFIER" | awk '{print $1}')
SPARTAN_HASH_AFTER=$(sha256sum "$SPARTAN" | awk '{print $1}')
DORIAN_HASH_AFTER=$(sha256sum "$DORIAN_LIB" | awk '{print $1}')
DORIAN_CK_HASH_AFTER=$(sha256sum "$DORIAN_CHECKOUT" | awk '{print $1}')

[ "$VERIFIER_HASH_BEFORE" = "$VERIFIER_HASH_AFTER" ]
[ "$SPARTAN_HASH_BEFORE" = "$SPARTAN_HASH_AFTER" ]
[ "$DORIAN_HASH_BEFORE" = "$DORIAN_HASH_AFTER" ]
[ "$DORIAN_CK_HASH_BEFORE" = "$DORIAN_CK_HASH_AFTER" ]

echo "ORIGINAL_VERIFIER_PRESERVED=YES"
echo "ORIGINAL_SPARTAN_BINARY_PRESERVED=YES"
echo "DORIAN_SOURCE_PRESERVED=YES"

# ------------------------------------------------------------
# 8. Memory and OOM audit
# ------------------------------------------------------------
cat /sys/fs/cgroup/memory.events > "$OUT/results/cgroup_after_remaining.txt"
OOM_BEFORE=$(awk '$1=="oom" {print $2}' "$OUT/results/cgroup_before_remaining.txt")
OOM_AFTER=$(awk '$1=="oom" {print $2}' "$OUT/results/cgroup_after_remaining.txt")
KILL_BEFORE=$(awk '$1=="oom_kill" {print $2}' "$OUT/results/cgroup_before_remaining.txt")
KILL_AFTER=$(awk '$1=="oom_kill" {print $2}' "$OUT/results/cgroup_after_remaining.txt")

if [ "$OOM_BEFORE" != "$OOM_AFTER" ] || [ "$OOM_KILL_BEFORE" != "$OOM_KILL_AFTER" ]; then
    MEMORY_STATUS=FAIL
else
    MEMORY_STATUS=PASS
fi

# ------------------------------------------------------------
# 9. Results and SHA-256
# ------------------------------------------------------------
cat > "$OUT/results/D_group_remaining_results.csv" <<EOF
case,expected,actual,exit_code,classification
BASELINE_AUTHENTICATED,ACCEPT,ACCEPT,$BASE_RC,BASELINE
BASELINE_SPARTAN,ACCEPT,ACCEPT,$BASE_SPARTAN_RC,BASELINE
D13_MUTATED_NIZK,REJECT,$([ "$D13_STATUS" = PASS ] && echo REJECT || echo UNCONFIRMED),$D13_RC,CRYPTOGRAPHIC_SPARTAN
D14_TRUNCATED_BUNDLE,REJECT,REJECT,1,PARSER_REJECTION
D15_WRONG_LEAF,REJECT,$([ "$D15_STATUS" = PASS ] && echo REJECT || echo UNCONFIRMED),$D15_RC,CRYPTOGRAPHIC_SPARTAN
D16_WRONG_ROOT,REJECT,$([ "$D16_STATUS" = PASS ] && echo REJECT || echo UNCONFIRMED),$D16_RC,CRYPTOGRAPHIC_SPARTAN
EOF

sha256sum "$SOURCE" "$D13_MUTANT" "$SPARTAN_PROOF" "$VERIFIER" "$SPARTAN" "$OUT"/logs/*.log > "$OUT/results/D_group_remaining_sha256.txt"

cat > "$OUT/results/D_group_remaining_summary.txt" <<EOF
D13_STATUS=$D13_STATUS
D14_STATUS=PASS
D15_STATUS=$D15_STATUS
D16_STATUS=$D16_STATUS
MEMORY_STATUS=$MEMORY_STATUS
ORIGINAL_VERIFIER_PRESERVED=YES
ORIGINAL_SPARTAN_BINARY_PRESERVED=YES
DORIAN_SOURCE_PRESERVED=YES
EOF

if [ "$D13_STATUS" = PASS ] && [ "$D15_STATUS" = PASS ] && [ "$D16_STATUS" = PASS ] && [ "$MEMORY_STATUS" = PASS ]; then
    echo "D_GROUP_REMAINING_STATUS=PASS" | tee -a "$OUT/results/D_group_remaining_summary.txt"
    echo "D_GROUP_REMAINING_STATUS=PASS"
else
    echo "D_GROUP_REMAINING_STATUS=FAIL" | tee -a "$OUT/results/D_group_remaining_summary.txt"
    echo "D_GROUP_REMAINING_STATUS=FAIL"
    exit 1
fi
echo "FINAL_OUTPUT=$OUT"
