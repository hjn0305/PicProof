#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$ROOT/cleanroom-output"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/picproof-cleanroom.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$OUT"
: > "$OUT/build.log"
: > "$OUT/verify.stdout"
: > "$OUT/verify.stderr"

log() { printf '%s\n' "$*" | tee -a "$OUT/build.log"; }
die() { printf 'ERROR: %s\n' "$*" | tee -a "$OUT/build.log" >&2; exit 1; }

log "=== PicProof clean-room smoke test ==="
log "release_root=$ROOT"
log "workdir=$WORK"

cd "$ROOT"
sha256sum -c SHA256SUMS > "$OUT/sha256_check.log" 2>&1 || die "SHA256SUMS verification failed"
log "RELEASE_HASHES=PASS"

tar -xzf source/sigpop-picproof-*.tar.gz -C "$WORK"
tar -xzf source/sonobe-decider-*.tar.gz -C "$WORK"

SIGPOP_DIR="$(find "$WORK" -maxdepth 1 -type d -name 'sigpop-picproof-*' -print -quit)"
SONOBE_DIR="$(find "$WORK" -maxdepth 1 -type d -name 'sonobe-decider-*' -print -quit)"
[[ -n "$SIGPOP_DIR" && -n "$SONOBE_DIR" ]] || die "source extraction failed"

if [[ -f "$ROOT/metadata/Cargo.lock.sigpop" ]]; then
  cp "$ROOT/metadata/Cargo.lock.sigpop" "$SIGPOP_DIR/Cargo.lock"
  log "SIGPOP_CARGO_LOCK=metadata"
fi
if [[ ! -f "$SONOBE_DIR/Cargo.lock" && -f "$ROOT/metadata/Cargo.lock.sonobe" ]]; then
  cp "$ROOT/metadata/Cargo.lock.sonobe" "$SONOBE_DIR/Cargo.lock"
  log "SONOBE_CARGO_LOCK=metadata"
fi

log "sigpop_source=$SIGPOP_DIR"
log "sonobe_source=$SONOBE_DIR"
log "rustc=$(rustc --version)"
log "cargo=$(cargo --version)"

log "=== Building Sig-PoP release verifiers ==="
cargo build --manifest-path "$SIGPOP_DIR/Cargo.toml" --release \
  --example sigma_extract_cmpk \
  --example spartan_merkle_linked >> "$OUT/build.log" 2>&1 || die "Sig-PoP build failed"
log "SIGPOP_BUILD=PASS"

log "=== Building Sonobe standalone verifier ==="
cargo build --manifest-path "$SONOBE_DIR/Cargo.toml" --release \
  --bin jisa_package_verify >> "$OUT/build.log" 2>&1 || die "Sonobe build failed"
log "SONOBE_BUILD=PASS"
log "CLEAN_BUILD=PASS"

TRUSTED_ROOT="$(tr -d '[:space:]' < "$ROOT/artifact/trusted_root.txt")"
VERIFY_CMD=(
  "$SONOBE_DIR/target/release/jisa_package_verify"
  --proof "$ROOT/artifact/picproof_v3_64b.proof"
  --verifier-key "$ROOT/artifact/decider_vk.bin"
  --trusted-root "$TRUSTED_ROOT"
  --sigpop-dir "$SIGPOP_DIR"
  --expected-merkle-depth 16
  --image "$ROOT/artifact/input_64b.bin"
  --output "$OUT/standalone_verify.json"
)

printf '%q ' "${VERIFY_CMD[@]}" > "$OUT/verify.command"
printf '\n' >> "$OUT/verify.command"

set +e
"${VERIFY_CMD[@]}" > "$OUT/verify.stdout" 2> "$OUT/verify.stderr"
VERIFY_EXIT=$?
set -e
printf '%s\n' "$VERIFY_EXIT" > "$OUT/verify.exit"
cat "$OUT/verify.stdout" | tee -a "$OUT/build.log"
cat "$OUT/verify.stderr" | tee -a "$OUT/build.log" >&2

if [[ "$VERIFY_EXIT" -ne 0 ]]; then
  die "standalone verifier exited with $VERIFY_EXIT"
fi
grep -q 'STANDALONE PACKAGE VERIFY ACCEPT' "$OUT/verify.stdout" || die "accept marker missing"
python3 - "$OUT/standalone_verify.json" <<'PY'
import json, sys
with open(sys.argv[1], 'r', encoding='utf-8') as f:
    data = json.load(f)
if data.get('accept') is not True:
    raise SystemExit('accept=true missing from JSON')
PY

log "CLEAN_OLD_ARTIFACT_VERIFY=PASS"
log "verify_exit=$VERIFY_EXIT"

{
  echo "package_sha256=$(sha256sum "$ROOT/artifact/picproof_v3_64b.proof" | awk '{print $1}')"
  echo "decider_vk_sha256=$(sha256sum "$ROOT/artifact/decider_vk.bin" | awk '{print $1}')"
  echo "input_64b_sha256=$(sha256sum "$ROOT/artifact/input_64b.bin" | awk '{print $1}')"
  echo "sigpop_source_sha256=$(sha256sum "$SIGPOP_DIR/../"*"sigpop"* 2>/dev/null | awk '{print $1}' | head -n1 || true)"
  echo "sonobe_source_sha256=$(sha256sum "$SONOBE_DIR/../"*"sonobe"* 2>/dev/null | awk '{print $1}' | head -n1 || true)"
} > "$OUT/artifact_hashes.txt" 2>/dev/null || true

log "cleanroom_output=$OUT"
