#!/usr/bin/env bash
set -euo pipefail

ROOT="$(pwd)"
PATCH_FILE="${1:-picproof_phase2_compile_fixes.patch}"

if [[ ! -f "$ROOT/Cargo.toml" ]]; then
  echo "ERROR: run this script from the Circ crate root (Cargo.toml not found)." >&2
  exit 2
fi
for f in src/ecdsa/ca_registry.rs src/ecdsa/registry_binding.rs; do
  [[ -f "$ROOT/$f" ]] || { echo "ERROR: missing $f" >&2; exit 2; }
done
[[ -f "$PATCH_FILE" ]] || { echo "ERROR: patch file not found: $PATCH_FILE" >&2; exit 2; }

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup_dir="$ROOT/phase2_compile_fix_backup/$stamp"
mkdir -p "$backup_dir/src/ecdsa"
cp -a src/ecdsa/ca_registry.rs "$backup_dir/src/ecdsa/ca_registry.rs"
cp -a src/ecdsa/registry_binding.rs "$backup_dir/src/ecdsa/registry_binding.rs"
echo "Backup created: $backup_dir"

echo "=== Patch dry-run ==="
patch --dry-run -p1 < "$PATCH_FILE"

echo "=== Apply patch ==="
patch -p1 < "$PATCH_FILE"

echo "=== Verify key fixes ==="
grep -n 'let signature: P256Signature' src/ecdsa/ca_registry.rs
grep -n 'crate::ecdsa::picproof_k::PROFILE' src/ecdsa/ca_registry.rs
grep -n 'toy_merkle_hash' src/ecdsa/ca_registry.rs
grep -n 'incremented_leaf' src/ecdsa/registry_binding.rs

if grep -nE 'left \* 31 \+ right \* 17|l \* 31 \+ r \* 17|current \* 31 \+ sibling \* 17|sibling \* 31 \+ current \* 17|\(leaf \+ 1\)' src/ecdsa/ca_registry.rs src/ecdsa/registry_binding.rs; then
  echo "ERROR: an old problematic expression remains." >&2
  exit 1
fi

echo "PATCH_APPLY=PASS"
echo "Next: rerun the same CA test; do not cargo clean."
