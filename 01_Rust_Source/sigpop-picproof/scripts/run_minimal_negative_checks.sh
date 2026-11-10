#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
cp -a "$ROOT/bin/sigpop" "$TMP/sigpop"
cp "$ROOT/fixture/decider_vk.bin" "$TMP/vk.bin"
flip_byte() {
  python3 - "$1" "$2" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]); off=int(sys.argv[2]); b=bytearray(p.read_bytes())
if not (0 <= off < len(b)): raise SystemExit('offset out of range')
b[off] ^= 0x01
p.write_bytes(b)
PY
}
# G6-like: corrupt the VK; ProfileGuard must reject before proof verification.
flip_byte "$TMP/vk.bin" 100
set +e
"$ROOT/bin/jisa_package_verify" --proof "$ROOT/fixture/package.proof" \
 --verifier-key "$TMP/vk.bin" --trusted-profile "$ROOT/fixture/trusted_profile.json" \
 --sigpop-dir "$TMP/sigpop" --image "$ROOT/fixture/64k.bin" --output "$TMP/g6.json" \
 >"$TMP/g6.stdout" 2>"$TMP/g6.stderr"
rc1=$?
set -e
[ "$rc1" -ne 0 ] || { echo 'G6-like check unexpectedly accepted'; exit 1; }
! grep -q 'Decider pi_final:.*PASS' "$TMP/g6.stdout"
# G7a-like: corrupt Sigma executable; content fingerprint must reject.
flip_byte "$TMP/sigpop/target/release/examples/sigma_extract_cmpk" 100
set +e
"$ROOT/bin/jisa_package_verify" --proof "$ROOT/fixture/package.proof" \
 --verifier-key "$ROOT/fixture/decider_vk.bin" --trusted-profile "$ROOT/fixture/trusted_profile.json" \
 --sigpop-dir "$TMP/sigpop" --image "$ROOT/fixture/64k.bin" --output "$TMP/g7.json" \
 >"$TMP/g7.stdout" 2>"$TMP/g7.stderr"
rc2=$?
set -e
[ "$rc2" -ne 0 ] || { echo 'G7a-like check unexpectedly accepted'; exit 1; }
! grep -q 'Decider pi_final:.*PASS' "$TMP/g7.stdout"
echo 'minimal negative checks PASS'
