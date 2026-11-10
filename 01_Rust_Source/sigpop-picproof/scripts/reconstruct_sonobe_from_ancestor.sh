#!/usr/bin/env bash
set -euo pipefail
# Optional audit path: reconstruct c286 content state from an archived 3492e95 tree.
# Usage: ./reconstruct_sonobe_from_ancestor.sh /path/to/sonobe-decider-3492e95e /tmp/c286-rebuilt
if [ "$#" -ne 2 ]; then
  echo "usage: $0 <ancestor-dir> <output-dir>" >&2
  exit 2
fi
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ANCESTOR="$1"
OUT="$2"
rm -rf "$OUT"
cp -a "$ANCESTOR" "$OUT"
cd "$OUT"
git apply --check "$ROOT/provenance/c286_source_evidence/c286_from_3492e95.patch"
git apply "$ROOT/provenance/c286_source_evidence/c286_from_3492e95.patch"
sha256sum -c "$ROOT/provenance/c286_source_evidence/FINAL_SOURCE_SHA256SUMS"
