#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/source/sigpop-927baae9"
cargo build --release --locked \
  --example sigma_extract_cmpk \
  --example spartan_merkle_linked
