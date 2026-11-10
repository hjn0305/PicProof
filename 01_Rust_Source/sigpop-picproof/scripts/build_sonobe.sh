#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/source/sonobe-c286-content-exact"
cargo build --release --locked -p sonobe-ivc \
  --bin jisa_unified_e2e --bin jisa_package_verify \
  --no-default-features --features parallel
