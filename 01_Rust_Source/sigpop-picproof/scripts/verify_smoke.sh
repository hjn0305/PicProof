#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
"$ROOT/bin/jisa_package_verify" \
  --proof "$ROOT/fixture/package.proof" \
  --verifier-key "$ROOT/fixture/decider_vk.bin" \
  --trusted-profile "$ROOT/fixture/trusted_profile.json" \
  --sigpop-dir "$ROOT/bin/sigpop" \
  --image "$ROOT/fixture/64k.bin" \
  --output "$ROOT/fixture/smoke_verify_result.json"
