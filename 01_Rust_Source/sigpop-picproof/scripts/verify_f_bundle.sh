#!/usr/bin/env bash
set -euo pipefail

BUNDLE="$1"
DIGEST_HEX="$2"

VERIFIER="${PICPROOF_VERIFIER:?Set PICPROOF_VERIFIER}"
TRUSTED_FP="${PICPROOF_TRUSTED_CA_FP:?Set PICPROOF_TRUSTED_CA_FP}"

exec "$VERIFIER" verify \
    --proof-in "$BUNDLE" \
    --digest-hex "$DIGEST_HEX" \
    --trusted-ca-fingerprint "$TRUSTED_FP"
