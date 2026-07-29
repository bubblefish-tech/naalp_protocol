#!/usr/bin/env bash
# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# N-AALP verification recipe (CLAUDE.md), the single "one command" gradeable loop:
#   1. regenerate every conformance vector from its independent (non-circular) oracle,
#   2. Go   — build + vet + test -race,
#   3. Rust — build + test,
#   4. assert the regenerated vectors match the committed vectors (oracle is
#      deterministic and the committed corpus is current).
#
# The loop fails loudly: any oracle error, build error, test failure, or a drift
# between oracle output and the committed corpus exits non-zero. Go commands force
# GOWORK=off so the module resolves against its own go.mod regardless of any
# inherited go.work (this box inherits an unrelated GOWORK).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PY="${PYTHON:-python}"

echo "== [1/5] regenerate vectors from independent oracles =="
shopt -s nullglob
oracles=(tools/*_oracle.py)
if [ ${#oracles[@]} -eq 0 ]; then
  echo "   (no oracles yet)"
else
  for o in "${oracles[@]}"; do
    echo "   oracle: $o"
    "$PY" "$o"
  done
fi

echo "== [2/5] Go: build + vet + test -race (GOWORK=off) =="
( cd impl/go \
    && GOWORK=off go build ./... \
    && GOWORK=off go vet ./... \
    && GOWORK=off CGO_ENABLED=1 go test -race -count=1 ./... )

echo "== [3/5] Rust: build + test =="
( cd impl/rust && cargo build --quiet && cargo test --quiet )

echo "== [4/5] Go == Rust deterministic byte-parity: COSE_Sign1 + object envelope (R-16.2) =="
if [ -f vectors/cose/cases.json ]; then
  seed=$("$PY" -c "import json;print(json.load(open('vectors/cose/cases.json'))['mldsa_keygen'][0]['seed_hex'])")
  sig_go=$(cd impl/go && GOWORK=off go run ./cmd/naalp-cose-sig "$seed")
  sig_rs=$(cd impl/rust && cargo run --quiet --example naalp_cose_sig -- "$seed")
  if [ "$sig_go" != "$sig_rs" ]; then
    echo "ERROR: Go and Rust produced different COSE_Sign1 bytes for the same key+payload" >&2
    echo "   go:   ${sig_go:0:48}..." >&2
    echo "   rust: ${sig_rs:0:48}..." >&2
    exit 1
  fi
  echo "   COSE_Sign1  Go == Rust (${#sig_go} hex chars): ${sig_go:0:32}..."
  if [ -f vectors/envelope/cases.json ]; then
    env_go=$(cd impl/go && GOWORK=off go run ./cmd/naalp-envelope "$seed")
    env_rs=$(cd impl/rust && cargo run --quiet --example naalp_envelope -- "$seed")
    if [ "$env_go" != "$env_rs" ]; then
      echo "ERROR: Go and Rust produced different object envelopes for the same key+object" >&2
      echo "   go:   ${env_go:0:48}..." >&2
      echo "   rust: ${env_rs:0:48}..." >&2
      exit 1
    fi
    echo "   envelope    Go == Rust (${#env_go} hex chars): ${env_go:0:32}..."
  fi
else
  echo "   (no COSE corpus yet — skipped)"
fi

echo "== [5/5] vectors current (oracle output == committed corpus, LF-normalized) =="
if ! git diff --quiet -- vectors/; then
  echo "ERROR: regenerated vectors differ from the committed corpus (stale vectors or" >&2
  echo "       a non-deterministic oracle). Re-commit the regenerated vectors:" >&2
  git --no-pager diff --stat -- vectors/ >&2
  exit 1
fi

echo "ALL GREEN"
