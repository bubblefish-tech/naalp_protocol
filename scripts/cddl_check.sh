#!/usr/bin/env bash
# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# CDDL conformance gate (T14): the wire-format module spec/naalp-draft-00.cddl is
#   1. well-formed (parses in the Bormann `cddl` tool, no error, no unused rule), and
#   2. actually validates real conformance bytes — every positive vector below validates
#      against its production, and cross-rule mismatches are rejected.
#
# The `cddl` tool validates against the FIRST rule in the module, so for each construction we
# prepend `start = <rule>` to make that production the start rule, then validate the canonical
# CBOR bytes extracted from the committed vectors. This proves the prose CDDL and the graded
# implementations agree (a stranger could build from the CDDL alone).
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
CDDL="${CDDL:-cddl}"
PY="${PYTHON:-python}"
MODULE="spec/naalp-draft-00.cddl"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fail=0
pass=0

# well-formedness: the module must parse (generate an instance of the root) with no error.
echo "== CDDL well-formedness =="
if err=$("$CDDL" "$MODULE" generate 1 2>&1 >/dev/null); then
  if echo "$err" | grep -qiE "unused|error|expected"; then
    echo "  FAIL: module parses with warnings/errors:"; echo "$err" | grep -iE "unused|error|expected" | head; fail=1
  else
    echo "  PASS: module is well-formed (no unused rule, no error)"
  fi
else
  echo "  FAIL: module does not parse:"; echo "$err" | head; fail=1
fi

# validate <rule> <cbor-file> — expect exit 0; report PASS/FAIL.
expect_valid() {
  local rule="$1" cbor="$2" label="$3"
  { echo "start = $rule"; cat "$MODULE"; } > "$TMP/rule.cddl"
  if "$CDDL" "$TMP/rule.cddl" validate "$cbor" >/dev/null 2>&1; then
    echo "  PASS  $label  validates against $rule"; pass=$((pass+1))
  else
    echo "  FAIL  $label  does NOT validate against $rule"; fail=1
  fi
}

# expect a mismatch to be REJECTED — exit non-zero.
expect_invalid() {
  local rule="$1" cbor="$2" label="$3"
  { echo "start = $rule"; cat "$MODULE"; } > "$TMP/rule.cddl"
  if "$CDDL" "$TMP/rule.cddl" validate "$cbor" >/dev/null 2>&1; then
    echo "  FAIL  $label  wrongly validates against $rule (should be rejected)"; fail=1
  else
    echo "  PASS  $label  correctly rejected by $rule"; pass=$((pass+1))
  fi
}

# hexfield <out.cbor> <vector.json> <path...> — traverse a JSON path (dict keys, or all-digit
# list indices) to a hex string and write its bytes. No eval; the path is fixed script data.
hexfield() {
  local out="$1" vec="$2"; shift 2
  "$PY" - "$out" "$vec" "$@" <<'PY'
import json,sys
out, vec = sys.argv[1], sys.argv[2]
c = json.load(open(vec))
for p in sys.argv[3:]:
    c = c[int(p)] if p.lstrip('-').isdigit() else c[p]
open(out, 'wb').write(bytes.fromhex(c))
PY
}

echo "== CDDL positive validation (committed vectors validate against their production) =="
hexfield "$TMP/approval.cbor"   vectors/approval/cases.json   approvals 0 record_hex
expect_valid naalp-approval        "$TMP/approval.cbor"   "approval body"
hexfield "$TMP/consume.cbor"    vectors/approval/cases.json   ledger consumes 0 entry_hex
expect_valid naalp-consume-entry   "$TMP/consume.cbor"    "consume-ledger entry"
hexfield "$TMP/receipt.cbor"    vectors/audit/cases.json      chain receipts 0 body_hex
expect_valid naalp-receipt         "$TMP/receipt.cbor"    "audit receipt"
hexfield "$TMP/delivery.cbor"   vectors/delivery/cases.json   updates 0 body_hex
expect_valid naalp-delivery-update "$TMP/delivery.cbor"   "delivery.update"
hexfield "$TMP/sopen.cbor"      vectors/stream/cases.json     open_body_hex
expect_valid naalp-stream-open     "$TMP/sopen.cbor"      "stream open"
hexfield "$TMP/scommit.cbor"    vectors/stream/cases.json     commit_body_hex
expect_valid naalp-stream-commit   "$TMP/scommit.cbor"    "stream commit"
hexfield "$TMP/scheck.cbor"     vectors/stream/cases.json     checkpoint_body_hex
expect_valid naalp-stream-checkpoint "$TMP/scheck.cbor"   "stream checkpoint"
hexfield "$TMP/carriage.cbor"   vectors/carriage/jsonrpc/cases.json body_hex
expect_valid naalp-carriage-body   "$TMP/carriage.cbor"   "carriage body (JSONRPC)"
hexfield "$TMP/reconcile.cbor"  vectors/federation/cases.json record_hex
expect_valid naalp-reconcile       "$TMP/reconcile.cbor"  "reconcile record"
hexfield "$TMP/safety.cbor"     vectors/effect/cases.json     safety_label cbor_hex
expect_valid naalp-safety-label    "$TMP/safety.cbor"     "safety label"

echo "== CDDL negative validation (cross-rule mismatches are rejected) =="
expect_invalid naalp-receipt   "$TMP/approval.cbor"  "approval body vs receipt rule"
expect_invalid naalp-approval  "$TMP/receipt.cbor"   "receipt body vs approval rule"
expect_invalid naalp-reconcile "$TMP/delivery.cbor"  "delivery update vs reconcile rule"

echo
if [ "$fail" -eq 0 ]; then
  echo "CDDL CHECK: ALL GREEN ($pass constructions validated)"
  exit 0
else
  echo "CDDL CHECK: FAILED"
  exit 1
fi
