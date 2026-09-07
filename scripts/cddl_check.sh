#!/usr/bin/env bash
# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# CDDL conformance gate (T14): the wire-format module spec/naalp-draft-01.cddl is
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
MODULE="spec/naalp-draft-01.cddl"
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
hexfield "$TMP/forkproof.cbor"  vectors/audit/cases.json      fork_proof preimage_hex
expect_valid naalp-fork-proof      "$TMP/forkproof.cbor"  "fork proof (draft-01, sigs elided)"
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
hexfield "$TMP/deleg.cbor"      vectors/delegation/cases.json grants 0 body_hex
expect_valid naalp-delegation-grant "$TMP/deleg.cbor"    "delegation grant (with scope)"
hexfield "$TMP/deleg_ns.cbor"   vectors/delegation/cases.json grants 1 body_hex
expect_valid naalp-delegation-grant "$TMP/deleg_ns.cbor" "delegation grant (no scope)"
# T1.5 ledger-signed consume receipt: the base receipt validates against naalp-consume-receipt.
hexfield "$TMP/consume_receipt.cbor" vectors/consume_receipt/cases.json base body_hex
expect_valid naalp-consume-receipt "$TMP/consume_receipt.cbor" "ledger-signed consume receipt (T1.5)"
# R-TDCS-5 audience field + R-TDCS-3 coarse refusal (C22, design.md §25). The audience-bearing
# approval exercises the OPTIONAL ?6 member; the refusal cases validate the closed-set object, and
# the two negatives prove the CDDL itself rejects a leaked-detail extra field and an outcome outside
# the closed set (not just the impl parser).
hexfield "$TMP/appr_aud.cbor"    vectors/trust_decision/cases.json audience cases 0 record_hex
expect_valid naalp-approval "$TMP/appr_aud.cbor" "approval carrying an audience (R-TDCS-5, ?6)"
hexfield "$TMP/refusal_den.cbor" vectors/trust_decision/cases.json refusal cases 0 record_hex
expect_valid naalp-refusal "$TMP/refusal_den.cbor" "coarse refusal (denied, R-TDCS-3)"
hexfield "$TMP/refusal_unv.cbor" vectors/trust_decision/cases.json refusal cases 2 record_hex
expect_valid naalp-refusal "$TMP/refusal_unv.cbor" "coarse refusal (unverifiable, R-TDCS-3)"
hexfield "$TMP/refusal_leak.cbor" vectors/trust_decision/cases.json refusal reject detail_leak_extra_field_hex
expect_invalid naalp-refusal "$TMP/refusal_leak.cbor" "refusal with an extra field (detail leak)"
hexfield "$TMP/refusal_unk.cbor" vectors/trust_decision/cases.json refusal reject unknown_outcome_hex
expect_invalid naalp-refusal "$TMP/refusal_unk.cbor" "refusal with an outcome outside the closed set"
# R-TDCS-1 trust-decision input-class registry enum: a known class id validates, an out-of-set id is
# rejected (the CDDL enum agrees with the registry CSV, which registry_drift.py also asserts).
printf '\x05' > "$TMP/tdic_known.cbor"    # CBOR uint 5 = verification-procedure (in the closed set)
expect_valid trust-decision-input-class "$TMP/tdic_known.cbor" "input-class id 5 (known)"
printf '\x18\x63' > "$TMP/tdic_unk.cbor"  # CBOR uint 99 (outside the registry)
expect_invalid trust-decision-input-class "$TMP/tdic_unk.cbor" "input-class id 99 (out of set)"
# T1.3 recheck-procedure enum: a known procedure id validates against the closed registry.
printf '\x02' > "$TMP/recheck_known.cbor"       # CBOR uint 2 = verify-cose-sign1 (known)
expect_valid recheck-procedure "$TMP/recheck_known.cbor" "recheck procedure id 2 (known)"
# T1.6 per-signer counter: a counter-bearing object body validates against naalp-object, and a bare
# forward-only position (any 64-bit uint, incl. one too large for a normal int) validates against the
# signer-counter production.
hexfield "$TMP/counter_obj.cbor" vectors/signer_counter/cases.json cases 0 full_hex
expect_valid naalp-object "$TMP/counter_obj.cbor" "object carrying ext[14] signer-counter (T1.6)"
printf '\x05' > "$TMP/counter_small.cbor"       # CBOR uint 5 (a small position)
expect_valid signer-counter "$TMP/counter_small.cbor" "signer-counter position 5"
printf '\x1b\x00\x20\x00\x00\x00\x00\x00\x00' > "$TMP/counter_big.cbor"  # CBOR uint 2^53
expect_valid signer-counter "$TMP/counter_big.cbor" "signer-counter position 2^53 (large uint)"
# C17 N-AALP-CONT flow continuation: flow-open, continuation, checkpoint, and flow-commit bodies each
# validate against their production. A big-seq continuation (seq > 2^53) also validates (the counter
# field is an open uint), proving the CDDL admits the oversized-counter round-trip case.
hexfield "$TMP/flowopen.cbor"   vectors/continuation/cases.json flow_open body_hex
expect_valid naalp-flow-open        "$TMP/flowopen.cbor"   "flow open (C17)"
hexfield "$TMP/cont.cbor"       vectors/continuation/cases.json continuations 0 body_hex
expect_valid naalp-continuation     "$TMP/cont.cbor"       "continuation link (C17)"
hexfield "$TMP/flowcheck.cbor"  vectors/continuation/cases.json checkpoint body_hex
expect_valid naalp-flow-checkpoint  "$TMP/flowcheck.cbor"  "flow checkpoint (C17)"
hexfield "$TMP/flowcommit.cbor" vectors/continuation/cases.json flow_commit body_hex
expect_valid naalp-flow-commit      "$TMP/flowcommit.cbor" "flow commit (C17)"
hexfield "$TMP/cont_bigseq.cbor" vectors/continuation/cases.json big_seq body_hex
expect_valid naalp-continuation     "$TMP/cont_bigseq.cbor" "continuation seq > 2^53 (C17 oversized counter)"
# C18 signed description / directory primitive: the description body, a directory version, and a
# foreign-description import each validate against their production.
hexfield "$TMP/desc.cbor"        vectors/description/cases.json description body_hex
expect_valid naalp-description        "$TMP/desc.cbor"       "signed description body (C18)"
hexfield "$TMP/desc_op.cbor"     vectors/description/cases.json description operations 0 body_hex
expect_valid naalp-description-operation "$TMP/desc_op.cbor" "description operation (C18)"
hexfield "$TMP/dir.cbor"         vectors/description/cases.json directory a body_hex
expect_valid naalp-directory          "$TMP/dir.cbor"        "signed directory body (C18)"
hexfield "$TMP/desc_import.cbor" vectors/description/cases.json import body_hex
expect_valid naalp-description-import  "$TMP/desc_import.cbor" "foreign-description import (C18)"
# C19 name bindings + A2A task-state profile: a name-binding body, a task-transition body, and a
# known task-state value each validate against their production.
hexfield "$TMP/namebind.cbor" vectors/naming/cases.json name bindings 0 body_hex
expect_valid naalp-name-binding    "$TMP/namebind.cbor"   "signed name binding (C19)"
hexfield "$TMP/tasktrans.cbor" vectors/naming/cases.json a2a transitions 0 body_hex
expect_valid naalp-task-transition "$TMP/tasktrans.cbor"  "signed A2A task transition (C19)"
printf '\x03' > "$TMP/state_known.cbor"          # CBOR uint 3 = auth-required (a defined A2A state)
expect_valid task-state "$TMP/state_known.cbor" "A2A task-state 3 (auth-required, defined)"
# C20 governed negotiation + risk labels + trust: an offer, an accept, a risk label, a labeled
# object, and a trust ref each validate against their production; a known role/profile/critical value
# validates against its closed enum.
hexfield "$TMP/neg_offer.cbor"  vectors/negotiation/cases.json negotiation offer body_hex
expect_valid naalp-negotiation-offer  "$TMP/neg_offer.cbor"  "negotiation offer (C20)"
hexfield "$TMP/neg_accept.cbor" vectors/negotiation/cases.json negotiation accept body_hex
expect_valid naalp-negotiation-accept "$TMP/neg_accept.cbor" "negotiation accept (C20)"
hexfield "$TMP/risk_label.cbor" vectors/negotiation/cases.json risk sample_labels sensitive_critical body_hex
expect_valid naalp-risk-label   "$TMP/risk_label.cbor" "risk label (C20)"
hexfield "$TMP/labeled.cbor"    vectors/negotiation/cases.json risk labeled_objects 0 with_labels body_hex
expect_valid naalp-labeled-object "$TMP/labeled.cbor" "labeled object carrying risk labels (C20)"
hexfield "$TMP/trustref.cbor"   vectors/negotiation/cases.json trust ref_a body_hex
expect_valid naalp-trust-ref    "$TMP/trustref.cbor"   "trust ref (C20)"
printf '\x02' > "$TMP/role_known.cbor"           # CBOR uint 2 = accept (a defined negotiation role)
expect_valid negotiation-role "$TMP/role_known.cbor" "negotiation-role 2 (accept, defined)"
printf '\x01' > "$TMP/prof_known.cbor"           # CBOR uint 1 = streaming (a pre-registered profile)
expect_valid negotiation-profile "$TMP/prof_known.cbor" "negotiation-profile 1 (streaming, registered)"
printf '\x01' > "$TMP/crit_known.cbor"           # CBOR uint 1 = critical (a valid must-understand flag)
expect_valid risk-critical "$TMP/crit_known.cbor" "risk-critical 1 (valid must-understand flag)"
# C21 payment import + UI consent + portable gateway evidence: a payment-import body, a charge binding,
# a UI event, and a gateway decision each validate against their production; a known format/kind/
# decision value validates against its closed enum.
hexfield "$TMP/pay_import.cbor" vectors/payment/cases.json imports ap2 body_hex
expect_valid naalp-payment-import "$TMP/pay_import.cbor" "payment import (C21)"
hexfield "$TMP/pay_charge.cbor"  vectors/payment/cases.json imports ap2 charge_binding body_hex
expect_valid naalp-payment-charge-binding "$TMP/pay_charge.cbor" "payment charge binding (C21)"
printf '\x02' > "$TMP/payfmt_known.cbor"         # CBOR uint 2 = acp-delegated-token (registered)
expect_valid naalp-payment-format "$TMP/payfmt_known.cbor" "payment-format 2 (acp, registered)"
hexfield "$TMP/ui_event.cbor"    vectors/agui/cases.json chain events 2 body_hex
expect_valid naalp-ui-event "$TMP/ui_event.cbor" "ui event (approved) (C21)"
printf '\x02' > "$TMP/uikind_known.cbor"         # CBOR uint 2 = approved (a defined UI-event kind)
expect_valid ui-event-kind "$TMP/uikind_known.cbor" "ui-event-kind 2 (approved, defined)"
hexfield "$TMP/gw_decision.cbor" vectors/gateway/cases.json decisions deny body_hex
expect_valid naalp-gateway-decision "$TMP/gw_decision.cbor" "gateway decision (deny) (C21)"
printf '\x01' > "$TMP/gwdec_known.cbor"          # CBOR uint 1 = deny (a defined gateway decision)
expect_valid gw-decision "$TMP/gwdec_known.cbor" "gw-decision 1 (deny, defined)"

echo "== CDDL negative validation (cross-rule mismatches are rejected) =="
expect_invalid naalp-receipt   "$TMP/approval.cbor"  "approval body vs receipt rule"
expect_invalid naalp-approval  "$TMP/receipt.cbor"   "receipt body vs approval rule"
expect_invalid naalp-reconcile "$TMP/delivery.cbor"  "delivery update vs reconcile rule"
expect_invalid naalp-fork-proof "$TMP/receipt.cbor"  "receipt body vs fork-proof rule"
expect_invalid naalp-receipt   "$TMP/forkproof.cbor" "fork proof vs receipt rule"
expect_invalid naalp-delegation-grant "$TMP/receipt.cbor" "receipt body vs delegation-grant rule"
expect_invalid naalp-receipt   "$TMP/deleg.cbor"     "delegation grant vs receipt rule"
# T1.5: the ledger-signed consume receipt is distinct from the ledger's internal consume-entry and
# from the audit receipt — cross-rule bytes are rejected.
expect_invalid naalp-consume-entry   "$TMP/consume_receipt.cbor" "consume receipt vs consume-entry rule"
expect_invalid naalp-consume-receipt "$TMP/receipt.cbor"         "audit receipt vs consume-receipt rule"
# T1.3: a procedure id outside the closed registry {1..4} is rejected by recheck-procedure.
printf '\x18\x63' > "$TMP/recheck_unknown.cbor"  # CBOR uint 99 (unknown, outside the registry)
expect_invalid recheck-procedure "$TMP/recheck_unknown.cbor" "recheck procedure id 99 (unknown)"
# T1.6: the signer-counter production is a uint; a non-uint (a text string) is rejected.
printf '\x61\x78' > "$TMP/counter_tstr.cbor"    # CBOR tstr "x" (not a uint)
expect_invalid signer-counter "$TMP/counter_tstr.cbor" "signer-counter rejects a non-uint (tstr)"
# C17: the four CONT objects are distinct; a 2-field flow-commit is not a 3-field checkpoint
# (look-alike), and an effect_ceiling / effect OUTSIDE the closed `effect` enum (0..3) is rejected —
# this grades the audit-fix 0a (out-of-lattice ceiling/effect) at the CDDL level.
expect_invalid naalp-flow-checkpoint  "$TMP/flowcommit.cbor" "flow commit vs checkpoint rule (look-alike)"
expect_invalid naalp-flow-commit      "$TMP/flowcheck.cbor"  "checkpoint vs flow-commit rule"
expect_invalid naalp-continuation     "$TMP/flowopen.cbor"   "flow open vs continuation rule"
expect_invalid naalp-receipt          "$TMP/flowopen.cbor"   "flow open vs receipt rule"
hexfield "$TMP/flowopen_ceil4.cbor" vectors/continuation/cases.json range_reject flow_open_ceiling_body_hex
expect_invalid naalp-flow-open  "$TMP/flowopen_ceil4.cbor" "flow open with effect_ceiling 4 (outside closed effect)"
hexfield "$TMP/cont_eff4.cbor" vectors/continuation/cases.json range_reject continuation_effect_body_hex
expect_invalid naalp-continuation "$TMP/cont_eff4.cbor" "continuation with effect 4 (outside closed effect)"
# C18: the three description objects are distinct from each other and from the audit receipt.
expect_invalid naalp-directory        "$TMP/desc.cbor"        "description body vs directory rule"
expect_invalid naalp-description      "$TMP/dir.cbor"         "directory body vs description rule"
expect_invalid naalp-description      "$TMP/desc_import.cbor" "import body vs description rule"
expect_invalid naalp-receipt          "$TMP/desc.cbor"        "description body vs receipt rule"
# C18: an import whose format is outside the closed naalp-description-format set {1,2,3} is rejected —
# this grades the audit-fix 0d (unknown format) at the CDDL level.
hexfield "$TMP/desc_import_unkfmt.cbor" vectors/description/cases.json import unknown_format body_hex
expect_invalid naalp-description-import "$TMP/desc_import_unkfmt.cbor" "import with format 99 (outside closed naalp-description-format)"
# C19: the name binding and task transition are distinct from each other and from the audit receipt.
expect_invalid naalp-task-transition  "$TMP/namebind.cbor"    "name binding vs task-transition rule"
expect_invalid naalp-name-binding     "$TMP/tasktrans.cbor"   "task transition vs name-binding rule"
expect_invalid naalp-receipt          "$TMP/namebind.cbor"    "name binding vs receipt rule"
expect_invalid naalp-name-binding     "$TMP/receipt.cbor"     "receipt body vs name-binding rule"
# C19: a task-state value outside the closed set {0..7} is rejected by task-state.
printf '\x08' > "$TMP/state_unknown.cbor"        # CBOR uint 8 (no such A2A state)
expect_invalid task-state "$TMP/state_unknown.cbor" "A2A task-state 8 (undefined)"
# C20: offer/counter/accept are distinguished by their fixed role literal, so an offer body never
# validates as an accept (and vice-versa); the C20 objects are distinct from each other and from the
# audit receipt; a profile outside the closed set and a critical flag of 2 are rejected.
expect_invalid naalp-negotiation-accept "$TMP/neg_offer.cbor"  "offer body vs accept rule (role literal)"
expect_invalid naalp-negotiation-offer  "$TMP/neg_accept.cbor" "accept body vs offer rule (role literal)"
expect_invalid naalp-receipt            "$TMP/neg_offer.cbor"  "offer body vs receipt rule"
expect_invalid naalp-trust-ref          "$TMP/risk_label.cbor" "risk label vs trust-ref rule"
expect_invalid naalp-negotiation-offer  "$TMP/labeled.cbor"    "labeled object vs negotiation-offer rule"
expect_invalid naalp-labeled-object     "$TMP/trustref.cbor"   "trust ref vs labeled-object rule"
hexfield "$TMP/neg_unkprof.cbor" vectors/negotiation/cases.json negotiation unknown_profile_offer body_hex
expect_invalid naalp-negotiation-offer "$TMP/neg_unkprof.cbor" "offer with profile 99 (outside closed set)"
printf '\x18\x63' > "$TMP/prof_unknown.cbor"     # CBOR uint 99 (not a pre-registered profile)
expect_invalid negotiation-profile "$TMP/prof_unknown.cbor" "negotiation-profile 99 (unregistered)"
printf '\x02' > "$TMP/crit_bad.cbor"             # CBOR uint 2 (a critical flag outside {0,1})
expect_invalid risk-critical "$TMP/crit_bad.cbor" "risk-critical 2 (outside {0,1})"
# C21: the payment-import, ui-event, and gateway-decision are distinct from each other and from the
# audit receipt; and a format/kind/decision value outside its closed enum is rejected. (The
# payment-import and its charge-binding share one 6-field shape by design — the charge-binding is the
# payment-import's fields with foreign replaced by its content-id — so they are distinguished by
# position and semantics, not by CDDL structure, and are NOT asserted to reject each other.)
expect_invalid naalp-gateway-decision "$TMP/pay_import.cbor" "payment import vs gateway-decision rule"
expect_invalid naalp-ui-event "$TMP/gw_decision.cbor" "gateway decision vs ui-event rule"
expect_invalid naalp-gateway-decision "$TMP/ui_event.cbor" "ui event vs gateway-decision rule"
expect_invalid naalp-receipt "$TMP/pay_import.cbor" "payment import vs receipt rule"
expect_invalid naalp-receipt "$TMP/gw_decision.cbor" "gateway decision vs receipt rule"
printf '\x18\x63' > "$TMP/payfmt_unknown.cbor"   # CBOR uint 99 (not a registered payment format)
expect_invalid naalp-payment-format "$TMP/payfmt_unknown.cbor" "payment-format 99 (unregistered)"
printf '\x18\x63' > "$TMP/uikind_unknown.cbor"   # CBOR uint 99 (no such UI-event kind)
expect_invalid ui-event-kind "$TMP/uikind_unknown.cbor" "ui-event-kind 99 (undefined)"
printf '\x18\x63' > "$TMP/gwdec_unknown.cbor"    # CBOR uint 99 (no such gateway decision)
expect_invalid gw-decision "$TMP/gwdec_unknown.cbor" "gw-decision 99 (undefined)"

echo "== Part-1 wire-format edge-case positives (minimal objects validate) =="
# Edge case #4 (minimal): the smallest legal object for each kind validates against its production.
# (Edge case #1 keys-out-of-order is a CANONICAL-ENCODING property, not a grammar one — the cddl tool
# validates structure regardless of map key order — so it is graded by the Go/Rust cbor NonCanonical
# tests, not here.)
hexfield "$TMP/mcp_min.cbor"       vectors/mcp/cases.json         edge_cases minimal body_hex
expect_valid naalp-mcp-tool-call     "$TMP/mcp_min.cbor"     "minimal mcp tool-call (C16 #4)"
hexfield "$TMP/mcp_cb.cbor"        vectors/mcp/cases.json         edge_cases look_alike call_binding_body_hex
expect_valid naalp-mcp-call-binding  "$TMP/mcp_cb.cbor"      "mcp call-binding (sibling kind, valid as its own rule)"
hexfield "$TMP/neg_min_offer.cbor" vectors/negotiation/cases.json edge_cases minimal offer body_hex
expect_valid naalp-negotiation-offer "$TMP/neg_min_offer.cbor" "minimal negotiation offer (C20 #4)"
hexfield "$TMP/neg_min_lab.cbor"   vectors/negotiation/cases.json edge_cases minimal labeled_object body_hex
expect_valid naalp-labeled-object    "$TMP/neg_min_lab.cbor" "minimal labeled-object (C20 #4)"
hexfield "$TMP/neg_min_tr.cbor"    vectors/negotiation/cases.json edge_cases minimal trust_ref body_hex
expect_valid naalp-trust-ref         "$TMP/neg_min_tr.cbor"  "minimal trust-ref (C20 #4)"
hexfield "$TMP/gw_min.cbor"        vectors/gateway/cases.json     edge_cases minimal body_hex
expect_valid naalp-gateway-decision  "$TMP/gw_min.cbor"      "minimal gateway decision (C21 #4)"

echo "== Part-1 wire-format edge-case negatives (absent mandatory field / cross-kind look-alike) =="
# Edge case #2 (empty-vs-absent): a body whose MANDATORY field is ABSENT is rejected (empty-present is a
# distinct, valid body; the omitted-field body is not — graded at the wire level here).
hexfield "$TMP/mcp_abs.cbor"  vectors/mcp/cases.json         edge_cases empty_vs_absent absent_annotations body_hex
expect_invalid naalp-mcp-tool-call     "$TMP/mcp_abs.cbor"  "mcp tool-call missing annotations field (C16 #2)"
hexfield "$TMP/neg_cabs.cbor" vectors/negotiation/cases.json edge_cases empty_vs_absent causes absent_field body_hex
expect_invalid naalp-negotiation-offer "$TMP/neg_cabs.cbor" "negotiation offer missing causes field (C20 #2)"
hexfield "$TMP/neg_labs.cbor" vectors/negotiation/cases.json edge_cases empty_vs_absent labels absent_field body_hex
expect_invalid naalp-labeled-object    "$TMP/neg_labs.cbor" "labeled-object missing labels field (C20 #2)"
hexfield "$TMP/agui_abs.cbor" vectors/agui/cases.json        edge_cases empty_vs_absent absent_field body_hex
expect_invalid naalp-ui-event          "$TMP/agui_abs.cbor" "ui-event missing action field (C21 #2)"
hexfield "$TMP/pay_abs.cbor"  vectors/payment/cases.json     edge_cases empty_vs_absent absent_field body_hex
expect_invalid naalp-payment-import    "$TMP/pay_abs.cbor"  "payment-import missing foreign field (C21 #2)"
hexfield "$TMP/gw_abs.cbor"   vectors/gateway/cases.json     edge_cases empty_vs_absent absent_field body_hex
expect_invalid naalp-gateway-decision  "$TMP/gw_abs.cbor"   "gateway-decision missing policy field (C21 #2)"
# Edge case #5 (look-alike): a sibling kind or a near-miss body is rejected by the target production.
hexfield "$TMP/mcp_la.cbor"   vectors/mcp/cases.json         edge_cases look_alike call_binding_body_hex
expect_invalid naalp-mcp-tool-call     "$TMP/mcp_la.cbor"   "call-binding body vs tool-call rule (C16 #5)"
hexfield "$TMP/neg_tam.cbor"  vectors/negotiation/cases.json edge_cases look_alike trust_ref_as_message body_hex
expect_invalid naalp-negotiation-offer "$TMP/neg_tam.cbor"  "trust-ref body vs negotiation-offer rule (C20 #5)"
hexfield "$TMP/neg_mat.cbor"  vectors/negotiation/cases.json edge_cases look_alike message_as_trust_ref body_hex
expect_invalid naalp-trust-ref         "$TMP/neg_mat.cbor"  "message body vs trust-ref rule (C20 #5)"
hexfield "$TMP/agui_la.cbor"  vectors/agui/cases.json        edge_cases look_alike body_hex
expect_invalid naalp-ui-event          "$TMP/agui_la.cbor"  "ui-event missing prev vs ui-event rule (C21 #5 near-miss)"
hexfield "$TMP/pay_la.cbor"   vectors/payment/cases.json     edge_cases look_alike body_hex
expect_invalid naalp-payment-import    "$TMP/pay_la.cbor"   "payment-import with bstr currency vs import rule (C21 #5 near-miss)"
hexfield "$TMP/gw_la.cbor"    vectors/gateway/cases.json     edge_cases look_alike body_hex
expect_invalid naalp-gateway-decision  "$TMP/gw_la.cbor"    "ui-event body vs gateway-decision rule (C21 #5 look-alike)"

echo
if [ "$fail" -eq 0 ]; then
  echo "CDDL CHECK: ALL GREEN ($pass constructions validated)"
  exit 0
else
  echo "CDDL CHECK: FAILED"
  exit 1
fi
