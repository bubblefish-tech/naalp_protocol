#!/usr/bin/env bash
# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# N-AALP conformance harness (C14, T14) — the single command that grades the whole protocol:
#
#   [1] two-implementation parity     scripts/verify.sh
#       (regenerate every non-circular oracle -> Go build+vet+test-race -> Rust build+test ->
#        Go == Rust byte-identical COSE_Sign1 + object envelope -> vector-drift gate)
#   [2] CDDL conformance              scripts/cddl_check.sh
#       (spec/naalp-draft-00.cddl is well-formed in the Bormann `cddl` tool AND validates the
#        committed vectors against their production; cross-rule mismatches are rejected)
#   [3] registry drift                scripts/registry_drift.py
#       (the machine-readable registries stay consistent with the graded vectors)
#   [4] cross-language conformance    harness/cross_language.sh
#       (the shared op-replay corpus is driven through every reference SDK adapter with the
#        naalp-conform runner, and deterministic ML-DSA COSE_Sign1 is byte-identical across langs)
#
# A construction is "graded" only when both implementations agree with the independent oracle
# (R-16.1/R-16.2) AND, where it has a wire production, the CDDL validates its bytes. This runner
# prints a per-construction table and exits non-zero if any gate fails.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

step() { echo; echo "######## $1 ########"; }

step "[1/3] two-implementation parity (scripts/verify.sh)"
bash scripts/verify.sh; p1=$?

step "[2/3] CDDL conformance (scripts/cddl_check.sh)"
bash scripts/cddl_check.sh; p2=$?

step "[3/4] registry drift (scripts/registry_drift.py)"
"${PYTHON:-python}" scripts/registry_drift.py; p3=$?

step "[4/4] cross-language conformance (harness/cross_language.sh)"
bash harness/cross_language.sh; p4=$?

step "per-construction conformance table"
# Each row is graded by the gates above (Go + Rust vs the independent oracle, and — where it has a
# wire production — the CDDL). Printed only when all four gates are green.
if [ "$p1" -eq 0 ] && [ "$p2" -eq 0 ] && [ "$p3" -eq 0 ] && [ "$p4" -eq 0 ]; then
  printf '  %-28s %-8s %-8s %-8s %s\n' "construction" "Go" "Rust" "CDDL" "oracle"
  printf '  %-28s %-8s %-8s %-8s %s\n' "----------------------------" "----" "----" "----" "------"
  row() { printf '  %-28s %-8s %-8s %-8s %s\n' "$1" "graded" "graded" "$2" "$3"; }
  row "C1 deterministic CBOR"        "n/a"   "RFC 8949 + SHA-384 KAT"
  row "C2 COSE_Sign1 + ML-DSA"       "n/a"   "RFC 9052 + NIST ACVP + RFC 8032"
  row "C3 object envelope"           "n/a"   "independent tamper/ext vectors"
  row "C4 identity / signer-id"      "n/a"   "multiformats PeerHandle constructor"
  row "C5 effect + authorization"    "yes"   "N-PAMP SafetyLabel + lattice matrix"
  row "C6 approval + consume ledger" "yes"   "compare-and-set hash-chain model"
  row "C7 audit + causal + ordering" "yes"   "SHA-384 chain + topo model"
  row "C8 delivery + switchboard"    "yes"   "delivery.update bytes"
  row "C9 native streaming"          "yes"   "rolling SHA-384 constructor"
  row "C11 transport bindings"       "n/a"   "one object across four bindings"
  row "C12 foreign carriage"         "yes"   "octet-exact per-class round-trip"
  row "C10 twenty channel surfaces"  "n/a"   "independent channel table (65 kinds)"
  row "T13 federated reconcile"      "yes"   "deterministic causal-merge model"
  row "cross-language (go,rust)"     "yes"   "op-replay corpus + ML-DSA consensus"
  echo
  echo "N-AALP CONFORMANCE: ALL GREEN — two implementations agree on every graded construction;"
  echo "CDDL well-formed and validates the corpus; no registry drift; the reference SDK adapters"
  echo "agree on the shared corpus and produce byte-identical deterministic ML-DSA signatures."
  exit 0
else
  echo "  parity=$([ $p1 -eq 0 ] && echo ok || echo FAIL)  cddl=$([ $p2 -eq 0 ] && echo ok || echo FAIL)  registry=$([ $p3 -eq 0 ] && echo ok || echo FAIL)  cross-lang=$([ $p4 -eq 0 ] && echo ok || echo FAIL)"
  echo "N-AALP CONFORMANCE: FAILED"
  exit 1
fi
