<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Red-evidence: N-AALP evidentiality primitive

Mutation-survival evidence for the load-bearing properties of `naalp_evidentiality`. Each row
was produced by actually editing `naalp_evidentiality/evidentiality.py` (never any
`impl/python/naalp/*` file, which is Part-1 and out of scope for this task), confirming the
named test(s) flip RED for the stated reason, then restoring the file from a `.bak` copy
(never `git checkout`), clearing `__pycache__` (`PYTHONDONTWRITEBYTECODE=1` set for every run
so no stale bytecode can mask a mutation or fake a revert), and re-running the full suite GREEN
with the file's hash re-confirmed identical to the pre-mutation baseline.

Baseline / reverted file hash for `naalp_evidentiality/evidentiality.py` (SHA-256), confirmed
identical before mutation 1 and after every one of the four reverts below:

```
b380b333b78fccfd15a5b3f874e2ecd65e411ec3631cd60b0a93e17f749677a4
```

Run command (from `ecosystem/naalp-evidentiality/`, invoking the real installed Python
interpreter for this platform -- on Windows the Microsoft-Store `python`/`python3`
execution-alias stubs resolve ahead of a real install on `PATH` and hang, so on that platform
invoke the actual interpreter binary directly rather than the bare `python` command):

```
PYTHONDONTWRITEBYTECODE=1 python -m unittest -v tests.test_evidentiality
```

All commands below were run from `ecosystem/naalp-evidentiality/` with
`PYTHONDONTWRITEBYTECODE=1` set and `__pycache__` removed immediately before every test
invocation (mutate, revert, and re-confirm), so no cached `.pyc` could report a result that did
not come from the file on disk at that moment. Full suite size: 7 test methods (2 of which,
`test_admit_cases` and `test_reject_cases`, run 4 and 13 `subTest` cases respectively).

## Non-circular vector provenance (established before any mutation test)

`scripts/build_vectors.py` is the oracle: it NEVER imports `naalp_evidentiality.evidentiality`
(the code under test). Every expected admit/reject verdict in `vectors/cases.json` is authored
directly from the specification's text and the closed basis-registry design table, not computed by the
module under test. Its own asserts (which abort the build if they fail) cross-check the
non-cryptographic wire bytes against independent authorities before any vector is written:

- **Content id** (basis 0 and basis 3 fixtures): `naalp.cbor.content_id`'s formula
  (`multihash(0x20, 0x30) || SHA-384(body)`) is independently re-derived via
  `tools/cbor_oracle.py`'s from-scratch deterministic-CBOR encoder plus Python's standard-library
  `hashlib.sha384` (not `naalp.cbor`, and not `naalp_evidentiality`) and compared byte-for-byte
  to `naalp.cbor.content_id`'s own output for the same body -- confirmed equal (`assert`) before
  the vectors file is written.
- **Signer id** (basis 0 and basis 2 fixtures): `naalp.identity.signer_id` is independently
  re-derived via `tools/signerid_oracle.py`'s multicodec/multihash/multibase constructor (an
  existing top-level oracle, shared with no code path `naalp_evidentiality` touches) for the
  SAME public key, and confirmed equal.
- **Receipt body bytes** (basis 2 fixture): `naalp.audit.Receipt.bytes()` (the `{1:prev,2:obj,
  3:seq,4:at}` deterministic-CBOR encoding a real `naalp.audit.Authority.append()` call produces)
  is independently re-derived via `tools/audit_oracle.py`'s encoding convention and confirmed
  equal for receipt 0 of the real 3-receipt chain the vectors build.
- **Cryptographic material** (the ML-DSA signatures and the audit receipt chain's real
  signatures): produced with the real, independently-graded Part-1 SDK
  (`naalp.cose.mldsa_sign` / `naalp.audit.Authority`) -- legitimate reuse of the SAME primitives
  `naalp_evidentiality.evidentiality` itself delegates every check to (see that module's own
  docstring), not the code under test manufacturing its own expected values. `tools/audit_oracle.py`
  and `tools/cose_oracle.py` both document that a from-scratch Python ML-DSA is out of scope for
  this codebase's oracles; the signature/chain BYTES are graded elsewhere (two-implementation
  byte-parity, `vectors/cose/nist_acvp_mldsa.json`), and this task reuses those already-graded
  primitives rather than re-deriving them.

All grounding asserts passed (`scripts/build_vectors.py` exits 0) before any test below ran.

## M1 -- fail-open bypass of the bare-assertion refusal (`test_reject_cases[bare_assertion]` + `test_basis_code_with_no_basis_ref_refused`)

**Mutated:** `verify_and_admit()`, disabled the branch that refuses a bare assertion:

```diff
-    if assertion.basis_code is None or assertion.basis_ref is None:
-        raise EvidentialityError("NoBasis", "assertion carries no derivation basis (%r)" % (assertion.what,))
+    if False:  # MUTATION M1 (red-evidence): never refuse a bare assertion -- fail-open.
+        raise EvidentialityError("NoBasis", "assertion carries no derivation basis (%r)" % (assertion.what,))
```

**RED, confirmed:** 2 of 7 test methods failed --

```
ERROR: test_basis_code_with_no_basis_ref_refused
AttributeError: 'NoneType' object has no attribute 'signer_id'
FAIL: test_reject_cases (case='bare_assertion')
AssertionError: 'UnknownBasis' != 'NoBasis'
```

With the guard disabled, a bare assertion (`basis_code=None`) falls through to the
registry-membership check, which correctly still refuses it (`None not in _BASIS_NAMES`) but
with the WRONG named error (`UnknownBasis` instead of `NoBasis`) -- confirming the "no bare
assertion without provenance" requirement is enforced by THIS specific branch, not merely by
downstream luck. A basis_code that IS registered but carries `basis_ref=None` (the direct test)
falls all the way through to a real re-check function and crashes on `None.signer_id` -- an
uncaught `AttributeError`, not a clean fail-closed refusal, demonstrating the guard is what
turns a malformed assertion into a NAMED error rather than an unhandled crash. The other 5 test
methods (12 further subTest cases) were unaffected -- exactly the boundary this mutation
targets.

**Reverted:** the file was restored from its `.bak` copy (never `git checkout`), `__pycache__`
cleared, hash re-confirmed `b380b333b78fccfd15a5b3f874e2ecd65e411ec3631cd60b0a93e17f749677a4`.
**GREEN, confirmed:** 7/7 test methods pass (17 subTest cases total).

## M2 -- basis-registry dispatch routing (`test_admit_cases[oracle_established_admit]` + `test_reject_cases[oracle_unregistered / oracle_input_mismatch / oracle_value_mismatch]`)

**Mutated:** `verify_and_admit()`, routed basis 1 (oracle-established) to the WRONG re-check
function:

```diff
     elif assertion.basis_code == BASIS_ORACLE_ESTABLISHED:
-        _recheck_oracle_established(assertion, evidence, oracle_registry)
+        _recheck_authority_attested(assertion, evidence)  # MUTATION M2 (red-evidence): wrong dispatch target
```

**RED, confirmed:** 4 of 7 test methods failed (1 admit subTest + 3 reject subTests) --

```
ERROR: test_admit_cases (case='oracle_established_admit')
  (OracleEvidence is not an AuthorityEvidence -> EvidenceMissing, so the previously-admitted
   case now raises)
FAIL: test_reject_cases (case='oracle_unregistered')
AssertionError: 'EvidenceMissing' != 'OracleUnregistered'
FAIL: test_reject_cases (case='oracle_input_mismatch')
AssertionError: 'EvidenceMissing' != 'OracleInputMismatch'
FAIL: test_reject_cases (case='oracle_value_mismatch')
AssertionError: 'EvidenceMissing' != 'OracleValueMismatch'
```

Every basis-1 case (the one admit case and all three basis-1-specific reject cases) flipped,
because `_recheck_authority_attested` immediately rejects `OracleEvidence` as the wrong evidence
type (`EvidenceMissing`) before it can ever reach the real oracle-registry logic. All basis-0,
basis-2, and basis-3 cases (10 further subTest cases) were UNAFFECTED -- exactly isolating this
mutation to the basis-registry DISPATCH itself, which is precisely the property this task's own
docstring names as this module's own logic (as opposed to the delegated Part-1 primitives).

**Reverted:** restored from `.bak`, `__pycache__` cleared, hash re-confirmed
`b380b333b78fccfd15a5b3f874e2ecd65e411ec3631cd60b0a93e17f749677a4`.
**GREEN, confirmed:** 7/7 test methods pass (17 subTest cases total).

## M3 -- authority-attested chain-integrity re-check (`test_reject_cases[chain_invalid]`)

**Mutated:** `_recheck_authority_attested()`, removed the call that re-verifies the receipt
chain for real:

```diff
-    try:
-        audit.verify_chain(evidence.receipts, evidence.sigs, evidence.authority_alg, evidence.authority_pubkey)
-    except audit.AuditError as e:
-        raise EvidentialityError("ChainInvalid", "receipt chain does not verify: %s" % (e.kind,))
-    if evidence.receipts[seq].obj != assertion.value_content_id:
+    # MUTATION M3 (red-evidence): never re-verify the chain -- pretend it always verifies.
+    if evidence.receipts[seq].obj != assertion.value_content_id:
```

**RED, confirmed:** 1 of 7 test methods failed --

```
FAIL: test_reject_cases (case='chain_invalid')
AssertionError: 'ReceiptNotAtSeq' != 'ChainInvalid'
```

With `naalp.audit.verify_chain` never called, a chain with a broken `prev` link at seq 1 is no
longer caught by the intended `ChainInvalid` path; the `chain_invalid` fixture happens to still
raise an error (its tampered receipt's `obj` differs from the asserted value, so
`ReceiptNotAtSeq` fires instead), but with the WRONG named error -- proving the actual chain
re-verify was skipped rather than merely coincidentally still-passing. All 6 other test methods
(16 further subTest cases, including the genuinely valid `authority_attested_admit` case, whose
real chain was never broken) were unaffected -- exactly isolating this mutation to the
chain-integrity re-check `naalp.audit.verify_chain` performs, distinct from the separate
receipt-at-sequence check below it.

**Reverted:** restored from `.bak`, `__pycache__` cleared, hash re-confirmed
`b380b333b78fccfd15a5b3f874e2ecd65e411ec3631cd60b0a93e17f749677a4`.
**GREEN, confirmed:** 7/7 test methods pass (17 subTest cases total).

## M4 -- input-computed's two-independent-checks property (`test_reject_cases[input_computed_input_mismatch]`)

**Mutated:** `_recheck_input_computed()`, removed the check that binds the evidence to the
NAMED input (leaving only the check that the recomputed id matches the asserted value):

```diff
     recomputed = cbor.content_id(evidence.input_bytes)
-    if recomputed != assertion.basis_ref.input_content_id:
-        raise EvidentialityError("InputMismatch", "evidence input does not match the named input content id")
+    # MUTATION M4 (red-evidence): never check the evidence against the named input content id.
     if recomputed != assertion.value_content_id:
```

**RED, confirmed:** 1 of 7 test methods failed --

```
FAIL: test_reject_cases (case='input_computed_input_mismatch')
AssertionError: 'RecomputeMismatch' != 'InputMismatch'
```

The `input_computed_input_mismatch` fixture supplies evidence bytes that are NEITHER the named
input NOR the asserted value's own preimage, so it still raises an error even with the
`InputMismatch` branch gone (`RecomputeMismatch` fires instead) -- but with the WRONG named
error, proving the FIRST of the two independent checks (binding evidence to `basis_ref`'s
claimed input identity) was skipped. All 6 other test methods (16 further subTest cases,
including `input_computed_admit` and `input_computed_recompute_mismatch`, whose evidence bytes
genuinely match `basis_ref.input_content_id` and so never exercise the removed branch either
way) were unaffected -- confirming the two checks in `_recheck_input_computed` are independently
meaningful, not one accidentally subsuming the other.

**Reverted:** restored from `.bak`, `__pycache__` cleared, hash re-confirmed
`b380b333b78fccfd15a5b3f874e2ecd65e411ec3631cd60b0a93e17f749677a4`.
**GREEN, confirmed:** 7/7 test methods pass (17 subTest cases total).

## Why these four, and why every mutation targets `evidentiality.py` rather than `naalp.*`

`naalp_evidentiality` is glue: every cryptographic, identity, and chain check (COSE signature
verify, the C4 signer id, the receipt-chain re-verify, the deterministic-CBOR content id) is
delegated to the real Part-1 `naalp.identity` / `naalp.cose` / `naalp.audit` / `naalp.cbor`
primitives, which carry their own graded red-evidence elsewhere in this codebase (out of scope
for this task -- Part-1 files are not touched here). What IS this task's own code, and therefore
what these four mutations target, is exactly what this module's own docstring names as its
logic: the basis-registry DISPATCH (M1: that a malformed/bare assertion is refused with the
RIGHT named error rather than falling through or crashing; M2: that each basis code routes to
its OWN re-check procedure, not another basis's) and the fail-closed REFUSAL CHOICES within each
re-check (M3: that the authority-attested basis actually re-verifies the chain rather than
trusting the receipt list as-is; M4: that the input-computed basis's two independently-populated
fields -- what the evidence IS and what the assertion CLAIMS -- are both actually checked, not
just one). All four are exactly the properties THIS module must get right -- not the
underlying SDK: "the record states how it knows," enforced by actually running
the stated basis, not by trusting the label.
