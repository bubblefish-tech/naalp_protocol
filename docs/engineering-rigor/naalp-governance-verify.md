<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Red-evidence: naalp-governance-verify (offline mixed-kind chain verifier and replay)

Mutation-survival evidence for `naalp_governance_verify/verify.py`'s causal-order property
("a broken causal link -- a cause naming a record at or after its own dependent -- is fail-closed rejected,
never silently accepted"). Produced by actually editing `naalp_governance_verify/verify.py`
(never `naalp_kit/binding.py` or `impl/python/naalp/*`, both out of scope and already separately
graded), confirming the named test flips RED for the stated reason, then restoring the file from
a `.bak` copy (never `git checkout` -- this tree is uncommitted), clearing `__pycache__`
(`PYTHONDONTWRITEBYTECODE=1` set for every run), and re-running the full 20-test suite GREEN.

Baseline / reverted file hash for `naalp_governance_verify/verify.py` (SHA-256), confirmed
identical before the mutation and after the revert (19103 bytes both times):

```
8591cfa4c3e770b66de67db8e137705d5f4e4d5f72c4f9296b7f2ac2761fa985
```

Run command (from the repo root, invoking the real installed Python interpreter for this
platform -- on Windows the Microsoft-Store `python`/`python3` execution-alias stubs resolve
ahead of a real install on `PATH` and hang, so invoke the actual interpreter binary directly
rather than the bare `python` command):

```
PYTHONDONTWRITEBYTECODE=1 python -m pytest ecosystem/naalp-governance-verify/tests/test_verify.py -v
```

## M1 -- out-of-order-causal-link-fail-closed (`test_verify_chain_rejects_an_out_of_order_causal_link`)

**Mutated:** `verify_chain`'s causal-order check -- the `if referent_index >= link.index:` guard
that rejects a `causes[]` entry naming a record at or after its own dependent in the log (a
reordered / dropped-link chain) -- disabled:

```diff
-            if referent_index >= link.index:
+            # MUTATION M1 (red-evidence, naalp-governance-verify): the out-of-order causal-link
+            # check disabled -- a cause naming a record at or after its own dependent would be
+            # silently accepted (the exact reordered/dropped-link defect this property exists to catch).
+            if False:
                 raise ChainOrderBroken(
                     "record %d (content id %s) causes[] names record %d, which appears at or "
                     "after it in the log -- an out-of-order / reordered / dropped causal link"
                     % (link.index, link.content_id.hex(), referent_index), index=link.index)
```

**Result:** exactly one test failed, for the intended reason --
`test_verify_chain_rejects_an_out_of_order_causal_link`:

```
FAILED ecosystem/naalp-governance-verify/tests/test_verify.py::test_verify_chain_rejects_an_out_of_order_causal_link
Failed: DID NOT RAISE ChainOrderBroken
```

All 19 other tests stayed GREEN under the mutation (confirming the mutation's blast radius is
exactly the property it targets, not a coincidental wider break):

```
19 passed, 1 failed
```

**Reverted:** `mv verify.py.bak verify.py` (never `git checkout` -- the tree is uncommitted; a
checkout on an untracked/uncommitted file either no-ops silently or discards unrelated pending
work). SHA-256 confirmed
byte-identical to the pre-mutation baseline above. Full suite re-run GREEN:

```
20 passed in 4.44s
```

## Why this mutation, specifically

`test_verify_chain_rejects_an_out_of_order_causal_link` is this module's headline fail-closed
property ("reordered/dropped chain links flagged"; the module's own acceptance
criterion: "fail-closed on any bad signature / broken causes-chain / missing referent"). The
other four fail-closed tests (`test_verify_chain_rejects_a_tampered_signature`,
`test_verify_chain_rejects_a_missing_referent`, `test_verify_chain_rejects_a_duplicate_content_id`,
`test_verify_chain_rejects_an_unresolved_signer`) each exercise a DIFFERENT branch of
`verify_chain`/`_verify_one` and were confirmed to stay red-capable by direct code inspection
(each raises its own distinct exception type from a distinct `if`/`except` site with no shared
guard) -- the out-of-order check was chosen for the recorded mutation because it is the one whose
absence is easiest to mistake for "harmless" (the chain still verifies cryptographically; only
its CAUSAL STRUCTURE claim would be silently trusted), making it the highest-value single
mutation to prove.

## Non-circularity

Every test's expected-verify-or-reject outcome is established independently of
`naalp_governance_verify`'s own code: every signed record is built via the real
`naalp.ez.Signer.sign` and every content id used to wire a `causes[]` link is obtained via an
independent `naalp.ez.verify` decode (never through `verify_chain`/`_verify_one`, the module
under test) -- see `test_verify.py`'s `_sign` helper and its module docstring. Tamper fixtures
(bad signature, missing referent, out-of-order link, duplicate content id, truncated log,
non-signed garbage bytes) are hand-constructed byte edits made directly against the test file's
own fixtures, not derived from any output of the module under test.
