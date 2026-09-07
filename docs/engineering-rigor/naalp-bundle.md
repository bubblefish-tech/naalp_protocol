<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Red-evidence: N-AALP offline proof bundle

Mutation-survival evidence for the three load-bearing properties described below. Each row
was produced by actually editing `naalp_bundle/bundle.py` (never `impl/python/naalp/*`, which is
Part-1 and out of scope for this task), confirming the named test(s) flip RED for the stated
reason, then restoring the file from a `.bak` copy (never `git checkout`), clearing
`__pycache__` (`PYTHONDONTWRITEBYTECODE=1` set for every run so no stale bytecode can mask a
mutation or fake a revert), and re-running the full suite GREEN with the file hash confirmed
restored.

Baseline / reverted file hash for `naalp_bundle/bundle.py` (SHA-256), confirmed identical before
mutation 1 and after every one of the three reverts below:

```
cc7accb1c7b0dedd711a624da12288aa0ea97cfb5a8a3c56e28c03c2092a077d
```

Run command (from `ecosystem/naalp-bundle/`, invoking the real installed Python interpreter for
this platform -- on Windows the Microsoft-Store `python`/`python3` execution-alias stubs resolve
ahead of a real install on `PATH` and hang, so on that platform invoke the actual interpreter
binary directly rather than the bare `python` command):

```
PYTHONDONTWRITEBYTECODE=1 python -m unittest -v tests.test_bundle
```

All commands below were run from `ecosystem/naalp-bundle/` with `PYTHONDONTWRITEBYTECODE=1` set
and `__pycache__` removed immediately before every test invocation (mutate, revert, and
re-confirm), so no cached `.pyc` could report a result that did not come from the file on disk
at that moment.

## M1 -- the non-circular-anchor refusal (`test_self_anchored_bundle_is_refused`,
`test_self_asserted_keys_round_trip_through_wire_bytes`)

**Mutated:** `verify_bundle()`, the check that refuses a trust anchor built from the bundle's
own self-asserted key material (the whole point of the module):

```diff
-    if getattr(anchor, "_self_derived", False):
+    if False:  # MUTATION M1 (red-evidence): never refuse a self-derived anchor
```

**RED, confirmed:**

```
FAIL: test_self_anchored_bundle_is_refused
AssertionError: BundleError not raised
FAIL: test_self_asserted_keys_round_trip_through_wire_bytes
AssertionError: BundleError not raised
```

With the check defeated, a bundle whose ONLY source of a verifying key is the bundle itself
(`TrustAnchor.from_bundle_self_asserted`) verifies successfully instead of being refused --
exactly the circular-verification bug this whole module exists to prevent (never verify against
a key the artifact under test supplies). The other 16 tests were
unaffected (this path is reached only when the anchor is genuinely self-derived).

**Reverted:** the file was restored from its `.bak` copy (never `git checkout`), `__pycache__`
cleared, hash re-confirmed `cc7accb1c7b0dedd711a624da12288aa0ea97cfb5a8a3c56e28c03c2092a077d`.
**GREEN, confirmed:** 18/18 tests pass.

## M2 -- the receipt-to-approval cross-binding (`test_receipt_naming_a_different_approval_rejected`)

**Mutated:** `verify_bundle()`, the check that a bundle's consume receipt actually names THIS
bundle's own approval (a bundle-level check with no Part-1 analogue -- Part-1's own
`approval.verify_consume_receipt` checks only that the receipt is a genuine ledger-signed
statement, never that it names any PARTICULAR approval):

```diff
-    if bytes(bundle.receipt.approval_id) != bytes(bundle.approval.id()):
+    if False:  # MUTATION M2 (red-evidence): never cross-check the receipt against this approval
        raise BundleError("ReceiptApprovalMismatch", "the consume receipt does not name this bundle's approval")
```

**RED, confirmed:**

```
FAIL: test_receipt_naming_a_different_approval_rejected
AssertionError: BundleError not raised
```

The test builds a receipt that is genuinely, validly signed by the real ledger -- just for a
DIFFERENT, also-genuinely-consumed approval. With the cross-check defeated, this mismatched
receipt verifies successfully as if it proved consumption of the bundle's own approval, which it
does not: a bundle could then claim "this approval's consumption is proven" while the receipt it
carries actually proves consumption of something else entirely. 17 of 18 tests still passed (only
this one path is reached by a mismatched-but-individually-valid receipt/approval pair).

**Reverted:** restored from `.bak`, `__pycache__` cleared, hash re-confirmed
`cc7accb1c7b0dedd711a624da12288aa0ea97cfb5a8a3c56e28c03c2092a077d`.
**GREEN, confirmed:** 18/18 tests pass.

## M3 -- the receipt's ledger signature is actually checked (`test_tampered_receipt_signature_rejected`,
`test_corrupted_algorithm_field_rejected_with_named_error`)

**Mutated:** `verify_bundle()`, the final delegated call that verifies the receipt is a genuine
ledger-signed statement (`naalp.approval.verify_consume_receipt`, via the `_call_named` wrapper):

```diff
-    _call_named(approval.verify_consume_receipt, bundle.receipt, rcpt_alg, receipt_pk, bundle.receipt_sig)
+    pass  # MUTATION M3 (red-evidence): never actually check the receipt's ledger signature
```

**RED, confirmed:**

```
FAIL: test_tampered_receipt_signature_rejected
AssertionError: ApprovalError not raised
FAIL: test_corrupted_algorithm_field_rejected_with_named_error
AssertionError: BundleError not raised
```

With the call removed, a receipt with a corrupted signature byte -- or a corrupted algorithm
number that would otherwise crash the underlying verifier into a wrapped, named error -- passes
through `verify_bundle` unexamined: the bundle would "verify" a consume receipt whose signature
was never actually checked, which is the exact security property the receipt exists to provide.
16 of 18 tests still passed (both flipped tests are the only ones whose assertion depends on this
specific call actually running; `test_receipt_naming_a_different_approval_rejected`, which fails
BEFORE this call is reached, was unaffected).

**Reverted:** restored from `.bak`, `__pycache__` cleared, hash re-confirmed
`cc7accb1c7b0dedd711a624da12288aa0ea97cfb5a8a3c56e28c03c2092a077d`.
**GREEN, confirmed:** 18/18 tests pass. `examples/isolation_demo.py` also re-run clean (exit 0)
after the final revert.

## Why these three, and why the mutation targets `bundle.py` rather than `naalp.envelope`/`naalp.approval`

`naalp_bundle` is glue and a verification choke point: every cryptographic and encoding
operation (object signature verify, approval signature verify, consume-receipt signature verify,
deterministic-CBOR encode/decode, content-id hashing) is delegated to the real Part-1 primitives,
which carry their own graded red-evidence and conformance corpora elsewhere (out of scope for
this task -- Part-1 files are not touched here). What IS this task's own code, and therefore what
these three mutations target, is the bundle's OWN choices: that it actually refuses an anchor
sourced from the artifact under test rather than trusting it (M1 -- the non-circular-verification
property the whole module exists to enforce), that it cross-checks the receipt genuinely names
the approval it is bundled with rather than any validly-signed receipt at all (M2 -- a check with
no Part-1 analogue), and that it does not silently skip the one signature check that proves the
receipt is real (M3). All three are exactly the properties this bundle must get right -- not the
underlying Part-1 SDK.
