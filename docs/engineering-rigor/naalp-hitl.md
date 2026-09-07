<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Red-evidence: N-AALP HITL interceptor

Mutation-survival evidence for the three load-bearing tests described below. Each row
was produced by actually editing `naalp_hitl/interceptor.py` (never `impl/python/naalp/*`,
which is Part-1 and out of scope for this task), confirming the named test flips RED for the
stated reason, then restoring the file from a `.bak` copy (never `git checkout`), clearing
`__pycache__` (`PYTHONDONTWRITEBYTECODE=1` set for every run so no stale bytecode can mask a
mutation or fake a revert), and re-running the full suite GREEN.

Baseline / reverted file hash for `naalp_hitl/interceptor.py` (SHA-256), confirmed identical
before mutation 1 and after every one of the three reverts below:

```
9f5a90ac9703c60ce4f721aa79053d4fe4fe91f82bc2bbf4073c0704a17ae25a
```

Run command (from `ecosystem/naalp-hitl/`, invoking the real installed Python interpreter for
this platform -- on Windows the Microsoft-Store `python`/`python3` execution-alias stubs
resolve ahead of a real install on `PATH` and hang, so on that platform invoke the actual
interpreter binary directly rather than the bare `python` command):

```
PYTHONDONTWRITEBYTECODE=1 python -m unittest -v tests.test_interceptor
```

All commands below were run from `ecosystem/naalp-hitl/` with `PYTHONDONTWRITEBYTECODE=1` set
and `__pycache__` removed immediately before every test invocation (mutate, revert, and
re-confirm), so no cached `.pyc` could report a result that did not come from the file on disk
at that moment.

## M1 -- valid-resume (`test_approved_action_pauses_then_resumes`)

**Mutated:** `HITLInterceptor.intercept()`, the line reached only after a successful
`verify_and_consume()` (the RESUME step):

```diff
-        return action.execute()
+        return None  # MUTATION M1 (red-evidence): never actually resume the action
```

**RED, confirmed:**

```
FAIL: test_approved_action_pauses_then_resumes
AssertionError: None != 'TRANSFERRED'
```

`result` was `None` instead of `"TRANSFERRED"` -- the exact assertion the mutation defeats.
The other 13 tests were unaffected (this path is reached only by a real granted approval).

**Reverted:** the file was restored from its `.bak` copy (never `git checkout`), `__pycache__`
cleared, hash re-confirmed `9f5a90ac9703c60ce4f721aa79053d4fe4fe91f82bc2bbf4073c0704a17ae25a`.
**GREEN, confirmed:** 14/14 tests pass.

## M2 -- expired-fail-closed (`test_expired_fails_closed_through_intercept`)

**Mutated:** `HITLInterceptor.verify_and_consume()`, the clock-injection line (the interceptor's
own `now`/`pos_time` plumbing -- the property the task requires be enforced via injection,
never a hardcoded value):

```diff
-        pos_time = self._clock() if pos_time is None else pos_time
+        pos_time = 0  # MUTATION M2 (red-evidence): ignore the injected clock entirely (never expires)
```

**RED, confirmed:**

```
FAIL: test_expired_fails_closed_through_intercept
AssertionError: ApprovalError not raised
FAIL: test_expired_approval_fails_closed
AssertionError: ApprovalError not raised
```

With the clock forced to epoch 0, `pos_time > a.not_after` is never true for any real
`not_after`, so an approval that is already expired is silently treated as still valid -- a
genuine fail-open regression, not a crash. Exactly the two expiry-dependent tests flipped
(12 of 14 still passed); every other check (signature, audience, effect, single-use) is
independent of the clock and was unaffected.

**Reverted:** restored from `.bak`, `__pycache__` cleared, hash re-confirmed
`9f5a90ac9703c60ce4f721aa79053d4fe4fe91f82bc2bbf4073c0704a17ae25a`.
**GREEN, confirmed:** 14/14 tests pass.

## M3 -- single-use-fail-closed (`test_reuse_of_same_approval_fails_closed_through_intercept`)

**Mutated:** `HITLInterceptor.verify_and_consume()`, wrapped the ledger consume call to swallow
exactly the single-use error and pretend it succeeded:

```diff
-        return approval.consume_approval(
-            record, self._approver_alg, self._approver_pubkey, sig, args_content_id,
-            pos_time, required_effect, self._ledger, self._identity,
-        )
+        try:
+            return approval.consume_approval(
+                record, self._approver_alg, self._approver_pubkey, sig, args_content_id,
+                pos_time, required_effect, self._ledger, self._identity,
+            )
+        except approval.ApprovalError as e:
+            if e.kind == "AlreadyConsumed":
+                # MUTATION M3 (red-evidence): silently swallow a replay as if it succeeded.
+                return None
+            raise
```

**RED, confirmed:**

```
FAIL: test_reuse_of_same_approval_fails_closed_through_intercept
AssertionError: ApprovalError not raised
FAIL: test_reuse_of_same_approval_fails_closed
AssertionError: ApprovalError not raised
```

With `AlreadyConsumed` swallowed, `verify_and_consume()` returns normally on the second use of
the SAME approval object, so `intercept()` falls through to `return action.execute()` a second
time -- the replayed approval would have executed the action again (the exact single-use
violation the interceptor exists to prevent). Exactly the two reuse-dependent tests flipped
(12 of 14 still passed).

**Reverted:** restored from `.bak`, `__pycache__` cleared, hash re-confirmed
`9f5a90ac9703c60ce4f721aa79053d4fe4fe91f82bc2bbf4073c0704a17ae25a`.
**GREEN, confirmed:** 14/14 tests pass.

## The AU-2/AU-3 structured refusal log + AU-10 non-repudiation signed record

Mutation-survival evidence for the seven mutations recorded below. Each was produced by
actually editing `naalp_hitl/interceptor.py` or `naalp_hitl/nonrepudiation.py` (never
`impl/python/naalp/*`), confirming the named test(s) flip RED for the stated reason, then
restoring the file from a `.bak` copy (never `git checkout`, since this tree is uncommitted),
clearing `__pycache__` (`PYTHONDONTWRITEBYTECODE=1` set for every run), and re-running the full
suite (21/21) GREEN.

Baseline / reverted file hashes (SHA-256), confirmed identical before mutation M4 and after
every one of the seven reverts below:

```
naalp_hitl/interceptor.py:     647f3ca848e109186916262ef4fc7ed24aa524ad71090318fe57ca9516284fd1
naalp_hitl/nonrepudiation.py:  5101bcc360a7a13d13137d983462c0ff9fadb03a5f1045e778002498b6e13f09
naalp_hitl/refusal_log.py:     1cc50d3dfe3d7ac3b63d0593721cc71978a120c4ae045000e4741f83cd1e12d8 (never mutated; hashed for completeness)
naalp_hitl/__init__.py:        d24a8193a7d010c79206ace97dccee4d52043cb4fdb740a7256f76dfdfbd52cd (never mutated; hashed for completeness)
```

Run command (from `ecosystem/naalp-hitl/`, invoking the real installed Python interpreter for
this platform, not the Microsoft-Store `python`/`python3` stubs):

```
PYTHONDONTWRITEBYTECODE=1 python -m unittest -v tests.test_interceptor
```

### M4 -- Layer-1 persistence (`test_layer1_persists_every_au3_field_on_bad_signature`)

**Mutated:** `HITLInterceptor._on_refusal()` in `interceptor.py`, the line that actually
persists the AU-3 entry:

```diff
-        self._refusal_log.record(entry)  # persist-before-propagate; a fault here propagates, not err
+        pass  # MUTATION M4 (red-evidence): never actually persist the AU-3 log entry
```

**RED, confirmed:** `test_layer1_persists_every_au3_field_on_bad_signature` failed
(`AssertionError: 0 != 1`), together with `test_layer2_absent_below_threshold_even_with_signing_key_configured`,
`test_denied_approval_fails_closed_and_never_executes`, and 2 errors from
`test_logging_failure_propagates_and_still_blocks_execution` /
`test_layer1_persists_on_direct_verify_and_consume_with_default_kind_and_principal` (5 total).

**Reverted:** restored from `.bak`, `__pycache__` cleared, hash re-confirmed
`647f3ca848e109186916262ef4fc7ed24aa524ad71090318fe57ca9516284fd1`. **GREEN, confirmed:** 21/21.

### M5 -- non-repudiation predicate fail-open (`test_layer2_absent_below_threshold_even_with_signing_key_configured`)

**Mutated:** `_on_refusal()`'s Layer-2 gate: dropped the threshold check, so ANY refusal signs
whenever a key is configured, regardless of effect:

```diff
-        if self._signing_alg is not None and self._signing_seed is not None \
-                and self.requires_non_repudiation(required_effect):
+        if self._signing_alg is not None and self._signing_seed is not None:
+            # MUTATION M5: ignore the non-repudiation threshold entirely
```

**RED, confirmed:**
```
FAIL: test_layer2_absent_below_threshold_even_with_signing_key_configured
AssertionError: RefusalDecisionRecord(...) is not None : below threshold: NEVER mint a signed record, key or no key
```
Exactly the one test targeting this property flipped (20 of 21 still passed).

**Reverted:** restored from `.bak`, `__pycache__` cleared, hash re-confirmed
`647f3ca848e109186916262ef4fc7ed24aa524ad71090318fe57ca9516284fd1`. **GREEN, confirmed:** 21/21.

### M6 -- non-repudiation predicate fail-closed-forever (`test_layer2_mints_a_real_verifiable_signed_record_at_threshold`)

**Mutated:** `HITLInterceptor.requires_non_repudiation()` forced to always return `False`:

```diff
-        return effect >= self._non_repudiation_threshold
+        return False  # MUTATION M6: never eligible, even at/above threshold
```

**RED, confirmed:**
```
FAIL: test_layer2_mints_a_real_verifiable_signed_record_at_threshold
AssertionError: unexpectedly None
ERROR: test_outcome_mapping_for_every_refusal_kind (AttributeError: 'NoneType' object has no attribute 'outcome')
```
An at-threshold refusal with a real signing key configured no longer produced a signed record
at all -- Layer 2 became permanently unreachable. 19 of 21 still passed.

**Reverted:** restored from `.bak`, `__pycache__` cleared, hash re-confirmed
`647f3ca848e109186916262ef4fc7ed24aa524ad71090318fe57ca9516284fd1`. **GREEN, confirmed:** 21/21.

### M7 -- fabricated signature (`test_layer2_mints_a_real_verifiable_signed_record_at_threshold`)

**Mutated:** `sign_refusal_record()` in `nonrepudiation.py` returns a fixed, bogus value instead
of a real signature:

```diff
-    return cose.mldsa_sign(alg, seed, rec.bytes())
+    return b"\x00" * 64  # MUTATION M7: fabricate a bogus, unverifiable signature
```

**RED, confirmed:**
```
FAIL: test_layer2_mints_a_real_verifiable_signed_record_at_threshold
AssertionError: False is not true
```
`verify_refusal_record(record, alg, interceptor_pubkey, sig)` on the fabricated bytes correctly
failed to verify -- the exact real-cryptography assertion this task requires. 20 of 21 passed.

**Reverted:** restored from `.bak`, `__pycache__` cleared, hash re-confirmed
`5101bcc360a7a13d13137d983462c0ff9fadb03a5f1045e778002498b6e13f09`. **GREEN, confirmed:** 21/21.

### M8 -- wrong outcome mapping (`test_outcome_mapping_for_every_refusal_kind`)

**Mutated:** `refusal_outcome_for_reason()` in `nonrepudiation.py` collapses the whole closed
outcome set to `REFUSAL_DENIED` regardless of the reason kind:

```diff
-    if kind in _HELD_KINDS:
-        return approval.REFUSAL_HELD
-    if kind in _UNVERIFIABLE_KINDS:
-        return approval.REFUSAL_UNVERIFIABLE
-    return approval.REFUSAL_DENIED
+    return approval.REFUSAL_DENIED  # MUTATION M8: collapse the whole closed set to DENIED
```

**RED, confirmed:**
```
FAIL: test_outcome_mapping_for_every_refusal_kind
AssertionError: 0 != 1   (ApprovalRequired mapped to DENIED instead of HELD)
FAIL: test_layer2_mints_a_real_verifiable_signed_record_at_threshold
AssertionError: 0 != 2   (BadSignature mapped to DENIED instead of UNVERIFIABLE)
```
19 of 21 still passed (every test that does not assert a specific non-DENIED outcome).

**Reverted:** restored from `.bak`, `__pycache__` cleared, hash re-confirmed
`5101bcc360a7a13d13137d983462c0ff9fadb03a5f1045e778002498b6e13f09`. **GREEN, confirmed:** 21/21.

### M9 -- wrong record-id reference (`test_layer2_mints_a_real_verifiable_signed_record_at_threshold`)

**Mutated:** `_on_refusal()` in `interceptor.py` derives the coarse `Refusal` from the WRONG
bytes (empty) instead of the actual signed record:

```diff
-            refusal = approval.refusal_from_record(outcome_code, record.bytes())
+            refusal = approval.refusal_from_record(outcome_code, b"")
+            # MUTATION M9: reference the wrong bytes instead of the real signed record
```

**RED, confirmed:**
```
FAIL: test_layer2_mints_a_real_verifiable_signed_record_at_threshold
AssertionError: b' 08\xb0...' != b' 0\xac\xdd...'   (refusal.record != record.content_id())
```
The coarse `Refusal` no longer named the record that was actually signed -- exactly the
closure property (`refusal.record == record.content_id()`) this task requires. 20 of
21 still passed.

**Reverted:** restored from `.bak`, `__pycache__` cleared, hash re-confirmed
`647f3ca848e109186916262ef4fc7ed24aa524ad71090318fe57ca9516284fd1`. **GREEN, confirmed:** 21/21.

### M10 -- the audit log bypassed on the `intercept()` human-decline path (`test_denied_approval_fails_closed_and_never_executes`)

**Mutated:** `HITLInterceptor.intercept()`'s `decision is None` branch stopped routing through
`_on_refusal()` entirely (raises the bare `HITLError` directly, as before this feature existed):

```diff
-            err = HITLError(
-                "ApprovalDenied", "the human operator declined to approve %r" % (action.kind,)
-            )
-            raise self._on_refusal(
-                err, kind=action.kind, args_content_id=args_id, required_effect=action.effect,
-                approver_identity="", source_principal=action.principal,
-            )
+            # MUTATION M10: bypass the audit log entirely on the human-decline path.
+            raise HITLError(
+                "ApprovalDenied", "the human operator declined to approve %r" % (action.kind,)
+            )
```

**RED, confirmed:**
```
FAIL: test_denied_approval_fails_closed_and_never_executes
AssertionError: 0 != 1   (no Layer-1 entry was persisted for a human decline)
ERROR: test_outcome_mapping_for_every_refusal_kind (AttributeError: 'HITLError' object has no attribute 'd6')
```
19 of 21 still passed. This confirms `intercept()`'s OWN wiring into `_on_refusal` for the one
refusal reason (`ApprovalDenied`) that never passes through `verify_and_consume` at all --
distinct from M4, which targets `_on_refusal`'s internals reached from either caller.

**Reverted:** restored from `.bak`, `__pycache__` cleared, hash re-confirmed
`647f3ca848e109186916262ef4fc7ed24aa524ad71090318fe57ca9516284fd1`. **GREEN, confirmed:** 21/21.

### Why these seven, and why the mutation targets stay inside `naalp_hitl/`

Exactly as for M1-M3 above: every piece of cryptography (`naalp.cose.mldsa_sign` /
`cose_verify1_raw`), the closed outcome vocabulary and its `Refusal` /
`refusal_from_record` / `parse_refusal` machinery, and canonical CBOR encoding are the real,
already-graded Part-1 `naalp.approval` / `naalp.cose` / `naalp.cbor` primitives -- untouched by
this task. What this feature adds, and therefore what M4-M10 target, is entirely `naalp_hitl`'s own new
code: that it actually calls the log sink on every refusal path including the one
(`ApprovalDenied`) that never reaches `verify_and_consume` (M4, M10); that the non-repudiation
threshold gate is neither always-on nor always-off (M5, M6); that the signature `_on_refusal`
attaches is the interceptor's own REAL signature over the REAL record bytes, not a fabricated
placeholder (M7); that the reason->outcome mapping actually discriminates the three outcomes
rather than collapsing them (M8); and that the coarse `Refusal` references the record that was
actually signed (M9).

## Why these three, and why the mutation targets `interceptor.py` rather than `naalp.approval`

`naalp_hitl` is glue: every cryptographic and ledger check (signature, args-content-id binding,
expiry, effect-ceiling, atomic single-use consume) is delegated to the real Part-1
`naalp.approval` primitive, which carries its own graded red-evidence in `impl/python/tests`
against `vectors/approval/cases.json` (out of scope for this task -- Part-1 files are not
touched here). What IS this task's own code, and therefore what these three mutations target,
is the interceptor's OWN choices: that it actually calls `action.execute()` only after a real
consume (M1), that it feeds the checks a REAL injected clock rather than a fixed value (M2),
and that it does not paper over the one error `naalp.approval` raises specifically to prevent
replay (M3). All three are exactly the properties this component depends on the interceptor --
not the underlying SDK -- to get right.
