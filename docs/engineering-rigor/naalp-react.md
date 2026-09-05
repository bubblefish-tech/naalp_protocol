<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Red-evidence: N-AALP ReAct bridge

Mutation-survival evidence for four load-bearing tests described below. Each row was
produced by actually editing `naalp_react/bridge.py` (never `impl/python/naalp/*`, which is
Part-1 and out of scope for this task, and never the sibling `naalp_hitl`/`naalp_validator`
packages, which are only imported by this task's tests), confirming the named test(s) flip
RED for the stated reason, then restoring the file from a `.bak` copy (never `git checkout`),
clearing `__pycache__` (`PYTHONDONTWRITEBYTECODE=1` set for every run so no stale bytecode
can mask a mutation or fake a revert), and re-running the full suite GREEN.

Baseline / reverted file hash for `naalp_react/bridge.py` (SHA-256), confirmed identical
before mutation 1 and after every one of the four reverts below:

```
34589b50422c7aa6bd2da712b8f5f489ad444f30946d10dd8e01b5d35679dc6a
```

Run command (from `ecosystem/naalp-react/`, invoking the real installed Python interpreter
for this platform -- on Windows the Microsoft-Store `python`/`python3` execution-alias stubs
resolve ahead of a real install on `PATH` and hang, so on that platform invoke the actual
interpreter binary directly rather than the bare `python` command):

```
PYTHONDONTWRITEBYTECODE=1 python -m unittest -v tests.test_bridge
```

All commands below were run from `ecosystem/naalp-react/` with `PYTHONDONTWRITEBYTECODE=1`
set and `__pycache__` removed immediately before every test invocation (mutate, revert, and
re-confirm), so no cached `.pyc` could report a result that did not come from the file on
disk at that moment. Baseline (pre-mutation) and every post-revert run: 13/13 tests GREEN.

## M1 -- pre-send validator refusal (`test_validator_rejects_malformed_action_pre_send`)

**Mutated:** `ReActBridge.action_to_request()`, the line that decides whether an injected
validator's refusal is actually acted on:

```diff
             result = self._validator(candidate)
-            if not result:
+            if False:  # MUTATION M1 (red-evidence): never actually act on a validator refusal
```

**RED, confirmed:**

```
FAIL: test_validator_rejects_malformed_action_pre_send
AssertionError: ReActError not raised
```

With the refusal branch dead, a candidate the real `naalp_validator.validate` flags
`EffectDeclarationMismatch` on (a `Workflow/TaskCreate` Action carrying `READ_ONLY` against
its declared `non_idempotent_write`) is signed and emitted anyway. The other 12 tests were
unaffected (this branch is reached only when a `validator` is injected and it returns falsy).

**Reverted:** the file was restored from its `.bak` copy (never `git checkout`),
`__pycache__` cleared, hash re-confirmed
`34589b50422c7aa6bd2da712b8f5f489ad444f30946d10dd8e01b5d35679dc6a`.
**GREEN, confirmed:** 13/13 tests pass.

## M2 -- HITL refusal is swallowed (`test_effecting_action_denied_by_hitl_is_never_emitted`)

**Mutated:** `ReActBridge.action_to_request()`, the HITL-gated emit path -- wrapped the real
`hitl.intercept()` call so any exception it raises (a decline, a bad signature, an expired
approval -- every fail-closed outcome `naalp_hitl.HITLInterceptor` can produce) is caught and
the guarded emit runs anyway:

```diff
-            self._hitl.intercept(pending)  # raises fail-closed on any refusal; never calls _sign_and_emit then
+            try:
+                self._hitl.intercept(pending)
+            except Exception:  # MUTATION M2 (red-evidence): swallow a HITL refusal and emit anyway
+                _sign_and_emit()
```

**RED, confirmed:**

```
FAIL: test_effecting_action_denied_by_hitl_is_never_emitted
AssertionError: HITLError not raised
```

With the decline swallowed, a human operator's "no" no longer prevents the effecting action
from being signed and handed to the transport -- the exact bypass this property exists to rule
out. Every other test still passed (12/13): this branch only fires when a
`hitl` hook is injected AND it raises, which no other test triggers.

**Reverted:** restored from `.bak`, `__pycache__` cleared, hash re-confirmed
`34589b50422c7aa6bd2da712b8f5f489ad444f30946d10dd8e01b5d35679dc6a`.
**GREEN, confirmed:** 13/13 tests pass.

(A test-infrastructure note recorded here for honesty: the FIRST attempt at this mutation
run surfaced a real Windows file-locking bug in the test file itself -- `ledger.close()` was
sequenced strictly AFTER the `assertRaises`/`assertEqual` calls, so when M2 made the expected
exception NOT raise, `assertRaises.__exit__` raised its own `AssertionError` immediately and
skipped `ledger.close()` entirely; the still-open WAL file handle then made
`tempfile.TemporaryDirectory.__exit__`'s cleanup fail with `PermissionError: [WinError 32]`
on Windows, masking the real assertion failure behind an unrelated traceback. Fixed by moving
`ledger.close()` into a `finally:` block in the three tests that open a ledger
(`test_below_threshold_action_bypasses_hitl_and_still_emits`,
`test_effecting_action_denied_by_hitl_is_never_emitted`,
`test_effecting_action_approved_by_hitl_is_signed_and_emitted`) so the WAL handle is always
released before the temp directory tears down, regardless of assertion outcome. This is a
test-harness fix, not a `bridge.py` change, and does not affect the baseline hash above.)

## M3 -- causal linkage never enforced (`test_missing_causal_linkage_fails_closed` /
`test_wrong_causal_linkage_fails_closed`)

**Mutated:** `ReActBridge.response_to_observation()`, the membership check against the
response's own `causes[]`:

```diff
-        if request.id not in obj.causes:
+        if False:  # MUTATION M3 (red-evidence): never enforce the causal-linkage check
```

**RED, confirmed:**

```
FAIL: test_missing_causal_linkage_fails_closed
AssertionError: True is not false
FAIL: test_wrong_causal_linkage_fails_closed
AssertionError: True is not false
```

With the check dead, a real, correctly-signed, correctly-addressed response that names NO
causal edge back to the request (or names a completely unrelated one) is accepted as a valid
Observation anyway -- exactly the failure mode this property rules out. Exactly the two
causal-linkage-dependent tests flipped (11 of 13 still passed); every other verification step
(signature, audience) is independent of this check and was unaffected.

**Reverted:** restored from `.bak`, `__pycache__` cleared, hash re-confirmed
`34589b50422c7aa6bd2da712b8f5f489ad444f30946d10dd8e01b5d35679dc6a`.
**GREEN, confirmed:** 13/13 tests pass.

## M4 -- response audience never checked (`test_wrong_audience_fails_closed` /
`test_absent_audience_fails_closed`)

**Mutated:** `ReActBridge.response_to_observation()`, replaced the real Part-1 point-of-use
audience gate call with a no-op:

```diff
-            envelope.check_audience(obj, self._self_identity, consume_once=True)
+            pass  # MUTATION M4 (red-evidence): never actually check the response's audience
```

**RED, confirmed:**

```
FAIL: test_wrong_audience_fails_closed
AssertionError: True is not false
FAIL: test_absent_audience_fails_closed
AssertionError: True is not false
```

With the audience gate dead, a real, correctly-signed, correctly-causally-linked response
addressed to a DIFFERENT agent -- or carrying no audience at all -- is accepted as this
bridge's own Observation. Exactly the two audience-dependent tests flipped (11 of 13 still
passed); the causal-linkage and signature checks are independent of this call and were
unaffected.

**Reverted:** restored from `.bak`, `__pycache__` cleared, hash re-confirmed
`34589b50422c7aa6bd2da712b8f5f489ad444f30946d10dd8e01b5d35679dc6a`.
**GREEN, confirmed:** 13/13 tests pass.

## Why these four, and why every mutation targets `bridge.py` rather than a Part-1/sibling primitive

`naalp_react` is glue: every cryptographic and structural check (signature verification,
content-id binding, the audience point-of-use gate, the CDDL/registry validation the
optional `validator` hook performs, the ledger/consume logic the optional `hitl` hook drives)
is delegated to the real Part-1 `naalp.envelope`/`naalp.channels` primitives or the real
sibling `naalp_hitl`/`naalp_validator` packages, each of which carries its own graded
red-evidence out of scope for this task. What IS this task's own code, and therefore what
these four mutations target, is the bridge's OWN choices: that a validator's refusal is
actually acted on (M1), that a HITL hook's refusal actually prevents the emit rather than
being swallowed (M2), that a response is actually checked for the causal edge back to its
request (M3), and that a response is actually checked against the required audience (M4).
All four are exactly the properties this bridge must get right -- not the
underlying SDK or the sibling ecosystem packages.
