<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Red-evidence: N-AALP verify-at-use guard

Mutation-survival evidence for the load-bearing properties of `naalp_verify_at_use`. Each row
was produced by actually editing `naalp_verify_at_use/verify_at_use.py` (never any
`impl/python/naalp/*` file, which is Part-1 and out of scope for this task), confirming the
named test(s) flip RED for the stated reason, then restoring the file from a `.bak` copy
(never `git checkout`), clearing `__pycache__` (`PYTHONDONTWRITEBYTECODE=1` set for every run
so no stale bytecode can mask a mutation or fake a revert), and re-running the full suite
GREEN with the file's hash re-confirmed identical to the pre-mutation baseline.

Baseline / reverted file hash for `naalp_verify_at_use/verify_at_use.py` (SHA-256), confirmed
identical before mutation 1 and after every one of the four reverts below:

```
75c51cb134a746108f402c93b53010bddf9fac25896ef83ef7e8484fc298a19c
```

Run command (from `ecosystem/naalp-verify-at-use/`, invoking the real installed Python
interpreter for this platform -- on Windows the Microsoft-Store `python`/`python3`
execution-alias stubs resolve ahead of a real install on `PATH` and hang, so on that platform
invoke the actual interpreter binary directly rather than the bare `python` command):

```
PYTHONDONTWRITEBYTECODE=1 python -m unittest -v tests.test_verify_at_use
```

All commands below were run from `ecosystem/naalp-verify-at-use/` with
`PYTHONDONTWRITEBYTECODE=1` set and `__pycache__` removed immediately before every test
invocation (mutate, revert, and re-confirm), so no cached `.pyc` could report a result that
did not come from the file on disk at that moment. Full suite size: 18 tests.

## Non-circular vector provenance (established before any mutation test)

`OracleGroundingTests` confirms, before any fail-closed test relies on them, that the two
Part-1 wire primitives this guard's checks depend on match an authority OUTSIDE the code
under test (naalp.approval / naalp.identity / naalp.cbor):

- **Approval body bytes**: `tools/approval_oracle.py` (an existing top-level oracle, read
  only) builds `vectors/approval/cases.json`'s approval "A" body with `tools/cbor_oracle.py`'s
  from-scratch deterministic-CBOR encoder -- not `naalp.cbor`. Re-deriving the identical body
  through `naalp.approval.ApprovalRecord(...).bytes()` and comparing to the oracle's
  `record_hex` is a genuine non-circular check on the wire encoding
  `naalp.approval.verify_approval` (called inside `consume_approval`, which this guard
  delegates to) depends on.
- **Signer id**: `tools/signerid_oracle.py` (an existing top-level oracle, read only) is an
  independent multicodec/multihash/multibase constructor for the self-certifying signer id,
  sharing no code with `naalp.identity`. Checked against (1) the pinned,
  GRADED `vectors/identity/cases.json` Ed25519 fixture (built from RFC 8032's own published
  test key -- an id no part of this package derived), and (2) the same oracle invoked directly
  on a freshly generated ML-DSA-65 key this package's own tests sign with.
- **RevocationRecord body bytes**: independently re-derived via `tools/cbor_oracle.py`'s
  `{1: key, 2: not_after}` map encoding and compared to
  `naalp.identity.RevocationRecord(...).bytes()`.

All three passed before any fail-closed mutation test below was written against them.

## M1 -- fail-open bypass (`test_valid_approval_executes_exactly_once` +5 others)

**Mutated:** `VerifyAtUseGuard.execute()`, removed the call to the re-verify choke point
entirely:

```diff
-        pos_time = self._clock() if pos_time is None else pos_time
-        args_id = cbor.content_id(action.args)
-        self.verify_and_consume(record, sig, args_id, action.effect, pos_time)  # RESUME only past this line
-        return action.run()
+        pos_time = self._clock() if pos_time is None else pos_time
+        args_id = cbor.content_id(action.args)
+        # MUTATION M1 (red-evidence): skip the re-verify entirely -- fail-open.
+        return action.run()
```

**RED, confirmed:** 6 of 18 tests failed --

```
FAIL: test_exactly_once_under_race
AssertionError: 8 != 1 : the action must run exactly once under a race
FAIL: test_expired_at_use_through_execute_never_runs
AssertionError: ApprovalError not raised
FAIL: test_reuse_through_execute_never_runs_a_second_time
AssertionError: ApprovalError not raised
FAIL: test_revoked_key_through_execute_never_runs
AssertionError: ApprovalError not raised
FAIL: test_valid_approval_executes_exactly_once
AssertionError: False is not true   (ledger.is_consumed(rec.id()))
FAIL: test_wrong_audience_through_execute_never_runs
AssertionError: ApprovalError not raised
```

Every test driven THROUGH `execute()` (the concurrency test included -- it drives `execute()`
in 8 threads) flipped: with the re-verify skipped, `execute()` runs the action unconditionally
regardless of expiry, reuse, revocation, or audience, and a raced approval runs 8 times instead
of once. The 12 tests that call `verify_and_consume()` directly (the choke point itself, not
`execute()`) were unaffected -- exactly the boundary this mutation targets.

**Reverted:** the file was restored from its `.bak` copy (never `git checkout`), `__pycache__`
cleared, hash re-confirmed `75c51cb134a746108f402c93b53010bddf9fac25896ef83ef7e8484fc298a19c`.
**GREEN, confirmed:** 18/18 tests pass.

## M2 -- ignore the injected use-time clock (`test_valid_at_issuance_expired_at_use_time_fails_closed` +3 others)

**Mutated:** `VerifyAtUseGuard.verify_and_consume()`, the clock-injection line (the guard's
own `now`/`pos_time` plumbing -- the property the requirement text explicitly names: "valid at
issuance but expired ... at use-time"):

```diff
-        pos_time = self._clock() if pos_time is None else pos_time
+        pos_time = 0  # MUTATION M2 (red-evidence): ignore the injected use-time clock entirely
```

**RED, confirmed:** 4 of 18 tests failed --

```
FAIL: test_valid_at_issuance_expired_at_use_time_fails_closed
AssertionError: ApprovalError not raised
FAIL: test_valid_at_issuance_key_revoked_at_use_time_fails_closed
AssertionError: ApprovalError not raised
FAIL: test_expired_at_use_through_execute_never_runs
AssertionError: ApprovalError not raised
FAIL: test_revoked_key_through_execute_never_runs
AssertionError: ApprovalError not raised
```

With the clock forced to epoch 0, `pos_time > a.not_after` is never true for any real
`not_after` (defeating expiry) and `pos_time > revocation.not_after` is never true for any
real revocation (defeating key liveness) -- both a genuine fail-open regression, not a crash.
Exactly the four clock-dependent tests flipped (14 of 18 still passed); every clock-independent
check (signature, audience, effect, single-use, args binding) was unaffected.

**Reverted:** restored from `.bak`, `__pycache__` cleared, hash re-confirmed
`75c51cb134a746108f402c93b53010bddf9fac25896ef83ef7e8484fc298a19c`.
**GREEN, confirmed:** 18/18 tests pass.

## M3 -- single-use-at-settlement (`test_reuse_fails_closed` +2 others)

**Mutated:** `VerifyAtUseGuard.verify_and_consume()`, wrapped the ledger consume call to
swallow exactly the single-use error and pretend it succeeded:

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

**RED, confirmed:** 3 of 18 tests failed --

```
FAIL: test_exactly_once_under_race
AssertionError: 8 != 1 : the action must run exactly once under a race
FAIL: test_reuse_fails_closed
AssertionError: ApprovalError not raised
FAIL: test_reuse_through_execute_never_runs_a_second_time
AssertionError: ApprovalError not raised
```

With `AlreadyConsumed` swallowed, a second (or eighth, under the race) use of the SAME
approval falls through as if it were fresh -- exactly the single-use-at-settlement violation
this guard exists to prevent. Exactly the three reuse-dependent tests flipped (15 of 18 still
passed).

**Reverted:** restored from `.bak`, `__pycache__` cleared, hash re-confirmed
`75c51cb134a746108f402c93b53010bddf9fac25896ef83ef7e8484fc298a19c`.
**GREEN, confirmed:** 18/18 tests pass.

## M4 -- key-liveness re-check (`test_valid_at_issuance_key_revoked_at_use_time_fails_closed` +1 other)

**Mutated:** `VerifyAtUseGuard.verify_and_consume()`, disabled the key-revocation branch so it
is never taken:

```diff
         approver_id = identity.signer_id(self._approver_alg, self._approver_pubkey)
         revocation = self._revocations.get(approver_id)
-        if revocation is not None and identity.revoked_at(revocation, pos_time):
+        if False:  # MUTATION M4 (red-evidence): never honor a registered key revocation
             raise approval.ApprovalError("KeyRevoked", "approver key is revoked as of use-time")
```

**RED, confirmed:** 2 of 18 tests failed --

```
FAIL: test_valid_at_issuance_key_revoked_at_use_time_fails_closed
AssertionError: ApprovalError not raised
FAIL: test_revoked_key_through_execute_never_runs
AssertionError: ApprovalError not raised
```

With the revocation branch dead, an approval signed under a key this guard has been told is
revoked is treated as if the key were still live -- the exact "revoked" property this guard names
alongside expired/consumed/out-of-audience. Exactly the two revocation-dependent tests flipped
(16 of 18 still passed); the sibling test asserting a FUTURE-dated revocation does NOT yet
block use (`test_key_revoked_only_in_the_future_does_not_block_use_now`) stayed green in both
the baseline and the mutant, since it never took the `raise` branch either way -- confirming
the mutation targets exactly the revocation check and nothing else.

**Reverted:** restored from `.bak`, `__pycache__` cleared, hash re-confirmed
`75c51cb134a746108f402c93b53010bddf9fac25896ef83ef7e8484fc298a19c`.
**GREEN, confirmed:** 18/18 tests pass.

## Why these four, and why every mutation targets `verify_at_use.py` rather than `naalp.*`

`naalp_verify_at_use` is glue: every cryptographic, identity, and ledger check (signature,
args-content-id binding, expiry, key-liveness, effect-ceiling, atomic single-use consume) is
delegated to the real Part-1 `naalp.approval` / `naalp.identity` primitives, which carry their
own graded red-evidence in `impl/python/tests` against `vectors/approval/cases.json` and
`vectors/identity/cases.json` (out of scope for this task -- Part-1 files are not touched
here). What IS this task's own code, and therefore what these four mutations target, is the
guard's OWN choices: that `execute()` actually re-verifies before it ever resumes (M1), that
every check is judged against a REAL injected use-time clock rather than a fixed value (M2),
that it does not paper over the one error `naalp.approval` raises specifically to prevent
replay (M3), and that it actually re-checks key liveness -- the "revoked" property that has no
Part-1 analogue and is this guard's own addition composing `naalp.identity.revoked_at` (M4).
All four are exactly the properties this guard must get right -- not the
underlying SDK.
