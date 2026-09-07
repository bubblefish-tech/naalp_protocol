<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Red-evidence: N-AALP mixed-mode HTTP discrimination SDK

Mutation-survival evidence for the four load-bearing anti-bypass properties. Each row was
produced by actually editing `naalp_mixed_mode/endpoint.py` or `naalp_mixed_mode/migration.py`
(never `impl/python/naalp/*`, which is Part-1 and out of scope for this task), confirming the
named test flips RED for the stated reason, then restoring the file (from a `.bak` copy for M1,
M3, and M4, via a hand-reversed `Edit` for M2 -- see note below -- never `git checkout`, since
this tree is uncommitted), clearing `__pycache__` (`PYTHONDONTWRITEBYTECODE=1` set for every run
so no stale bytecode can mask a mutation or fake a revert), and re-running the full suite (26/26
as of M4) GREEN.

Baseline / reverted file hashes (SHA-256), confirmed identical before every mutation below and
after every one of the reverts:

```
naalp_mixed_mode/endpoint.py:   b36ccf06c6349823acfd56d6638e12bc09f47e36d1d430c3b890e04870934991  (M1/M2 baseline)
naalp_mixed_mode/endpoint.py:   b102eeecf84b702c88b1c9cb0fe63ed6456440efd179c5fd0125805e598771b2  (M4 baseline, after allow_legacy add)
naalp_mixed_mode/migration.py:  e824aa98224dd1fe6daf809ebb810b91dacf3a22a5148c9213b35dc2dff8e206
```

Run command (from the repo root, invoking the real installed Python interpreter for this
platform -- on Windows the Microsoft-Store `python`/`python3` execution-alias stubs resolve
ahead of a real install on PATH and hang, so invoke the actual interpreter binary directly
rather than the bare `python` command):

```
PYTHONDONTWRITEBYTECODE=1 python -m pytest ecosystem/naalp-mixed-mode -v
```

## M1 -- self-asserted legacy audience treated as authoritative

**Property:** the anti-bypass rule -- a legacy (unsigned) JSON record targeting a
consume-once (channel, kind) must be refused REGARDLESS of what audience the untrusted body
claims, because there is no signature behind that claim to bind it.

**Mutated:** `MixedModeEndpoint._handle_legacy()` in `endpoint.py` -- copied the JSON's
self-asserted `audience` field onto the surrogate object instead of leaving it absent:

```diff
+                claimed_audience = str(payload.get("audience", ""))
                 surrogate = envelope.Object(
                     kind=key[1], channel=key[0], signer=b"", created=0,
-                    effect=requested_effect, body=cbor.M([]),
+                    effect=requested_effect, body=cbor.M([]), audience=claimed_audience,
                 )
```

**RED, confirmed:**

```
FAILED ecosystem/naalp-mixed-mode/tests/test_endpoint.py::LegacyPathTests::test_legacy_consume_once_self_asserted_audience_still_rejected
AssertionError: EnvelopeError not raised
1 failed, 24 passed in 0.92s
```

`envelope.check_audience`'s `o.audience == self_authority` branch now returns a pass (`None`)
for a legacy record that correctly guessed (or was simply told) the audience string, because
the mutated code trusts the claim -- exactly the request-smuggling shape this property forecloses.
Exactly the one test targeting a CORRECT self-asserted audience flipped; the sibling test
targeting an ABSENT audience (`test_legacy_consume_once_without_signed_audience_is_rejected`)
still passed, because `payload.get("audience", "")` still defaults to `""` when the field is
missing, and an empty audience still trips `check_audience`'s absent-audience-on-consume-once
branch -- confirming the mutation is precisely targeted at the self-assertion path, not a
blanket disabling of the check.

**Reverted:** the file was restored from its `.bak` copy (never `git checkout`), `__pycache__`
cleared, hash re-confirmed `b36ccf06c6349823acfd56d6638e12bc09f47e36d1d430c3b890e04870934991`.
**GREEN, confirmed:** 25/25 tests pass.

## M2 -- authorization failures on a validly-parsed strict object must never fall back to legacy

**Property:** §13.8(a) says the endpoint falls back to legacy "if and only if" the strict
PARSE fails -- an authorization failure (EffectNotAuthorized, WrongAudience) on a validly
signed, correctly parsed object must be a hard refusal of the whole request, never a silent
reinterpretation as a permissive legacy record.

**Mutated:** `MixedModeEndpoint.handle()` in `endpoint.py` -- widened the `try` block to also
cover `_authorize_strict()`, so a `PolicyError`/`EnvelopeError` raised during authorization
(both `ValueError` subclasses) falls into the SAME except clause as a genuine parse failure:

```diff
         try:
             obj = envelope.verify(self._profile, self._alg, self._pubkey, self._kind_validator, body)
+            # widen the fallback to cover authorization failures too
+            return self._authorize_strict(obj)
         except ValueError:
             return self._handle_legacy(body, correlation=correlation, method=method)
-        return self._authorize_strict(obj)
```

**RED, confirmed:**

```
FAILED ecosystem/naalp-mixed-mode/tests/test_endpoint.py::StrictPathTests::test_consume_once_kind_without_audience_is_refused
FAILED ecosystem/naalp-mixed-mode/tests/test_endpoint.py::StrictPathTests::test_effect_exceeding_grant_ceiling_is_refused_never_falls_back_to_legacy
FAILED ecosystem/naalp-mixed-mode/tests/test_endpoint.py::StrictPathTests::test_signer_with_no_registered_grant_is_refused
3 failed, 22 passed in 0.94s
```

Each of the three flipped tests asserted `policy.PolicyError` / `envelope.EnvelopeError`; with
the mutation, the authorization failure was instead swallowed and the (binary CBOR/COSE) body
was re-routed into `_handle_legacy`, which raised `MixedModeError("LegacyMalformed")` instead
(the wrong exception TYPE, not merely a passed/failed flip) -- concretely observed as
`naalp_mixed_mode.endpoint.MixedModeError: LegacyMalformed: ...` in place of the expected
`PolicyError`/`EnvelopeError`. The other 22 tests, none of which exercise a strict object that
fails authorization, were unaffected.

**Reverted:** the mutation was hand-reversed with `Edit` back to the exact pre-mutation text
(no `.bak` was taken for this specific edit -- see note below), `__pycache__` cleared, hash
re-confirmed `b36ccf06c6349823acfd56d6638e12bc09f47e36d1d430c3b890e04870934991` (byte-identical
to the pre-M1 baseline, since M1 had already been reverted and hash-confirmed before M2 began).
**GREEN, confirmed:** 25/25 tests pass.

*Note on the revert method:* the discipline for this task is "restore via `mv` (`.bak`), NEVER
`git checkout`". M1 and M3 each took a `.bak` copy before mutating and restored via
`Move-Item`. For M2 the `.bak` step was omitted and the mutation was instead reversed with an
exact-text `Edit` back to the pre-mutation source; the SHA-256 comparison against the SAME
recorded baseline hash used for M1 (both target `endpoint.py`, and M2 was applied and reverted
strictly after M1's own revert-and-hash-confirm) is the evidence that the hand-reversal
reproduced the byte-exact original -- not a `.bak` restore, but hash-verified identical to one.

## M3 -- RFC 9745 Sunset-not-before-Deprecation ordering constraint

**Property:** RFC 9745 requires "the timestamp given in the `Sunset` HTTP header field MUST
NOT be earlier than the one given in the `Deprecation` header field" -- `MigrationPolicy`
enforces this at construction, fail-closed, rather than emitting an internally-contradictory
header pair.

**Mutated:** `MigrationPolicy.__init__()` in `migration.py` -- dropped the ordering check
entirely:

```diff
-        if sunset_epoch_seconds < deprecated_since_epoch_seconds:
-            raise MigrationError(
-                "InvertedTimestamps",
-                "the Sunset timestamp must not be earlier than the Deprecation timestamp (RFC 9745)",
-            )
+        # MUTATION M3 (red-evidence): drop the RFC 9745 Sunset-not-before-Deprecation check.
+        pass
```

**RED, confirmed:**

```
FAILED ecosystem/naalp-mixed-mode/tests/test_migration.py::MigrationPolicyTests::test_inverted_timestamps_refused_at_construction
AssertionError: MigrationError not raised
1 failed, 24 passed in 0.92s
```

Exactly the one test targeting the inverted-timestamp construction path flipped; every other
test (including `test_equal_timestamps_are_permitted`, which shares the boundary condition
`sunset == deprecated`) was unaffected.

**Reverted:** the file was restored from its `.bak` copy (never `git checkout`), `__pycache__`
cleared, hash re-confirmed `e824aa98224dd1fe6daf809ebb810b91dacf3a22a5148c9213b35dc2dff8e206`.
**GREEN, confirmed:** 25/25 tests pass.

## M4 -- no implicit legacy fallback without an explicit `allow_legacy=True` opt-in

**Property (closing a cross-SDK parity gap identified against the Go SDK's
`Endpoint.AllowLegacy`/`ErrLegacyDisabled`):** a `MixedModeEndpoint`
constructed WITHOUT `allow_legacy=True` (the default is `False`, strict-only) MUST refuse a
request whose strict parse fails -- `MixedModeError("LegacyDisabled")` -- rather than
implicitly falling back to the legacy JSON path. There is no second, permissive parser a
caller can reach without opting in.

**Mutated:** `MixedModeEndpoint.handle()` in `endpoint.py` -- dropped the `allow_legacy` check
entirely, so a strict-parse failure always falls back to `_handle_legacy` regardless of what
the caller passed at construction:

```diff
         try:
             obj = envelope.verify(self._profile, self._alg, self._pubkey, self._kind_validator, body)
         except ValueError:
-            if not self._allow_legacy:
-                raise MixedModeError(
-                    "LegacyDisabled",
-                    "endpoint is strict-only; allow_legacy was not explicitly enabled, so a "
-                    "strict-parse failure is refused rather than silently retried as legacy",
-                )
+            # MUTATION M4 (red-evidence): ignore self._allow_legacy, always fall back.
             return self._handle_legacy(body, correlation=correlation, method=method)
         return self._authorize_strict(obj)
```

**RED, confirmed:**

```
FAILED ecosystem/naalp-mixed-mode/tests/test_endpoint.py::LegacyPathTests::test_default_endpoint_refuses_legacy_body_without_allow_legacy_opt_in
AssertionError: MixedModeError not raised
1 failed, 25 passed in 0.95s
```

Exactly the one test targeting the default (`allow_legacy` unset) strict-only endpoint
flipped -- it constructs a `MixedModeEndpoint` with no `allow_legacy` argument (so the
attribute is `False`) and asserts a legacy JSON body raises `MixedModeError("LegacyDisabled")`;
with the mutation the same body was instead silently processed via `_handle_legacy` and
returned a `MixedModeResult` (no exception at all), the exact implicit-fallback shape this
property forecloses. All 25 other tests -- including every `LegacyPathTests`/`StrictPathTests` case that
constructs its endpoint via the two test-helper methods, both of which pass
`allow_legacy=True` explicitly -- were unaffected, confirming the mutation is precisely
targeted at the opt-in gate and not a blanket change to legacy handling.

**Reverted:** the file was restored from its `.bak` copy (never `git checkout`), `__pycache__`
cleared, hash re-confirmed `b102eeecf84b702c88b1c9cb0fe63ed6456440efd179c5fd0125805e598771b2`
(byte-identical to the pre-mutation baseline recorded above).
**GREEN, confirmed:** 26/26 tests pass.

## Why these four

Every cryptographic and effect-lattice check the strict path relies on (COSE_Sign1 signature
verification, the C10 channel/kind effect declaration, the C5 authorization lattice, the
§2.5.3 audience gate) is the real, already-graded Part-1 `naalp.envelope`/`naalp.channels`/
`naalp.policy` primitive, untouched by this task and carrying its own conformance corpus
elsewhere in the tree. What IS this task's own code, and therefore what M1-M4 target, is
`naalp_mixed_mode`'s own choices: that a legacy record's self-asserted audience is NEVER
copied onto anything the strict `check_audience` gate inspects (M1); that an authorization
failure on a validly-parsed strict object is a hard refusal, never a silent reinterpretation
as a permissive legacy record (M2); that the migration policy's own RFC 9745 compliance
constraint is actually enforced, not merely documented (M3); and that the legacy fallback path
itself is unreachable without an explicit `allow_legacy=True` opt-in at construction, so a
strict-only endpoint's caller cannot be silently downgraded into accepting untyped legacy
bodies (M4, mirroring the Go SDK's `AllowLegacy` field). All four are exactly the
properties this SDK must get right -- not the underlying Part-1 SDK.
