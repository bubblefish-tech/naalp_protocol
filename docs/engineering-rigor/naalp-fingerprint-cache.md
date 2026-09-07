<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Red-evidence: N-AALP signer-id fingerprint cache

Mutation-survival evidence for the two load-bearing fail-closed properties described below.
Each row was produced by actually editing
`naalp_fingerprint_cache/fingerprint_cache.py` (never any `impl/python/naalp/*` file, which is
Part-1 and out of scope for this task), confirming the named test(s) flip RED for the stated
reason, then restoring the file from a `.bak` copy (never `git checkout`), clearing
`__pycache__` (`PYTHONDONTWRITEBYTECODE=1` set for every run so no stale bytecode can mask a
mutation or fake a revert), and re-running the full suite GREEN.

Baseline / reverted file hash for `naalp_fingerprint_cache/fingerprint_cache.py` (SHA-256),
confirmed identical before mutation 1 and after both reverts below:

```
b902a01ce0c1c2f198d2f70a9e12cec76579627a722ed23feb593c1c86fa8062
```

Run command (from `ecosystem/naalp-fingerprint-cache/`, invoking the real installed Python
interpreter for this platform -- on Windows the Microsoft-Store `python`/`python3`
execution-alias stubs resolve ahead of a real install on `PATH` and hang, so on that platform
invoke the actual interpreter binary directly rather than the bare `python` command):

```
PYTHONDONTWRITEBYTECODE=1 python -m unittest -v tests.test_fingerprint_cache
```

All commands below were run from `ecosystem/naalp-fingerprint-cache/` with
`PYTHONDONTWRITEBYTECODE=1` set and `__pycache__` removed immediately before every test
invocation (mutate, revert, and re-confirm), so no cached `.pyc` could report a result that did
not come from the file on disk at that moment.

## M1 -- key-swap-without-proof-refused (`test_key_swap_without_proof_fails_closed`)

**Mutated:** `FingerprintCache.check_and_pin()`, the branch reached when a fingerprint changed
and no rotation proof was offered:

```diff
-        if rotation_object is None:
-            raise FingerprintCacheError(
-                "KeyPinViolation",
-                "fingerprint changed for %r with no rotation proof offered "
-                "(pinned=%s, presented=%s)" % (logical_id, pinned.fingerprint, new_fingerprint),
-            )
+        if rotation_object is None:
+            # MUTATION M1 (red-evidence): accept a changed fingerprint with no rotation proof at
+            # all, re-pinning unconditionally instead of refusing KeyPinViolation.
+            entry = PinnedIdentity(alg=alg, pubkey=bytes(pubkey), fingerprint=new_fingerprint)
+            self._pins[logical_id] = entry
+            return entry
```

**RED, confirmed:**

```
FAIL: test_key_swap_without_proof_fails_closed
AssertionError: FingerprintCacheError not raised
```

With the "no proof offered" branch skipping straight to an unconditional re-pin, a presented key
with a completely different fingerprint -- no rotation object at all, i.e. no attempt to justify
the change -- is silently accepted and the cache re-pins to it. This is the exact key-swap /
impersonation the cache exists to detect. Exactly the one test that exercises this
branch flipped (10 of 11 still passed); every other test either never reaches this branch (first
use, same-fingerprint) or supplies a non-`None` `rotation_object` and is unaffected.

**Reverted:** the file was restored from its `.bak` copy (never `git checkout`), `__pycache__`
cleared, hash re-confirmed
`b902a01ce0c1c2f198d2f70a9e12cec76579627a722ed23feb593c1c86fa8062`.
**GREEN, confirmed:** 11/11 tests pass.

## M2 -- forged-rotation-proof-refused (`test_forged_rotation_proof_fails_closed`,
`test_rotation_object_for_a_different_pin_is_rejected`)

**Mutated:** `FingerprintCache.check_and_pin()`, the call into the real Part-1 tag-98
Rotation-object verifier:

```diff
-        envelope.verify_rotation_object(
-            self._profile,
-            pinned.alg, pinned.pubkey,
-            alg, pubkey,
-            _is_identity_rotation_kind,
-            rotation_object,
-        )
+        try:
+            envelope.verify_rotation_object(
+                self._profile,
+                pinned.alg, pinned.pubkey,
+                alg, pubkey,
+                _is_identity_rotation_kind,
+                rotation_object,
+            )
+        except envelope.EnvelopeError:
+            # MUTATION M2 (red-evidence): silently swallow a forged/invalid rotation proof and
+            # re-pin anyway, as if it had verified.
+            pass
```

**RED, confirmed:**

```
FAIL: test_forged_rotation_proof_fails_closed
AssertionError: EnvelopeError not raised
FAIL: test_rotation_object_for_a_different_pin_is_rejected
AssertionError: EnvelopeError not raised
```

With `envelope.EnvelopeError` swallowed, a rotation object whose OLD leg does not verify under
the currently-pinned key -- a forged co-signature (both legs signed by an attacker's own key,
`test_forged_rotation_proof_fails_closed`), or a rotation object minted for a completely
unrelated key pair (`test_rotation_object_for_a_different_pin_is_rejected`) -- is accepted and
the cache re-pins to the attacker-presented key anyway: exactly the forged-rotation-proof
impersonation the cache exists to refuse. Exactly the two tests that exercise a
rejected `envelope.verify_rotation_object` call flipped (9 of 11 still passed);
`test_single_signature_rotation_rejected` is unaffected because that case raises a plain
`ValueError` (not an `envelope.EnvelopeError`) while parsing the tag-18 object -- a different
exception type this `except` clause does not catch -- so it continues to propagate and reject
correctly even under this mutation.

**Reverted:** restored from `.bak`, `__pycache__` cleared, hash re-confirmed
`b902a01ce0c1c2f198d2f70a9e12cec76579627a722ed23feb593c1c86fa8062`.
**GREEN, confirmed:** 11/11 tests pass.

## Why these two, and why the mutation targets `fingerprint_cache.py` rather than
## `naalp.identity` / `naalp.envelope`

`naalp_fingerprint_cache` is glue: the fingerprint itself is computed entirely by the real Part-1
primitive `naalp.identity.signer_id`, and every rotation-proof check (both legs verify, exactly
two legs in the fixed old/new order, the profile signature floor, the tag-98 framing) is
delegated entirely to the real Part-1 primitive `naalp.envelope.verify_rotation_object`, which
carries its own graded red-evidence in `impl/python/tests/test_rotation.py` against
`vectors/rotation/cases.json` (out of scope for this task -- Part-1 files are not touched here).
What IS this task's own code, and therefore what these two mutations target, is the cache's OWN
decision table: that a changed fingerprint with no proof is refused rather than silently
accepted (M1), and that a rejection from the real verifier is honored rather than papered over
(M2). Both are exactly the properties this cache must get right -- not the
underlying SDK; the SDK's own cryptography is never re-derived or re-approximated
here.
