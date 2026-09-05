<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Red-evidence: N-AALP A2A agent-coordination bridge

Mutation-survival evidence for the three load-bearing properties described below. Each row
was produced by actually editing `naalp_a2a_bridge/a2a_bridge.py` (never
`impl/python/naalp/naming.py` or `impl/python/naalp/description.py`, which are Part-1 and out of
scope for this task), confirming the named test(s) flip RED for the stated reason, then
restoring the file from a `.bak` copy (never `git checkout`), clearing `__pycache__`
(`PYTHONDONTWRITEBYTECODE=1` set for every run so no stale bytecode can mask a mutation or fake a
revert), and re-running the full suite GREEN with the file hash confirmed restored.

Baseline / reverted file hash for `naalp_a2a_bridge/a2a_bridge.py` (SHA-256), confirmed identical
before mutation 1 and after every one of the three reverts below:

```
1e344a7883c175801f57f784b716f950b1fa68a5a4fd23a4747fb117bfc54378
```

Run command (from `ecosystem/naalp-a2a-bridge/`, invoking the real installed Python interpreter
for this platform -- on Windows the Microsoft-Store `python`/`python3` execution-alias stubs
resolve ahead of a real install on `PATH` and hang, so on that platform invoke the actual
interpreter binary directly rather than the bare `python` command):

```
PYTHONDONTWRITEBYTECODE=1 python -m unittest -v tests.test_a2a_bridge
```

All commands below were run from `ecosystem/naalp-a2a-bridge/` with `PYTHONDONTWRITEBYTECODE=1`
set and `__pycache__` removed immediately before every test invocation (mutate, revert, and
re-confirm), so no cached `.pyc` could report a result that did not come from the file on disk at
that moment.

## M1 -- fail fast, before a signature is ever spent, on an illegal A2A edge
(`test_illegal_edge_refused_before_signing`)

**Mutated:** `bridge_activity()`, the eager legal-edge gate this bridge runs BEFORE it ever signs
a transition -- reusing the real Part-1 `naming.verify_transition` (the same table
`naming.verify_task_chain` itself consults):

```diff
         t = naming.Transition(task, card_id, frm, to, i, prev)
-        naming.verify_transition(t.frm, t.to)  # fail fast: the real Part-1 legal-edge gate
+        pass  # MUTATION M1 (red-evidence): never check the edge is legal before signing it
         transitions.append(t)
```

**RED, confirmed:**

```
FAIL: test_illegal_edge_refused_before_signing
AssertionError: NamingError not raised
```

With the check defeated, `bridge_activity` happily signs a chain containing an illegal A2A edge
(here: `working -> completed -> working`, a transition out of the terminal state `completed`,
which the A2A category rules -- and the real Part-1 legal-edge table -- forbid). This is a
genuine bridge-level property distinct from what Part-1's own `naming.verify_task_chain` proves
at verification time: a caller of `bridge_activity` learns their activity was illegal
IMMEDIATELY, at construction, rather than only later when someone else tries to verify it (and
never spends a signature on bytes that were never going to be accepted). 11 of 12 tests still
passed (the other tests either never construct an illegal edge, or exercise the verification path
directly, which `naming.verify_task_chain` -- untouched by this mutation -- still enforces).

**Reverted:** the file was restored from its `.bak` copy (never `git checkout`), `__pycache__`
cleared, hash re-confirmed `1e344a7883c175801f57f784b716f950b1fa68a5a4fd23a4747fb117bfc54378`.
**GREEN, confirmed:** 12/12 tests pass.

## M2 -- `verify_activity` actually delegates to the real Part-1 chain verifier
(`test_tampered_and_reordered_chain_refused`, `test_activity_bound_to_a_foreign_card_is_refused`)

**Mutated:** `verify_activity()`, replacing the real, fully-checking delegated call
(`naming.verify_task_chain`: every signature, prev/seq linkage, the card binding, the start
state, contiguity, and the A2A legal-edge table) with a bare structural decode that checks
NONE of it:

```diff
-    verified = naming.verify_task_chain(activity_objs, card_id, profile, alg, pubkey)
+    # MUTATION M2 (red-evidence): parse without verifying -- no signature, linkage, card-binding,
+    # start-state, contiguity, or legal-edge check at all.
+    verified = [naming.parse_transition(cose.parse_sign1_raw(o)[1]) for o in activity_objs]
     task_id = verified[0].task.decode("utf-8")
```

**RED, confirmed:**

```
FAIL: test_activity_bound_to_a_foreign_card_is_refused
AssertionError: NamingError not raised
FAIL: test_tampered_and_reordered_chain_refused
AssertionError: NamingError not raised
```

With the delegated call defeated, `verify_activity` (and therefore `verify_and_recover`, which
calls it) "recovers" a foreign-native activity from a chain whose signature was tampered, whose
transitions were presented out of order, and whose card scope does not match at all -- exactly
the security properties this bridge exists to preserve across the boundary. Both flipped tests
are the only ones whose assertion depends on `naming.verify_task_chain`'s real checks actually
running; the other 10 tests either build a genuinely-valid chain and never reach a rejection path,
or exercise `bridge_activity`'s own construction-time checks (M1's territory), which this
mutation does not touch.

**Reverted:** restored from `.bak`, `__pycache__` cleared, hash re-confirmed
`1e344a7883c175801f57f784b716f950b1fa68a5a4fd23a4747fb117bfc54378`.
**GREEN, confirmed:** 12/12 tests pass.

## M3 -- the task chain's card scope is bound non-circularly, never self-referentially
(`test_activity_bound_to_a_foreign_card_is_refused`)

**Mutated:** `verify_and_recover()`, the point where the task chain's expected scope is derived.
The correct code derives it from `verify_card`'s own independently-verified result (`im.id()`);
the mutation instead reads it back OUT of the very activity being verified (its own first
transition's claimed `card` field), making the binding check vacuous by construction -- the
exact circular-verification shape `naalp_bundle`'s non-circular-anchor property was built to
catch, one boundary over:

```diff
     resolved_card, im = verify_card(card_obj, card_pubkey, alg, profile)
-    card_id = im.id()  # the bound scope, derived from the attestation THIS call just verified
+    # MUTATION M3 (red-evidence): derive the "expected" scope from the activity's OWN claimed
+    # card field instead of from the attestation this call itself just verified -- self-
+    # referential, so any activity trivially "matches" whatever card it already claims.
+    card_id = naming.parse_transition(cose.parse_sign1_raw(activity_objs[0])[1]).card
     verified, events = verify_activity(activity_objs, card_id, task_pubkey, alg, profile)
```

**RED, confirmed:**

```
FAIL: test_activity_bound_to_a_foreign_card_is_refused
AssertionError: NamingError not raised
```

The test builds TWO independently, genuinely valid attestations -- card A (importer key A, the
`billing-agent` card) and card B (importer key B, a different card) -- and an activity that is
genuinely, correctly bound to card B's scope. Verifying that activity against card A's attestation
should be refused (`ForeignCard`): card A is real, the activity chain is real, but they do not
name the same scope. Under the mutation, `verify_and_recover` no longer asks "does this activity
match the card I was ACTUALLY handed" -- it asks "does this activity match whatever card it
already claims to be for," which is trivially always true, silently discarding card A entirely.
11 of 12 tests still passed (every other test either presents the activity's true, matching card,
or never reaches `verify_and_recover` at all).

**Reverted:** restored from `.bak`, `__pycache__` cleared, hash re-confirmed
`1e344a7883c175801f57f784b716f950b1fa68a5a4fd23a4747fb117bfc54378`.
**GREEN, confirmed:** 12/12 tests pass. `examples/isolation_demo.py` also re-run clean (exit 0)
after the final revert.

## Why these three, and why the mutation targets `a2a_bridge.py` rather than
`naalp.naming`/`naalp.description`

`naalp_a2a_bridge` is glue and a boundary-crossing choke point: every cryptographic and encoding
operation (ML-DSA signature verify, deterministic-CBOR encode/decode, content-id hashing, the
A2A legal-edge table itself) is delegated to the real Part-1 primitives, which carry their own
graded red-evidence and conformance corpus elsewhere (`impl/python/tests/test_naming.py`,
`vectors/naming/cases.json`; out of scope for this task -- Part-1 files are not touched here).
What IS this task's own code, and therefore what these three mutations target, is the bridge's
OWN choices: that it fails fast on an illegal edge before ever spending a signature on it (M1 --
a property with no Part-1 analogue, since `naming.Transition`/`naming.sign_transition` perform no
legality check of their own), that its verification entry point actually calls the real Part-1
chain verifier rather than merely parsing (M2 -- the delegation itself is this bridge's
responsibility to get right), and that the scope a task chain is checked against is derived from
an independent verification rather than trusted from the artifact under test (M3 -- the
non-circular-binding discipline). All three are exactly the properties this bridge depends on
getting right -- not the underlying Part-1 SDK.
