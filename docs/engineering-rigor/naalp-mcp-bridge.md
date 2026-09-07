<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Red-evidence: N-AALP MCP tool-integration bridge

Mutation-survival evidence for the three load-bearing properties described below. Each
row was produced by actually editing `naalp_mcp_bridge/mcp_bridge.py` (never
`impl/python/naalp/*`, which is Part-1 and out of scope for this task), confirming the named
test(s) flip RED for the stated reason, then restoring the file from a `.bak` copy (never `git
checkout`), clearing `__pycache__` (`PYTHONDONTWRITEBYTECODE=1` set for every run so no stale
bytecode can mask a mutation or fake a revert), and re-running the full suite GREEN with the file
hash confirmed restored.

Baseline / reverted file hash for `naalp_mcp_bridge/mcp_bridge.py` (SHA-256), confirmed identical
before mutation 1 and after every one of the three reverts below:

```
ce045182d2a3d14be1089ad4e70a0c11bea8399a97b5b5276a541f15015b585d
```

Run command (from `ecosystem/naalp-mcp-bridge/`, invoking the real installed Python interpreter
for this platform -- on Windows the Microsoft-Store `python`/`python3` execution-alias stubs
resolve ahead of a real install on `PATH` and hang, so on that platform invoke the actual
interpreter binary directly rather than the bare `python` command):

```
PYTHONDONTWRITEBYTECODE=1 python -m unittest -v tests.test_mcp_bridge
```

All commands below were run from `ecosystem/naalp-mcp-bridge/` with `PYTHONDONTWRITEBYTECODE=1`
set and `__pycache__` removed immediately before every test invocation (mutate, revert, and
re-confirm), so no cached `.pyc` could report a result that did not come from the file on disk at
that moment. The full suite is 20 tests, all green at baseline.

## M1 -- octet-exact recovery is real, not a re-encoding
(`test_raw_bytes_non_canonical_round_trip_byte_identical`)

**Mutated:** `receive_tool_call()`, the recovery step that returns the carried foreign
`args_bytes` VERBATIM -- the core octet-exact property ("never re-serialized, canonicalized,
or rewritten"):

```diff
-    tool_bytes = resolved.tool_call.tool
-    args_bytes = resolved.tool_call.args
-    tool_definition = _parse_tool_definition(tool_bytes)
-    arguments = _decode_json(args_bytes, "call arguments", "ForeignBodyNotJSON")
+    tool_bytes = resolved.tool_call.tool
+    tool_definition = _parse_tool_definition(tool_bytes)
+    arguments = _decode_json(resolved.tool_call.args, "call arguments", "ForeignBodyNotJSON")
+    args_bytes = canonical_json_bytes(arguments)  # re-encode instead of recovering verbatim
```

**RED, confirmed:**

```
FAIL: test_raw_bytes_non_canonical_round_trip_byte_identical
AssertionError: b'{"a":1,"b":2,"text":"remember the milk"}' != b'{"b": 2,   "a": 1, "text": "remember the milk"}' : recovered args bytes must be byte-identical
```

The deliberately non-canonical input bytes (extra whitespace, keys out of alphabetical order)
are exactly what makes this mutation observable: a re-encoded value is semantically equivalent
but byte-DIFFERENT, which is precisely the failure the octet-exact property forbids (a carried
foreign message MUST NOT be re-serialized). The 5 oracle-vector round-trip cases in
`OracleByteIdentity` did NOT catch this mutation (their fixtures happen to already be in
canonical form), which is why this test's fixture is deliberately non-canonical -- confirming the
independent-vector tests alone are an insufficient net for this specific property, and this
targeted test is the one that closes the gap. 18 of 20 tests still passed (only the two tests
whose assertion depends on this exact recovery -- the round-trip byte-identity checks -- are
reached by a re-encoded-but-equivalent value).

**Reverted:** the file was restored from its `.bak` copy (never `git checkout`), `__pycache__`
cleared, hash re-confirmed `ce045182d2a3d14be1089ad4e70a0c11bea8399a97b5b5276a541f15015b585d`.
**GREEN, confirmed:** 20/20 tests pass.

## M2 -- the annotation->effect mapping is genuinely applied
(`test_unannotated_tool_defaults_to_destructive`, `test_idempotent_write_maps_correctly`,
`test_signer_may_escalate_declared_effect_above_the_mapping`,
`test_all_oracle_tool_calls_round_trip_and_match`,
`test_dict_convenience_round_trip_preserves_effect_and_audience_relevant_fields`)

**Mutated:** `carry_tool_call()`, the call into Part-1's published mapping table -- replaced
with a hardcoded constant, so every tool -- destructive, idempotent, or unannotated -- is
treated as `read_only`:

```diff
-    mapped = mcp.map_annotations_to_effect(annotations)
+    mapped = 0  # every call treated as read_only regardless of its actual annotations
```

**RED, confirmed:**

```
FAIL: test_unannotated_tool_defaults_to_destructive       AssertionError: 0 != 3
FAIL: test_idempotent_write_maps_correctly                 AssertionError: 0 != 1
FAIL: test_signer_may_escalate_declared_effect_above_the_mapping   AssertionError: 0 != 1
FAIL: test_all_oracle_tool_calls_round_trip_and_match       AssertionError: 0 != 2 : case append_note
FAIL: test_dict_convenience_round_trip_preserves_effect_and_audience_relevant_fields  AssertionError: 0 != 3
ERROR: test_raw_bytes_non_canonical_round_trip_byte_identical
    naalp.mcp.McpError: EffectUnderDeclared: declared effect is below the annotation-mapped effect
```

With the mapping defeated, every effect-class assertion across the mapping-fidelity tests and the
independent oracle's own 5 tool-call vectors fails on the actual value, and one test additionally
surfaces as a clean, correctly-named `EffectUnderDeclared` from the REAL Part-1 enforcement path
(because that test's `declared_effect` was left at its honest, non-mutated value while the
now-broken `mapped` collapsed to 0, so Part-1's own under-declaration check -- itself untouched --
correctly caught the now-inconsistent pair). This is exactly the kind of secondary, real-crypto
confirmation that shows the delegation to Part-1 is genuine: a broken caller-side mapping trips a
downstream, independently-correct Part-1 check, not a silently-swallowed exception. 11 of 20 tests
still passed (every test whose tool happens to be genuinely `read_only`, or whose assertion does
not depend on the mapped/declared effect value, is unaffected).

**Reverted:** restored from `.bak`, `__pycache__` cleared, hash re-confirmed
`ce045182d2a3d14be1089ad4e70a0c11bea8399a97b5b5276a541f15015b585d`.
**GREEN, confirmed:** 20/20 tests pass.

## M3 -- the approval-binding delegation is real, not a no-op
(`test_approval_authorizes_the_exact_call_and_is_single_use`,
`test_approval_bound_to_original_args_rejects_changed_args_call`,
`test_approval_bound_to_original_tool_description_rejects_changed_description_call`)

**Mutated:** `BridgedCall.authorize()`, the delegation to the real Part-1 per-call approval gate
(`naalp.mcp.authorize_call`) -- a bundle-level check with no separate re-implementation of its
own, so defeating the delegation itself is the only way to break this property from bridge code:

```diff
-    return mcp.authorize_call(self.resolved, appr, approver_alg, approver_pubkey, appr_sig, by, now, ledger)
+    return None  # skip delegation to the real Part-1 approval gate entirely
```

**RED, confirmed:**

```
FAIL: test_approval_authorizes_the_exact_call_and_is_single_use
AssertionError: ApprovalError not raised
FAIL: test_approval_bound_to_original_args_rejects_changed_args_call
AssertionError: McpError not raised
FAIL: test_approval_bound_to_original_tool_description_rejects_changed_description_call
AssertionError: McpError not raised
```

With delegation skipped, `authorize()` silently "succeeds" no matter what: a wrong-args approval
(AC-6.1.2), a wrong-tool-description approval (AC-6.1.3), and a replayed already-consumed
approval all pass through with no error and, critically, no ledger append -- exactly the security
property the per-call approval gate exists to prevent (an approval for one call authorizing a
DIFFERENT call, or a spent approval authorizing twice). 17 of 20 tests still passed (only the
three tests whose assertion exercises `authorize()`'s rejection paths are reached).

**Reverted:** restored from `.bak`, `__pycache__` cleared, hash re-confirmed
`ce045182d2a3d14be1089ad4e70a0c11bea8399a97b5b5276a541f15015b585d`.
**GREEN, confirmed:** 20/20 tests pass. `examples/isolation_demo.py` also re-run clean (exit 0)
after the final revert.

## Why these three, and why the mutation targets `mcp_bridge.py` rather than `naalp.mcp`/`naalp.envelope`

`naalp_mcp_bridge` is a developer-facing boundary layer: every cryptographic and wire-construction
operation (ML-DSA sign/verify, deterministic-CBOR encode/decode, the annotation->effect mapping
TABLE itself, the more-severe resolution, the call-binding content id, the approval + single-use
consume ledger) is delegated to the real Part-1 `naalp.mcp` / `naalp.envelope` / `naalp.approval`
primitives, which carry their own graded red-evidence and conformance corpora elsewhere (out of
scope for this task -- Part-1 files are not touched here). What IS this task's own code, and
therefore what these three mutations target, is the bridge's OWN responsibility: that it recovers
the carried foreign octets VERBATIM rather than silently re-deriving them (M1 -- the core
octet-exact property this whole module exists to provide), that it actually CALLS Part-1's
published mapping rather than hardcoding a constant (M2 -- the property that turns an unenforced
MCP hint into a signed, enforced effect claim), and that its convenience `authorize()` method
genuinely delegates to Part-1's per-call approval gate rather than silently no-opping (M3 -- the
property AC-6.1.2/AC-6.1.3 depend on). All three are exactly the properties this bridge must
get right -- not the underlying Part-1 SDK.
