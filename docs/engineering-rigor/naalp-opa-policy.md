<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Red-evidence: N-AALP OPA/Rego policy-enforcement integration

Mutation-survival evidence for the load-bearing properties of `naalp_opa_policy`. Each row
was produced by actually editing `naalp_opa_policy/opa_policy.py` (never any `impl/python/naalp/*`
file, which is Part-1 and out of scope for this task), confirming the named test(s) flip RED
for the stated reason, then restoring the file from a `.bak` copy (never `git checkout`),
clearing `__pycache__` (`PYTHONDONTWRITEBYTECODE=1` set for every run so no stale bytecode
can mask a mutation or fake a revert), and re-running the full suite GREEN with the file's
hash re-confirmed identical to the pre-mutation baseline.

Baseline / reverted file hash for `naalp_opa_policy/opa_policy.py` (SHA-256), confirmed
identical before mutation 1 and after every one of the four reverts below:

```
584a6e5057bef754a6599d8e6a346ec7e98e7428a3c5bd012fb305440953f922
```

Run command (from `ecosystem/naalp-opa-policy/`, invoking the real installed Python
interpreter for this platform -- on Windows the Microsoft-Store `python`/`python3`
execution-alias stubs resolve ahead of a real install on `PATH` and hang, so on that platform
invoke the actual interpreter binary directly rather than the bare `python` command):

```
PYTHONDONTWRITEBYTECODE=1 python -m unittest -v tests.test_opa_policy
```

All commands below were run from `ecosystem/naalp-opa-policy/` with
`PYTHONDONTWRITEBYTECODE=1` set and `__pycache__` removed immediately before every test
invocation (mutate, revert, and re-confirm), so no cached `.pyc` could report a result that
did not come from the file on disk at that moment. Full suite size: 10 tests. Every mutation
and revert below was performed with a real, running `opa` binary (github.com/open-policy-agent/opa
v1.19.1, installed this session via `winget install --id open-policy-agent.opa -e
--accept-package-agreements --accept-source-agreements`) -- nothing in this evidence is
produced against a stub or fake engine.

## OPA engine install + invocation notes (established before any test was written)

- Installed via `winget install --id open-policy-agent.opa -e --accept-package-agreements
  --accept-source-agreements` (the naive `winget install openpolicyagent.OPA` package id
  does not exist in the winget index; `winget search opa` surfaced the
  real id `open-policy-agent.opa`, version 1.19.1). Confirmed via `opa version` in a freshly
  spawned process (a new process picks up the winget-updated PATH without any manual refresh):
  `Version: 1.19.1`, `Rego Version: v1`.
- **Reproduced Windows defect, hand-confirmed this session:** the real `opa` binary's file
  loader mis-parses an absolute path whose first path component is a drive letter followed by
  a colon (the shape `opa eval -d <driveletter>:<backslash>...\policies ...`) as a URL whose
  scheme is that drive letter, and fails with a bogus `GetFileAttributesEx \Users\...: The
  system cannot find the path specified` error -- confirmed by running the identical `opa
  eval` invocation twice, once with an absolute drive-rooted path (fails) and once with a
  `cwd`-relative path (succeeds). `OPAEngine._run` works around this on every platform by
  ALWAYS invoking `opa` with `cwd` set to the parent of the policy directory and passing only
  the directory's basename on the command line -- an absolute path is never handed to `opa`.
- **`opa eval` result shapes, hand-confirmed this session** (these are exactly what
  `OPAEngine._run`/`decide` branch on):
  - A clean Allow: `{"result": [{"expressions": [{"value": true, ...}]}]}`, exit 0.
  - A clean Deny: `{"result": [{"expressions": [{"value": false, ...}]}]}`, exit 0.
  - A missing policy file/dir or a Rego parse error: `{"errors": [{"message": "..."}]}` (or,
    for a parse error, an additional `"code": "rego_parse_error"` and `"location"`), exit 2.
  - An undefined query (a package with no matching rule): bare `{}`, exit 0 -- no `"result"`
    key at all.
  - `-I`/`--stdin-input` reads the JSON input document from stdin; `-d <dir>` recursively
    loads every `*.rego`/`*.json`/`*.yaml` under that one directory (confirmed against a real
    run loading `naalp_authz.rego` + `data.json` together via a single `-d`).

## Non-circular vector provenance (established before any mutation test)

`OracleGroundingTests.test_conformance_vectors_match_real_engine` confirms, before any
fail-closed or mapping test below relies on it, that all 9 hand-derived `{input, expected}`
pairs (5 allow, 4 deny) in `vectors/conformance_vectors.json` -- each `expected` value derived by reading the
three rule bodies (`effect_within_ceiling` / `signer_matches_grant` / `audience_ok`) in the
checked-in `naalp_opa_policy/policies/naalp_authz.rego` against that vector's own `input`
fields, exactly as an administrator reading the policy would reason about it -- match what the
REAL `opa` engine actually returns for that policy. The oracle is the real engine evaluating
the real checked-in `.rego`/`data.json`; nothing in this package's own Python code produced
any `expected` value. `MappingConformanceTests` then reproduces four of those same logical
scenarios (matching-everything allow, effect-over-ceiling deny, wrong-audience deny, and the
exact input-document shape) through REAL, cryptographically signed-and-verified N-AALP
objects (`naalp.envelope.sign` / `naalp.envelope.verify`, real ML-DSA-65 keys via
`naalp.cose.mldsa_keygen`) and confirms `naalp_opa_policy.build_input` +
`naalp_opa_policy.authorize_with_policy` reach the identical Allow/Deny outcome the grounded
vector predicts -- so the code genuinely under test by this package (the mapping and the
fail-closed integration, not the policy engine) is graded against a REAL cryptographic
pipeline, never a synthetic dict standing in for a real object.

## M1 -- fail-open on an unreachable/erroring engine (`test_engine_unreachable_denies_even_a_would_be_allow`)

**Mutated:** `OPAEngine.decide()`, the exception branch around the real `opa` subprocess call:

```diff
         try:
             result = self._run(input_doc)
         except OPAEngineError:
-            return False  # fail-closed: an unreachable/erroring engine denies, never allows
+            return True  # MUTATION M1 (red-evidence): fail-open on an unreachable/erroring engine
```

**RED, confirmed:** 1 of 10 tests failed --

```
FAIL: test_engine_unreachable_denies_even_a_would_be_allow
AssertionError: PolicyError not raised
```

The test builds a real, policy-conformant object, first confirms it is genuinely Allowed by
a REAL reachable engine (so the scenario is provably a "would-be-allow"), then repeats the
identical call against an `OPAEngine` configured with a nonexistent `opa_binary`. With the
mutation, an unreachable engine is silently treated as an Allow and no `PolicyError` is
raised -- exactly the fail-open regression this property exists to prevent. The direct
lower-level check (`test_opa_engine_error_raises_opaengineerror_internally`, which asserts on
`OPAEngineError` at the `_run()` layer rather than `decide()`'s boolean) is UNAFFECTED, since
`_run()` itself is untouched by this mutation -- confirming the mutation targets exactly the
`decide()` fail-closed wrapping and nothing upstream of it.

**Reverted:** the file was restored from its `.bak` copy (never `git checkout`), `__pycache__`
cleared, hash re-confirmed `584a6e5057bef754a6599d8e6a346ec7e98e7428a3c5bd012fb305440953f922`.
**GREEN, confirmed:** 10/10 tests pass.

## M2 -- skip the OPA consult entirely (`test_deny_is_actually_enforced_before_a_would_be_allow` +4 others)

**Mutated:** `authorize_with_policy()`, the enforcement choke point:

```diff
     input_doc = build_input(obj, alg, verified_pubkey, grant)
-    if not engine.decide(input_doc):
+    # MUTATION M2 (red-evidence): skip the OPA consult entirely -- always proceed as allowed.
+    if False and not engine.decide(input_doc):
         raise policy.PolicyError(
```

**RED, confirmed:** 5 of 10 tests failed --

```
FAIL: test_deny_is_actually_enforced_before_a_would_be_allow
AssertionError: PolicyError not raised
FAIL: test_engine_unreachable_denies_even_a_would_be_allow
AssertionError: PolicyError not raised
FAIL: test_undefined_query_result_denies_even_a_would_be_allow
AssertionError: PolicyError not raised
FAIL: test_destructive_effect_over_ceiling_is_denied
AssertionError: PolicyError not raised
FAIL: test_wrong_audience_object_is_denied
AssertionError: PolicyError not raised
```

Every test that expects `authorize_with_policy` to raise `PolicyError` flipped, because the
mutated `if` condition can never evaluate its right-hand side and the function always falls
through as if the (never-run) engine had allowed the object -- exactly the "the policy
consult was silently bypassed" failure this property exists to prevent. The 5 tests that
expect NO exception (a genuine Allow) were unaffected, since a function that always allows is
indistinguishable from a correct one on those inputs alone -- exactly the boundary this
mutation targets.

**Reverted:** restored from `.bak`, `__pycache__` cleared, hash re-confirmed
`584a6e5057bef754a6599d8e6a346ec7e98e7428a3c5bd012fb305440953f922`.
**GREEN, confirmed:** 10/10 tests pass.

## M3 -- trust the object's self-asserted `signer` field (`test_signer_resolved_from_verified_pubkey_not_self_asserted_field` +4 others)

**Mutated:** `build_input()`, the principal-resolution line (the property this
package's own module docstring names explicitly):

```diff
-    principal = policy.resolve_auth_principal(
-        policy.SOURCE_SIGNATURE, identity.signer_id(alg, verified_pubkey)
-    )
+    # MUTATION M3 (red-evidence): trust the object's own self-asserted `signer` body field
+    # instead of the cryptographically-resolved principal.
+    principal = obj.signer.decode("utf-8", errors="replace")
     return {
```

**RED, confirmed:** 5 of 10 tests failed/errored --

```
FAIL: test_signer_resolved_from_verified_pubkey_not_self_asserted_field
AssertionError: 'attacker-claimed-identity-not-the-real-signer' != 'bciqn4bwilfr74zzc6ou6xlkgqzi7selw2tc2lxepf34pbcpilun6f4q'
FAIL: test_build_input_matches_grounded_vector_shape
AssertionError: {...'signer': '<mojibake decode of the raw pubkey bytes>'...} != {...'signer': 'bciqo2gxjfh673...'...}
ERROR: test_undefined_query_result_denies_even_a_would_be_allow
naalp.policy.PolicyError: EffectNotAuthorized: policy engine denied the object (...signer='<mojibake>')
ERROR: test_matching_read_only_object_is_allowed
naalp.policy.PolicyError: EffectNotAuthorized: policy engine denied the object (...signer='<mojibake>')
ERROR: test_engine_unreachable_denies_even_a_would_be_allow (via its "confirm a real reachable
engine allows this" sanity assertion)
```

The dedicated test flipped directly (the deliberately spoofed `signer` body field
`b"attacker-claimed-identity-not-the-real-signer"` leaks straight into `doc["signer"]` instead
of being replaced by the resolved principal). More significantly, every OTHER test that builds
an ordinary real object (`signer=pk`, the real raw ML-DSA-65 public-key bytes, which is NOT a
valid identity string and does not survive UTF-8 decoding cleanly) also broke, several of them
turning a previously-clean Allow into an unexpected `PolicyError`, because `obj.signer`'s raw
bytes are never the correct principal string -- confirming this mutation corrupts the identity
on EVERY real object, not only an adversarial one, which is exactly why `obj.signer` must
never be trusted as an identity (policy.py's own module docstring: only a signature-derived
identity is an authorization principal).

**Reverted:** restored from `.bak`, `__pycache__` cleared, hash re-confirmed
`584a6e5057bef754a6599d8e6a346ec7e98e7428a3c5bd012fb305440953f922`.
**GREEN, confirmed:** 10/10 tests pass.

## M4 -- fail-open on an undefined query result (`test_undefined_query_result_denies_even_a_would_be_allow`)

**Mutated:** `OPAEngine.decide()`, the undefined-result branch:

```diff
         results = result.get("result")
         if not results:
-            return False  # fail-closed: an undefined query result denies
+            return True  # MUTATION M4 (red-evidence): fail-open on an undefined query result
```

**RED, confirmed:** 1 of 10 tests failed --

```
FAIL: test_undefined_query_result_denies_even_a_would_be_allow
AssertionError: PolicyError not raised
```

The test first confirms a real object is genuinely Allowed by an `OPAEngine` pointed at the
package's real query (`data.naalp.authz.allow`), then repeats the identical call with an
`OPAEngine` configured to query a nonexistent rule (`data.naalp.authz.no_such_rule_exists`),
which `opa eval` resolves cleanly (exit 0) but with NO `"result"` key in its JSON output --
the "engine ran fine, but there is nothing to allow" case, distinct from M1's "the engine
itself could not run at all". With the mutation, this undefined result is treated as an
Allow and no `PolicyError` is raised. Exactly the one test targeting this branch flipped (9 of
10 still passed), confirming this mutation is isolated from M1's exception-handling branch and
from M2's enforcement choke point.

**Reverted:** restored from `.bak`, `__pycache__` cleared, hash re-confirmed
`584a6e5057bef754a6599d8e6a346ec7e98e7428a3c5bd012fb305440953f922`.
**GREEN, confirmed:** 10/10 tests pass.

## Why these four, and why every mutation targets `opa_policy.py` rather than `naalp.*` or the real `opa` engine

`naalp_opa_policy` is glue over TWO real, independently-graded systems it never re-implements:
the Part-1 SDK (`naalp.envelope`/`naalp.identity`/`naalp.policy`/`naalp.cose`, whose own
cryptography and effect-lattice logic carry their own graded red-evidence and are out of
scope for this task) and the real `opa` binary (whose Rego evaluation semantics are OPA's own
concern, not this package's -- re-implementing them would be exactly the fake-verifier
failure this programme's rules forbid). What IS this task's own code, and therefore what these
four mutations target, is this package's own choices: that `decide()` actually treats an
unreachable/erroring engine as a Deny (M1) rather than silently allowing, that
`authorize_with_policy()` actually consults the engine before ever returning cleanly (M2)
rather than becoming a no-op gate, that the identity fed into the policy is the
cryptographically-resolved principal and never the object's own self-asserted `signer` field
(M3) -- the property this integration exists to preserve across the OPA boundary -- and
that `decide()` treats an undefined query result as a Deny (M4) exactly as it treats an
unreachable engine, but via a genuinely distinct code path (a clean `opa` run with no matching
rule, rather than a failed `opa` invocation). All four are exactly the properties this
integration must get right -- not the SDK, and not the OPA engine itself.
