<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Red-evidence: naalp-adk-plugin (ADK reference framework adapter)

Mutation-survival evidence for `naalp_adk_plugin/adk_plugin.py`'s property ("gating mode
short-circuits a tool call... when its declared effect is uncovered by the grant" -- fail
CLOSED, never fail open). Produced by actually editing `naalp_adk_plugin/adk_plugin.py` (never
`naalp_kit/binding.py` or `impl/python/naalp/*`, both out of scope and already separately
graded), confirming the named tests flip RED for the stated reason, then restoring the file from
a `.bak` copy (never `git checkout` -- this tree is uncommitted), clearing `__pycache__`
(`PYTHONDONTWRITEBYTECODE=1` set for every run), and re-running the full 28-test suite GREEN.

Baseline / reverted file hash for `naalp_adk_plugin/adk_plugin.py` (SHA-256), confirmed identical
before the mutation and after the revert:

```
576c890df12481839183ce6857dad2907f77fa852435a38a41f26c5c51ce5083
```

Run command (from the repo root, invoking the real installed Python interpreter for this
platform -- on Windows the Microsoft-Store `python`/`python3` execution-alias stubs resolve
ahead of a real install on `PATH` and hang, so invoke the actual interpreter binary directly
rather than the bare `python` command):

```
PYTHONDONTWRITEBYTECODE=1 python -m pytest ecosystem/naalp-adk-plugin/tests/test_adk_plugin.py -v
```

## M1 -- gating-fails-closed-never-open (`test_gating_denies_when_declared_effect_exceeds_grant_ceiling`, `test_gating_denies_when_grant_principal_does_not_match_the_signer`)

**Mutated:** `before_tool_callback`'s gating `except policy.PolicyError` branch -- the ONE place
this property requires a genuine authorization refusal to surface as an ADK deny-return (a
non-`None` dict, which ADK's own `BasePlugin` contract treats as "stop the tool execution and
return this response immediately") rather than being silently absorbed:

```diff
         try:
             binding.authorize_action(verified, self._grant)
         except policy.PolicyError as e:
-            # this property: the ADK deny-return -- a non-None dict short-circuits the tool call and IS
-            # the response (base_plugin.py); the tool never runs.
-            return {
-                "naalp_governance_denied": True,
-                "kind": e.kind,
-                "reason": str(e),
-                "tool": tool.name,
-            }
+            # MUTATION M1 (red-evidence, naalp-adk-plugin): swallow the denial and let the tool
+            # proceed anyway -- the exact fail-OPEN defect this property forbids.
+            pass
         return None  # authorized: proceed with the tool call unmodified
```

**RED, confirmed:**

```
FAILED ecosystem/naalp-adk-plugin/tests/test_adk_plugin.py::test_gating_denies_when_declared_effect_exceeds_grant_ceiling
    assert result is not None
E   assert None is not None

FAILED ecosystem/naalp-adk-plugin/tests/test_adk_plugin.py::test_gating_denies_when_grant_principal_does_not_match_the_signer
    assert result["naalp_governance_denied"] is True
E   TypeError: 'NoneType' object is not subscriptable

2 failed, 4 passed, 22 deselected
```

With the deny-return branch replaced by `pass`, `before_tool_callback` returned `None` for a
tool call whose declared effect exceeded the grant's ceiling (and for one whose grant principal
did not match the signer) -- ADK reads `None` as "proceed unmodified," so the mutated plugin
would have let a tool run that gating mode exists to stop. Every other test in the file was
unaffected (4 of the 6 `-k gating` tests still passed, along with all 22 non-gating tests) --
this mutation targets only the branch a genuine authorization refusal reaches.

**Reverted:** the file was restored from its `.bak` copy (never `git checkout` -- this tree is
uncommitted), `__pycache__` cleared, hash re-confirmed
`576c890df12481839183ce6857dad2907f77fa852435a38a41f26c5c51ce5083`.

**GREEN, confirmed:** 28/28 tests pass.

## Why this mutation, and why the target stays inside `naalp_adk_plugin/`

Every cryptographic, encoding, and authorization operation `before_tool_callback` reaches
(`naalp_kit.binding.sign_action`/`verify_action`/`authorize_action`, and beneath those the
real Part-1 core -- `naalp.ez`, `naalp.envelope`, `naalp.policy.Grant.authorize_object`) is
already-graded, untouched by this task, and carries its own red-evidence elsewhere. What
`naalp_adk_plugin/adk_plugin.py` adds, and therefore what this
mutation targets, is entirely this module's OWN new code: translating a real
`naalp.policy.PolicyError` refusal into ADK's own deny-return convention. This is the one
property that is specific
to the ADK adapter layer rather than to the core or sibling binding it wraps -- and it is the
security-critical one: a governance kit whose gating mode can silently fail open is worse than
one with no gating mode at all.

## Environment note (verified against the currently installed package, not memory)

`google-adk==2.8.0` was installed into this session's Python environment (`pip install
google-adk`) specifically to read `google/adk/plugins/base_plugin.py` (the real, current
`BasePlugin` ABC and its coroutine callback signatures) and to construct real `BaseTool`/`Event`
objects in the test suite -- not a training-data guess at a young, moving plugin API. The
confirmed current surface this module depends on: `BasePlugin.__init__(self, name: str)`;
`before_tool_callback(self, *, tool, tool_args, tool_context) -> Optional[dict]`;
`after_tool_callback(self, *, tool, tool_args, tool_context, result) -> Optional[dict]`;
`on_event_callback(self, *, invocation_context, event) -> Optional[Event]`;
`ReadonlyContext.invocation_id -> str` (the property backing `ToolContext`/`InvocationContext`).
