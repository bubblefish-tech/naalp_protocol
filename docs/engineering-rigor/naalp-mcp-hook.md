<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Red-evidence: naalp-mcp-hook (MCP framework-hook adapter)

Mutation-survival evidence for `naalp_mcp_hook/mcp_hook.py`'s property ("keep MCP
annotations OPAQUE -- never decode/parse annotation contents to derive a decision"). Produced by
actually editing `naalp_mcp_hook/mcp_hook.py` (never `naalp_kit/binding.py` or
`impl/python/naalp/*`, both out of scope and already separately graded), confirming the named
test flips RED for the stated reason, then restoring the file from a `.bak` copy (never
`git checkout` -- this tree is uncommitted), clearing `__pycache__`
(`PYTHONDONTWRITEBYTECODE=1` set for every run), and re-running the full 35-test suite GREEN.

Baseline / reverted file hash for `naalp_mcp_hook/mcp_hook.py` (SHA-256), confirmed identical
before the mutation and after the revert:

```
64152cd304d5c1038e99c9818b76ce4879ca9670f37150ff1b0bccdf7e7c6f8d
```

Run command (from the repo root, invoking the real installed Python interpreter for this
platform -- on Windows the Microsoft-Store `python`/`python3` execution-alias stubs resolve
ahead of a real install on `PATH` and hang, so invoke the actual interpreter binary directly
rather than the bare `python` command):

```
PYTHONDONTWRITEBYTECODE=1 python -m pytest ecosystem/naalp-mcp-hook/tests/test_mcp_hook.py -v
```

## M1 -- annotations-stay-opaque-never-decoded (`test_effect_is_never_derived_from_annotation_hints`)

**Mutated:** two sites, both required for the mutation to have any real effect (a single-site
mutation that references a never-populated attribute would be a no-op, not a genuine defect):

1. `list_tools()` -- stash the RAW, decoded `types.ToolAnnotations` object per tool name (not
   just its opaque content id), the first step toward reading a hint's boolean value:

```diff
         result = await super().list_tools(*args, **kwargs)
         for tool in result.tools:
             cid = annotations_content_id(tool.annotations)
             if cid is not None:
                 self._naalp_annotation_cids[tool.name] = cid
+            # MUTATION M1 (red-evidence, naalp-mcp-hook): stash the raw, DECODED annotations
+            # object too -- the opacity violation call_tool's mutation below reads from.
+            if not hasattr(self, "_naalp_raw_annotations"):
+                self._naalp_raw_annotations = {}
+            self._naalp_raw_annotations[tool.name] = tool.annotations
         return result
```

2. `call_tool()` -- when the effect is otherwise unclassified, read the stashed annotations
   object's `readOnlyHint` boolean VALUE and derive an effect from it -- exactly the
   `naalp-mcp-bridge`-style decode this module's own opacity guarantee forbids:

```diff
         effect = self._classify_effect(name, args_dict)
+        # MUTATION M1 (red-evidence, naalp-mcp-hook): decode the tool's cached annotations the
+        # way naalp-mcp-bridge does, and derive effect from a hint's boolean VALUE -- the exact
+        # opacity violation this module exists to forbid.
+        if effect is None:
+            _ann_obj = getattr(self, "_naalp_raw_annotations", {}).get(name)
+            if _ann_obj is not None and _ann_obj.readOnlyHint:
+                effect = policy.READ_ONLY
```

**RED, confirmed:**

```
FAILED ecosystem/naalp-mcp-hook/tests/test_mcp_hook.py::test_effect_is_never_derived_from_annotation_hints
    assert read_only_hinted_call.effect == policy.DESTRUCTIVE  # SAME, despite the opposite hint
E   assert 0 == 3
E    +  where 0 = <naalp.envelope.Object object at 0x...>.effect
E    +  and   3 = policy.DESTRUCTIVE

1 failed, 34 passed
```

With the mutation in place, a tool whose real MCP `ToolAnnotations` carried `readOnlyHint=True`
(and `destructiveHint=False`) resolved to a signed, VERIFIED N-AALP object with `effect ==
READ_ONLY (0)` instead of the fail-closed `DESTRUCTIVE (3)` default -- i.e. the mutated adapter
DID successfully decode the annotation's boolean hint and let it steer a real authorization-grade
field, precisely the behavior this module exists to forbid (and precisely what `naalp-mcp-bridge`
correctly does, for its OWN, different job, via `naalp.mcp.map_annotations_to_effect`). Every
other test in the file was unaffected (34 of 35 tests still passed, including
`test_payload_never_contains_raw_annotation_hint_text`, which targets a DIFFERENT opacity facet
-- the payload's literal bytes -- and was never touched by this mutation) -- this mutation
targets only the effect-derivation path a genuine annotation decode would reach.

**Reverted:** the file was restored from its `.bak` copy (never `git checkout` -- this tree is
uncommitted), `__pycache__` cleared, hash re-confirmed
`64152cd304d5c1038e99c9818b76ce4879ca9670f37150ff1b0bccdf7e7c6f8d`.

**GREEN, confirmed:** 35/35 tests pass.

## Why this mutation, and why the target stays inside `naalp_mcp_hook/`

Every cryptographic, encoding, and authorization operation `call_tool`/`list_tools` reaches
(`naalp_kit.binding.sign_action`/`verify_action`/`authorize_action`, and beneath those the real
Part-1 core -- `naalp.ez`, `naalp.envelope`, `naalp.cbor.content_id`, `naalp.policy.Grant.
authorize_object`) is already-graded, untouched by this task, and carries its own red-evidence
elsewhere. What `naalp_mcp_hook/mcp_hook.py` adds, and therefore
what this mutation targets, is entirely this module's OWN new code: whether a real MCP tool's real
`ToolAnnotations` object is ever read for its semantic CONTENT. This is the one property that
distinguishes this module from the pre-existing `ecosystem/naalp-mcp-bridge` and is the reason it
is a DISTINCT adapter rather than an extension of that library -- a governance
kit that silently decodes what it promises to keep opaque would defeat the specific design
guarantee ("even against an unmodified third-party server") this module exists to provide.

## Environment note (verified against the currently installed package, not memory)

The official `mcp` package, version **1.27.1**, was already installed in this session's Python
environment (confirmed via `pip show mcp`: `Author: Anthropic, PBC`) and used directly for this
module and its test suite -- a real `mcp.server.fastmcp.FastMCP` server, a real
`mcp.ClientSession` subclass (`NaalpGovernedClientSession`), and real `mcp.types.ToolAnnotations`
objects, connected over real `anyio` memory-object streams
(`mcp.shared.memory.create_client_server_memory_streams`, the same in-process transport the MCP
SDK's own test suite uses) with a real `initialize()` handshake.

Cross-checked THIS session against the current PyPI release (`pypi.org/pypi/mcp/json`): the
latest release line is **2.1.1** (released 2026-08-24), "a major rework of the SDK... to support
the 2026-07-28 MCP specification." Installed into an isolated venv (never touching the
environment's 1.27.1 install, which another local tool depends on) purely to confirm the hook
point this module relies on -- `mcp.client.session.ClientSession.call_tool`, a plain overridable
`async def` instance method -- is stable across the rework (2.1.1 adds keyword-only extras for
new elicitation/task features; this module forwards `*args, **kwargs` through them unexamined,
so it is unaffected by the addition). Confirmed by reading `mcp/client/session.py` and
`mcp/shared/session.py` in both versions, and by grepping the installed package tree for
"middleware"/"interceptor": the MCP Python SDK has no separate client-side plugin/middleware
registry (unlike ADK's `BasePlugin`); ordinary subclassing of `ClientSession` IS the SDK's own
extensibility mechanism for this purpose, confirmed real and stable across the current major
version boundary.
