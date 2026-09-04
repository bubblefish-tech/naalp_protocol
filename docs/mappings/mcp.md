<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Protocol mapping: Model Context Protocol (MCP)

MCP lets a tool declare behavioural *annotations* (`readOnlyHint`, `destructiveHint`,
`idempotentHint`, `openWorldHint`) on a `tools/list` definition. The MCP specification is explicit
that these are **unenforced hints**: *"For trust & safety and security, clients MUST consider tool
annotations to be untrusted unless they come from trusted servers"* (MCP tools page, spec revisions
2025-06-18 and 2025-11-25). An annotation is not an authorization construct.

The **NAALP-MCP binding profile** (the draft's Foreign Carriage by Class section) maps that untrusted hint to a *signed effect claim
by a named key*, enforced fail-closed — without inventing a new envelope, encoding, signature,
identity, or audit mechanism. An MCP tool call becomes an ordinary N-AALP object on the Bridge
channel (`0x000D`), reusing the closed effect lattice, the approval + single-use consume ledger, and
the content-id framing already defined for every other N-AALP object.

Reference implementation: [`ecosystem/naalp-mcp-bridge`](https://github.com/bubblefish-tech/naalp_protocol/tree/main/ecosystem/naalp-mcp-bridge)
(Python), built directly on the Part-1 `naalp.mcp` / `naalp.envelope` / `naalp.approval` primitives —
every cryptographic and wire operation is delegated to those, never re-derived. Mutation-tested.

## What maps to what

| MCP-native shape | N-AALP wire object | Carried how |
|---|---|---|
| A `tools/list` tool definition (JSON, with `annotations`) | `naalp-mcp-tool-call` field 1 (`tool`, bstr) | octet-for-octet, never re-serialized |
| A JSON-RPC 2.0 `tools/call` request's `params.arguments` | `naalp-mcp-tool-call` field 2 (`args`, bstr) | octet-for-octet, never re-serialized |
| The tool definition's `annotations` object | `naalp-mcp-annotations` (map, keys 1-4) | transcribed once, at the boundary (§ below) |
| — | `naalp-mcp-call-binding` `{1: tool_id, 2: args_id}` | derived; an approval binds this pair |

`naalp-mcp-tool-call` is tier-1 Bridge-channel object, kind `McpToolCall` (1) — a named escalation
over the frozen baseline Carriage kind (0). The wrapper's own effect is the envelope's normal effect
field (field 7), not a body field.

### The annotation transcription

The N-AALP spine has no CBOR boolean, so each JSON hint is carried as the uint `1` (true) / `0`
(false) under `naalp-mcp-annotations` keys 1..4 (`readOnly`, `destructive`, `idempotent`,
`openWorld`). An **absent** hint is distinct on the wire from a present `0` and takes its own MCP
default when the effect mapping is computed.

### The published annotation → effect mapping

The closed four-effect lattice (`read_only < idempotent_write < non_idempotent_write < destructive`)
is reached by a published table (`vectors/registry/mcp.csv`), applying each hint's MCP default when
the annotation is absent:

| `readOnlyHint` | `destructiveHint` | `idempotentHint` | → effect |
|---|---|---|---|
| true | any | any | `read_only` |
| false | true | any | `destructive` |
| false | false | true | `idempotent_write` |
| false | false | false | `non_idempotent_write` |

`destructiveHint` defaults to **true** and `readOnlyHint` defaults to **false**, so a tool with **no
annotations at all** maps to `destructive` — the fail-closed collapse to the most severe outcome,
matching the spine rule that an absent effect on a state-changing object is `destructive`.
`openWorldHint` is carried for accountability but never enters the effect mapping. An annotation set
that would resolve outside the lattice is rejected `MalformedAnnotation`, never defaulted to benign.

### The wrapping signer is accountable

The wrapper's declared envelope effect is under the wrapping signer's ML-DSA signature. A verifier
independently recomputes the annotation-derived effect from the *carried* annotations and enforces
the **more severe** of the two — a disagreement collapses up, never down, and is attributable to the
wrapping signer's key. A signer that declares *below* its own tool's annotations is rejected
fail-closed (`EffectUnderDeclared`): a lying tool cannot escape by wrapping a `destructive` action
under a `read_only` declaration.

### Approval binds the exact call

A per-call approval binds the content id of the `(tool_id, args_id)` call binding, reusing the
existing approval + single-use consume ledger. A changed tool description or changed arguments
yields a new call content id and invalidates any prior approval bound to the old one. The approval's
granted effect must cover the call's enforced (more-severe) effect, must be unexpired, and is
consumed exactly once.

## Using the bridge

```python
from naalp_mcp_bridge import carry_tool_call_from_objects, receive_tool_call, bridged_call_request
from naalp import cose, policy

# Exactly what an MCP client already holds: a tool definition from tools/list, and a
# JSON-RPC 2.0 tools/call request naming that tool and its arguments.
tool_definition = {
    "name": "transfer_funds",
    "description": "Transfer funds between two accounts",
    "annotations": {"readOnlyHint": False, "destructiveHint": True},
}
call_request = {
    "jsonrpc": "2.0", "id": 7, "method": "tools/call",
    "params": {"name": "transfer_funds", "arguments": {"to": "acct-778-441", "amount": 500000}},
}

signer_seed = bytes([0xC1]) * 32
signer_pk = cose.mldsa_keygen("ML-DSA-65", signer_seed)

carried = carry_tool_call_from_objects(
    tool_definition, call_request, signer_seed=signer_seed, created=1_800_000_000_000,
)
# carried.declared_effect / carried.annotation_mapped_effect are both `destructive` here.

# Later, standing alone, holding only the wire bytes and the signer's public key:
recv = receive_tool_call(carried.signed_object, cose.PROFILE_PUBLIC, cose.ALG_MLDSA65, signer_pk)
assert recv.tool_bytes == carried.tool_bytes           # octet-exact recovery
assert bridged_call_request(recv, rpc_id=7) == call_request   # the original JSON-RPC request, back
assert recv.enforced_effect == policy.DESTRUCTIVE
```

Two ingestion paths are offered: `carry_tool_call` / `receive_tool_call` operate on **raw foreign
octets** — the literal bytes a tool-definition document and a call's arguments document had on the
wire, the strictest form of octet-for-octet carriage; `carry_tool_call_from_objects` /
`bridged_call_request` (used above) are the convenience layer for a caller holding already-parsed
MCP objects — each object is serialized to canonical JSON bytes *exactly once*, at the ingest
boundary, and those bytes are what is carried from then on.

A tampered signed object fails closed with a named error (`BadSignature`); an approval for a
different call's argument set is rejected `ApprovalRequired` with no ledger append; a replayed
(already-consumed) approval is rejected `AlreadyConsumed`. See
[`ecosystem/naalp-mcp-bridge/examples/isolation_demo.py`](https://github.com/bubblefish-tech/naalp_protocol/blob/main/ecosystem/naalp-mcp-bridge/examples/isolation_demo.py)
for the full runnable demonstration of all four properties.

## Failure modes

| Error kind | When |
|---|---|
| `MalformedAnnotation` | An annotation set maps outside the closed effect lattice |
| `EffectUnderDeclared` | The wrapping signer's declared effect is below the annotation-mapped effect |
| `EffectOutsideLattice` | The declared effect is not in `{0..3}` |
| `ToolCallMalformed` | The body is not `{1: tool, 2: args, 3: annotations}`, or not a tier-1 Bridge `McpToolCall` |
| `ApprovalRequired` | The approval does not bind the exact call, or under-grants the enforced effect |
| `AlreadyConsumed` | The approval has already been spent |
| `ForeignToolNotJSON` / `ForeignBodyNotJSON` (bridge-only) | The carried octets do not decode as UTF-8 JSON |
| `ToolNameMismatch` (bridge-only) | A `tools/call` request names a different tool than the supplied definition |

Every check is fail-closed: a failing object is rejected whole, returns its named error, and causes
no state change. A baseline-only endpoint (validating only the frozen kinds) correctly rejects an
`McpToolCall` as `UnknownKind`.

## What this mapping does not decide

- **MCP transport and server discovery.** How an MCP server is found or connected to is out of
  scope; this profile governs a *carried* tool call, not the MCP session.
- **A general foreign-annotation vocabulary.** Only the four documented MCP behavioural hints are
  mapped here; another protocol's own hint vocabulary would need its own binding profile under the
  same carriage-not-adoption discipline.
- **Non-Go/Rust SDK ports.** The profile is graded on the Go and Rust two-implementation parity path
  against a non-circular oracle; the Python bridge above is an ecosystem package built on the Python
  SDK, and porting the profile itself to the other reference SDKs is tracked in the parity ledger.

See also: [the object model](../spec/object-model.md), [effects and safety](../spec/object-model.md),
and the [A2A mapping](a2a.md) for the sibling agent-coordination profile.
