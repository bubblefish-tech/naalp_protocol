# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""The N-AALP MCP tool-integration bridge (Part-2 E2.1, ecosystem requirement R4.1/4.2/4.3;
design.md Sec.19 "The NAALP-MCP binding profile" + Sec.13 "Foreign carriage by class").

A developer building against the Model Context Protocol already holds two MCP-native JSON
objects: a tool DEFINITION (as returned by `tools/list`, carrying the tool's behavioural
`annotations`) and a JSON-RPC 2.0 `tools/call` REQUEST (`{"jsonrpc":"2.0","id":...,
"method":"tools/call","params":{"name":...,"arguments":{...}}}`). This module is the bridge
between that MCP-native shape and the real N-AALP NAALP-MCP wire profile: it maps a foreign
tool-call into a signed N-AALP object, and on the receiving side verifies that object and
RECOVERS the original foreign octets byte-identical, so a developer never has to hand-build a
`naalp.mcp.Annotations` object or hand-assemble the wrapper envelope themselves.

Every cryptographic and wire-construction operation -- deterministic CBOR encoding, ML-DSA
sign/verify, the annotation->effect mapping, the more-severe resolution, the call-binding
content id, the approval + single-use consume ledger -- is delegated to the real Part-1
`naalp.mcp` / `naalp.envelope` / `naalp.approval` primitives (design.md Sec.19); nothing here
re-derives or re-approximates any of it. What this module adds, and what naalp.mcp does NOT
provide, is the developer-facing boundary: parsing the MCP JSON shapes into the `annotations`
object the profile expects, capturing the foreign `tool`/`args` octets ONCE at that boundary so
they are carried octet-for-octet from then on (never re-serialized -- design.md Sec.19.1 /
R-14.4), and recovering both the raw foreign bytes AND developer-usable Python objects on the
receiving side, with the profile's enforced effect / mismatch / call-binding content id exposed
directly on the result.

Two ingestion paths are offered:

  - `carry_tool_call` / `receive_tool_call` operate on RAW FOREIGN OCTETS (the literal bytes a
    tool-definition document and a call's arguments document had on the wire) -- the strictest,
    most literal form of "octet-for-octet"; nothing is parsed except to read the `annotations`
    the profile's mapping needs, and the exact input bytes are what gets carried and recovered.
  - `carry_tool_call_from_objects` / `bridged_call_request` are the convenience layer for a
    caller holding already-PARSED MCP objects (Python dicts from `json.loads`): each object is
    serialized to canonical JSON bytes EXACTLY ONCE, at the ingest boundary, and those bytes are
    what is carried from then on -- the same octet-for-octet guarantee, one step earlier.
"""
from . import _bootstrap  # noqa: F401  (repo-relative sys.path setup; must run before `naalp` imports)

import json
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Sequence

from naalp import cose, mcp

# The MCP ToolAnnotations JSON field names (modelcontextprotocol.io ToolAnnotations interface,
# the same names design.md Sec.19.2 / tools/mcp_oracle.py's MCP_ANNOTATION_CONTRACT quote) ->
# the snake_case attribute naalp.mcp.Annotations expects. A hint's ABSENCE from the foreign JSON
# is distinct from a present `false` (Sec.19.2): this table is walked by `in` membership, never
# by `.get(..., default)`, so an absent key leaves the corresponding Annotations attribute None.
_MCP_HINT_ATTR = {
    "readOnlyHint": "read_only",
    "destructiveHint": "destructive",
    "idempotentHint": "idempotent",
    "openWorldHint": "open_world",
}


class BridgeError(mcp.McpError):
    """A named, fail-closed bridge-layer error; .kind is the stable error kind. Every kind with a
    Part-1 analogue (MalformedAnnotation, EffectUnderDeclared, EffectOutsideLattice,
    ToolCallMalformed, ApprovalRequired, AlreadyConsumed, BadSignature, ...) is raised directly
    by naalp.mcp / naalp.envelope / naalp.approval and never re-wrapped here. This subclass
    exists only for outcomes with NO Part-1 analogue -- Part-1 has no notion of a foreign JSON
    tool-call shape at all, so decoding it is entirely this bridge's own responsibility:

      ForeignToolNotJSON    -- the tool-definition octets do not decode as a UTF-8 JSON object
      ForeignBodyNotJSON    -- the call-arguments octets do not decode as UTF-8 JSON
      ForeignCallMalformed  -- a JSON-RPC tools/call request is missing params/name
      ToolNameMismatch      -- the call names a different tool than the supplied definition
    """


# ---- foreign-native (MCP JSON) <-> naalp.mcp.Annotations --------------------------------------

def annotations_from_mcp_dict(mcp_annotations: Optional[Mapping[str, Any]]) -> "mcp.Annotations":
    """Transcribe an MCP tool definition's `annotations` object (or None/absent) into the
    naalp.mcp.Annotations the profile's mapping operates on. Each hint is copied ONLY when the
    JSON key is PRESENT (an absent hint stays None, distinct on the wire from a present `false`
    -- design.md Sec.19.2); a present hint whose value is not a JSON boolean is rejected
    (MalformedAnnotation has a Part-1 analogue for the annotation MAP itself, but "this MCP JSON
    field is not a boolean" is a bridge-only decode failure with no such analogue)."""
    if mcp_annotations is None:
        return mcp.Annotations()
    if not isinstance(mcp_annotations, Mapping):
        raise BridgeError("ForeignToolNotJSON", "MCP annotations is not a JSON object")
    kwargs = {}
    for json_key, attr in _MCP_HINT_ATTR.items():
        if json_key in mcp_annotations:
            v = mcp_annotations[json_key]
            if not isinstance(v, bool):
                raise BridgeError("ForeignToolNotJSON", "%s is not a JSON boolean" % json_key)
            kwargs[attr] = v
    return mcp.Annotations(**kwargs)


def _mldsa_param_name(alg: int) -> str:
    if alg == cose.ALG_MLDSA87:
        return "ML-DSA-87"
    if alg == cose.ALG_MLDSA65:
        return "ML-DSA-65"
    raise BridgeError("ForeignToolNotJSON", "alg %d is not a registered ML-DSA algorithm" % alg)


def _decode_json(raw: bytes, what: str, error_kind: str):
    try:
        return json.loads(bytes(raw).decode("utf-8"))
    except UnicodeDecodeError as e:
        raise BridgeError(error_kind, "%s is not valid UTF-8: %s" % (what, e))
    except json.JSONDecodeError as e:
        raise BridgeError(error_kind, "%s is not valid JSON: %s" % (what, e))


def _parse_tool_definition(tool_bytes: bytes) -> dict:
    obj = _decode_json(tool_bytes, "tool definition", "ForeignToolNotJSON")
    if not isinstance(obj, dict):
        raise BridgeError("ForeignToolNotJSON", "tool definition JSON is not an object")
    return obj


def canonical_json_bytes(obj: Any) -> bytes:
    """The ONE deterministic serialization this bridge ever applies to a foreign-native JSON
    object: sorted keys, no incidental whitespace, UTF-8, not ASCII-escaped. Applied exactly
    ONCE, at the `carry_tool_call_from_objects` ingest boundary -- the resulting bytes are then
    carried through N-AALP octet-for-octet (design.md Sec.19.1 / R-14.4) and are never
    re-derived from the Python object a second time anywhere downstream. Exposed publicly so a
    caller can reproduce (and thereby independently verify) the exact bytes this bridge carries."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# ---- carry: foreign octets -> a signed N-AALP McpToolCall object ------------------------------

@dataclass(frozen=True)
class CarriedCall:
    """The result of carrying one foreign MCP tool call into a signed N-AALP object."""

    signed_object: bytes            # the signed McpToolCall wire object (envelope §2, COSE_Sign1)
    tool_bytes: bytes               # the exact foreign tool-definition octets carried (unaltered input)
    args_bytes: bytes               # the exact foreign call-argument octets carried (unaltered input)
    annotation_mapped_effect: int   # the effect the tool's OWN annotations mapped to (§19.3)
    declared_effect: int            # the wrapping signer's declared envelope effect (field 7)
    call_binding_content_id: bytes  # the (tool_id, args_id) binding content id an approval binds (§19.5)


def carry_tool_call(tool_bytes: bytes, args_bytes: bytes, *, signer_seed: bytes,
                     alg: int = cose.ALG_MLDSA65, created: int, causes: Sequence[bytes] = (),
                     profile: int = cose.PROFILE_PUBLIC, declared_effect: Optional[int] = None
                     ) -> CarriedCall:
    """Carry a foreign MCP tool call -- the RAW tool-definition octets and the RAW call-argument
    octets, exactly as received off the wire -- into a signed N-AALP McpToolCall object.

    `tool_bytes` MUST decode as a UTF-8 JSON object; its `annotations` field (if present) is
    read ONLY to build the naalp.mcp.Annotations the profile's published mapping operates on
    (§19.3) -- `tool_bytes` itself is never rewritten and is what gets carried (§19.1). `args_bytes`
    is carried unexamined (the profile does not need to parse the call arguments at all).

    `declared_effect` is the wrapping signer's own declared effect (envelope field 7); when
    omitted it defaults to the tool's own annotation-mapped effect (the honest case: a signer
    that simply attests what its tool's annotations already say). Passing an explicit value lets
    a caller build the escalation / under-declaration scenarios §19.4 defines -- signing succeeds
    either way (design.md: "under-declaration is not rejected here"); `receive_tool_call` is
    where an under-declared object is rejected (`EffectUnderDeclared`), the enforcement point.

    Raises BridgeError(ForeignToolNotJSON) if `tool_bytes` does not decode as a JSON object, or
    mcp.McpError(EffectOutsideLattice) if `declared_effect` is outside {0..3}."""
    tool_bytes = bytes(tool_bytes)
    args_bytes = bytes(args_bytes)
    tool_def = _parse_tool_definition(tool_bytes)
    annotations = annotations_from_mcp_dict(tool_def.get("annotations"))
    mapped = mcp.map_annotations_to_effect(annotations)
    if declared_effect is None:
        declared_effect = mapped

    tc = mcp.ToolCall(tool_bytes, args_bytes, annotations)
    signer_pk = cose.mldsa_keygen(_mldsa_param_name(alg), bytes(signer_seed))
    obj = tc.envelope_object(signer_pk, created, profile, declared_effect, causes)
    signed = mcp.sign_tool_call(obj, alg, bytes(signer_seed))

    return CarriedCall(
        signed_object=signed, tool_bytes=tool_bytes, args_bytes=args_bytes,
        annotation_mapped_effect=mapped, declared_effect=declared_effect,
        call_binding_content_id=tc.call_binding().content_id(),
    )


def carry_tool_call_from_objects(tool_definition: Mapping[str, Any], call_request: Mapping[str, Any],
                                  *, signer_seed: bytes, alg: int = cose.ALG_MLDSA65, created: int,
                                  causes: Sequence[bytes] = (), profile: int = cose.PROFILE_PUBLIC,
                                  declared_effect: Optional[int] = None) -> CarriedCall:
    """Convenience for a caller holding already-PARSED MCP objects rather than raw wire octets:
    `tool_definition` is an MCP Tool object (`{"name":..., "annotations": {...}, ...}`, as
    returned by `tools/list`) and `call_request` is a JSON-RPC 2.0 `tools/call` request
    (`{"jsonrpc":"2.0","id":...,"method":"tools/call","params":{"name":...,"arguments":{...}}}`).

    Validates the call names the SAME tool the definition describes (a bridge-only sanity check
    with no Part-1 analogue -- Part-1's naalp.mcp has no notion of a tool "name" at all, only
    opaque tool/args bytes), raising BridgeError(ToolNameMismatch) on a mismatch. Serializes each
    object to canonical JSON bytes EXACTLY ONCE (`canonical_json_bytes`) and hands off to
    `carry_tool_call` -- from that point on the same octet-for-octet carriage guarantee applies."""
    if not isinstance(tool_definition, Mapping) or "name" not in tool_definition:
        raise BridgeError("ForeignToolNotJSON", "tool definition must be a JSON object with a name")
    if not isinstance(call_request, Mapping) or not isinstance(call_request.get("params"), Mapping):
        raise BridgeError("ForeignCallMalformed", "call request must carry a JSON-RPC params object")
    params = call_request["params"]
    if "name" not in params:
        raise BridgeError("ForeignCallMalformed", "call request params must carry a tool name")
    if params["name"] != tool_definition["name"]:
        raise BridgeError(
            "ToolNameMismatch",
            "call request names %r but the supplied tool definition is %r"
            % (params["name"], tool_definition["name"]),
        )
    tool_bytes = canonical_json_bytes(dict(tool_definition))
    args_bytes = canonical_json_bytes(params.get("arguments", {}))
    return carry_tool_call(tool_bytes, args_bytes, signer_seed=signer_seed, alg=alg, created=created,
                            causes=causes, profile=profile, declared_effect=declared_effect)


# ---- receive: verify a signed N-AALP McpToolCall object, recover the foreign call -------------

@dataclass(frozen=True)
class BridgedCall:
    """The result of verifying and recovering one carried MCP tool call. `tool_bytes` /
    `args_bytes` are the RECOVERED foreign octets, proven byte-identical to what was originally
    carried (they are read straight out of the verified naalp.mcp.ToolCall body -- never
    re-serialized -- design.md Sec.19.1 / R-14.4). `tool_definition` / `arguments` are the same
    bytes additionally parsed back into Python objects, for developer convenience.

    `enforced_effect` is the C5-authorization-grade effect (the more-severe resolution of the
    tool's own annotations against the wrapping signer's declared effect -- §19.4); `mismatch` is
    True iff the two disagreed (attributable to the wrapping signer's key)."""

    signer: bytes
    content_id: bytes
    tool_bytes: bytes
    args_bytes: bytes
    tool_definition: dict
    arguments: Any
    annotation_mapped_effect: int
    declared_effect: int
    enforced_effect: int
    mismatch: bool
    call_binding_content_id: bytes
    resolved: "mcp.Resolved"   # the underlying Part-1 result, for authorize() / direct inspection

    def authorize(self, appr, approver_alg, approver_pubkey, appr_sig, by, now, ledger):
        """Enforce the profile's per-call approval gate for THIS resolved call, delegating
        entirely to the real Part-1 primitive (naalp.mcp.authorize_call): the approval MUST bind
        this exact call's binding content id (tool_id + args_id -- a wrong-tool or wrong-args
        approval is rejected `ApprovalRequired`, fail-closed, with no ledger append), its granted
        effect must cover `enforced_effect`, and it is consumed single-use. Returns None on
        authorization; raises the named naalp.mcp.McpError / naalp.approval.ApprovalError
        otherwise."""
        return mcp.authorize_call(self.resolved, appr, approver_alg, approver_pubkey, appr_sig, by, now, ledger)


def receive_tool_call(signed_object: bytes, profile: int, alg: int, pubkey: bytes) -> BridgedCall:
    """Verify a signed N-AALP McpToolCall object end-to-end (real ML-DSA signature verification,
    content-id recomputation, kind/tier/channel dispatch, the annotation->effect mapping
    recomputed from the CARRIED annotations, and the more-severe resolution -- all delegated to
    naalp.mcp.verify_tool_call), then RECOVER the exact foreign octets that were carried and
    parse them back into developer-usable Python objects.

    Raises the named naalp.envelope.EnvelopeError / naalp.mcp.McpError on any verification
    failure (fail-closed, no partial result); raises BridgeError(ForeignToolNotJSON /
    ForeignBodyNotJSON) if the RECOVERED octets do not decode as UTF-8 JSON (only possible for an
    object this bridge did not itself produce, or one whose signer lied about carrying JSON --
    the signature and profile checks above have already passed by the time this can happen)."""
    resolved = mcp.verify_tool_call(profile, alg, pubkey, signed_object)
    tool_bytes = resolved.tool_call.tool
    args_bytes = resolved.tool_call.args
    tool_definition = _parse_tool_definition(tool_bytes)
    arguments = _decode_json(args_bytes, "call arguments", "ForeignBodyNotJSON")
    return BridgedCall(
        signer=resolved.signer, content_id=resolved.content_id,
        tool_bytes=tool_bytes, args_bytes=args_bytes,
        tool_definition=tool_definition, arguments=arguments,
        annotation_mapped_effect=resolved.annotation_mapped, declared_effect=resolved.declared,
        enforced_effect=resolved.enforced, mismatch=resolved.mismatch,
        call_binding_content_id=resolved.tool_call.call_binding().content_id(),
        resolved=resolved,
    )


def bridged_call_request(bridged: BridgedCall, *, rpc_id: Any = None) -> dict:
    """Reconstruct a JSON-RPC 2.0 `tools/call` request dict from a verified, recovered
    BridgedCall -- the mirror of `carry_tool_call_from_objects`, for a caller that wants the
    call back in the exact developer-facing shape it went in as, rather than raw octets."""
    return {
        "jsonrpc": "2.0",
        "id": rpc_id,
        "method": "tools/call",
        "params": {"name": bridged.tool_definition.get("name"), "arguments": bridged.arguments},
    }
