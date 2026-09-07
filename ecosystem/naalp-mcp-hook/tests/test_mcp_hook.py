# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Mutation-surviving tests for K3, the N-AALP Governance Kit's MCP framework-hook adapter
(ecosystem/naalp-mcp-hook/naalp_mcp_hook/mcp_hook.py). Every assertion here would fail if its
target function were replaced by a constant return (anti-fake rule A5).

Non-circularity (F3): every recorded signed object is independently decoded and verified through
`naalp.ez.verify` -- the same real, already-graded Part-1 core -- never merely re-read through
naalp_mcp_hook's own bookkeeping. `binding._extract_payload` is reused from K0 (a DIFFERENT,
already-graded module) purely to pull the opaque payload bytes back out of a verified body for
comparison; K3's OWN new code (payload construction, annotation content-id binding, chain-recorder
bookkeeping, gating decision) is never used to validate itself.

REAL MCP SDK OBJECTS throughout: a genuine `mcp.server.fastmcp.FastMCP` server (with real
`types.ToolAnnotations` on its tools) is run in-process, connected to a real
`NaalpGovernedClientSession` over real `anyio` memory-object streams
(`mcp.shared.memory.create_client_server_memory_streams`, the same in-process transport the MCP
SDK's own test suite uses) via a real `initialize()` handshake -- never a hand-built
`CallToolResult` or a mocked session.

THE LOAD-BEARING PROPERTY (K3-1): annotations stay OPAQUE. `test_effect_is_never_derived_from_
annotation_hints` and `test_payload_never_contains_raw_annotation_hint_text` are the two tests
that would fail if this module were changed to DECODE annotation hints (the way
`ecosystem/naalp-mcp-bridge` correctly does for its own, different job) -- see RED-EVIDENCE.md
for the recorded mutation proving it.

Run (from the repo root, PYTHONDONTWRITEBYTECODE=1, using the real Python interpreter -- not the
Microsoft Store `python`/`python3` execution-alias stubs, which hang):
    PYTHONDONTWRITEBYTECODE=1 python -m pytest ecosystem/naalp-mcp-hook/tests/test_mcp_hook.py -v
"""
import asyncio
import io
import os
import sys

import anyio
import pytest

# ecosystem/naalp-mcp-hook's package dir name has a hyphen and so cannot itself be part of a
# dotted import path; insert its own directory (the parent of this tests/ dir) onto sys.path so
# `naalp_mcp_hook` (the underscore package, sibling of tests/) is importable regardless of the
# invocation cwd -- same problem naalp-adk-plugin's tests/test_adk_plugin.py solves the same way.
sys.path.insert(0, os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")))

from naalp_mcp_hook.mcp_hook import (
    ChainRecorder, NaalpGovernedClientSession, EffectClassifier,
    CHANNEL_BRIDGE, KIND_CARRIAGE, canonical_json_bytes, annotations_content_id,
    record_server_tool_call,
)
from naalp_kit import binding
from naalp import cose, ez, policy

import mcp.shared.memory as mcp_memory
from mcp import types
from mcp.server.fastmcp import FastMCP


def _seed(b):
    return bytes([b]) * 32


def _signer(b=0x21):
    return ez.Signer(_seed(b), alg=cose.ALG_MLDSA65, profile=cose.PROFILE_PUBLIC)


def _decode_and_verify(signer, signed_bytes):
    """Independently decode+verify a signed object through the real Part-1 core (F3), NOT
    through naalp_mcp_hook's own code path."""
    return ez.verify(signer.public_key, signed_bytes)


async def _serve_and_run(server_setup, client_fn, **session_kwargs):
    """Run a real FastMCP server in-process, connect a real NaalpGovernedClientSession to it
    over real anyio memory streams, perform the real `initialize()` handshake, run `client_fn`
    against the live session, and return its result. `server_setup(server)` registers real
    tools (with real annotations) on a real FastMCP instance before the connection is made."""
    server = FastMCP("naalp-k3-test-server")
    server_setup(server)
    mcp_server = server._mcp_server
    async with mcp_memory.create_client_server_memory_streams() as (client_streams, server_streams):
        client_read, client_write = client_streams
        server_read, server_write = server_streams
        async with anyio.create_task_group() as tg:
            tg.start_soon(lambda: mcp_server.run(
                server_read, server_write, mcp_server.create_initialization_options(),
                raise_exceptions=True,
            ))
            async with NaalpGovernedClientSession(
                read_stream=client_read, write_stream=client_write, **session_kwargs,
            ) as session:
                await session.initialize()
                out = await client_fn(session)
            tg.cancel_scope.cancel()
    return out


def _run(coro):
    return asyncio.run(coro)


def _no_annotations_server(server):
    @server.tool()
    def read_only_tool() -> str:
        return "ok"


def _destructive_annotated_server(server, call_log=None):
    @server.tool(annotations=types.ToolAnnotations(destructiveHint=True, readOnlyHint=False))
    def delete_row(id: int) -> str:
        if call_log is not None:
            call_log.append(id)
        return "deleted %d" % id


def _two_differently_annotated_tools_server(server):
    @server.tool(annotations=types.ToolAnnotations(destructiveHint=True, readOnlyHint=False))
    def tool_marked_destructive() -> str:
        return "a"

    @server.tool(annotations=types.ToolAnnotations(destructiveHint=False, readOnlyHint=True))
    def tool_marked_read_only() -> str:
        return "b"


# --- canonical_json_bytes ------------------------------------------------------------------

def test_canonical_json_bytes_is_deterministic_regardless_of_key_order():
    a = canonical_json_bytes({"b": 1, "a": 2})
    b = canonical_json_bytes({"a": 2, "b": 1})
    assert a == b == b'{"a":2,"b":1}'


def test_canonical_json_bytes_returns_bytes():
    assert isinstance(canonical_json_bytes({"x": 1}), bytes)


# --- annotations_content_id: the K3-1 opacity binding primitive itself -----------------------

def test_annotations_content_id_is_none_when_no_annotations():
    assert annotations_content_id(None) is None


def test_annotations_content_id_is_50_bytes_with_the_real_multihash_prefix():
    cid = annotations_content_id(types.ToolAnnotations(destructiveHint=True))
    assert len(cid) == 50  # S-3: 2-byte multihash prefix + 48-byte SHA-384 digest, never 48 alone
    assert cid[:2] == b"\x20\x30"


def test_annotations_content_id_is_deterministic_for_the_same_annotations():
    a = annotations_content_id(types.ToolAnnotations(destructiveHint=True, readOnlyHint=False))
    b = annotations_content_id(types.ToolAnnotations(destructiveHint=True, readOnlyHint=False))
    assert a == b


def test_annotations_content_id_differs_for_different_annotations():
    a = annotations_content_id(types.ToolAnnotations(destructiveHint=True))
    b = annotations_content_id(types.ToolAnnotations(destructiveHint=False))
    assert a != b  # tamper-evident binding: different content -> different id


# --- ChainRecorder ---------------------------------------------------------------------------

def test_chain_recorder_append_writes_length_prefixed_record():
    stream = io.BytesIO()
    rec = ChainRecorder(stream)
    rec.append("sess-1", b"hello", b"\x01" * 50)
    data = stream.getvalue()
    assert data[:4] == (5).to_bytes(4, "big")
    assert data[4:9] == b"hello"
    assert len(data) == 9


def test_chain_recorder_last_cause_empty_before_any_append():
    rec = ChainRecorder(io.BytesIO())
    assert rec.last_cause("sess-1") == ()


def test_chain_recorder_last_cause_tracks_most_recent_append_per_session():
    rec = ChainRecorder(io.BytesIO())
    rec.append("sess-1", b"a", b"\x01" * 50)
    assert rec.last_cause("sess-1") == (b"\x01" * 50,)
    rec.append("sess-1", b"b", b"\x02" * 50)
    assert rec.last_cause("sess-1") == (b"\x02" * 50,)
    assert rec.last_cause("sess-2") == ()


def test_chain_recorder_append_rejects_non_bytes_signed_bytes():
    rec = ChainRecorder(io.BytesIO())
    with pytest.raises(TypeError):
        rec.append("sess-1", "not bytes", b"\x01" * 50)


def test_chain_recorder_append_rejects_empty_content_id():
    rec = ChainRecorder(io.BytesIO())
    with pytest.raises(TypeError):
        rec.append("sess-1", b"x", b"")


def test_chain_recorder_read_all_round_trips_records_in_order():
    stream = io.BytesIO()
    rec = ChainRecorder(stream)
    rec.append("s", b"first", b"\x01" * 50)
    rec.append("s", b"second-longer", b"\x02" * 50)
    stream.seek(0)
    assert ChainRecorder.read_all(stream) == [b"first", b"second-longer"]


def test_chain_recorder_read_all_raises_on_truncated_length_prefix():
    with pytest.raises(ValueError):
        ChainRecorder.read_all(io.BytesIO(b"\x00\x00"))


def test_chain_recorder_read_all_raises_on_truncated_record_body():
    with pytest.raises(ValueError):
        ChainRecorder.read_all(io.BytesIO((10).to_bytes(4, "big") + b"short"))


# --- NaalpGovernedClientSession construction ---------------------------------------------------

def test_session_is_a_real_mcp_client_session_subclass():
    from mcp import ClientSession
    assert issubclass(NaalpGovernedClientSession, ClientSession)


def test_session_construction_requires_grant_when_gating_enabled():
    async def _build():
        async with mcp_memory.create_client_server_memory_streams() as (cs, ss):
            with pytest.raises(ValueError):
                NaalpGovernedClientSession(
                    read_stream=cs[0], write_stream=cs[1], signer=_signer(), recorder=ChainRecorder(io.BytesIO()),
                    gating=True,
                )
    _run(_build())


# --- call_tool: observe-only mode, real signed+verified capture -------------------------------

def test_call_tool_observe_only_returns_the_real_unmodified_mcp_result():
    async def client(session):
        return await session.call_tool("read_only_tool", {})
    result = _run(_serve_and_run(
        _no_annotations_server, client, signer=_signer(), recorder=ChainRecorder(io.BytesIO()),
    ))
    assert result.isError is False
    assert result.content[0].text == "ok"


def test_call_tool_signs_a_real_verifiable_object_on_the_bridge_carriage_kind():
    signer = _signer()
    stream = io.BytesIO()

    async def client(session):
        await session.call_tool("read_only_tool", {})
    _run(_serve_and_run(_no_annotations_server, client, signer=signer, recorder=ChainRecorder(stream)))
    stream.seek(0)
    call_record, _result_record = ChainRecorder.read_all(stream)
    obj = _decode_and_verify(signer, call_record)  # F3: independent core verify
    assert obj.channel == CHANNEL_BRIDGE
    assert obj.kind == KIND_CARRIAGE
    assert obj.signer == signer.signer_id.encode("utf-8")


def test_call_tool_fail_closed_effect_default_is_destructive_when_unclassified():
    signer = _signer()
    stream = io.BytesIO()

    async def client(session):
        await session.call_tool("read_only_tool", {})
    _run(_serve_and_run(_no_annotations_server, client, signer=signer, recorder=ChainRecorder(stream)))
    stream.seek(0)
    call_record, _result_record = ChainRecorder.read_all(stream)
    obj = _decode_and_verify(signer, call_record)
    assert obj.effect == policy.DESTRUCTIVE  # K0-3's fail-closed default, never a guessed benign


def test_call_tool_honors_a_caller_supplied_effect_classifier():
    signer = _signer()
    stream = io.BytesIO()
    classifier: EffectClassifier = lambda name, args: policy.READ_ONLY

    async def client(session):
        await session.call_tool("read_only_tool", {})
    _run(_serve_and_run(
        _no_annotations_server, client, signer=signer, recorder=ChainRecorder(stream),
        effect_classifier=classifier,
    ))
    stream.seek(0)
    call_record, _result_record = ChainRecorder.read_all(stream)
    obj = _decode_and_verify(signer, call_record)
    assert obj.effect == policy.READ_ONLY


def test_call_tool_payload_carries_the_real_tool_name_and_args_opaquely():
    signer = _signer()
    stream = io.BytesIO()

    async def client(session):
        await session.call_tool("read_only_tool", {"n": 7})
    _run(_serve_and_run(_no_annotations_server, client, signer=signer, recorder=ChainRecorder(stream)))
    stream.seek(0)
    call_record, _result_record = ChainRecorder.read_all(stream)
    obj = _decode_and_verify(signer, call_record)
    recovered = binding._extract_payload(obj.body)  # reuse K0's own graded extractor
    assert recovered == canonical_json_bytes({
        "mcp_event": "tool_call", "tool": "read_only_tool", "arguments": {"n": 7},
        "annotations_content_id": None,
    })


# --- K3-1: annotation opacity -- the load-bearing property ------------------------------------

def test_call_tool_binds_a_known_tools_annotations_by_content_id_in_the_payload():
    signer = _signer()
    stream = io.BytesIO()

    async def client(session):
        await session.list_tools()  # populates the annotation content-id cache
        await session.call_tool("delete_row", {"id": 1})
    _run(_serve_and_run(_destructive_annotated_server, client, signer=signer, recorder=ChainRecorder(stream)))
    stream.seek(0)
    call_record, _result_record = ChainRecorder.read_all(stream)
    obj = _decode_and_verify(signer, call_record)
    recovered = binding._extract_payload(obj.body)
    expected_cid = annotations_content_id(types.ToolAnnotations(destructiveHint=True, readOnlyHint=False))
    assert recovered == canonical_json_bytes({
        "mcp_event": "tool_call", "tool": "delete_row", "arguments": {"id": 1},
        "annotations_content_id": expected_cid.hex(),
    })


def test_call_tool_without_list_tools_first_carries_no_annotation_binding():
    """The cache is populated only by list_tools(); a call_tool() with no prior list_tools() call
    on this session correctly has nothing to bind (never fabricated)."""
    signer = _signer()
    stream = io.BytesIO()

    async def client(session):
        await session.call_tool("delete_row", {"id": 1})  # no list_tools() call first
    _run(_serve_and_run(_destructive_annotated_server, client, signer=signer, recorder=ChainRecorder(stream)))
    stream.seek(0)
    call_record, _result_record = ChainRecorder.read_all(stream)
    obj = _decode_and_verify(signer, call_record)
    recovered = binding._extract_payload(obj.body)
    payload = canonical_json_bytes({
        "mcp_event": "tool_call", "tool": "delete_row", "arguments": {"id": 1},
        "annotations_content_id": None,
    })
    assert recovered == payload


def test_effect_is_never_derived_from_annotation_hints():
    """THE load-bearing K3-1 test. Two tools carry OPPOSITE annotation hints (one flagged
    destructive, one flagged read-only) via real MCP ToolAnnotations. With NO effect_classifier
    supplied, BOTH resolve to the SAME fail-closed DESTRUCTIVE default -- proving this module
    never reads a hint's boolean value to derive an effect (the naalp-mcp-bridge behavior K3-1
    forbids here). If this module were mutated to decode annotations the way naalp-mcp-bridge
    does, `tool_marked_read_only`'s captured effect would become READ_ONLY (0), not
    DESTRUCTIVE (3) -- see RED-EVIDENCE.md."""
    signer = _signer()
    stream = io.BytesIO()

    async def client(session):
        await session.list_tools()
        await session.call_tool("tool_marked_destructive", {})
        await session.call_tool("tool_marked_read_only", {})
    _run(_serve_and_run(
        _two_differently_annotated_tools_server, client, signer=signer, recorder=ChainRecorder(stream),
    ))
    stream.seek(0)
    records = ChainRecorder.read_all(stream)
    destructive_call = _decode_and_verify(signer, records[0])
    read_only_hinted_call = _decode_and_verify(signer, records[2])  # records[1] is the first result
    assert destructive_call.effect == policy.DESTRUCTIVE
    assert read_only_hinted_call.effect == policy.DESTRUCTIVE  # SAME, despite the opposite hint


def test_payload_never_contains_raw_annotation_hint_text():
    """A second, independent proof of opacity: the captured payload bytes never contain the raw
    MCP annotation field NAMES at all -- only an opaque hex content id -- because this module
    never re-serializes the annotations object into the payload, only its hash."""
    signer = _signer()
    stream = io.BytesIO()

    async def client(session):
        await session.list_tools()
        await session.call_tool("delete_row", {"id": 9})
    _run(_serve_and_run(_destructive_annotated_server, client, signer=signer, recorder=ChainRecorder(stream)))
    stream.seek(0)
    call_record, _result_record = ChainRecorder.read_all(stream)
    obj = _decode_and_verify(signer, call_record)
    recovered = binding._extract_payload(obj.body)
    for banned in (b"destructiveHint", b"readOnlyHint", b"idempotentHint", b"openWorldHint"):
        assert banned not in recovered


def test_effect_classifier_signature_never_receives_annotations():
    """Structural proof: the effect_classifier is called with exactly (tool_name, arguments) --
    never a third argument carrying annotations -- so a classifier CANNOT read hint values even
    if it wanted to."""
    signer = _signer()
    calls = []

    def classifier(name, args):
        calls.append((name, args))
        return None

    async def client(session):
        await session.list_tools()
        await session.call_tool("delete_row", {"id": 3})
    _run(_serve_and_run(
        _destructive_annotated_server, client, signer=signer, recorder=ChainRecorder(io.BytesIO()),
        effect_classifier=classifier,
    ))
    assert calls == [("delete_row", {"id": 3})]  # exactly 2 positional args, no annotations


# --- call_tool: gating mode ---------------------------------------------------------------------

def test_gating_denies_when_declared_effect_exceeds_grant_ceiling_and_never_sends_the_real_call():
    signer = _signer()
    grant = policy.Grant(principal=signer.signer_id, max_effect=policy.READ_ONLY)
    call_log = []

    async def client(session):
        return await session.call_tool("delete_row", {"id": 99})
    result = _run(_serve_and_run(
        lambda s: _destructive_annotated_server(s, call_log), client,
        signer=signer, recorder=ChainRecorder(io.BytesIO()), gating=True, grant=grant,
        # no classifier -> fail-closed DESTRUCTIVE, which exceeds the READ_ONLY ceiling
    ))
    assert result.isError is True
    assert "naalp_governance_denied" in result.content[0].text
    assert call_log == []  # the real tool handler NEVER ran -- denied before the request was sent


def test_gating_still_records_the_denied_attempt():
    signer = _signer()
    grant = policy.Grant(principal=signer.signer_id, max_effect=policy.READ_ONLY)
    stream = io.BytesIO()

    async def client(session):
        await session.call_tool("delete_row", {"id": 1})
    _run(_serve_and_run(
        _destructive_annotated_server, client, signer=signer, recorder=ChainRecorder(stream),
        gating=True, grant=grant,
    ))
    stream.seek(0)
    records = ChainRecorder.read_all(stream)
    assert len(records) == 1  # a denial is still a provenance-worthy captured action (no result record)


def test_gating_allows_when_declared_effect_is_covered_by_grant():
    signer = _signer()
    grant = policy.Grant(principal=signer.signer_id, max_effect=policy.NON_IDEMPOTENT_WRITE)
    call_log = []

    async def client(session):
        return await session.call_tool("delete_row", {"id": 5})
    result = _run(_serve_and_run(
        lambda s: _destructive_annotated_server(s, call_log), client,
        signer=signer, recorder=ChainRecorder(io.BytesIO()), gating=True, grant=grant,
        effect_classifier=lambda name, args: policy.IDEMPOTENT_WRITE,
    ))
    assert result.isError is False
    assert call_log == [5]  # authorized -> the real tool ran


def test_gating_denies_when_grant_principal_does_not_match_the_signer():
    signer = _signer()
    grant = policy.Grant(principal="a-different-signer-id", max_effect=policy.DESTRUCTIVE)

    async def client(session):
        return await session.call_tool("read_only_tool", {})
    result = _run(_serve_and_run(
        _no_annotations_server, client,
        signer=signer, recorder=ChainRecorder(io.BytesIO()), gating=True, grant=grant,
    ))
    assert result.isError is True


# --- causal chaining across calls in the same session (K3's chain recorder) --------------------

def test_call_and_result_chain_via_causes():
    signer = _signer()
    stream = io.BytesIO()

    async def client(session):
        await session.call_tool("read_only_tool", {})
    _run(_serve_and_run(_no_annotations_server, client, signer=signer, recorder=ChainRecorder(stream)))
    stream.seek(0)
    call_bytes, result_bytes = ChainRecorder.read_all(stream)
    call_obj = _decode_and_verify(signer, call_bytes)
    result_obj = _decode_and_verify(signer, result_bytes)
    assert call_obj.causes == []                    # first captured action in a fresh session
    assert result_obj.causes == [call_obj.id]        # the result chains to the call's REAL id


def test_causes_do_not_leak_across_different_session_keys():
    signer = _signer()
    stream = io.BytesIO()
    recorder = ChainRecorder(stream)

    async def client_a(session):
        await session.call_tool("read_only_tool", {})
    async def client_b(session):
        await session.call_tool("read_only_tool", {})
    _run(_serve_and_run(_no_annotations_server, client_a, signer=signer, recorder=recorder, session_key="sess-A"))
    _run(_serve_and_run(_no_annotations_server, client_b, signer=signer, recorder=recorder, session_key="sess-B"))
    stream.seek(0)
    records = ChainRecorder.read_all(stream)
    first_of_b = _decode_and_verify(signer, records[2])  # sess-A wrote 2 (call+result), sess-B's first is index 2
    assert first_of_b.causes == []  # a different session's first action never chains to another session


# --- optional, operator-controlled server-side recording (K3 item 6) --------------------------

def test_record_server_tool_call_returns_the_handlers_real_result_unchanged():
    signer = _signer()

    async def handler(name, args):
        return {"echo": args}

    wrapped = record_server_tool_call(signer, ChainRecorder(io.BytesIO()), handler)
    result = asyncio.run(wrapped("some_tool", {"x": 1}))
    assert result == {"echo": {"x": 1}}


def test_record_server_tool_call_signs_a_matchable_content_id_payload():
    """The server-side capture produces the SAME canonical payload shape as the client-side
    capture for the identical logical call -- 'matchable by content id' (K3 item 6)."""
    signer = _signer()
    stream = io.BytesIO()

    async def handler(name, args):
        return "ok"

    wrapped = record_server_tool_call(signer, ChainRecorder(stream), handler)
    asyncio.run(wrapped("read_only_tool", {"n": 7}))
    stream.seek(0)
    [record] = ChainRecorder.read_all(stream)
    obj = _decode_and_verify(signer, record)
    recovered = binding._extract_payload(obj.body)
    assert recovered == canonical_json_bytes({
        "mcp_event": "tool_call", "tool": "read_only_tool", "arguments": {"n": 7},
        "annotations_content_id": None,
    })
    # identical to the client-side payload shape for the same logical call:
    client_side_equivalent = canonical_json_bytes({
        "mcp_event": "tool_call", "tool": "read_only_tool", "arguments": {"n": 7},
        "annotations_content_id": None,
    })
    assert recovered == client_side_equivalent


def test_record_server_tool_call_never_alters_the_handlers_behavior_on_exception():
    signer = _signer()

    async def handler(name, args):
        raise RuntimeError("boom")

    wrapped = record_server_tool_call(signer, ChainRecorder(io.BytesIO()), handler)
    with pytest.raises(RuntimeError):
        asyncio.run(wrapped("some_tool", {}))
