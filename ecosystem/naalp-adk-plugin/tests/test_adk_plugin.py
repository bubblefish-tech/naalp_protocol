# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Mutation-surviving tests for K1, the N-AALP Governance Kit's reference ADK adapter
(ecosystem/naalp-adk-plugin/naalp_adk_plugin/adk_plugin.py). Every assertion here would fail if
its target function were replaced by a constant return (anti-fake rule A5).

Non-circularity (F3): every recorded signed object is independently decoded and verified
through `naalp.envelope.verify` / `naalp.ez.verify` -- the same real, already-graded Part-1
core -- never merely re-read through naalp_adk_plugin's own bookkeeping. The one exception is
`binding._extract_payload`, reused from K0 (a DIFFERENT, already-graded module) purely to pull
the opaque payload bytes back out of a verified body for comparison; K1's OWN new code (payload
construction, chain-recorder bookkeeping, gating decision) is never used to validate itself.

`before_tool_callback`/`after_tool_callback`/`on_event_callback` are real ADK `BasePlugin`
coroutine methods; they are driven here with `asyncio.run(...)` (no `pytest-asyncio` dependency
needed for three call sites). `tool`/`event` are REAL `google.adk` objects (`BaseTool`, `Event`)
constructed directly, confirmed instantiable with minimal required fields this session.
`tool_context`/`invocation_context` are minimal stand-ins carrying only the ONE attribute this
module's code actually reads (`.invocation_id`, confirmed against the real, currently-installed
`google-adk==2.8.0` `ReadonlyContext.invocation_id` property) -- constructing ADK's real `Context`
requires a full `InvocationContext`/`Session`/`RunConfig` graph that is ADK's own test surface,
not this module's.

Run (from the repo root, PYTHONDONTWRITEBYTECODE=1, using the real Python interpreter -- not
the Microsoft Store `python`/`python3` execution-alias stubs, which hang):
    PYTHONDONTWRITEBYTECODE=1 python -m pytest ecosystem/naalp-adk-plugin/tests/test_adk_plugin.py -v
"""
import asyncio
import io
import json
import os
import sys

import pytest

# ecosystem/naalp-adk-plugin's package dir name has a hyphen and so cannot itself be part of a
# dotted import path; insert its own directory (the parent of this tests/ dir) onto sys.path so
# `naalp_adk_plugin` (the underscore package, sibling of tests/) is importable regardless of the
# invocation cwd -- same problem naalp-a2a-bridge's tests/_paths.py exists to solve.
sys.path.insert(0, os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")))

from naalp_adk_plugin.adk_plugin import (
    ChainRecorder, NaalpGovernancePlugin, CHANNEL_BRIDGE, KIND_CARRIAGE, canonical_json_bytes,
)
from naalp_kit import binding
from naalp import cose, ez, policy

from google.adk.tools.base_tool import BaseTool
from google.adk.events.event import Event


def _seed(b):
    return bytes([b]) * 32


def _signer(b=0x21):
    return ez.Signer(_seed(b), alg=cose.ALG_MLDSA65, profile=cose.PROFILE_PUBLIC)


class _StubToolContext:
    """Minimal stand-in exposing ONLY `.invocation_id` -- see module docstring."""

    def __init__(self, invocation_id):
        self.invocation_id = invocation_id


def _decode_and_verify(signer, signed_bytes):
    """Independently decode+verify a signed object through the real Part-1 core (F3), NOT
    through naalp_adk_plugin's own code path."""
    return ez.verify(signer.public_key, signed_bytes)


def _tool(name="write_file"):
    return BaseTool(name=name, description="test tool: " + name)


# --- canonical_json_bytes ------------------------------------------------------------------

def test_canonical_json_bytes_is_deterministic_regardless_of_key_order():
    a = canonical_json_bytes({"b": 1, "a": 2})
    b = canonical_json_bytes({"a": 2, "b": 1})
    assert a == b == b'{"a":2,"b":1}'


def test_canonical_json_bytes_returns_bytes():
    assert isinstance(canonical_json_bytes({"x": 1}), bytes)


# --- ChainRecorder ---------------------------------------------------------------------------

def test_chain_recorder_append_writes_length_prefixed_record():
    stream = io.BytesIO()
    rec = ChainRecorder(stream)
    rec.append("sess-1", b"hello", b"\x01" * 50)
    data = stream.getvalue()
    assert data[:4] == (5).to_bytes(4, "big")
    assert data[4:9] == b"hello"
    assert len(data) == 9  # exactly one length-prefixed record, nothing more


def test_chain_recorder_last_cause_empty_before_any_append():
    rec = ChainRecorder(io.BytesIO())
    assert rec.last_cause("sess-1") == ()


def test_chain_recorder_last_cause_tracks_most_recent_append_per_session():
    rec = ChainRecorder(io.BytesIO())
    rec.append("sess-1", b"a", b"\x01" * 50)
    assert rec.last_cause("sess-1") == (b"\x01" * 50,)
    rec.append("sess-1", b"b", b"\x02" * 50)
    assert rec.last_cause("sess-1") == (b"\x02" * 50,)  # replaced, not accumulated
    assert rec.last_cause("sess-2") == ()  # a different session is untouched


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
    records = ChainRecorder.read_all(stream)
    assert records == [b"first", b"second-longer"]


def test_chain_recorder_read_all_empty_stream_is_empty_list():
    assert ChainRecorder.read_all(io.BytesIO()) == []


def test_chain_recorder_read_all_raises_on_truncated_length_prefix():
    stream = io.BytesIO(b"\x00\x00")  # 2 bytes, not a full 4-byte length prefix
    with pytest.raises(ValueError):
        ChainRecorder.read_all(stream)


def test_chain_recorder_read_all_raises_on_truncated_record_body():
    stream = io.BytesIO((10).to_bytes(4, "big") + b"short")  # claims 10 bytes, has 5
    with pytest.raises(ValueError):
        ChainRecorder.read_all(stream)


# --- NaalpGovernancePlugin construction -------------------------------------------------------

def test_plugin_is_a_real_adk_base_plugin_subclass():
    from google.adk.plugins.base_plugin import BasePlugin
    plugin = NaalpGovernancePlugin(_signer(), ChainRecorder(io.BytesIO()))
    assert isinstance(plugin, BasePlugin)
    assert plugin.name == "naalp_governance"


def test_plugin_construction_requires_grant_when_gating_enabled():
    with pytest.raises(ValueError):
        NaalpGovernancePlugin(_signer(), ChainRecorder(io.BytesIO()), gating=True)


def test_plugin_construction_gating_with_grant_succeeds():
    grant = policy.Grant(principal="whoever", max_effect=policy.DESTRUCTIVE)
    plugin = NaalpGovernancePlugin(
        _signer(), ChainRecorder(io.BytesIO()), gating=True, grant=grant,
    )
    assert plugin._gating is True


# --- before_tool_callback: observe-only mode --------------------------------------------------

def test_before_tool_callback_observe_only_returns_none():
    signer = _signer()
    plugin = NaalpGovernancePlugin(signer, ChainRecorder(io.BytesIO()))
    result = asyncio.run(plugin.before_tool_callback(
        tool=_tool(), tool_args={"path": "/tmp/x"}, tool_context=_StubToolContext("inv-1"),
    ))
    assert result is None  # observe-only never modifies ADK's tool-execution flow


def test_before_tool_callback_signs_a_real_verifiable_object_on_the_bridge_carriage_kind():
    signer = _signer()
    stream = io.BytesIO()
    plugin = NaalpGovernancePlugin(signer, ChainRecorder(stream))
    asyncio.run(plugin.before_tool_callback(
        tool=_tool("read_db"), tool_args={"q": "select 1"},
        tool_context=_StubToolContext("inv-2"),
    ))
    stream.seek(0)
    [record] = ChainRecorder.read_all(stream)
    obj = _decode_and_verify(signer, record)  # F3: real, independent core verify
    assert obj.channel == CHANNEL_BRIDGE
    assert obj.kind == KIND_CARRIAGE
    assert obj.signer == signer.signer_id.encode("utf-8")


def test_before_tool_callback_fail_closed_effect_default_is_destructive_when_unclassified():
    signer = _signer()
    stream = io.BytesIO()
    plugin = NaalpGovernancePlugin(signer, ChainRecorder(stream))  # no effect_classifier
    asyncio.run(plugin.before_tool_callback(
        tool=_tool(), tool_args={}, tool_context=_StubToolContext("inv-3"),
    ))
    stream.seek(0)
    [record] = ChainRecorder.read_all(stream)
    obj = _decode_and_verify(signer, record)
    assert obj.effect == policy.DESTRUCTIVE  # K0-3's fail-closed default, never a guessed benign


def test_before_tool_callback_honors_a_caller_supplied_effect_classifier():
    signer = _signer()
    stream = io.BytesIO()
    plugin = NaalpGovernancePlugin(
        signer, ChainRecorder(stream),
        effect_classifier=lambda name, args: policy.READ_ONLY,
    )
    asyncio.run(plugin.before_tool_callback(
        tool=_tool("list_files"), tool_args={}, tool_context=_StubToolContext("inv-4"),
    ))
    stream.seek(0)
    [record] = ChainRecorder.read_all(stream)
    obj = _decode_and_verify(signer, record)
    assert obj.effect == policy.READ_ONLY


def test_before_tool_callback_payload_carries_the_real_tool_name_and_args_opaquely():
    signer = _signer()
    stream = io.BytesIO()
    plugin = NaalpGovernancePlugin(signer, ChainRecorder(stream))
    asyncio.run(plugin.before_tool_callback(
        tool=_tool("delete_row"), tool_args={"id": 42},
        tool_context=_StubToolContext("inv-5"),
    ))
    stream.seek(0)
    [record] = ChainRecorder.read_all(stream)
    obj = _decode_and_verify(signer, record)
    recovered = binding._extract_payload(obj.body)  # reuse K0's own graded extractor
    assert recovered == canonical_json_bytes({"tool": "delete_row", "args": {"id": 42}})


# --- before_tool_callback: gating mode ---------------------------------------------------------

def test_gating_denies_when_declared_effect_exceeds_grant_ceiling():
    signer = _signer()
    grant = policy.Grant(principal=signer.signer_id, max_effect=policy.READ_ONLY)
    plugin = NaalpGovernancePlugin(
        signer, ChainRecorder(io.BytesIO()), gating=True, grant=grant,
        # no classifier -> fail-closed DESTRUCTIVE, which exceeds the READ_ONLY ceiling
    )
    result = asyncio.run(plugin.before_tool_callback(
        tool=_tool("rm_rf"), tool_args={}, tool_context=_StubToolContext("inv-6"),
    ))
    assert result is not None
    assert result["naalp_governance_denied"] is True
    assert result["kind"] == "EffectNotAuthorized"


def test_gating_still_records_the_denied_attempt():
    signer = _signer()
    grant = policy.Grant(principal=signer.signer_id, max_effect=policy.READ_ONLY)
    stream = io.BytesIO()
    plugin = NaalpGovernancePlugin(
        signer, ChainRecorder(stream), gating=True, grant=grant,
    )
    asyncio.run(plugin.before_tool_callback(
        tool=_tool("rm_rf"), tool_args={}, tool_context=_StubToolContext("inv-7"),
    ))
    stream.seek(0)
    records = ChainRecorder.read_all(stream)
    assert len(records) == 1  # a denial is still a provenance-worthy captured action


def test_gating_allows_when_declared_effect_is_covered_by_grant():
    signer = _signer()
    grant = policy.Grant(principal=signer.signer_id, max_effect=policy.NON_IDEMPOTENT_WRITE)
    plugin = NaalpGovernancePlugin(
        signer, ChainRecorder(io.BytesIO()), gating=True, grant=grant,
        effect_classifier=lambda name, args: policy.IDEMPOTENT_WRITE,
    )
    result = asyncio.run(plugin.before_tool_callback(
        tool=_tool("upsert_row"), tool_args={}, tool_context=_StubToolContext("inv-8"),
    ))
    assert result is None  # authorized -> proceeds unmodified


def test_gating_denies_when_grant_principal_does_not_match_the_signer():
    signer = _signer()
    grant = policy.Grant(principal="a-different-signer-id", max_effect=policy.DESTRUCTIVE)
    plugin = NaalpGovernancePlugin(
        signer, ChainRecorder(io.BytesIO()), gating=True, grant=grant,
    )
    result = asyncio.run(plugin.before_tool_callback(
        tool=_tool(), tool_args={}, tool_context=_StubToolContext("inv-9"),
    ))
    assert result["naalp_governance_denied"] is True


# --- after_tool_callback: never gates -----------------------------------------------------------

def test_after_tool_callback_returns_none_and_never_gates_even_with_an_uncovered_effect():
    signer = _signer()
    grant = policy.Grant(principal=signer.signer_id, max_effect=policy.READ_ONLY)
    stream = io.BytesIO()
    plugin = NaalpGovernancePlugin(
        signer, ChainRecorder(stream), gating=True, grant=grant,
    )
    result = asyncio.run(plugin.after_tool_callback(
        tool=_tool(), tool_args={}, tool_context=_StubToolContext("inv-10"),
        result={"status": "ok"},
    ))
    assert result is None  # K1-4: after_tool_callback records only, it never gates
    stream.seek(0)
    assert len(ChainRecorder.read_all(stream)) == 1


def test_after_tool_callback_payload_includes_the_result():
    signer = _signer()
    stream = io.BytesIO()
    plugin = NaalpGovernancePlugin(signer, ChainRecorder(stream))
    asyncio.run(plugin.after_tool_callback(
        tool=_tool("read_db"), tool_args={"q": "select 1"},
        tool_context=_StubToolContext("inv-11"), result={"rows": [1, 2, 3]},
    ))
    stream.seek(0)
    [record] = ChainRecorder.read_all(stream)
    obj = _decode_and_verify(signer, record)
    recovered = json.loads(binding._extract_payload(obj.body))
    assert recovered == {"tool": "read_db", "args": {"q": "select 1"}, "result": {"rows": [1, 2, 3]}}


# --- on_event_callback ---------------------------------------------------------------------------

def test_on_event_callback_returns_none_and_carries_the_real_event_model_dump_json():
    signer = _signer()
    stream = io.BytesIO()
    plugin = NaalpGovernancePlugin(signer, ChainRecorder(stream))
    event = Event(author="test-agent", invocation_id="inv-12")
    result = asyncio.run(plugin.on_event_callback(
        invocation_context=_StubToolContext("inv-12"), event=event,
    ))
    assert result is None
    stream.seek(0)
    [record] = ChainRecorder.read_all(stream)
    obj = _decode_and_verify(signer, record)
    recovered = binding._extract_payload(obj.body)
    assert recovered == event.model_dump_json().encode("utf-8")


# --- causal chaining across calls in the same ADK session (K1 chain recorder) -------------------

def test_causes_link_two_captured_actions_in_the_same_session():
    signer = _signer()
    stream = io.BytesIO()
    recorder = ChainRecorder(stream)
    plugin = NaalpGovernancePlugin(signer, recorder)
    ctx = _StubToolContext("inv-chain")
    asyncio.run(plugin.before_tool_callback(tool=_tool("a"), tool_args={}, tool_context=ctx))
    asyncio.run(plugin.after_tool_callback(
        tool=_tool("a"), tool_args={}, tool_context=ctx, result={},
    ))
    stream.seek(0)
    first_bytes, second_bytes = ChainRecorder.read_all(stream)
    first = _decode_and_verify(signer, first_bytes)
    second = _decode_and_verify(signer, second_bytes)
    assert first.causes == []                 # the first captured action in a fresh session
    assert second.causes == [first.id]         # the second one chains to the first's REAL id


def test_causes_do_not_leak_across_different_sessions():
    signer = _signer()
    stream = io.BytesIO()
    recorder = ChainRecorder(stream)
    plugin = NaalpGovernancePlugin(signer, recorder)
    asyncio.run(plugin.before_tool_callback(
        tool=_tool("a"), tool_args={}, tool_context=_StubToolContext("sess-A"),
    ))
    asyncio.run(plugin.before_tool_callback(
        tool=_tool("b"), tool_args={}, tool_context=_StubToolContext("sess-B"),
    ))
    stream.seek(0)
    _first_bytes, second_bytes = ChainRecorder.read_all(stream)
    second = _decode_and_verify(signer, second_bytes)
    assert second.causes == []  # a NEW session's first action never chains to another session
