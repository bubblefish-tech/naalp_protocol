# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
K4 -- the portability harness: drives each `naalp_governance_portability.corpus.GovernanceCase`
through K1 (ADK), K2 (A2A), and K3 (MCP) using each framework's OWN real stimulus shape, and
returns a `NormalizedOutcome` the test suite grades against the corpus's independent oracle.

Non-circularity (F3): every `NormalizedOutcome.verified` is obtained by INDEPENDENTLY re-decoding
the adapter's recorded signed bytes through `naalp.ez.verify` -- the same real, already-graded
Part-1 core every adapter itself calls, but invoked HERE by this module directly against the raw
bytes pulled out of a fresh `ChainRecorder` stream, never by trusting an adapter's own internal
`VerifiedAction`/bookkeeping. `adapter_denied`/`adapter_denial_kind` capture each adapter's OWN
observable denial surface (a dict for K1, a raised `PolicyError` for K2, an `isError`
`CallToolResult` for K3) exactly as an embedding developer would see it -- these are expected to
differ in SHAPE across frameworks (that is the "framework-specific wrapping" K4's brief names as
legitimate variation); the test suite cross-checks them against `corpus.expected_denied()`, the
independent oracle, never against each other.
"""
import asyncio
import io
from dataclasses import dataclass
from typing import Any, Optional

from . import _bootstrap  # noqa: F401

from naalp import ez, policy
from naalp_kit import binding

from .corpus import GovernanceCase


class BrokenSigner:
    """A signer whose `.sign()` always raises -- used ONLY for the `core_sign_failure` corpus
    case, to force K0's own documented `SignFailed` path (K0-5) identically through every
    adapter's real capture code (never a mock of the adapter itself; the adapter code runs for
    real and hits a real exception at the one seam K0 defines for a core failure)."""

    public_key = b"\x00" * 32
    signer_id = "did:naalp:k4-broken-signer"

    def sign(self, *args, **kwargs):
        raise RuntimeError("K4 test: simulated core signer failure")


@dataclass
class NormalizedOutcome:
    adapter: str
    case_id: str
    verified: Optional[Any] = None          # naalp.envelope.Object, independently re-verified
    core_error: Optional[BaseException] = None
    adapter_denied: Optional[bool] = None    # None when the case is not gated
    adapter_denial_kind: Optional[str] = None


def _classifier(case: GovernanceCase):
    if case.declared_effect is None:
        return None
    return lambda *_a, **_kw: case.declared_effect


def _signer_for(case: GovernanceCase, real_signer):
    return BrokenSigner() if case.force_core_failure else real_signer


def _independent_verify(real_signer, records):
    """The F3 non-circular re-check shared by every driver below: decode+verify the recorded
    signed bytes through the real core, independent of the adapter that produced them."""
    if not records:
        return None
    return ez.verify(real_signer.public_key, records[0])


# --- K1 (ADK) ------------------------------------------------------------------------------

def run_k1(case: GovernanceCase, real_signer) -> NormalizedOutcome:
    from naalp_adk_plugin.adk_plugin import ChainRecorder, NaalpGovernancePlugin
    from google.adk.tools.base_tool import BaseTool

    class _StubToolContext:
        def __init__(self, invocation_id):
            self.invocation_id = invocation_id

    stream = io.BytesIO()
    recorder = ChainRecorder(stream)
    signer = _signer_for(case, real_signer)
    gating = case.grant_max_effect is not None
    grant = policy.Grant(principal=signer.signer_id, max_effect=case.grant_max_effect) if gating else None
    plugin = NaalpGovernancePlugin(
        signer, recorder, gating=gating, grant=grant, effect_classifier=_classifier(case),
    )
    tool = BaseTool(name=case.tool_name, description="k4 case: " + case.case_id)
    ctx = _StubToolContext("k4-" + case.case_id)

    core_error = None
    adapter_denied = None
    adapter_denial_kind = None
    try:
        result = asyncio.run(plugin.before_tool_callback(
            tool=tool, tool_args=dict(case.args), tool_context=ctx,
        ))
    except Exception as e:  # noqa: BLE001 -- deliberately broad: this IS the core-failure probe
        core_error = e
    else:
        if gating:
            adapter_denied = result is not None
            adapter_denial_kind = result.get("kind") if adapter_denied else None

    stream.seek(0)
    records = ChainRecorder.read_all(stream)
    verified = _independent_verify(real_signer if not case.force_core_failure else signer, records)
    return NormalizedOutcome("K1-ADK", case.case_id, verified, core_error, adapter_denied, adapter_denial_kind)


def run_k1_chain(real_signer):
    """Drives two captured actions through the SAME K1 session and returns the two
    independently re-verified objects, for cross-adapter causal-chaining comparison."""
    from naalp_adk_plugin.adk_plugin import ChainRecorder, NaalpGovernancePlugin
    from google.adk.tools.base_tool import BaseTool

    class _StubToolContext:
        def __init__(self, invocation_id):
            self.invocation_id = invocation_id

    stream = io.BytesIO()
    recorder = ChainRecorder(stream)
    plugin = NaalpGovernancePlugin(real_signer, recorder)
    ctx = _StubToolContext("k4-chain")
    asyncio.run(plugin.before_tool_callback(tool=BaseTool(name="a", description="a"), tool_args={}, tool_context=ctx))
    asyncio.run(plugin.after_tool_callback(
        tool=BaseTool(name="a", description="a"), tool_args={}, tool_context=ctx, result={},
    ))
    stream.seek(0)
    first_b, second_b = ChainRecorder.read_all(stream)
    return ez.verify(real_signer.public_key, first_b), ez.verify(real_signer.public_key, second_b)


# --- K2 (A2A) --------------------------------------------------------------------------------

def run_k2(case: GovernanceCase, real_signer) -> NormalizedOutcome:
    from naalp_a2a_hook.a2a_hook import ChainRecorder, NaalpA2AClientInterceptor
    from a2a.client.interceptors import BeforeArgs
    from a2a.types.a2a_pb2 import SendMessageRequest, Role, AgentCard
    import json as _json

    stream = io.BytesIO()
    recorder = ChainRecorder(stream)
    signer = _signer_for(case, real_signer)
    gating = case.grant_max_effect is not None
    grant = policy.Grant(principal=signer.signer_id, max_effect=case.grant_max_effect) if gating else None
    interceptor = NaalpA2AClientInterceptor(
        signer, recorder, gating=gating, grant=grant, effect_classifier=_classifier(case),
        session_key="k4-" + case.case_id,
    )

    req = SendMessageRequest()
    req.message.message_id = "k4-" + case.case_id
    req.message.role = Role.ROLE_USER
    part = req.message.parts.add()
    part.text = _json.dumps({"tool": case.tool_name, "args": case.args}, sort_keys=True)
    card = AgentCard()
    card.name = "k4-peer-agent"
    before_args = BeforeArgs(input=req, method="send_message", agent_card=card)

    core_error = None
    adapter_denied = None
    adapter_denial_kind = None
    try:
        asyncio.run(interceptor.before(before_args))
    except policy.PolicyError as e:
        adapter_denied = True
        adapter_denial_kind = e.kind
    except Exception as e:  # noqa: BLE001 -- deliberately broad: this IS the core-failure probe
        core_error = e
    else:
        if gating:
            adapter_denied = False

    stream.seek(0)
    records = ChainRecorder.read_all(stream)
    verified = _independent_verify(real_signer if not case.force_core_failure else signer, records)
    return NormalizedOutcome("K2-A2A", case.case_id, verified, core_error, adapter_denied, adapter_denial_kind)


def run_k2_chain(real_signer):
    from naalp_a2a_hook.a2a_hook import ChainRecorder, NaalpA2AClientInterceptor
    from a2a.client.interceptors import BeforeArgs, AfterArgs
    from a2a.types.a2a_pb2 import SendMessageRequest, SendMessageResponse, Role, AgentCard

    stream = io.BytesIO()
    recorder = ChainRecorder(stream)
    interceptor = NaalpA2AClientInterceptor(real_signer, recorder, session_key="k4-chain")
    card = AgentCard()
    card.name = "peer"

    req = SendMessageRequest()
    req.message.message_id = "m1"
    req.message.role = Role.ROLE_USER
    req.message.parts.add().text = "hello"
    asyncio.run(interceptor.before(BeforeArgs(input=req, method="send_message", agent_card=card)))

    resp = SendMessageResponse()
    resp.message.message_id = "m2"
    resp.message.role = Role.ROLE_AGENT
    resp.message.parts.add().text = "reply"
    asyncio.run(interceptor.after(AfterArgs(result=resp, method="send_message", agent_card=card)))

    stream.seek(0)
    first_b, second_b = ChainRecorder.read_all(stream)
    return ez.verify(real_signer.public_key, first_b), ez.verify(real_signer.public_key, second_b)


# --- K3 (MCP) --------------------------------------------------------------------------------

async def _run_k3_async(case: GovernanceCase, real_signer) -> NormalizedOutcome:
    import anyio
    import mcp.shared.memory as mcp_memory
    from mcp.server.fastmcp import FastMCP
    from naalp_mcp_hook.mcp_hook import ChainRecorder, NaalpGovernedClientSession

    server = FastMCP("naalp-k4-portability-server")

    @server.tool(name=case.tool_name)
    def _tool() -> str:  # a fixed no-argument tool -- K4 grades effect/channel/kind/denial
        return "ok"      # outcomes, not literal argument-payload content per case

    mcp_server = server._mcp_server

    stream = io.BytesIO()
    recorder = ChainRecorder(stream)
    signer = _signer_for(case, real_signer)
    gating = case.grant_max_effect is not None
    grant = policy.Grant(principal=signer.signer_id, max_effect=case.grant_max_effect) if gating else None

    core_error = None
    adapter_denied = None
    adapter_denial_kind = None

    async with mcp_memory.create_client_server_memory_streams() as (client_streams, server_streams):
        client_read, client_write = client_streams
        server_read, server_write = server_streams
        async with anyio.create_task_group() as tg:
            tg.start_soon(lambda: mcp_server.run(
                server_read, server_write, mcp_server.create_initialization_options(),
                raise_exceptions=True,
            ))
            try:
                async with NaalpGovernedClientSession(
                    read_stream=client_read, write_stream=client_write,
                    signer=signer, recorder=recorder, session_key="k4-" + case.case_id,
                    gating=gating, grant=grant, effect_classifier=_classifier(case),
                ) as session:
                    await session.initialize()
                    result = await session.call_tool(case.tool_name, {})
                    if gating:
                        adapter_denied = bool(result.isError)
                        if adapter_denied:
                            text = result.content[0].text
                            parts = text.split(": ", 2)
                            adapter_denial_kind = parts[1] if len(parts) > 1 else None
            except Exception as e:  # noqa: BLE001 -- deliberately broad: the core-failure probe
                core_error = _unwrap_task_group_error(e)
            tg.cancel_scope.cancel()

    stream.seek(0)
    records = ChainRecorder.read_all(stream)
    verified = _independent_verify(real_signer if not case.force_core_failure else signer, records)
    return NormalizedOutcome("K3-MCP", case.case_id, verified, core_error, adapter_denied, adapter_denial_kind)


def _unwrap_task_group_error(e: BaseException) -> BaseException:
    """`anyio.create_task_group()` wraps an exception raised inside its `async with` body in a
    Python 3.11+ `ExceptionGroup` (structural task-group semantics, not a naalp/K3 behavior).
    K4 grades the REAL underlying error K3's own code raised (e.g. `binding.SignFailed`), so
    unwrap one level when the group holds exactly one sub-exception; a genuinely multi-exception
    group is returned as-is (nothing here would know which one is "the" answer)."""
    exceptions = getattr(e, "exceptions", None)
    if exceptions is not None and len(exceptions) == 1:
        return exceptions[0]
    return e


def run_k3(case: GovernanceCase, real_signer) -> NormalizedOutcome:
    return asyncio.run(_run_k3_async(case, real_signer))


async def _run_k3_chain_async(real_signer):
    import anyio
    import mcp.shared.memory as mcp_memory
    from mcp.server.fastmcp import FastMCP
    from naalp_mcp_hook.mcp_hook import ChainRecorder, NaalpGovernedClientSession

    server = FastMCP("naalp-k4-chain-server")

    @server.tool(name="chained_tool")
    def _tool() -> str:
        return "ok"

    mcp_server = server._mcp_server
    stream = io.BytesIO()
    recorder = ChainRecorder(stream)

    async with mcp_memory.create_client_server_memory_streams() as (client_streams, server_streams):
        client_read, client_write = client_streams
        server_read, server_write = server_streams
        async with anyio.create_task_group() as tg:
            tg.start_soon(lambda: mcp_server.run(
                server_read, server_write, mcp_server.create_initialization_options(),
                raise_exceptions=True,
            ))
            async with NaalpGovernedClientSession(
                read_stream=client_read, write_stream=client_write,
                signer=real_signer, recorder=recorder, session_key="k4-chain",
            ) as session:
                await session.initialize()
                await session.call_tool("chained_tool", {})  # emits TWO records: call + result
            tg.cancel_scope.cancel()

    stream.seek(0)
    first_b, second_b = ChainRecorder.read_all(stream)
    return ez.verify(real_signer.public_key, first_b), ez.verify(real_signer.public_key, second_b)


def run_k3_chain(real_signer):
    return asyncio.run(_run_k3_chain_async(real_signer))


# --- K0-direct: the one fail-closed corpus entry no adapter can drive (S-1: channel/kind fixed) --

def run_k0_unknown_kind(real_signer):
    """K4-3's `UNKNOWN_KIND_CASE_ID` entry: driven directly against K0, since none of K1/K2/K3
    exposes a caller-controlled channel/kind. Returns the raised exception (expected:
    `naalp.channels.UnknownKind`)."""
    from .corpus import UNKNOWN_CHANNEL, UNKNOWN_KIND

    action = binding.CapturedAction(
        channel=UNKNOWN_CHANNEL, kind=UNKNOWN_KIND, payload=b"k4-unknown-kind-probe",
        effect=policy.READ_ONLY,
    )
    try:
        binding.sign_action(real_signer, action)
    except Exception as e:  # noqa: BLE001 -- returned for the caller to type-check
        return e
    raise AssertionError("K0 accepted an unregistered (channel, kind) pair -- fail-closed broke")


ADAPTERS = {
    "K1-ADK": run_k1,
    "K2-A2A": run_k2,
    "K3-MCP": run_k3,
}

__all__ = [
    "BrokenSigner", "NormalizedOutcome",
    "run_k1", "run_k1_chain", "run_k2", "run_k2_chain", "run_k3", "run_k3_chain",
    "run_k0_unknown_kind", "ADAPTERS",
]
