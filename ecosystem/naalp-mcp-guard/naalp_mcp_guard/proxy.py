# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""The N-AALP MCP guard's transport-agnostic message router (Group 6, Task A.1; AC-6.1.1/6.1.2).

`GuardProxy` is the ONE place that turns raw MCP JSON-RPC message dicts into effect-gate
decisions: it watches `tools/list` RESPONSES to learn each tool's real (possibly none) MCP
annotations, and gates every `tools/call` REQUEST through `naalp_mcp_guard.effect_gate.EffectGate`
before it may reach the wrapped server. Every other JSON-RPC method (`initialize`,
`resources/*`, `prompts/*`, `ping`, notifications, ...) is out of this module's scope entirely --
Requirement 6.1 gates the effecting tool-call path, not the whole protocol surface, and nothing
here claims otherwise.

This module never opens a socket, spawns a process, or frames stdio itself: `handle_tools_call`
and `note_tools_list_response` operate on already-decoded dicts and a caller-supplied `forward`
callback, so the real transport plumbing (`naalp_mcp_guard.cli._DownstreamServer`) and this
policy logic are tested independently -- a fake `forward` exercises the real gate/effect/receipt
logic with no subprocess involved."""
from . import _bootstrap  # noqa: F401  (repo-relative sys.path setup; must run before naalp imports)

import os
from typing import Any, Callable, Dict, Optional

from . import receipt as receipt_mod
from .effect_gate import EffectGate, GuardError


def _denied_result(req_id: Any, text: str) -> dict:
    """A fail-closed refusal, shaped as MCP's OWN vocabulary for "this call did not succeed" --
    a `CallToolResult(isError=true)` -- rather than a JSON-RPC protocol-level error, matching
    naalp_mcp_hook's identical convention (`naalp_governance_denied: ...`) for the same reason:
    an authorization refusal is a tool-level outcome the calling agent can read and act on, not a
    transport fault."""
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "result": {
            "isError": True,
            "content": [{"type": "text", "text": "naalp_guard_denied: %s" % text}],
        },
    }


class GuardProxy:
    """Owns the tool-definition cache (learned from real `tools/list` traffic) and drives one
    `EffectGate` for every gated `tools/call`. `receipts_dir`, when given, persists a
    self-contained, offline-verifiable receipt file (naalp_mcp_guard.receipt) for every gated
    attempt -- executed or denied -- under a name derived from the receipt's own content id (no
    caller-supplied filename is ever trusted as an identifier)."""

    def __init__(self, gate: EffectGate, *, receipts_dir: Optional[str] = None,
                 principal_of: Optional[Callable[[dict], str]] = None):
        self._gate = gate
        self._tools: Dict[str, dict] = {}
        self._receipts_dir = receipts_dir
        self._principal_of = principal_of
        if receipts_dir is not None:
            os.makedirs(receipts_dir, exist_ok=True)

    @property
    def known_tools(self) -> Dict[str, dict]:
        """Read-only view of the tool-definition cache, for tests/inspection."""
        return dict(self._tools)

    def note_tools_list_response(self, response: dict) -> None:
        """Cache every tool definition from a real `tools/list` RESPONSE. A tool the guard has
        never seen classifies via `EffectGate.classify`'s fail-closed empty-annotation default
        (P-CLOSED) -- this cache exists to give the classifier the tool's REAL annotations when
        they are known, never to grant anything by their absence."""
        result = response.get("result") if isinstance(response, dict) else None
        tools = result.get("tools") if isinstance(result, dict) else None
        if not isinstance(tools, list):
            return
        for t in tools:
            if isinstance(t, dict) and isinstance(t.get("name"), str):
                self._tools[t["name"]] = t

    def handle_tools_call(self, request: dict, forward: Callable[[], Any]) -> dict:
        """Gate ONE `tools/call` REQUEST end to end: classify (Family-1 + effect lattice),
        authorize (pause + human approval when required) and, only on success, invoke `forward()`
        -- the real downstream call, bound by the caller to this exact `request`. Always returns
        a JSON-RPC response shaped for `request`'s id: the real result on success, or a
        fail-closed `isError` result on ANY refusal (a malformed call, an unauthenticated/
        malformed carry, or a declined/expired/mismatched/already-consumed approval) -- never a
        silent pass and never an unhandled exception escaping to the transport layer."""
        req_id = request.get("id") if isinstance(request, dict) else None
        tool_name = None
        if isinstance(request, dict):
            params = request.get("params")
            if isinstance(params, dict):
                tool_name = params.get("name")
        principal = self._principal_of(request) if self._principal_of else ""

        try:
            decision = self._gate.classify(self._tools.get(tool_name), request)
        except GuardError as e:
            return _denied_result(req_id, "%s: %s" % (e.kind, e))

        try:
            result, rec, sig = self._gate.authorize_and_execute(decision, forward, principal=principal)
        except GuardError as e:
            self._persist_receipt(e.receipt, e.receipt_sig)
            return _denied_result(req_id, "%s: %s" % (e.kind, e))

        self._persist_receipt(rec, sig)
        return result

    def _persist_receipt(self, rec, sig) -> Optional[str]:
        if rec is None or sig is None or self._receipts_dir is None:
            return None
        name = "receipt-%s-%s.json" % (rec.created_ms, rec.content_id().hex()[:24])
        path = os.path.join(self._receipts_dir, name)
        receipt_mod.write_receipt_file(path, rec, self._gate.receipt_alg, self._gate.receipt_pubkey, sig)
        return path


__all__ = ["GuardProxy"]
