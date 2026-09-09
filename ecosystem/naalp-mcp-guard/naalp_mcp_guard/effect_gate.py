# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""The N-AALP MCP guard's effect-authorization core (Group 6, Task A.1(b)/(c); design.md
Sec.2.7; requirement 6.1; P-CLOSED, P-RUGPULL's precondition).

This module is transport-agnostic: it never touches a socket, a subprocess, or stdio framing.
Given ONE foreign MCP tool DEFINITION and ONE foreign MCP `tools/call` REQUEST (plain Python
dicts, exactly as `tools/list`/`tools/call` carry them on the wire), it does two things, each
delegating every cryptographic and ledger operation to an already-built, already-graded
component -- this module adds NO cryptography, NO CBOR encoding, and NO approval-consume logic
of its own:

  1. `EffectGate.classify` -- THE FAIL-CLOSED CLASSIFIER. Carries the call into a real signed
     N-AALP McpToolCall object under the guard's OWN key (via `naalp_mcp_bridge.mcp_bridge`),
     immediately self-verifies it through the identical real-crypto path a remote verifier would
     use, and resolves the ENFORCED effect (the more-severe of the tool's own annotations and the
     guard's declared claim). An unknown, missing, or name-mismatched tool definition classifies
     via an EMPTY annotation set under the call's own tool name, so `naalp.mcp`'s OWN published
     mapping table -- not a rule this module invents -- collapses it to `destructive`
     (destructiveHint defaults true), which in turn always requires approval (P-CLOSED).

  2. `EffectGate.authorize_and_execute` -- THE EFFECT GATE. For a call requiring approval, pauses
     it and routes it through the real `naalp_hitl.HITLInterceptor` (pause / human interface /
     audience-bound single-use approval-consume / D6 refusal audit -- all delegated), binding the
     approval to the EXACT call-binding content id (tool_id + args_id) this call classified to, so
     neither a changed tool description nor changed arguments can satisfy a prior approval
     (Requirement 6.1). A call below the approval threshold is forwarded immediately. Either way,
     a PQ-signed, offline-verifiable `naalp_mcp_guard.receipt.EffectReceipt` is minted for the
     outcome (executed or denied) -- an audit trail is recorded for every gated attempt, not only
     successes.

MCP-VERIFIED's own scoping applies throughout: this module authenticates the CALL as a real
signed N-AALP object the guard itself attests to, and audience/replay protection for the
approval-gated path is the SAME real Part-1 mechanism every other N-AALP approval consumer uses
(F1.2a/F1.3 CLOSED at that boundary); it makes no claim about wire-level replay protection on the
client<->guard leg itself (F1.3: "transport-dependent for wire replay"), and it never invents an
authentication mechanism MCP core or Part-1 does not already define."""
from . import _bootstrap  # noqa: F401  (repo-relative sys.path setup; must run before naalp/naalp_mcp_bridge/naalp_hitl imports)

import time
from dataclasses import dataclass
from typing import Any, Callable, Optional

from naalp import approval, cbor, cose, envelope, policy
from naalp_mcp_bridge import mcp_bridge
from naalp_hitl.interceptor import HITLInterceptor, PendingAction, default_clock_ms

from . import receipt as receipt_mod


class GuardError(Exception):
    """A named, fail-closed guard-layer error. `.kind` reuses the underlying
    naalp_mcp_bridge.BridgeError / naalp.mcp.McpError / naalp.envelope.EnvelopeError /
    naalp.approval.ApprovalError / naalp_hitl.HITLError kind directly wherever one applies --
    this module invents no error taxonomy of its own. On a denial raised out of
    `authorize_and_execute`, `.receipt` and `.receipt_sig` carry the minted denial receipt (the
    same "attach evidence to the raised error" idiom naalp_hitl.HITLInterceptor uses for `.d6`)."""

    def __init__(self, kind, msg=""):
        super().__init__("%s: %s" % (kind, msg) if msg else kind)
        self.kind = kind
        self.receipt: Optional[receipt_mod.EffectReceipt] = None
        self.receipt_sig: Optional[bytes] = None


def _mldsa_param_name(alg: int) -> str:
    """The ML-DSA parameter-set name `naalp.cose.mldsa_keygen` expects, for a registered N-AALP
    algorithm id. Kept local (not imported from naalp_mcp_bridge's own private helper of the same
    shape) -- each ecosystem package stays independently installable, matching the sibling
    convention (naalp_mcp_hook.canonical_json_bytes's own docstring states the same rule)."""
    if alg == cose.ALG_MLDSA87:
        return "ML-DSA-87"
    if alg == cose.ALG_MLDSA65:
        return "ML-DSA-65"
    raise ValueError("alg %r is not a registered ML-DSA algorithm" % (alg,))


@dataclass(frozen=True)
class GateDecision:
    """The result of classifying ONE tools/call request -- everything `authorize_and_execute`
    needs, computed exactly once. `call_binding` is the naalp.mcp.CallBinding (tool_id, args_id)
    this exact call's approval must bind (Requirement 6.1); `bridged.enforced_effect` is the C5
    authorization input (the more-severe of the tool's own annotations and the guard's declared
    claim); `requires_approval` is that effect checked against the configured threshold."""

    carried: "mcp_bridge.CarriedCall"
    bridged: "mcp_bridge.BridgedCall"
    call_binding: "mcp_bridge.mcp.CallBinding"
    requires_approval: bool
    tool_name: str


class EffectGate:
    """Group 6's guard core: one guard identity (an ML-DSA key it carries+self-verifies every
    call under), one durable approval ledger + human-approval interceptor (delegated wholesale to
    naalp_hitl.HITLInterceptor), and one receipt-signing key (defaults to the guard's own
    identity key -- MCP-VERIFIED F1.5's "receipts are self-attested" scoping when guard and
    server share one operator; pass `receipt_alg`/`receipt_seed` explicitly for a separate
    receipt-signing identity)."""

    def __init__(
        self,
        *,
        guard_seed: bytes,
        guard_identity: str,
        audience: str,
        approver_alg: int,
        approver_pubkey: bytes,
        human_interface,
        refusal_log,
        ledger,
        guard_alg: int = cose.ALG_MLDSA65,
        profile: int = cose.PROFILE_PUBLIC,
        approval_threshold: int = policy.NON_IDEMPOTENT_WRITE,
        clock_ms: Optional[Callable[[], int]] = None,
        receipt_alg: Optional[int] = None,
        receipt_seed: Optional[bytes] = None,
        non_repudiation_threshold: int = policy.DESTRUCTIVE,
    ):
        self._guard_seed = bytes(guard_seed)
        self._guard_alg = guard_alg
        self._profile = profile
        self._guard_identity = guard_identity
        self._audience = audience
        self._approval_threshold = approval_threshold
        self._clock = clock_ms or default_clock_ms
        self._guard_pubkey = cose.mldsa_keygen(_mldsa_param_name(guard_alg), self._guard_seed)

        self._receipt_alg = guard_alg if receipt_alg is None else receipt_alg
        self._receipt_seed = self._guard_seed if receipt_seed is None else bytes(receipt_seed)
        self._receipt_pubkey = cose.mldsa_keygen(_mldsa_param_name(self._receipt_alg), self._receipt_seed)

        # Every pause/human-interface/verify/audience/single-use-consume/D6-audit step is the
        # real Part-1-backed naalp_hitl primitive; this class supplies no alternate path to it.
        self._interceptor = HITLInterceptor(
            ledger, approver_alg, approver_pubkey, audience, guard_identity,
            human_interface, refusal_log, approval_threshold=approval_threshold,
            clock=self._clock, non_repudiation_threshold=non_repudiation_threshold,
        )

    @property
    def guard_pubkey(self) -> bytes:
        return self._guard_pubkey

    @property
    def receipt_alg(self) -> int:
        return self._receipt_alg

    @property
    def receipt_pubkey(self) -> bytes:
        return self._receipt_pubkey

    # ---- (1) THE FAIL-CLOSED CLASSIFIER --------------------------------------------------------

    def classify(self, tool_definition: Optional[dict], call_request: dict) -> GateDecision:
        """Classify ONE tools/call request against Family-1 + the closed effect lattice. Raises
        GuardError (fail-closed, nothing classified as safe) on any carry/verify failure --
        malformed JSON-RPC shape, a tool-name mismatch, a malformed annotation set, or (in
        principle, though unreachable via this call path since the guard signs what it just
        carried) a signature/content-id failure. `tool_definition` may be None or an unrelated
        tool's definition -- either way this falls back to an EMPTY annotation set under the
        call's own declared tool name, which `naalp.mcp.map_annotations_to_effect`'s own
        published, unmodified table maps to `destructive` (P-CLOSED): an unknown/over-scoped
        tool is never guessed benign."""
        name = None
        try:
            name = call_request["params"]["name"]
        except (KeyError, TypeError):
            pass
        if not isinstance(tool_definition, dict) or tool_definition.get("name") != name:
            tool_definition = {"name": name if isinstance(name, str) else ""}

        now = self._clock()
        try:
            carried = mcp_bridge.carry_tool_call_from_objects(
                tool_definition, call_request, signer_seed=self._guard_seed,
                alg=self._guard_alg, created=now, profile=self._profile,
            )
            bridged = mcp_bridge.receive_tool_call(
                carried.signed_object, self._profile, self._guard_alg, self._guard_pubkey,
            )
        except (mcp_bridge.mcp.McpError, envelope.EnvelopeError) as e:
            raise GuardError(getattr(e, "kind", e.__class__.__name__), str(e)) from e

        call_binding = bridged.resolved.tool_call.call_binding()
        requires = bridged.enforced_effect >= self._approval_threshold
        return GateDecision(
            carried=carried, bridged=bridged, call_binding=call_binding,
            requires_approval=requires, tool_name=tool_definition.get("name", ""),
        )

    # ---- (2) THE EFFECT GATE -------------------------------------------------------------------

    def authorize_and_execute(self, decision: GateDecision, forward: Callable[[], Any], *,
                               principal: str = ""):
        """Enforce the approval gate for `decision` and, only on success, call `forward()` (a
        zero-argument callable performing the REAL downstream effect -- supplied by the caller,
        never invoked here before authorization succeeds). Returns `(result, receipt, sig)` on
        success; raises GuardError (with `.receipt`/`.receipt_sig` attached) on denial. A
        PQ-signed EffectReceipt is minted on EITHER outcome -- an audit trail exists for every
        gated attempt (F1.5), not only successful ones.

        The approval is bound to `decision.call_binding.content_id()` -- the compound
        (tool_id, args_id) binding -- by constructing the naalp_hitl.PendingAction's `args` as
        THAT binding's own CBOR map: `naalp_hitl.HITLInterceptor.intercept()` computes
        `cbor.content_id(action.args)`, which for this exact Value equals
        `decision.call_binding.content_id()` (both encode the identical CBOR map and hash it the
        identical way -- naalp.mcp.CallBinding.content_id() is defined as exactly this). This is
        NOT a re-derivation of the binding: it is the one real primitive
        (`naalp.cbor.content_id`) applied to the one real Value naalp.mcp already builds,
        confirmed byte-identical by construction rather than by coincidence."""
        cb = decision.call_binding
        effect = decision.bridged.enforced_effect
        tool_name = decision.tool_name

        action = PendingAction(
            kind="mcp:tools/call:%s" % tool_name,
            effect=effect,
            args=cb.to_map(),
            execute=forward,
            args_summary="tool=%s enforced_effect=%s mismatch=%s" % (
                tool_name, policy.safety_label_name(effect), decision.bridged.mismatch),
            principal=principal,
        )
        try:
            result = self._interceptor.intercept(action)
        except approval.ApprovalError as err:
            rec = self._mint_receipt(
                cb=cb, effect=effect, decision=receipt_mod.DECISION_DENIED,
                reason=getattr(err, "kind", err.__class__.__name__), result_hash=b"",
                principal=principal, tool_name=tool_name,
            )
            sig = receipt_mod.sign_effect_receipt(rec, self._receipt_alg, self._receipt_seed)
            ge = GuardError(getattr(err, "kind", "ApprovalDenied"), str(err))
            ge.receipt, ge.receipt_sig = rec, sig
            raise ge from err

        result_hash = b""
        if result is not None:
            result_bytes = mcp_bridge.canonical_json_bytes(result)
            result_hash = cbor.content_id(result_bytes)
        rec = self._mint_receipt(
            cb=cb, effect=effect, decision=receipt_mod.DECISION_EXECUTED, reason="",
            result_hash=result_hash, principal=principal, tool_name=tool_name,
        )
        sig = receipt_mod.sign_effect_receipt(rec, self._receipt_alg, self._receipt_seed)
        return result, rec, sig

    def _mint_receipt(self, *, cb, effect, decision, reason, result_hash, principal, tool_name):
        return receipt_mod.EffectReceipt(
            tool_id=cb.tool_id, args_id=cb.args_id, call_id=cb.content_id(), effect=effect,
            decision=decision, reason=reason, result_hash=result_hash,
            principal=principal or "", tool_name=tool_name,
            guard_identity=self._guard_identity, created_ms=self._clock(),
        )


__all__ = ["EffectGate", "GateDecision", "GuardError"]
