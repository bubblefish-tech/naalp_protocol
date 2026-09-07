# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
The N-AALP ReAct bridge (Part-2 ecosystem task E1.1, requirement R2.1).

requirements.md R2.1: "A ReAct bridge SHALL map N-AALP tool-calling into the
Thought->Action->Observation loop: an agent Action becomes a signed N-AALP request; the
async response becomes the Observation."

    Action  -> ReActBridge.action_to_request()   -> a real signed, encoded N-AALP request
    response -> ReActBridge.response_to_observation() -> a verified, causally-linked Observation

This module performs NO cryptography, NO CBOR encoding, and NO second content-id
computation of its own: every byte-level and signature-level operation (canonical
encoding, content-id binding, deterministic ML-DSA sign/verify, the audience point-of-use
gate) is the real Part-1 reference implementation's own `naalp.envelope` /
`naalp.channels` code, imported and called directly (design.md "Buy-before-make"; the
ReAct bridge is N-AALP-specific glue -- the Thought/Action/Observation <-> signed-object
translation -- not a second copy of the envelope/COSE primitive). Any raw CBOR value
construction this module performs directly goes through the sibling `naalp_codec`
package (the blessed binding), never a hand-rolled encoder.

Design choice -- injected, composable, DUCK-TYPED hooks (never a hard import of a sibling
ecosystem package): `validator` and `hitl` are plain callables/objects whose CONTRACT
matches `naalp_validator.validate` and `naalp_hitl.HITLInterceptor` respectively, but this
module never imports either package. A caller wires a real `naalp_validator.validate` (or
any callable returning a truthy/falsy result with an optional `.violations`) as
`validator=`, and a real `naalp_hitl.HITLInterceptor` (or any object exposing
`.intercept(pending)` where `pending` has `.kind/.effect/.args/.execute/.args_summary`) as
`hitl=` -- exactly the shape `HITLInterceptor.intercept()` already expects, so a real
interceptor plugs in with zero adaptation. This keeps naalp_react buildable and testable
in total isolation (per this task's isolation-demo requirement) while still composing with
the other ecosystem packages exactly as the design intends.

Design choice -- audience reuse, not reinvention: verifying that a response is addressed
to THIS bridge reuses the real Part-1 point-of-use gate `naalp.envelope.check_audience`
(the same function every consuming authority in the protocol uses, design.md Sec.2.5.3)
with `consume_once=True`, so an ABSENT audience and a WRONG audience are both rejected
`WrongAudience` -- the identical fail-closed behaviour Part-1 already defines and grades,
never a bridge-local reimplementation of that rule.

Design choice -- causal linkage is a plain membership check, not `naalp.graph.verify_causal`:
`graph.verify_causal` reconciles a whole SET of causally-ordered nodes (positions, cycles)
and is the right tool for a multi-agent causal graph (design.md "multi-agent: causes[]
graph"), but this bridge asks a much narrower question -- does THIS ONE response object
name THIS ONE request's content id among its `causes[]`? That is a direct membership test
against the response's own (already content-id-verified, already signature-verified)
`causes` list, reported under the registered `CausalViolation` error name
(`naalp.naalperror.NAMES`), which is the correct semantic category for "the expected
causal edge is absent" even though the check does not run graph.verify_causal's specific
position/cycle algorithm.
"""
import time
from dataclasses import dataclass, field
from typing import Callable, Optional, Tuple

from . import _bootstrap  # noqa: F401  (side-effecting import: puts impl/python + naalp_codec on sys.path)

from naalp import channels, envelope
from naalp_codec import A, B, M, N, T, Tag, U  # noqa: F401  (re-exported for callers building Action.args)


def default_clock_ms() -> int:
    """The wall clock in epoch milliseconds -- the unit `naalp.envelope.Object.created` uses."""
    return int(time.time() * 1000)


class ReActError(ValueError):
    """A named, fail-closed ReAct-bridge error (E1.1/R2.1). `.kind` is either a registered
    N-AALP error name recomputed/propagated from the real Part-1 primitives this bridge
    calls (e.g. "BadSignature", "WrongAudience", "CausalViolation", "UnknownKind" --
    `naalp.naalperror.NAMES`), or one of this bridge's own two glue-layer outcomes:
    "ValidationRefused" (the injected pre-send validator rejected the candidate) and
    "NotEmitted" (an injected `hitl` returned normally without ever calling
    `PendingAction.execute`, so no request was produced -- a defensive guard against a
    non-conformant hitl implementation silently reporting success on an unsent request)."""

    def __init__(self, kind, msg=""):
        super().__init__("%s: %s" % (kind, msg) if msg else kind)
        self.kind = kind


@dataclass(frozen=True)
class Action:
    """R2.1's "Thought -> Action": an agent's intended tool/effect invocation, not yet an
    N-AALP object. `name` is a human-readable action/tool name (never placed on the wire
    directly; it is what a HITL front end shows a human, mirroring naalp_hitl's own
    `PendingAction.kind`). `channel`/`kind` select the registered N-AALP surface this
    Action maps onto (`naalp.channels.TABLE`); `effect` is the C5 effect class the object
    will carry; `args` is the request body -- a naalp_codec/naalp.cbor value (e.g.
    `naalp_codec.M([...])`), never a raw unwrapped Python value (this bridge defines no
    value-coercion rules of its own, per the module docstring). `causes` names any prior
    N-AALP object content ids this Action causally derives from (design.md "multi-agent:
    causes[] graph"); empty for a first-turn Action."""

    name: str
    channel: int
    kind: int
    effect: int
    args: object
    args_summary: str = ""
    causes: Tuple[bytes, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class Request:
    """The output of `action_to_request`: a real signed, encoded N-AALP request object
    (`payload`, the exact bytes to hand to a transport) plus its content id (`id`) -- the
    value an eventual response is expected to cite in its own `causes[]` for
    `response_to_observation` to accept it as causally linked to THIS request."""

    payload: bytes
    id: bytes


@dataclass(frozen=True)
class Observation:
    """R2.1's "Observation": the typed outcome of verifying an async N-AALP response.
    `ok=True` carries the verified response's registered kind `name` (`naalp.channels`)
    and its decoded `body` value. `ok=False` NEVER carries a body -- only the registered
    error `name` (`naalp.naalperror.NAMES`, e.g. "BadSignature"/"WrongAudience"/
    "CausalViolation"/"UnknownKind") and a human-readable `detail` -- a verification
    failure is a refusal, never a partially-trusted result."""

    ok: bool
    name: str = ""
    body: object = None
    error: Optional[str] = None
    detail: str = ""


@dataclass(frozen=True)
class _PendingAction:
    """The exact attribute shape `naalp_hitl.HITLInterceptor.intercept()` reads off its
    argument (`.kind`, `.effect`, `.args`, `.execute()`, `.args_summary`) -- defined here,
    duck-typed, rather than imported from `naalp_hitl`, so this module has NO hard
    dependency on the sibling package (module docstring, "injected, composable hooks")."""

    kind: str
    effect: int
    args: object
    execute: Callable[[], bytes]
    args_summary: str = ""


def _kind_validator(channel: int, kind: int) -> bool:
    """The `kind_validator` `naalp.envelope.verify` requires: True iff (channel, kind) is a
    registered baseline surface (`naalp.channels.lookup`), exactly the same registry every
    other ecosystem component (naalp_validator, naalp_hitl) checks against."""
    try:
        channels.lookup(channel, kind)
        return True
    except channels.UnknownKind:
        return False


class ReActBridge:
    """R2.1: translate an agent's `Action` into a real signed N-AALP request object, and an
    async N-AALP response back into a typed, verified `Observation`. The clock, the signing
    key, the audience/use-context, the transport, and the optional validator/HITL hooks are
    all constructor-injected (never a wall clock read inline, never a hidden global, never
    a network call this class makes itself) so the whole bridge is testable in isolation."""

    def __init__(
        self,
        *,
        alg: int,
        seed: bytes,
        signer_id: str,
        profile: int,
        audience: str,
        self_identity: str,
        responder_alg: int,
        responder_pubkey: bytes,
        clock: Callable[[], int] = default_clock_ms,
        validator: Optional[Callable[[object], object]] = None,
        hitl=None,
        transport=None,
    ):
        if not audience:
            raise ValueError("audience (the request's intended consuming authority) must be non-empty")
        if not self_identity:
            raise ValueError("self_identity (the required response audience) must be non-empty")
        self._alg = alg
        self._seed = bytes(seed)
        self._signer_id = signer_id
        self._profile = profile
        self._audience = audience
        self._self_identity = self_identity
        self._responder_alg = responder_alg
        self._responder_pubkey = responder_pubkey
        self._clock = clock
        self._validator = validator
        self._hitl = hitl
        self._transport = transport

    # ---- Thought -> Action -> signed N-AALP request -------------------------------------------

    def action_to_request(self, action: Action) -> Request:
        """R2.1: build the N-AALP request object for `action` (kind/channel/effect/body/
        audience/causes), OPTIONALLY reject it pre-sign via the injected `validator`
        (P-PRESIGN: nothing invalid reaches the wire), OPTIONALLY pause it for human
        approval via the injected `hitl` (an effecting Action is gated exactly as
        `naalp_hitl.HITLInterceptor` already gates one), then sign+encode it with the real
        Part-1 primitive and return the resulting bytes plus the request's content id.

        Raises `ReActError`/the injected validator's own error/the injected hitl's own
        error on ANY pre-send refusal; on every refusal path, `envelope.sign` is NEVER
        called (no signature is produced, so no bytes can leak to a transport) -- verified
        by red-evidence M2 against a swallowed HITL denial and the pre-send validator test.
        """
        candidate = envelope.Object(
            kind=action.kind,
            channel=action.channel,
            signer=self._signer_id.encode("utf-8"),
            created=self._clock(),
            effect=action.effect,
            body=action.args,
            causes=list(action.causes),
            profile=self._profile,
            audience=self._audience,
        )

        if self._validator is not None:
            result = self._validator(candidate)
            if not result:
                violations = getattr(result, "violations", None)
                detail = (
                    "; ".join("%s(%s)" % (getattr(v, "error", v), getattr(v, "field", None)) for v in violations)
                    if violations
                    else repr(result)
                )
                raise ReActError("ValidationRefused", "pre-send validation rejected the candidate: %s" % detail)

        emitted = []

        def _sign_and_emit():
            signed_bytes = envelope.sign(candidate, self._alg, self._seed)
            emitted.append(signed_bytes)
            if self._transport is not None:
                self._transport.send(signed_bytes)
            return signed_bytes

        if self._hitl is not None:
            pending = _PendingAction(
                kind=action.name,
                effect=action.effect,
                args=candidate.body,
                execute=_sign_and_emit,
                args_summary=action.args_summary or action.name,
            )
            self._hitl.intercept(pending)  # raises fail-closed on any refusal; never calls _sign_and_emit then
        else:
            _sign_and_emit()

        if not emitted:
            # Defensive (D3): an injected hitl that returns normally WITHOUT ever calling
            # execute() must not be mistaken for a successfully emitted request.
            raise ReActError("NotEmitted", "the injected hitl returned without emitting the request")

        return Request(payload=emitted[0], id=candidate.id)

    # ---- async N-AALP response -> Observation --------------------------------------------------

    def response_to_observation(self, response_bytes: bytes, request: Request) -> Observation:
        """R2.1: verify `response_bytes` end-to-end (signature + audience + the expected
        causal linkage back to `request`), then convert it into a typed `Observation`. A
        verification failure at ANY step returns a fail-closed `Observation(ok=False, ...)`
        carrying the named error -- it NEVER raises past this point and NEVER returns a
        body alongside `ok=False` (no silently-accepted partial result, task bar (c)/(d)/(e))."""
        try:
            obj = envelope.verify(
                self._profile, self._responder_alg, self._responder_pubkey, _kind_validator, response_bytes
            )
        except (ValueError, TypeError, IndexError) as e:
            return Observation(ok=False, error=getattr(e, "kind", "Malformed"), detail=str(e))

        try:
            # Reuse (never reinvent) the real Part-1 point-of-use audience gate: absent OR
            # wrong audience both reject WrongAudience (design.md Sec.2.5.3).
            envelope.check_audience(obj, self._self_identity, consume_once=True)
        except envelope.EnvelopeError as e:
            return Observation(ok=False, error=e.kind, detail=str(e))

        if request.id not in obj.causes:
            return Observation(
                ok=False,
                error="CausalViolation",
                detail="response causes[] does not name this request's content id (%s)" % request.id.hex(),
            )

        name, _effect, _variable = channels.lookup(obj.channel, obj.kind)
        return Observation(ok=True, name=name, body=obj.body)
