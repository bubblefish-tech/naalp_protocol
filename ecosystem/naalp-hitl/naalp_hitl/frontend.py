# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""The terminal front end for the N-AALP HITL interceptor (Part-2 E0.1, requirement R1.3).

R1.3 requires the approval UI contract be transport-agnostic and defined in terms of what the
human sees: the effect class, the content id, and the args. `TerminalFrontend` is one concrete
implementation of `HumanInterface` (interceptor.py) -- a human operator's local tool that holds
its OWN ML-DSA-65 signing identity (a seed, never transmitted), renders the ApprovalRequest to
stdout, reads a y/N decision from stdin, and -- on approval -- signs a REAL N-AALP approval
object with that key. Web and chat front ends are deferred (out of scope this task) but plug in
against the identical HumanInterface contract with no change to HITLInterceptor.
"""
from . import _bootstrap  # noqa: F401

import os
from typing import Optional

from naalp import approval, cose, policy

from .interceptor import ApprovalRequest, HumanInterface, default_clock_ms


def _effect_name(effect: int) -> str:
    try:
        return policy.safety_label_name(effect)
    except (IndexError, TypeError):
        return "unknown(%r)" % (effect,)


class TerminalFrontend(HumanInterface):
    """A human-operator terminal tool. Construction takes the operator's own approver identity
    (a signer id string) and ML-DSA-65 seed; `request_approval` renders the request, blocks on
    `input_fn` for the operator's decision, and on 'y' mints and signs a real ApprovalRecord
    bound to the request's exact content id and audience. `input_fn`/`output_fn`/`clock`/
    `nonce_fn` are injectable (defaulting to real `input`/`print`/wall clock/`os.urandom`) so the
    SAME real signing code path is exercised under test without requiring an interactive
    terminal."""

    def __init__(
        self,
        approver_id: str,
        seed: bytes,
        *,
        alg: int = cose.ALG_MLDSA65,
        grant: Optional[int] = None,
        validity_ms: int = 5 * 60 * 1000,
        input_fn=input,
        output_fn=print,
        clock=None,
        nonce_fn=None,
    ):
        self._approver_id = approver_id
        self._alg = alg
        self._seed = bytes(seed)
        self._grant = grant
        self._validity_ms = validity_ms
        self._input = input_fn
        self._output = output_fn
        self._clock = clock or default_clock_ms
        self._nonce_fn = nonce_fn or (lambda: os.urandom(16))

    def request_approval(self, request: ApprovalRequest):
        """Render `request` to the operator and return a signed (ApprovalRecord, sig) on 'y',
        or None on anything else (a decline is a decline, not an error -- HITLInterceptor turns
        a None decision into the named ApprovalDenied fail-closed error)."""
        self._output("=" * 64)
        self._output("N-AALP HITL approval request")
        self._output("  kind:       %s" % request.kind)
        self._output("  effect:     %s (%d)" % (_effect_name(request.effect), request.effect))
        self._output("  content-id: %s" % request.content_id.hex())
        self._output("  args:       %s" % request.args_summary)
        self._output("  audience:   %s" % request.audience)
        self._output("=" * 64)
        answer = self._input("Approve %r? [y/N]: " % request.kind).strip().lower()
        if answer != "y":
            return None
        grant = request.effect if self._grant is None else self._grant
        record = approval.ApprovalRecord(
            approves=request.content_id,
            approver=self._approver_id,
            grant=grant,
            nonce=self._nonce_fn(),
            not_after=self._clock() + self._validity_ms,
            audience=request.audience,
        )
        sig = approval.sign_approval(record, self._alg, self._seed)
        return record, sig
