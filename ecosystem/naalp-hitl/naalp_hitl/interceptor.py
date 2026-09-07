# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""The N-AALP HITL interceptor (Part-2 E0.1, requirement R1; design.md 'HITL interceptor'; D6
audit trail).

Wraps an effecting action whose effect class requires human approval: PAUSE the action,
route an ApprovalRequest to a pluggable HumanInterface, and RESUME only when a valid,
single-use, unexpired, audience-bound N-AALP approval object for that exact content id is
received -- otherwise FAIL CLOSED with the named error and never execute the action.

This module performs NO cryptography and NO ledger bookkeeping itself. Every check --
signature verification, the args-content-id binding, expiry, the effect-ceiling, and the
atomic single-use consume -- is delegated to the real Part-1 primitive
(naalp.approval.verify_audience / naalp.approval.consume_approval), which in turn calls the
real deterministic ML-DSA verification (naalp.cose) and the real durable, hash-chained,
single-writer consume ledger (naalp.approval.Ledger). That ledger is exactly the one graded
against vectors/approval/cases.json in impl/python/tests/test_approval.py; nothing here
re-derives or re-approximates it.

D6: every refusal path (a human decline, and every naalp.approval.ApprovalError raised out of
verify_and_consume) is persisted through a durable, pluggable AU-2/AU-3 structured-log sink
(refusal_log.RefusalLog; REQUIRED, no default -- an interceptor cannot be constructed without
one) BEFORE the error propagates, and -- only for a refusal of an action whose required effect
meets or exceeds `non_repudiation_threshold`, and only when a signing key is configured -- ALSO
mints an AU-10 non-repudiation signed refusal-decision record (nonrepudiation.py) and derives
the party-visible coarse naalp.approval.Refusal from it. See nonrepudiation.py's module
docstring for the closed-set outcome mapping and refusal_log.py for the AU-3 field set."""
from . import _bootstrap  # noqa: F401  (repo-relative sys.path setup; must run before `naalp` imports)

import time
from dataclasses import dataclass
from typing import Callable, Optional, Tuple

from naalp import approval, cbor, policy

from .refusal_log import RefusalLog, RefusalLogEntry
from .nonrepudiation import RefusalOutcome, refusal_outcome_for_reason, sign_refusal_record
from .nonrepudiation import RefusalDecisionRecord


class HITLError(approval.ApprovalError):
    """A named, fail-closed HITL-layer error. Most kinds are the reused Part-1 approval kinds
    (AlreadyConsumed, ApprovalExpired, ApprovalMismatch, AudienceMismatch, BadSignature,
    ApprovalRequired) raised directly by naalp.approval and never re-wrapped; this subclass
    exists only for the HITL-specific outcome that has no Part-1 analogue: ApprovalDenied (the
    human operator declined)."""


def default_clock_ms() -> int:
    """The wall clock in epoch milliseconds -- the same unit as ApprovalRecord.not_after."""
    return int(time.time() * 1000)


@dataclass(frozen=True)
class ApprovalRequest:
    """R1.3 the approval UI contract: exactly what a human sees before approving an action --
    the effect class, the exact content id of the args being approved, the action's kind, a
    human-readable summary of the args, and the audience (use context) the approval must name
    to be valid here. Transport-agnostic by construction: this one structure is all any front
    end (terminal here; web/chat pluggable later, per HumanInterface) needs to render."""

    content_id: bytes
    effect: int
    kind: str
    args_summary: str
    audience: str


@dataclass(frozen=True)
class PendingAction:
    """An effecting action paused for human approval. `args` is the exact canonical CBOR value
    (a naalp.cbor Value, e.g. cbor.M([...])) that this action's approval binds by content id
    (design.md Sec.7.1): changing any argument changes the content id, so an approval cannot be
    replayed against different arguments (ApprovalMismatch, enforced by naalp.approval).
    `execute` performs the real side effect and is invoked ONLY after a valid, single-use,
    audience-bound approval has been consumed -- never before, and never on any rejection.
    `principal` (D6) is the requesting party/principal that asked for this action -- the AU-3
    "source" field of any refusal-log entry a refusal of this action produces; "" when the
    caller supplies none (an honest absence, never a fabricated identity)."""

    kind: str
    effect: int
    args: object
    execute: Callable[[], object]
    args_summary: str = ""
    principal: str = ""


class HumanInterface:
    """R1.3 the pluggable human-operator interface contract. A front end implements exactly one
    method: given an ApprovalRequest, either return a signed (ApprovalRecord, signature) pair
    when the human approves, or None when the human declines. `TerminalFrontend` (frontend.py)
    is the only front end this task builds; a future web or chat front end plugs in against
    this identical contract without any change to HITLInterceptor."""

    def request_approval(
        self, request: ApprovalRequest
    ) -> Optional[Tuple["approval.ApprovalRecord", bytes]]:
        raise NotImplementedError


class HITLInterceptor:
    """R1: pause an effecting action requiring approval, route it to a human interface, and
    resume only on a real, verified, single-use N-AALP approval -- fail-closed on any failure,
    with no state change on rejection. All cryptography and ledger logic is delegated to the
    real Part-1 `naalp.approval` primitive (see module docstring).

    D6: `refusal_log` is REQUIRED (no default, exactly like `human_interface`) -- an interceptor
    cannot be constructed without a durable AU-3 audit sink, which is the whole point of closing
    this gap. `signing_alg`/`signing_seed` are OPTIONAL: when both are supplied, refusals of
    actions at/above `non_repudiation_threshold` also mint an AU-10 signed refusal-decision
    record (Layer 2); when either is absent, Layer 2 never runs and only Layer 1 logs (never a
    fabricated signature)."""

    def __init__(
        self,
        ledger,
        approver_alg: int,
        approver_pubkey: bytes,
        audience: str,
        identity: str,
        human_interface: HumanInterface,
        refusal_log: RefusalLog,
        approval_threshold: int = policy.NON_IDEMPOTENT_WRITE,
        clock: Callable[[], int] = default_clock_ms,
        signing_alg: Optional[int] = None,
        signing_seed: Optional[bytes] = None,
        non_repudiation_threshold: int = policy.DESTRUCTIVE,
    ):
        self._ledger = ledger
        self._approver_alg = approver_alg
        self._approver_pubkey = approver_pubkey
        self._audience = audience
        self._identity = identity
        self._human_interface = human_interface
        self._refusal_log = refusal_log
        self._approval_threshold = approval_threshold
        self._clock = clock
        self._signing_alg = signing_alg
        self._signing_seed = None if signing_seed is None else bytes(signing_seed)
        self._non_repudiation_threshold = non_repudiation_threshold

    def now_ms(self) -> int:
        """The interceptor's own clock, in epoch milliseconds (the unit ApprovalRecord.not_after
        and consume_approval's pos_time both use)."""
        return self._clock()

    def requires_approval(self, effect: int) -> bool:
        """R1.1: an effecting action's effect class requires human approval when it meets or
        exceeds the configured threshold -- by default policy.NON_IDEMPOTENT_WRITE, matching
        design.md's HITL trigger set {non_idempotent_write, destructive}. An action below the
        threshold (read_only / idempotent_write by default) is not gated at all."""
        return effect >= self._approval_threshold

    def requires_non_repudiation(self, effect: int) -> bool:
        """D6 Layer 2 trigger: a refusal of an action whose required effect meets or exceeds
        `non_repudiation_threshold` (default policy.DESTRUCTIVE) is eligible for a signed
        refusal-decision record -- mirroring `requires_approval`'s own threshold predicate.
        Eligibility alone does not mint a record: `_on_refusal` also requires a signing key to
        be configured (fail-closed, never a fabricated signature)."""
        return effect >= self._non_repudiation_threshold

    def _on_refusal(self, err, *, kind, args_content_id, required_effect, approver_identity, source_principal):
        """D6: persist the AU-3 structured-log entry for this refusal (Layer 1, unconditional --
        run BEFORE the error propagates), and -- only when a signing key is configured AND
        `required_effect` meets or exceeds the non-repudiation threshold -- also mint a signed
        RefusalDecisionRecord and derive the party-visible coarse Refusal from it (Layer 2).
        Attaches the result as `err.d6` (a RefusalOutcome) and returns `err` for the caller to
        raise. Fail-closed: if `self._refusal_log.record()` itself raises, that exception
        propagates in place of `err` (never silently swallowed -- either way no code path here
        ever reaches `action.execute()`), and Layer 2 is never partially applied -- it is either
        a real signed record + signature + Refusal together, or none of the three."""
        when_ms = self._clock()
        entry = RefusalLogEntry(
            what_kind=kind,
            what_content_id=bytes(args_content_id).hex(),
            when_ms=when_ms,
            where_identity=self._identity,
            where_audience=self._audience,
            source_principal=source_principal or "",
            outcome_reason=err.kind,
            approver_identity=approver_identity or "",
        )
        self._refusal_log.record(entry)  # persist-before-propagate; a fault here propagates, not err

        record = sig = refusal = None
        if self._signing_alg is not None and self._signing_seed is not None \
                and self.requires_non_repudiation(required_effect):
            record = RefusalDecisionRecord(
                what_kind=kind,
                what_content_id=bytes(args_content_id),
                when_ms=when_ms,
                where_identity=self._identity,
                where_audience=self._audience,
                source_principal=source_principal or "",
                outcome_reason=err.kind,
                approver_identity=approver_identity or "",
            )
            sig = sign_refusal_record(record, self._signing_alg, self._signing_seed)
            outcome_code = refusal_outcome_for_reason(err.kind)
            refusal = approval.refusal_from_record(outcome_code, record.bytes())

        err.d6 = RefusalOutcome(log_entry=entry, record=record, record_sig=sig, refusal=refusal)
        return err

    def intercept(self, action: PendingAction):
        """R1.1/R1.2: detect whether `action` needs approval; if not, execute it immediately.
        If it does, PAUSE by computing the exact args content id and routing an ApprovalRequest
        to the human interface (this call blocks until the human interface returns -- the
        'pause the execution thread' requirement), then verify+consume the returned approval
        object. RESUME (call action.execute()) happens on exactly one code path, reached only
        after a successful consume; every other path raises (with a D6 audit entry attached,
        see _on_refusal) and never calls action.execute()."""
        if not self.requires_approval(action.effect):
            return action.execute()

        args_id = cbor.content_id(action.args)
        request = ApprovalRequest(
            content_id=args_id,
            effect=action.effect,
            kind=action.kind,
            args_summary=action.args_summary or action.kind,
            audience=self._audience,
        )
        decision = self._human_interface.request_approval(request)  # PAUSE: blocks for the human
        if decision is None:
            err = HITLError(
                "ApprovalDenied", "the human operator declined to approve %r" % (action.kind,)
            )
            raise self._on_refusal(
                err, kind=action.kind, args_content_id=args_id, required_effect=action.effect,
                approver_identity="", source_principal=action.principal,
            )
        record, sig = decision
        self.verify_and_consume(  # only past this line: RESUME
            record, sig, args_id, action.effect, kind=action.kind, principal=action.principal,
        )
        return action.execute()

    def verify_and_consume(self, record, sig, args_content_id, required_effect, pos_time=None,
                            *, kind="", principal=""):
        """R1.2: verify the approval's audience, signature, args binding, expiry, and effect
        ceiling, then consume it EXACTLY ONCE through the real atomic Part-1 ledger. Raises the
        named naalp.approval.ApprovalError (AudienceMismatch / BadSignature / ApprovalMismatch /
        ApprovalExpired / ApprovalRequired / AlreadyConsumed) on any failure; a rejection at any
        of these steps appends nothing to the ledger (fail-closed, no partial state change).
        `pos_time` defaults to this interceptor's own clock (never a clock the approver or the
        caller supplies) -- pass it explicitly only for deterministic testing. `kind`/`principal`
        (D6, both optional, "" default) are the AU-3 "what"/"source" context this call has no
        other way to learn when invoked directly (not via `intercept()`); on any raise here, the
        D6 audit entry is recorded (see _on_refusal) before the error propagates."""
        pos_time = self._clock() if pos_time is None else pos_time
        try:
            # Audience is checked BEFORE the ledger is ever touched (design.md Sec.2.5.3's
            # unbypassable point-of-use gate): a wrong-audience approval causes no state change.
            approval.verify_audience(record, self._audience)
            return approval.consume_approval(
                record,
                self._approver_alg,
                self._approver_pubkey,
                sig,
                args_content_id,
                pos_time,
                required_effect,
                self._ledger,
                self._identity,
            )
        except approval.ApprovalError as err:
            raise self._on_refusal(
                err, kind=kind, args_content_id=args_content_id, required_effect=required_effect,
                approver_identity=record.approver, source_principal=principal,
            )
