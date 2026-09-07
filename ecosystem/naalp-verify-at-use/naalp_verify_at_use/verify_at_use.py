# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""The N-AALP verify-at-use guard (Part-2 E6.1, requirement R12.1; evidence-layer primitives).

An effecting object's authorization is judged valid at the moment it was ISSUED (or at the
moment an interceptor RECEIVED it). Neither moment is the moment that matters: by the time
the action actually EXECUTES, the same grant/approval may have expired, been consumed by a
concurrent caller, had its signing key revoked, or be presented outside the audience it was
scoped to. verify-at-use wraps the execute boundary and re-runs the FULL authorization check
-- signature, args binding, expiry, key-liveness, effect ceiling, single-use -- against a
clock supplied AT THE INSTANT OF USE, never the approver's clock and never a clock read
earlier in the request's lifetime. This is:

  * min-over-path authority: the action's required effect is checked against the approval's
    granted ceiling (the C5 lattice, naalp.policy.authorizes) at use-time, not issuance-time --
    the effective authority a caller actually gets to exercise is the minimum of "what was
    granted" and "what still holds right now";
  * single-use-at-settlement: the approval is consumed exactly once, atomically, at the same
    instant execution is authorized (naalp.approval.Ledger.consume) -- not at receipt, not
    speculatively, so two concurrent uses of the same approval can never both execute.

This module performs NO cryptography, NO CBOR encoding, and NO ledger bookkeeping itself.
Every check is delegated to the real Part-1 primitives:
  * naalp.approval.verify_audience / consume_approval (which internally calls verify_approval
    -> real deterministic ML-DSA verification via naalp.cose, the args-content-id binding, and
    expiry) and naalp.approval.Ledger (the real durable, hash-chained, single-writer atomic
    consume set) -- exactly the ledger graded against vectors/approval/cases.json.
  * naalp.identity.signer_id / revoked_at (the real self-certifying signer id and the real
    §5.3 key-revocation liveness check) -- exactly the identity primitive graded against
    vectors/identity/cases.json.
  * naalp.cbor.content_id (the real deterministic-CBOR args binding) and naalp.policy
    (the real C5 effect lattice).
Nothing here re-derives or re-approximates any of them.

Distinct from naalp_hitl.HITLInterceptor (E0.1): HITL pauses an action for a HUMAN decision
before it has ever been authorized. verify_at_use involves no human at all -- it RE-CHECKS an
authorization that may already have been granted (by a human, by policy, or by any other
issuer) at the moment the action is about to run, so a grant that was good a millisecond ago
cannot be relied upon a millisecond later. The two compose: an interceptor that gates on a
human decision can (and, per R12.1, SHOULD) route its resulting approval through a
VerifyAtUseGuard immediately before executing, rather than trusting the decision it already
made.
"""
from . import _bootstrap  # noqa: F401  (repo-relative sys.path setup; must run before `naalp` imports)

import time
from dataclasses import dataclass
from typing import Callable, Dict, Optional

from naalp import approval, cbor, identity  # noqa: F401 (identity re-exported for callers)


def default_clock_ms() -> int:
    """The wall clock in epoch milliseconds -- the same unit ApprovalRecord.not_after and
    identity.RevocationRecord.not_after both use. This is deliberately a FUNCTION, not a
    module-level constant: every check in this module takes its notion of "now" from a call
    made at the instant of use, never a value captured earlier and carried forward."""
    return int(time.time() * 1000)


@dataclass(frozen=True)
class GuardedAction:
    """An effecting action whose authorization MUST be re-verified at the instant it actually
    runs. `args` is the exact canonical CBOR value (a naalp.cbor Value, e.g. cbor.M([...]))
    the approval binds by content id (design.md §7.1): changing any argument changes the
    content id, so an approval cannot be replayed against different arguments
    (ApprovalMismatch, enforced by naalp.approval). `run` performs the real side effect and is
    invoked ONLY after every use-time check below has held -- never before, and never on any
    rejection."""

    args: object
    effect: int
    run: Callable[[], object]
    kind: str = ""


class VerifyAtUseGuard:
    """R12.1: wraps the execute boundary for ANY effecting action -- not only human-gated ones
    (naalp_hitl.HITLInterceptor is the sibling primitive that adds a human pause in FRONT of
    an authorization; this guard re-checks an authorization that already exists, at the moment
    it is about to be spent). Every check below is evaluated against a USE-TIME instant (the
    guard's own injected clock, or an explicit `pos_time` for deterministic testing) -- never
    a clock the approver, a prior interceptor, or the caller supplies:

      1. key liveness   -- the approver's signing key is not revoked as of use-time
                            (naalp.identity.revoked_at)                          -> "KeyRevoked"
      2. audience       -- the approval's OPTIONAL audience, if named, matches this guard's
                            audience (naalp.approval.verify_audience)             -> "AudienceMismatch"
      3. signature       -- the approval verifies under the approver's registered key
                            (naalp.approval.verify_approval, inside consume_approval)
                                                                                    -> "BadSignature"
      4. args binding    -- the approval's `approves` equals this action's args content id
                            (naalp.approval.verify_approval)                       -> "ApprovalMismatch"
      5. expiry          -- the approval is not past its not_after AT USE-TIME
                            (naalp.approval.verify_approval)                       -> "ApprovalExpired"
      6. effect ceiling  -- the granted effect covers the action's required effect
                            (naalp.policy.authorizes, inside consume_approval)     -> "ApprovalRequired"
      7. single-use      -- the approval has not already been consumed, and this consume is
                            atomic under the ledger's one lock (naalp.approval.Ledger.consume)
                                                                                    -> "AlreadyConsumed"

    `GuardedAction.run()` is called on EXACTLY ONE code path: after every one of the seven
    checks above has held. Every rejection is fail-closed: it raises the named error and
    causes NO state change (in particular, no ledger append -- consume() only appends on the
    single winning path, per §7.2)."""

    def __init__(
        self,
        ledger,
        approver_alg: int,
        approver_pubkey: bytes,
        audience: str,
        identity_id: str,
        revocations: Optional[Dict[str, "identity.RevocationRecord"]] = None,
        clock: Callable[[], int] = default_clock_ms,
    ):
        self._ledger = ledger
        self._approver_alg = approver_alg
        self._approver_pubkey = approver_pubkey
        self._audience = audience
        self._identity = identity_id
        # Already-verified revocation records this guard trusts, keyed by the revoked signer's
        # id string -- the same shape as naalp.delegation.verify_chain's `revoked` parameter
        # (a map of already-established revocation facts, not raw untrusted signed objects;
        # verifying an incoming RevocationRecord's OWN signature, via
        # naalp.identity.verify_revocation, is the caller's job at ingestion time, not this
        # guard's -- exactly as a delegation caller resolves `revoked` before calling
        # verify_chain).
        self._revocations = dict(revocations) if revocations else {}
        self._clock = clock

    def now_ms(self) -> int:
        """This guard's own clock, in epoch milliseconds -- the unit every check above uses."""
        return self._clock()

    def execute(self, action: GuardedAction, record, sig, pos_time: Optional[int] = None):
        """Re-verify `record`/`sig` against `action` at USE-TIME (the guard's clock, or the
        given `pos_time` for deterministic testing), then run the action. Raises the specific
        named naalp error on any failure; `action.run()` is reached only past a fully
        successful re-verify+consume."""
        pos_time = self._clock() if pos_time is None else pos_time
        args_id = cbor.content_id(action.args)
        self.verify_and_consume(record, sig, args_id, action.effect, pos_time)  # RESUME only past this line
        return action.run()

    def verify_and_consume(self, record, sig, args_content_id, required_effect, pos_time: Optional[int] = None):
        """The composed re-verification choke point, usable directly (as
        naalp_hitl.HITLInterceptor.verify_and_consume is) for tests or callers that already
        have their own args content id. Runs, in fail-closed order, key-liveness -> audience ->
        signature/binding/expiry/effect-ceiling/single-use-consume (the last five delegated
        whole to naalp.approval.consume_approval, the one impl-owned place that orders them).
        A rejection at any step touches the ledger not at all."""
        pos_time = self._clock() if pos_time is None else pos_time

        # 1. Key liveness, BEFORE the approval-layer checks or the ledger are ever touched: an
        #    approval signed under a key that has since been revoked is not live authority no
        #    matter how fresh the approval's own not_after looks.
        approver_id = identity.signer_id(self._approver_alg, self._approver_pubkey)
        revocation = self._revocations.get(approver_id)
        if revocation is not None and identity.revoked_at(revocation, pos_time):
            raise approval.ApprovalError("KeyRevoked", "approver key is revoked as of use-time")

        # 2. Audience, BEFORE the ledger is touched (design.md §2.5.3's unbypassable
        #    point-of-use gate): a wrong-audience approval causes no state change.
        approval.verify_audience(record, self._audience)

        # 3-7. Signature / args binding / expiry / effect ceiling / atomic single-use consume,
        #    all judged against pos_time -- the use-time instant, never issuance time.
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

    def register_revocation(self, revoked_signer_id: str, record: "identity.RevocationRecord") -> None:
        """Record an ALREADY-VERIFIED key-revocation fact this guard will honor from now on.
        `record` MUST already have passed naalp.identity.verify_revocation (this guard does
        not re-verify a revocation's own signature -- that is the ingestion-time caller's job,
        exactly as a delegation caller verifies a grant before adding it to its GrantSet)."""
        self._revocations[revoked_signer_id] = record
