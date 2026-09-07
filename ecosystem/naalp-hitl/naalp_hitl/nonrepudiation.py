# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""D6 Layer 2 -- AU-10 non-repudiation for the N-AALP HITL interceptor: a durable,
cryptographically-signed refusal-decision record for refusals of high-stakes actions, and the
party-visible coarse `naalp.approval.Refusal` derived from it.

This module mints NO new object kind and re-derives NO cryptography: `RefusalDecisionRecord`
carries the same six AU-3 fields as `refusal_log.RefusalLogEntry` (what/when/where/source/
outcome/identity), canonical-CBOR encoded and signed with the interceptor's OWN identity key
using the real deterministic ML-DSA signing primitive (`naalp.cose.mldsa_sign`) -- the exact
signing idiom `naalp.approval` already uses for `sign_approval` / `sign_held` /
`sign_consume_receipt`: the body bytes are signed directly (no COSE_Sign1 Sig_structure
wrapping), so this record fits the same family of "signed record" objects `naalp.approval`
defines rather than inventing a second signing convention.

The party-visible coarse view is built with the REUSED, registered R-TDCS-3 primitive
(`naalp.approval.refusal_from_record` / `.parse_refusal` / the closed `REFUSAL_DENIED` /
`REFUSAL_HELD` / `REFUSAL_UNVERIFIABLE` outcome set): the full signed record carries the
discriminating detail, and the coarse `Refusal` carries only the outcome and the record's
content id -- never the detail itself -- exactly the closure property R-TDCS-3 requires.
"""
from dataclasses import dataclass
from typing import Optional

from naalp import approval, cbor, cose
from naalp.cbor import U, B, T, M


@dataclass(frozen=True)
class RefusalDecisionRecord:
    """The AU-10 full signed refusal-decision record: the six AU-3 fields, canonical-CBOR
    encoded {1..8}. Signed by the interceptor's own identity key (`sign_refusal_record`); its
    content id is the value `naalp.approval.Refusal.record` references (R-TDCS-3) -- the coarse
    party-visible view never carries any of these fields directly."""

    what_kind: str
    what_content_id: bytes
    when_ms: int
    where_identity: str
    where_audience: str
    source_principal: str
    outcome_reason: str
    approver_identity: str

    def bytes(self) -> bytes:
        """Deterministic-CBOR encoding {1: what_kind, 2: what_content_id, 3: when_ms,
        4: where_identity, 5: where_audience, 6: source_principal, 7: outcome_reason,
        8: approver_identity}."""
        return cbor.encode(M([
            (U(1), T(self.what_kind)),
            (U(2), B(self.what_content_id)),
            (U(3), U(self.when_ms)),
            (U(4), T(self.where_identity)),
            (U(5), T(self.where_audience)),
            (U(6), T(self.source_principal)),
            (U(7), T(self.outcome_reason)),
            (U(8), T(self.approver_identity)),
        ]))

    def content_id(self) -> bytes:
        """The record's content id (multihash SHA-384 over `bytes()`) -- the value a
        `naalp.approval.Refusal` built from this record references (R-TDCS-3)."""
        return cbor.content_id(self.bytes())


def sign_refusal_record(rec: RefusalDecisionRecord, alg: int, seed: bytes) -> bytes:
    """Sign the refusal-decision record body with a real deterministic ML-DSA key derived from
    `seed` -- the same signing idiom as `naalp.approval.sign_approval` (raw body bytes, no COSE
    Sig_structure wrapping)."""
    return cose.mldsa_sign(alg, seed, rec.bytes())


def verify_refusal_record(rec: RefusalDecisionRecord, alg: int, pubkey: bytes, sig: bytes) -> bool:
    """Verify a refusal-decision record's signature under the interceptor's registered public
    key. Mirrors `naalp.cose.cose_verify1_raw` usage throughout `naalp.approval`."""
    return cose.cose_verify1_raw(alg, pubkey, rec.bytes(), sig)


# ---- reason -> closed-set outcome mapping ------------------------------------------------------
#
# naalp.approval defines a closed three-value outcome set: REFUSAL_DENIED / REFUSAL_HELD /
# REFUSAL_UNVERIFIABLE (R-TDCS-3). The interceptor produces several distinct
# naalp.approval.ApprovalError.kind / naalp_hitl.HITLError.kind values, and each must map onto
# exactly one of the three:
#
#   ApprovalRequired  -> HELD        the approval PRESENTED did not authorize this action (its
#                                     granted effect does not cover the required effect -- an
#                                     under-scoped grant), or its grant value was outside the
#                                     closed 0..3 vocabulary. Both are literally "an approval
#                                     [of sufficient scope] is required" -- the interceptor's own
#                                     Part-1 error name says so -- and are resolved by a FURTHER
#                                     step (obtaining a properly-scoped approval), which is
#                                     exactly what HELD means (design.md/naalp.approval doc:
#                                     "the action requires a further step not yet taken").
#
#   BadSignature       -> UNVERIFIABLE  the presented cryptographic evidence (the approval
#                                       signature) did not verify -- literally "required
#                                       evidence did not verify."
#
#   Every other kind    -> DENIED    ApprovalDenied (the human operator explicitly declined),
#                                     AlreadyConsumed (this exact approval's one permitted use is
#                                     already spent -- no amount of waiting revives it),
#                                     ApprovalMismatch (this approval does not bind these args),
#                                     AudienceMismatch (this approval does not name this
#                                     audience), and ApprovalExpired (this approval's validity
#                                     window has closed) are all TERMINAL for the exact approval
#                                     object presented: re-presenting the SAME object can never
#                                     later succeed, which is the defining property of DENIED as
#                                     opposed to HELD (a state a further step CAN resolve).
#
# Design note (recorded per the task's honesty requirement): a literal reading of one clause in
# this task's own brief ("a human decline / effect-ceiling -> denied") could be misread as
# routing the under-scoped-grant case (raised as ApprovalRequired) to DENIED, which would
# directly contradict the SAME brief's very next clause ("an ApprovalRequired/held state ->
# held"). Both clauses describe the one ApprovalRequired raise site in
# naalp.approval.consume_approval (there is no second, separate "held" error kind anywhere in
# this codebase), so they cannot both be followed literally. This module resolves the conflict
# by keeping ApprovalRequired -> HELD, because (a) it is the second clause's explicit, named
# instruction, (b) it matches the Part-1 error's own name, and (c) it is the only reading under
# which every one of the three REFUSAL_* outcomes is reachable at all -- the DENIED-only reading
# would leave REFUSAL_HELD permanently unreachable from this interceptor, which cannot be the
# intended design of a THREE-value closed outcome set.

_HELD_KINDS = frozenset({"ApprovalRequired"})
_UNVERIFIABLE_KINDS = frozenset({"BadSignature"})


def refusal_outcome_for_reason(kind: str) -> int:
    """Map one interceptor refusal-reason kind to the closed R-TDCS-3 outcome set. See the
    module-level note above for the exact mapping and why it was chosen."""
    if kind in _HELD_KINDS:
        return approval.REFUSAL_HELD
    if kind in _UNVERIFIABLE_KINDS:
        return approval.REFUSAL_UNVERIFIABLE
    return approval.REFUSAL_DENIED


@dataclass(frozen=True)
class RefusalOutcome:
    """What D6 produced for one refusal, attached to the raised error as `.d6`. `log_entry` is
    always present (Layer 1 runs on every refusal). `record` / `record_sig` / `refusal` are
    `None` together, or a real signed record / signature / coarse `Refusal` together --
    Layer 2 either fully applies or is fully absent, never partially (fail-closed: never a
    fabricated or partial signature)."""

    log_entry: object  # naalp_hitl.refusal_log.RefusalLogEntry
    record: Optional[RefusalDecisionRecord] = None
    record_sig: Optional[bytes] = None
    refusal: Optional["approval.Refusal"] = None
