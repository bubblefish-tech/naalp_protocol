# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""The N-AALP A2A agent-coordination bridge (Part-2 ecosystem task E2.2, requirements
R4.1/R4.2/R4.3; design.md sec22 "Name bindings and the A2A task-state profile", sec21.5/22.5 for
the card attestation).

A developer working against an A2A (Agent2Agent) stack holds two FOREIGN-NATIVE things: an A2A
Agent Card (raw bytes, whatever their client fetched from a card endpoint) and an ordered
sequence of TaskStatusUpdateEvent-shaped observations of one task's lifecycle -- a task id and
an A2A TaskState STRING ("submitted", "working", "input-required", "auth-required", "completed",
"canceled", "failed", "rejected"; A2A sec4.1.3), never an N-AALP wire code. This module maps
BOTH onto N-AALP's own signed, receipt-chained wire objects and back, reusing `naalp.naming` and
`naalp.description` for every cryptographic and encoding operation this package performs --
ML-DSA signing/verification, deterministic-CBOR body encoding, the T1 content-id framing, the
receipt-chain (prev/seq) construction, the A2A legal-edge table, and the confused-deputy
importer check are ALL the real Part-1 primitives, never re-implemented here.

This module's own value-add -- the part with no Part-1 analogue -- is exactly the boundary
crossing:

  - `bridge_card` / `verify_card`: wrap a raw A2A Agent Card into a signed C18
    naalp-description-import (carriage, not adoption: the card bytes are carried octet-for-octet,
    R-14.4) attesting the caller's OWN N-AALP effect/approval mapping for its skills -- an
    adoption decision the card itself carries no opinion on -- and recover the exact original
    card bytes back out of a verified attestation.
  - `bridge_activity` / `verify_activity`: translate an ordered A2A task-state-name-string
    activity into a signed naalp-task-transition chain bound to a card's scope, checking every
    edge against the real Part-1 A2A legal-edge table BEFORE it is ever signed, and recover the
    exact original state-name-string activity back out of a verified chain.
  - `verify_and_recover`: the combined entry point (R4.1-4.3) that independently verifies the
    card attestation FIRST and derives the task chain's bound scope from THAT verification's own
    content-id -- never from a caller-supplied bare card-id value the bridge would otherwise have
    to trust blindly (the same non-circular discipline naalp_bundle enforces for its trust
    anchor: authority comes from an independent verification, never from a value the artifact
    under test merely asserts about itself).

Every check is fail-closed (design sec15): a failing object is rejected whole, returns its named
error, and causes no state change. Most failure kinds are the real Part-1 errors (BadSignature,
IllegalTransition, TaskChainBroken, ForeignCard, NameMalformed, ImporterMismatch,
UnknownDescriptionFormat, DescMalformed, MalformedApprovalFlag, ...) raised directly by
`naalp.naming` / `naalp.description` and never re-wrapped here; `A2ABridgeError` exists only for
the outcomes that have no Part-1 analogue, because they happen strictly on the foreign-native
side of the boundary, before any N-AALP wire bytes exist: an unrecognized A2A TaskState string,
an empty activity, and a multi-task activity presented as one chain.
"""
from . import _bootstrap  # noqa: F401  (repo-relative sys.path setup; must run before `naalp` imports)

from dataclasses import dataclass
from typing import List, Sequence, Tuple

from naalp import cose, description, identity, naming


class A2ABridgeError(naming.NamingError):
    """A named, fail-closed A2A-bridge-layer error; .kind is the stable error kind. Exists only
    for outcomes with no Part-1 analogue (see module docstring); every other outcome is a real
    naalp.naming.NamingError or naalp.description.DescriptionError, raised directly."""


# The A2A TaskState vocabulary (design sec22.4; A2A sec4.1.3) -- the foreign-native string form,
# mapped onto naalp.naming's closed integer state codes. naalp.naming itself never sees a string;
# this table (and its exact reverse, naming.state_name) is this bridge's own contribution.
_STATE_BY_NAME = {
    "submitted": naming.STATE_SUBMITTED,
    "working": naming.STATE_WORKING,
    "input-required": naming.STATE_INPUT_REQUIRED,
    "auth-required": naming.STATE_AUTH_REQUIRED,
    "completed": naming.STATE_COMPLETED,
    "canceled": naming.STATE_CANCELED,
    "failed": naming.STATE_FAILED,
    "rejected": naming.STATE_REJECTED,
}

_PARAM_NAME = {cose.ALG_MLDSA65: "ML-DSA-65", cose.ALG_MLDSA87: "ML-DSA-87"}


def _state_code(name: str) -> int:
    """Translate an A2A TaskState string to its N-AALP wire code. A name outside the closed A2A
    vocabulary is A2ABridgeError('UnknownTaskState', ...) -- fail-closed, never defaulted."""
    try:
        return _STATE_BY_NAME[name]
    except KeyError:
        raise A2ABridgeError("UnknownTaskState", "not an A2A TaskState name: %r" % (name,))


def _keypair(alg: int, seed: bytes) -> bytes:
    return cose.mldsa_keygen(_PARAM_NAME.get(alg, "ML-DSA-65"), seed)


@dataclass(frozen=True)
class SkillMapping:
    """One A2A skill's N-AALP effect declaration -- the importer's OWN adoption decision. An A2A
    Agent Card names skills (capabilities) but carries no C5 effect class or approval
    requirement; the importer (the party wrapping the card) attests this mapping under its own
    signature, exactly as design sec21.5/22.5 describes for the card attestation's `operations`
    field."""

    skill: str
    effect: int
    requires_approval: bool


@dataclass(frozen=True)
class ForeignTaskEvent:
    """One A2A-native task-state observation, exactly as an A2A client's TaskStatusUpdateEvent
    stream (A2A sec7.6) or a polled Task.status surfaces it: the task id and the A2A TaskState
    STRING (A2A sec4.1.3) -- never the N-AALP wire code naalp.naming actually carries."""

    task_id: str
    state: str


# ==== the card side: bridge an A2A Agent Card into a signed C18 import ===========================

def bridge_card(
    importer_seed: bytes,
    card_bytes: bytes,
    mappings: Sequence[SkillMapping],
    alg: int = cose.ALG_MLDSA65,
) -> Tuple["description.Import", bytes]:
    """Wrap a raw A2A Agent Card -- exactly the bytes an A2A client fetched from a card endpoint,
    unparsed and unmodified (carriage, not adoption, R-14.4) -- into a signed
    naalp-description-import (design sec21.2), attesting `mappings` as the caller's own N-AALP
    effect/approval declaration for the card's skills. Reuses naalp.description end to end: the
    real deterministic ML-DSA signature (naalp.cose), the real deterministic-CBOR body encoding,
    the real importer self-certification (the signer id IS the importer field, so no other party
    can forge this attestation under this key). Returns the unsigned Import (for the caller's own
    inspection -- e.g. `im.id()` is the card's bound content-id, design sec22.5) and the tagged,
    signed COSE_Sign1 wire bytes to hand to a counterparty."""
    pk = _keypair(alg, importer_seed)
    importer_id = identity.signer_id(alg, pk).encode("utf-8")
    ops = [description.Operation(m.skill, m.effect, 1 if m.requires_approval else 0) for m in mappings]
    im = description.Import(importer_id, description.FORMAT_A2A_CARD, card_bytes, ops)
    obj = description.sign_import(im, alg, importer_seed)
    return im, obj


def verify_card(
    card_obj: bytes,
    pubkey: bytes,
    alg: int = cose.ALG_MLDSA65,
    profile: int = cose.PROFILE_PUBLIC,
) -> Tuple["description.ResolvedImport", "description.Import"]:
    """Verify a signed card-import object with the real Part-1 checks (signature under the
    profile floor, the confused-deputy importer-match -- `description.verify_import`) AND recover
    the exact original A2A Agent Card bytes it carried, octet-for-octet: the R4 property this
    bridge exists to prove. `description.verify_import` itself returns only a `ResolvedImport`
    (authority id + the foreign bytes' content-id, never the foreign bytes -- by design, since
    most callers only need the hash to confirm a card they already hold); recovering the bytes
    themselves is this bridge's own value-add, done by independently decoding the SAME
    already-signature-verified payload with `description.parse_import` (pure CBOR decode, no
    additional trust placed anywhere -- the security decision was already made by verify_import
    above). Returns (ResolvedImport, Import); `Import.foreign` is the recovered card bytes,
    `Import.operation(name)` recovers one skill's declared effect/approval, `Import.id()` is the
    card's bound content-id (the scope a task-transition chain's `card` field must name)."""
    resolved = description.verify_import(card_obj, profile, alg, pubkey)  # the security check
    _, payload, _ = cose.parse_sign1_raw(card_obj)  # obj already verified above; pure decode
    im = description.parse_import(payload)          # recover the exact original bytes
    return resolved, im


# ==== the activity side: bridge an A2A task-state history onto a signed C19 chain ================

def bridge_activity(
    task_events: Sequence[ForeignTaskEvent],
    card_id: bytes,
    seed: bytes,
    alg: int = cose.ALG_MLDSA65,
) -> Tuple[List["naming.Transition"], List[bytes]]:
    """Map an ordered A2A task-state activity -- exactly the sequence of TaskState strings an A2A
    client's status-update stream surfaced -- onto N-AALP's signed, receipt-chained
    naalp-task-transition objects (design sec22.2/22.4), bound to `card_id` (the content-id of an
    already-attested C18 A2A Agent Card, design sec22.5). Every event must name the SAME task
    (A2ABridgeError('ForeignTask', ...) otherwise -- a chain is for exactly one task); the first
    transition's `from` is the A2A start state (`submitted`, design sec22.4), and each
    transition's `from` is the prior transition's `to` (an A2A client observes a task's state
    move FROM its last-known value TO the newly reported one). Each edge is checked legal BEFORE
    it is ever signed -- `naming.verify_transition`, the real Part-1 legal-edge gate -- so an
    illegal edge is refused before a single signature is spent on it, rather than deferred to
    whenever the chain is next verified. Raises A2ABridgeError('UnknownTaskState', ...) for a
    state-name string outside the closed A2A vocabulary, A2ABridgeError('EmptyActivity', ...) for
    an empty sequence, A2ABridgeError('ForeignTask', ...) for a mixed-task activity, and the real
    Part-1 naming.NamingError('IllegalTransition', ...) for an edge the A2A category rules
    forbid. Returns (the unsigned Transition objects, the tagged signed COSE_Sign1 wire bytes in
    order) -- the wire bytes are what a counterparty verifies with `verify_activity` below."""
    if not task_events:
        raise A2ABridgeError("EmptyActivity", "no task-state events to bridge")
    task_id = task_events[0].task_id
    task = task_id.encode("utf-8")
    prev = naming.genesis()
    frm = naming.START_STATE
    transitions: List["naming.Transition"] = []
    for i, ev in enumerate(task_events):
        if ev.task_id != task_id:
            raise A2ABridgeError("ForeignTask", "every event in one chain must name the same task id")
        to = _state_code(ev.state)
        t = naming.Transition(task, card_id, frm, to, i, prev)
        naming.verify_transition(t.frm, t.to)  # fail fast: the real Part-1 legal-edge gate
        transitions.append(t)
        prev = t.head()
        frm = to
    objs = [naming.sign_transition(t, alg, seed) for t in transitions]
    return transitions, objs


def verify_activity(
    activity_objs: Sequence[bytes],
    card_id: bytes,
    pubkey: bytes,
    alg: int = cose.ALG_MLDSA65,
    profile: int = cose.PROFILE_PUBLIC,
) -> Tuple[List["naming.Transition"], List["ForeignTaskEvent"]]:
    """Verify a signed task-transition chain against `card_id` with the real Part-1 verifier
    (`naming.verify_task_chain`: every transition's signature, prev/seq linkage, the card
    binding, the start state, contiguity, and the A2A legal-edge table -- all fail-closed), then
    recover the exact original foreign-native A2A task-state activity: the task id and the
    ordered TaskState-name-STRING sequence, the R4 property this bridge exists to prove.
    Recovery is lossless -- `naming.state_name` is the exact reverse of the table
    `bridge_activity` consulted to build the chain, so `verify_activity(*bridge_activity(events,
    ...))` reproduces `events` value-for-value. Returns (the verified Transition objects, the
    recovered ForeignTaskEvent sequence). `card_id` is a parameter here so this function is
    usable standalone against an already-known scope; `verify_and_recover` below is the safer
    combined entry point that derives `card_id` from an independent verification rather than
    trusting a caller-supplied value."""
    verified = naming.verify_task_chain(activity_objs, card_id, profile, alg, pubkey)
    task_id = verified[0].task.decode("utf-8")
    events = [ForeignTaskEvent(task_id, naming.state_name(t.to)) for t in verified]
    return verified, events


# ==== the combined entry point: verify both, non-circularly bind the scope ========================

def verify_and_recover(
    card_obj: bytes,
    card_pubkey: bytes,
    activity_objs: Sequence[bytes],
    task_pubkey: bytes,
    alg: int = cose.ALG_MLDSA65,
    profile: int = cose.PROFILE_PUBLIC,
):
    """The full bridge verification entry point (R4.1-4.3): given the signed card-import object
    and the signed task-transition chain, independently verify BOTH under their own keys and
    recover BOTH foreign-native representations. The task chain's card binding is checked against
    the card id THIS call itself derives from `verify_card`'s own signature-verified result --
    NEVER against a caller-supplied bare bytes value the bridge would otherwise have to trust
    blindly. That non-circularity is the point: a task-transition chain built against one card's
    scope and merely presented alongside an unrelated (even genuinely, independently valid)
    card_obj is refused (`ForeignCard`) rather than silently accepted because some bare card-id
    parameter happened to match -- the same discipline naalp_bundle's TrustAnchor enforces for
    its own independent verification (never trust an artifact's claim about itself; derive
    authority from a source you checked). Returns (ResolvedImport, recovered card bytes, the
    Import, the verified Transition objects, the recovered ForeignTaskEvent activity)."""
    resolved_card, im = verify_card(card_obj, card_pubkey, alg, profile)
    card_id = im.id()  # the bound scope, derived from the attestation THIS call just verified
    verified, events = verify_activity(activity_objs, card_id, task_pubkey, alg, profile)
    return resolved_card, im.foreign, im, verified, events
