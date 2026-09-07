# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""C21 NAALP-AGUI UI-consent binding for the Python SDK (design.md §24; R-AGUI-1..6).

NAALP-AGUI binds a human-in-the-loop approval, captured in a user-interface event stream (the AG-UI
tool-lifecycle events an agent shows a user), to the EXACT action bytes by content id, and
RECEIPT-CHAINS the shown events so the shown sequence is provable offline. It introduces NO new
envelope, encoding, signature, identity, or audit mechanism (R-11.3): a UI event is an ordinary signed
N-AALP body (COSE_Sign1, §4), and the surface reuses the C7 audit receipt-chain construction (§8.1)
unchanged -- head = SHA-384(body), genesis prev = 48 zero bytes, a monotonic seq, the prior head
carried in `prev` so editing or omitting an event breaks the next event's linkage -- and the §7
approval binding (package approval) UNCHANGED.

  - UIEvent {1: session, 2: kind, 3: action, 4: seq, 5: prev} is one shown tool-lifecycle event.
    `kind` is a closed set (shown / args-shown / approved / rejected); `action` is the T1 content id
    of the action bytes shown to the user at this step; the chain is receipt-chained by prev/seq.

The load-bearing properties, graded across implementations:

  - A UI approval verifies ONLY against the EXACT action shown. verify_consent walks the shown chain,
    takes the action content id from the shown-and-approved event, and requires the action actually
    being executed to hash to THAT content id (ActionSubstituted otherwise) AND the human approval to
    bind it (the §7 approval, ApprovalMismatch otherwise). A substituted action has a different content
    id and is rejected.
  - A removed/omitted shown-event is detected with its POSITION. walk_shown enforces contiguity and
    returns UIChainBroken on a gap; detect_hole reports the first-broken position.

Every check is fail-closed (§15). Ported from impl/go/agui; the byte surface (kind vocabulary, event
bodies/heads/ids, action content ids, the shown-chain walk, hole position, rejections) is graded
against vectors/agui/cases.json; the signed shown-chain and the consent binding use real deterministic
ML-DSA-65 and are demonstrated in isolation (the corpus carries no signed vector).
"""
import hashlib

from . import approval, cbor, cose
from .cbor import U, B, M, N

# The width of a chain head / prev link (SHA-384 = 48 bytes), matching the C7 audit chain. Genesis is
# zero.
HEAD_SIZE = 48

# UI event kinds -- the closed AG-UI tool-lifecycle set. A kind outside the set is rejected
# (UnknownUIEventKind).
KIND_SHOWN = 0        # the action / tool call was shown (rendered) to the user
KIND_ARGS_SHOWN = 1   # the arguments were shown to the user
KIND_APPROVED = 2     # the user approved the shown action
KIND_REJECTED = 3     # the user rejected the shown action

_KIND_NAMES = {KIND_SHOWN: "shown", KIND_ARGS_SHOWN: "args-shown",
               KIND_APPROVED: "approved", KIND_REJECTED: "rejected"}


class AguiError(ValueError):
    """A named, fail-closed AGUI error; .kind is the stable error kind (mirroring the Go/Rust kinds
    UIMalformed, UIChainBroken, UnknownUIEventKind, ActionSubstituted, UINoConsent, plus the reused §7
    approval + cose kinds ApprovalMismatch / ApprovalExpired / BadSignature)."""

    def __init__(self, kind, msg=""):
        super().__init__("%s: %s" % (kind, msg) if msg else kind)
        self.kind = kind


def is_known_kind(code):
    """Whether code is one of the closed UI-event kinds."""
    return code in _KIND_NAMES


def kind_name(code):
    """The kind name, or 'unknown'."""
    return _KIND_NAMES.get(code, "unknown")


def genesis():
    """A fresh 48-octet zero prev -- the empty-chain link (the C7 chain genesis)."""
    return bytes(HEAD_SIZE)


def _head(b):
    return hashlib.sha384(bytes(b)).digest()


def content_id(b):
    """T1 framing multihash(0x20, SHA-384(body)) = 0x20 0x30 || SHA-384(body) (50 octets). The content
    id of an ACTION, which a UI event names in field 3 and a human approval binds."""
    return cbor.content_id(bytes(b))


# ---- UIEvent: one receipt-chained shown tool-lifecycle event (design §24) ---------------------

class UIEvent:
    """One shown tool-lifecycle event in a UI session's event stream. It chains onto the prior event:
    `prev` is the prior event's head (genesis for seq 0). `action` is the content id of the exact
    action bytes shown to the user at this step."""

    __slots__ = ("session", "kind", "action", "seq", "prev")

    def __init__(self, session, kind, action, seq, prev):
        self.session = bytes(session)
        self.kind = int(kind)
        self.action = bytes(action)
        self.seq = int(seq)
        self.prev = bytes(prev)

    def bytes(self):
        """Deterministic-CBOR encoding {1: session, 2: kind, 3: action, 4: seq, 5: prev}."""
        return cbor.encode(M([
            (U(1), B(self.session)),
            (U(2), U(self.kind)),
            (U(3), B(self.action)),
            (U(4), U(self.seq)),
            (U(5), B(self.prev)),
        ]))

    def head(self):
        """The chain head after this event: SHA-384 of the event body (48 octets). Because the body
        carries prev, editing any event breaks the next event's linkage."""
        return _head(self.bytes())

    def id(self):
        """The event's T1 content id (50 octets)."""
        return content_id(self.bytes())


def parse_ui_event(b):
    """Reconstruct a UIEvent from its body bytes alone. A non-canonical body, a non-map, a non-uint
    key, a mistyped field, or an absent mandatory field {1,2,3,4,5} is UIMalformed. Fail-closed."""
    try:
        v = cbor.decode(bytes(b))
    except cbor.NonCanonical:
        raise AguiError("UIMalformed", "ui-event body is not well-formed deterministic CBOR")
    if not isinstance(v, M):
        raise AguiError("UIMalformed", "ui-event body is not a map")
    sess = kind = action = seq = prev = None
    for k, val in v.pairs:
        if not isinstance(k, U):
            raise AguiError("UIMalformed", "non-uint ui-event key")
        if k.v == 1 and isinstance(val, B):
            sess = val.v
        elif k.v == 2 and isinstance(val, U):
            kind = val.v
        elif k.v == 3 and isinstance(val, B):
            action = val.v
        elif k.v == 4 and isinstance(val, U):
            seq = val.v
        elif k.v == 5 and isinstance(val, B):
            prev = val.v
        else:
            raise AguiError("UIMalformed", "unknown or mistyped ui-event field")
    if sess is None or kind is None or action is None or seq is None or prev is None:
        raise AguiError("UIMalformed", "ui-event body missing a mandatory field")
    return UIEvent(sess, kind, action, seq, prev)


def sign_ui_event(e, alg, seed):
    """Produce the tagged COSE_Sign1 object over the event body (real deterministic ML-DSA)."""
    return cose.cose_sign1(alg, seed, _protected_header(alg), e.bytes())


def verify_ui_event(obj, profile, alg, pubkey):
    """Verify the event's full signature under the profile, reconstruct it from the signed body bytes,
    and validate the kind against the closed set (UnknownUIEventKind). A bad signature propagates
    BadSignature. Fail-closed."""
    payload = _verify_sign1(obj, profile, alg, pubkey)
    e = parse_ui_event(payload)
    if not is_known_kind(e.kind):
        raise AguiError("UnknownUIEventKind", "ui-event kind is outside the closed set")
    return e


# ---- the shown chain: contiguity, walk, hole detection (mirrors the C7 chain) -----------------

class ShownEvent:
    """One step of a walked shown chain: the chain position, the event kind, the action content id
    shown, and the chain head after it."""

    __slots__ = ("seq", "kind", "action", "head")

    def __init__(self, seq, kind, action, head):
        self.seq = seq
        self.kind = kind
        self.action = bytes(action)
        self.head = bytes(head)


def walk_shown(events):
    """Verify a UI event chain's structural continuity OFFLINE (no signatures) and return the ordered
    shown events. It requires every event to name the SAME session, seq i to equal its index, each
    kind to be in the closed set, and prev to link to the previous event's head (genesis for seq 0). A
    gap, reorder, omitted event, or a session change is UIChainBroken (fail-closed); an unknown kind is
    UnknownUIEventKind."""
    out = []
    h = genesis()
    session = None
    for i, e in enumerate(events):
        if i == 0:
            session = e.session
        elif e.session != session:
            raise AguiError("UIChainBroken", "a chain is for exactly one session")
        if not is_known_kind(e.kind):
            raise AguiError("UnknownUIEventKind", "ui-event kind is outside the closed set")
        if e.seq != i or e.prev != h:
            raise AguiError("UIChainBroken", "ui-event prev/seq does not chain to the previous event")
        h = e.head()
        out.append(ShownEvent(e.seq, e.kind, e.action, h))
    return out


def verify_shown_chain(objs, profile, alg, pubkey):
    """Check a UI event chain offline against the UI authority's key. Each element is the tagged
    COSE_Sign1 object for one event; verify every signature under the profile (verify_ui_event), then
    enforce the same structural continuity as walk_shown. A bad signature propagates BadSignature; a
    broken link, seq gap, or session change is UIChainBroken. Detects any reorder, omission, or
    substitution of a shown event (§8.1). Fail-closed."""
    h = genesis()
    session = None
    out = []
    for i, obj in enumerate(objs):
        e = verify_ui_event(obj, profile, alg, pubkey)
        if i == 0:
            session = e.session
        elif e.session != session:
            raise AguiError("UIChainBroken", "a chain is for exactly one session")
        if e.seq != i or e.prev != h:
            raise AguiError("UIChainBroken", "ui-event prev/seq does not chain to the previous event")
        h = e.head()
        out.append(e)
    return out


def detect_hole(events):
    """Report whether a presented (possibly gappy) event list breaks contiguity -- a deleted/omitted
    shown-event -- and, if so, the FIRST-BROKEN POSITION: the index i where the i-th presented event's
    seq is not i or its prev does not link to the previous event's head. A contiguous list returns
    (0, False)."""
    h = genesis()
    for i, e in enumerate(events):
        if e.seq != i or e.prev != h:
            return i, True
        h = e.head()
    return 0, False


# ---- the UI consent binding (reuses the §7 approval) ------------------------------------------

def approved_action_cid(shown):
    """The content id of the action shown-and-approved in a walked chain, and whether an approved event
    is present. It is the content id a valid consent binds; a chain with no approved event has no
    consent to bind."""
    for ev in shown:
        if ev.kind == KIND_APPROVED:
            return bytes(ev.action), True
    return None, False


def verify_consent(chain, action_bytes, appr, approver_alg, approver_pubkey, appr_sig, now):
    """Bind a human-in-the-loop approval to the EXACT action shown in a UI event stream. It (1) walks
    the shown chain, rejecting any gap/reorder/omission (UIChainBroken); (2) takes the action content
    id from the shown-and-approved event (UINoConsent if there is none); (3) verifies the human §7
    approval binds THAT shown content id and has not expired (ApprovalMismatch / ApprovalExpired /
    BadSignature, from packages approval and cose); and (4) requires the action actually being executed
    (`action_bytes`) to hash to the shown-and-approved content id -- a SUBSTITUTED action has a
    different content id and is rejected (ActionSubstituted). Every failure returns its named error and
    authorizes nothing (fail-closed). On success the caller may execute exactly `action_bytes`."""
    shown = walk_shown(chain)                       # UIChainBroken / UnknownUIEventKind on a hole
    shown_cid, ok = approved_action_cid(shown)
    if not ok:
        raise AguiError("UINoConsent", "the shown chain carries no approved event")
    # The human approval must be a valid signature binding the shown-and-approved action content id.
    approval.verify_approval(appr, approver_alg, approver_pubkey, appr_sig, shown_cid, now)
    # The action actually being executed MUST be the exact one shown and approved: a substitution has a
    # different content id and is rejected. This is the seam a lax UI profile would drop.
    if content_id(action_bytes) != shown_cid:
        raise AguiError("ActionSubstituted", "the executed action is not the exact action shown+approved")
    return None


# ---- signing / verification helpers (COSE_Sign1 with the bare {1: alg} header) ------------------

def _protected_header(alg):
    """The bare {1: alg} COSE_Sign1 protected header (§4), as the reference cose.Sign1 emits."""
    return cbor.encode(M([(U(1), N(alg))]))


def _verify_sign1(obj, profile, alg, pubkey):
    """Verify a tagged COSE_Sign1 object under the profile floor with real crypto and return the
    payload. Mirrors the shared verify: alg registry, profile floor, key-alg match, signature.
    Fail-closed with a named AguiError."""
    prot, payload, sig = cose.parse_sign1_raw(obj)
    halg = _alg_from_protected(prot)
    level, known = cose.alg_level(halg)
    if not known:
        raise AguiError("UnknownAlg", "unregistered alg %d" % halg)
    if level < cose.profile_min_level(profile):
        raise AguiError("ProfileDowngrade", "signature level below the profile minimum")
    if halg != alg:
        raise AguiError("KeyAlgMismatch", "alg %d does not match the verifier key alg %d" % (halg, alg))
    tbs = cose.to_be_signed_raw(prot, payload)
    if not cose.cose_verify1_raw(halg, pubkey, tbs, sig):
        raise AguiError("BadSignature", "signature does not verify")
    return payload


def _alg_from_protected(prot):
    v = cbor.decode(prot)
    if isinstance(v, M):
        for k, val in v.pairs:
            if isinstance(k, U) and k.v == 1 and isinstance(val, (N, U)):
                return val.v
    raise AguiError("UIMalformed", "protected header has no alg")
