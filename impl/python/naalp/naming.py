# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""C19 name bindings and the signed A2A task-state profile for the Python SDK (design.md §22;
R-NAME-1..6, R-A2A-1..7).

C19 is two receipt-CHAINED, signed, OFFLINE-WALKABLE surfaces carried on N-AALP's own signed object.
Both reuse the C7 audit receipt-chain construction (§8.1) unchanged -- head = SHA-384(body), genesis
prev = 48 zero bytes, a monotonic seq, the prior head carried in the body so editing or omitting a
record breaks the next record's linkage -- and they add NO new envelope, encoding, signature,
identity, or audit mechanism (R-11.3): each object is an ordinary signed N-AALP body (COSE_Sign1, §4),
reusing the T1 content-id framing (§2.3) and the C7 chain.

Task 4.1 -- name bindings: NameBinding {1:name,2:signer,3:seq,4:prev} maps a name to a signer id and
CHAINS onto the prior binding for that name (prev = the prior binding's head; genesis prev is zero). A
key rotation is a NEW binding at the next seq naming the new signer. A binding is DATED BY its chain
position (seq); the envelope's `created` field is advisory only. A name's history is WALKABLE offline
(walk_history), a deleted/omitted binding leaves a detectable HOLE at the first-broken position
(detect_hole), and two bindings by ONE authority at the SAME (name, seq) naming DIFFERENT signers are
a FORK reported at that seq (detect_fork / NameForkProof).

Task 4.2 -- the signed A2A task-state profile: TaskState is the IMPORTED A2A (Agent2Agent) TaskState
vocabulary (carriage, not adoption): the eight states submitted, working, input-required,
auth-required, completed, canceled, failed, rejected (A2A §4.1.3: start = submitted; terminal =
completed/canceled/failed/rejected; interrupted = input-required/auth-required). A Transition
{1:task,2:card,3:from,4:to,5:seq,6:prev} is one receipt-CHAINED signed state transition. The legal-edge
table is DERIVED from those documented A2A category rules; verify_transition rejects an illegal edge,
and verify_task_chain walks a task's transition chain enforcing the start state, contiguity, the
legal-edge table, prev/seq linkage, the card binding, and the signatures. `card` is the content-id of
the A2A Agent Card attestation (a C18 naalp-description-import) that binds the profile to an
agent/operation; a transition carrying a foreign card is rejected.

Every check is fail-closed (§15): a failing object is rejected whole, returns its named error, and
causes no state change. Ported from impl/go/naming; graded against vectors/naming/cases.json.
"""
import hashlib

from . import cbor, cose
from .cbor import U, N, B, T, M

# The width of a chain head / prev link (SHA-384 = 48 bytes), matching the C7 audit chain. Genesis
# is zero.
HEAD_SIZE = 48


class NamingError(ValueError):
    """A named, fail-closed C19 error; .kind is the stable error kind (§15). The signature kinds
    (BadSignature, UnknownAlg, ProfileDowngrade, KeyAlgMismatch) are reused from the C2 cose layer so
    a verifier's verdict is identical to the Go reference."""

    def __init__(self, kind, msg=""):
        super().__init__("%s: %s" % (kind, msg) if msg else kind)
        self.kind = kind


def genesis():
    """A fresh 48-octet zero prev -- the empty-chain link (the C7 chain genesis)."""
    return bytes(HEAD_SIZE)


def _head(b):
    """SHA-384 over a body -- a 48-octet digest (the same construction as the C7 receipt head)."""
    return hashlib.sha384(bytes(b)).digest()


def _content_id(b):
    """T1 framing multihash(0x20, SHA-384(body)) = 0x20 0x30 || SHA-384(body) (50 octets)."""
    return cbor.content_id(bytes(b))


# ---- the COSE_Sign1 signing/verification helpers (reuse the C2 layer, R-11.3) ------------------

def _protected_header(alg):
    """The bare {1: alg} COSE_Sign1 protected header (§4), as the reference cose.Sign1 emits."""
    return cbor.encode(M([(U(1), N(alg))]))


def _alg_from_protected(prot):
    v = cbor.decode(prot)
    if isinstance(v, M):
        for k, val in v.pairs:
            if isinstance(k, U) and k.v == 1 and isinstance(val, (N, U)):
                return val.v
    raise NamingError("Malformed", "protected header has no alg")


def _verify_sign1(obj, profile, alg, pubkey):
    """Verify a tagged COSE_Sign1 object under the profile floor with real crypto and return the
    payload. Check order (mirroring cose.Verify1): alg registry -> profile floor -> key-alg match ->
    signature. Fail-closed with a named error."""
    prot, payload, sig = cose.parse_sign1_raw(obj)
    halg = _alg_from_protected(prot)
    level, known = cose.alg_level(halg)
    if not known:
        raise NamingError("UnknownAlg", "unregistered alg %d" % halg)
    if level < cose.profile_min_level(profile):
        raise NamingError("ProfileDowngrade", "signature level below the profile minimum")
    if halg != alg:
        raise NamingError("KeyAlgMismatch", "alg %d does not match the verifier key alg %d" % (halg, alg))
    tbs = cose.to_be_signed_raw(prot, payload)
    if not cose.cose_verify1_raw(halg, pubkey, tbs, sig):
        raise NamingError("BadSignature", "signature does not verify")
    return payload


# ==== Task 4.1 -- name bindings ===============================================================

class NameBinding:
    """Maps a name to a signer id at a chain position. It chains onto the prior binding for the same
    name: prev is the prior binding's head (genesis for seq 0). A key rotation is a new binding at the
    next seq naming the new signer. The binding is DATED BY seq; the envelope's `created` is advisory."""

    __slots__ = ("name", "signer", "seq", "prev")

    def __init__(self, name, signer, seq, prev):
        self.name = name                # the name being bound (a durable, human-readable name)
        self.signer = bytes(signer)     # the signer id this binding maps the name to (opaque bytes)
        self.seq = int(seq)             # monotonic per-name chain position; seq 0 is the genesis binding
        self.prev = bytes(prev)         # the prior binding's head (HEAD_SIZE bytes; genesis is zero)

    def bytes(self):
        """Deterministic-CBOR encoding {1:name,2:signer,3:seq,4:prev}."""
        return cbor.encode(M([
            (U(1), T(self.name)),
            (U(2), B(self.signer)),
            (U(3), U(self.seq)),
            (U(4), B(self.prev)),
        ]))

    def head(self):
        """The chain head after this binding: SHA-384 of the binding body (48 octets)."""
        return _head(self.bytes())

    def id(self):
        """The binding's T1 content-id (50 octets)."""
        return _content_id(self.bytes())


def parse_name_binding(b):
    """Reconstruct a NameBinding from its body bytes alone. A body that is not exactly the {1,2,3,4}
    map with the right value types is NameMalformed (fail-closed)."""
    m = _decode_map(b)
    if m is None:
        raise NamingError("NameMalformed", "body is not a well-formed name binding")
    name = _tstr_field(m, 1)
    signer = _bstr_field(m, 2)
    seq = _uint_field(m, 3)
    prev = _bstr_field(m, 4)
    if name is None or signer is None or seq is None or prev is None:
        raise NamingError("NameMalformed", "body is not a well-formed name binding")
    return NameBinding(name, signer, seq, prev)


def sign_binding(nb, alg, seed):
    """Produce the tagged COSE_Sign1 object over the binding body (real deterministic ML-DSA)."""
    return cose.cose_sign1(alg, seed, _protected_header(alg), nb.bytes())


def verify_binding(obj, profile, alg, pubkey):
    """Verify the binding's full signature under the profile, then reconstruct it from the signed body
    bytes. A bad signature is BadSignature; a malformed body is NameMalformed. Fail-closed."""
    payload = _verify_sign1(obj, profile, alg, pubkey)
    return parse_name_binding(payload)


class Registrar:
    """A naming authority that appends monotonic signed bindings for ONE name (mirroring the C7 audit
    authority). Each append records a name -> signer mapping at the next chain position; a rotation is
    simply an append naming the new signer. Signs with a real deterministic ML-DSA key from `seed`."""

    __slots__ = ("_name", "_alg", "_seed", "_head", "_seq")

    def __init__(self, name, alg, seed):
        self._name = name
        self._alg = alg
        self._seed = bytes(seed)
        self._head = genesis()
        self._seq = 0

    def append(self, subject):
        """Record a binding of the registrar's name to `subject` at the next chain position, returning
        (binding, tagged COSE_Sign1 object). Seq increases by one per append; the head advances."""
        nb = NameBinding(self._name, subject, self._seq, self._head)
        obj = sign_binding(nb, self._alg, self._seed)
        self._head = nb.head()
        self._seq += 1
        return nb, obj


class NameEvent:
    """One step of a walked name history: the chain position and the signer the name mapped to at that
    position, with the chain head after it."""

    __slots__ = ("seq", "signer", "head")

    def __init__(self, seq, signer, head):
        self.seq = int(seq)
        self.signer = bytes(signer)
        self.head = bytes(head)


def walk_history(bindings):
    """Verify a name-binding chain's structural continuity OFFLINE (no signatures) and return the
    ordered signer succession. Requires every binding to name the SAME name, seq i to equal its index,
    and prev to link to the previous binding's head (genesis zero for seq 0). A gap, reorder, omitted
    binding, or a name change is NameChainBroken (fail-closed). The CURRENT signer is the last event's
    signer."""
    events = []
    h = genesis()
    name = None
    for i, nb in enumerate(bindings):
        if i == 0:
            name = nb.name
        elif nb.name != name:
            raise NamingError("NameChainBroken", "a chain is for exactly one name")
        if nb.seq != i or nb.prev != h:
            raise NamingError("NameChainBroken", "prev/seq does not chain to the previous binding")
        h = nb.head()
        events.append(NameEvent(nb.seq, nb.signer, h))
    return events


def verify_chain(objs, profile, alg, pubkey):
    """Check a name-binding chain offline against the authority's key. Each element is the tagged
    COSE_Sign1 object for one binding. Verifies every signature under the profile (verify_binding),
    then enforces structural continuity -- every binding names the SAME name, seq i equals its index,
    prev links to the previous head -- returning the verified, ordered bindings. A bad signature is
    BadSignature; a broken link, a seq gap, or a name change is NameChainBroken. Fail-closed."""
    h = genesis()
    name = None
    out = []
    for i, obj in enumerate(objs):
        nb = verify_binding(obj, profile, alg, pubkey)
        if i == 0:
            name = nb.name
        elif nb.name != name:
            raise NamingError("NameChainBroken", "a chain is for exactly one name")
        if nb.seq != i or nb.prev != h:
            raise NamingError("NameChainBroken", "prev/seq does not chain to the previous binding")
        h = nb.head()
        out.append(nb)
    return out


def detect_hole(bindings):
    """Report whether a presented (possibly gappy) binding list breaks contiguity -- a deleted/omitted
    binding -- and, if so, the FIRST-BROKEN position: the index i where the i-th presented binding's
    seq is not i or its prev does not link to the previous binding's head. A contiguous list returns
    (0, False)."""
    h = genesis()
    for i, nb in enumerate(bindings):
        if nb.seq != i or nb.prev != h:
            return i, True
        h = nb.head()
    return 0, False


def detect_fork(a, b):
    """Compare two bindings for the SAME name and report whether they equivocate -- the SAME name and
    seq but DIFFERENT bodies (a different signer or prev) -- and, if so, the seq position at which they
    conflict. A different name or seq is a legitimate distinct binding; byte-identical bindings are a
    benign duplicate. Both non-fork cases return (0, False)."""
    if a.name != b.name or a.seq != b.seq:
        return 0, False
    if a.bytes() == b.bytes():
        return 0, False
    return a.seq, True


class NameForkProof:
    """Non-repudiable evidence of a name fork: two validly-signed NameBinding objects by ONE authority
    at the SAME (name, seq) naming DIFFERENT signers, carried as the accused authority's OWN two signed
    objects (the tagged COSE_Sign1 bytes). Because a single verifier checks BOTH signed objects, the
    proof is self-contained -- any third party confirms both signatures against the accused key."""

    __slots__ = ("signer", "signed_a", "signed_b")

    def __init__(self, signer, signed_a, signed_b):
        self.signer = bytes(signer)     # accused authority signer id (both objects verify under its key)
        self.signed_a = bytes(signed_a)
        self.signed_b = bytes(signed_b)

    def verify(self, profile, alg, pubkey):
        """Accept iff ALL hold: (1) the signer id is present; (2) BOTH signed objects verify under the
        key (which, because a single verifier checks both, proves one authority); (3) the two bindings
        share one name and seq; and (4) their bodies differ. Returns the seq position at which it
        forks. An unnamed signer, a different name/seq, or identical bodies is NameForkProofInvalid; a
        signature that does not verify is BadSignature. Fail-closed."""
        if len(self.signer) == 0:
            raise NamingError("NameForkProofInvalid", "an unnamed accused is not evidence")
        a = verify_binding(self.signed_a, profile, alg, pubkey)
        b = verify_binding(self.signed_b, profile, alg, pubkey)
        pos, fork = detect_fork(a, b)
        if not fork:
            raise NamingError("NameForkProofInvalid", "not the same (name, seq) or identical bodies")
        return pos


# ==== Task 4.2 -- the signed A2A task-state profile ===========================================

# TaskState codes (stable N-AALP wire codes for the imported A2A vocabulary; A2A §4.1.3).
STATE_SUBMITTED = 0       # acknowledged, not yet started (the start state)
STATE_WORKING = 1         # actively processed
STATE_INPUT_REQUIRED = 2  # interrupted, awaiting client input
STATE_AUTH_REQUIRED = 3   # interrupted, awaiting authentication
STATE_COMPLETED = 4       # terminal success
STATE_CANCELED = 5        # terminal, canceled before completion
STATE_FAILED = 6          # terminal, finished with an error
STATE_REJECTED = 7        # terminal, the agent declined the task

START_STATE = STATE_SUBMITTED

_STATE_NAMES = {
    STATE_SUBMITTED: "submitted", STATE_WORKING: "working", STATE_INPUT_REQUIRED: "input-required",
    STATE_AUTH_REQUIRED: "auth-required", STATE_COMPLETED: "completed", STATE_CANCELED: "canceled",
    STATE_FAILED: "failed", STATE_REJECTED: "rejected",
}
_TERMINAL = (STATE_COMPLETED, STATE_CANCELED, STATE_FAILED, STATE_REJECTED)
_INTERRUPTED = (STATE_INPUT_REQUIRED, STATE_AUTH_REQUIRED)


def state_name(s):
    return _STATE_NAMES.get(s, "unknown")


def is_state(s):
    return s in _STATE_NAMES


def is_terminal(s):
    return s in _TERMINAL


def is_interrupted(s):
    return s in _INTERRUPTED


def _build_legal_edges():
    active = (STATE_SUBMITTED, STATE_WORKING)
    m = set()
    m.add((STATE_SUBMITTED, STATE_WORKING))         # begin processing (the only active->active edge)
    for s in active:                                # active -> interrupted
        for t in _INTERRUPTED:
            m.add((s, t))
    for s in active:                                # active -> terminal
        for t in _TERMINAL:
            m.add((s, t))
    for s in _INTERRUPTED:                           # interrupted -> working (client acted)
        m.add((s, STATE_WORKING))
    for s in _INTERRUPTED:                           # interrupted -> terminal
        for t in _TERMINAL:
            m.add((s, t))
    return m


_LEGAL_EDGES = _build_legal_edges()


def legal_edge(frm, to):
    """Whether (frm -> to) is a legal A2A transition edge per the table. A self-loop, an edge out of a
    terminal state, an edge touching an undefined state, and any edge not in the table are all False."""
    if not is_state(frm) or not is_state(to):
        return False
    return (frm, to) in _LEGAL_EDGES


def legal_edges():
    """A copy of the legal transition table as a sorted list of (frm, to) pairs."""
    return sorted(_LEGAL_EDGES)


def verify_transition(frm, to):
    """The edge-legality gate: returns None iff (frm -> to) is a legal A2A edge, else raises
    NamingError(IllegalTransition). Fail-closed."""
    if not legal_edge(frm, to):
        raise NamingError("IllegalTransition", "not a legal A2A transition edge")
    return None


class Transition:
    """One signed, receipt-CHAINED A2A task state transition (design §22.4). It chains onto the prior
    transition of the same task: prev is the prior transition's head (genesis for seq 0). Dated by seq.
    card is the content-id of the A2A Agent Card attestation (a C18 import) that binds this profile to
    an agent/operation."""

    __slots__ = ("task", "card", "frm", "to", "seq", "prev")

    def __init__(self, task, card, frm, to, seq, prev):
        self.task = bytes(task)         # the task id (opaque bytes)
        self.card = bytes(card)         # content-id of the bound A2A Agent Card attestation (the C18 import)
        self.frm = int(frm)             # the source state
        self.to = int(to)               # the target state
        self.seq = int(seq)             # monotonic per-task chain position; seq 0's frm MUST be the start state
        self.prev = bytes(prev)         # the prior transition's head (HEAD_SIZE bytes; genesis is zero)

    def bytes(self):
        """Deterministic-CBOR encoding {1:task,2:card,3:from,4:to,5:seq,6:prev}."""
        return cbor.encode(M([
            (U(1), B(self.task)),
            (U(2), B(self.card)),
            (U(3), U(self.frm)),
            (U(4), U(self.to)),
            (U(5), U(self.seq)),
            (U(6), B(self.prev)),
        ]))

    def head(self):
        """The chain head after this transition: SHA-384 of the transition body (48 octets)."""
        return _head(self.bytes())

    def id(self):
        """The transition's T1 content-id (50 octets)."""
        return _content_id(self.bytes())


def parse_transition(b):
    """Reconstruct a Transition from its body bytes alone. A body that is not exactly the {1,2,3,4,5,6}
    map with the right value types is NameMalformed (fail-closed)."""
    m = _decode_map(b)
    if m is None:
        raise NamingError("NameMalformed", "body is not a well-formed task transition")
    task = _bstr_field(m, 1)
    card = _bstr_field(m, 2)
    frm = _uint_field(m, 3)
    to = _uint_field(m, 4)
    seq = _uint_field(m, 5)
    prev = _bstr_field(m, 6)
    if task is None or card is None or frm is None or to is None or seq is None or prev is None:
        raise NamingError("NameMalformed", "body is not a well-formed task transition")
    return Transition(task, card, frm, to, seq, prev)


def sign_transition(t, alg, seed):
    """Produce the tagged COSE_Sign1 object over the transition body (real deterministic ML-DSA)."""
    return cose.cose_sign1(alg, seed, _protected_header(alg), t.bytes())


def verify_transition_object(obj, profile, alg, pubkey):
    """Verify a transition's full signature under the profile, reconstruct it from the signed body
    bytes, AND check that its edge is legal. A bad signature is BadSignature; an illegal edge is
    IllegalTransition. Fail-closed."""
    payload = _verify_sign1(obj, profile, alg, pubkey)
    t = parse_transition(payload)
    verify_transition(t.frm, t.to)
    return t


def verify_task_chain(objs, card, profile, alg, pubkey):
    """Walk a task's transition chain offline against the authority's key and the bound card
    attestation. Enforces, in order and fail-closed: (1) the SIGNATURE of every transition
    (BadSignature otherwise); (2) prev/seq linkage (each prev links to the prior head, genesis zero for
    seq 0; seq i == index) -- a gap/reorder is TaskChainBroken; (3) the CARD BINDING (every
    transition's card equals `card`) -- ForeignCard otherwise; and (4) the START STATE (seq-0's frm is
    START_STATE), CONTIGUITY (each frm == the prior to), and the LEGAL-EDGE TABLE at every step
    (including the terminal-cannot-continue rule) -- IllegalTransition otherwise. Returns the verified,
    ordered transitions. It never authorizes; it accepts or rejects."""
    h = genesis()
    prev_to = None
    out = []
    for i, obj in enumerate(objs):
        payload = _verify_sign1(obj, profile, alg, pubkey)     # BadSignature (foreign/tampered)
        t = parse_transition(payload)
        if t.seq != i or t.prev != h:
            raise NamingError("TaskChainBroken", "prev/seq does not chain to the previous transition")
        if t.card != bytes(card):
            raise NamingError("ForeignCard", "transition binds a card other than the profile's bound card")
        if i == 0:
            if t.frm != START_STATE:
                raise NamingError("IllegalTransition", "the first transition must leave the start state")
        elif t.frm != prev_to:
            raise NamingError("IllegalTransition", "non-contiguous: this from must equal the prior to")
        verify_transition(t.frm, t.to)                          # an illegal edge (incl. from-terminal)
        h = t.head()
        prev_to = t.to
        out.append(t)
    return out


def detect_task_gap(transitions):
    """Report whether a presented (possibly gappy) transition list breaks contiguity -- a
    deleted/omitted or reordered transition -- and, if so, the FIRST-BROKEN position. A contiguous list
    returns (0, False). (The gap-evident detector for the task chain, mirroring detect_hole.)"""
    h = genesis()
    for i, t in enumerate(transitions):
        if t.seq != i or t.prev != h:
            return i, True
        h = t.head()
    return 0, False


# ---- small deterministic-CBOR field accessors (strict decode; NonCanonical propagates) ---------

def _decode_map(b):
    try:
        v = cbor.decode(bytes(b))
    except cbor.NonCanonical:
        return None
    return v if isinstance(v, M) else None


def _field(m, k):
    for kk, vv in m.pairs:
        if isinstance(kk, U) and kk.v == k:
            return vv
    return None


def _bstr_field(m, k):
    v = _field(m, k)
    return v.v if isinstance(v, B) else None


def _tstr_field(m, k):
    v = _field(m, k)
    return v.v if isinstance(v, T) else None


def _uint_field(m, k):
    v = _field(m, k)
    return v.v if isinstance(v, U) else None
