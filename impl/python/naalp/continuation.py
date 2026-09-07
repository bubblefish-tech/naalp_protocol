# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""C17 N-AALP-CONT flow continuation for the Python SDK (design.md §20; R-CONT-1..7).

N-AALP-CONT generalizes native streaming (one signed StreamOpen, cheap per-chunk data, one signed
StreamCommit over a rolling digest) into a domain-agnostic flow:

  - FlowOpen is the ONE full ML-DSA signature that fixes the flow's authority: its flow_id, its
    effect ceiling, and the content-ids of the approvals that authorize it up to that ceiling. The
    authority is reconstructable from the FlowOpen bytes ALONE (parse_flow_open).
  - Continuation is a CHEAP object: no per-object signature, only a SHA-384 hash-chain link. Each
    link's head is SHA-384(link body); its `prev` is the previous link's head; the genesis prev is
    the FlowOpen's head. A link carries its own effect, which MUST stay at or below the ceiling
    (AboveCeiling otherwise -- the cheap path can never escalate past the one full signature).
  - Checkpoint confirms a contiguous prefix and DETECTS A GAP (GapDetected).
  - FlowCommit is a second full ML-DSA signature binding the whole ordered sequence with ONE
    signature regardless of the number of continuations.

A continuation replayed under a different FlowOpen fails: it carries the originating flow_open_id
(WrongFlow) and its prev no longer chains to the other FlowOpen's head (ChainBroken). Every check is
fail-closed. Ported from impl/go/continuation; graded against vectors/continuation/cases.json. The
FlowOpen / FlowCommit signatures are real deterministic ML-DSA-65 (COSE_Sign1) but not corpus-graded.
"""
import hashlib

from . import cbor, cose, policy
from .cbor import U, N, B, A, M

# HeadSize is the width of a chain head / prev link (SHA-384 = 48 bytes). A FlowOpen head anchors a
# flow's continuation chain.
HEAD_SIZE = 48

_MAX_U64 = 2 ** 64 - 1


class ContError(ValueError):
    """A named, fail-closed N-AALP-CONT error; .kind is the stable error kind (§15)."""

    def __init__(self, kind, msg=""):
        super().__init__("%s: %s" % (kind, msg) if msg else kind)
        self.kind = kind


def _in_lattice(v):
    """Whether v is a value of the closed C5 effect lattice (0..3). An out-of-lattice value is
    rejected RangeError, NEVER normalized to destructive -- normalizing a CEILING to destructive
    would silently make an out-of-range ceiling the MOST-permissive one (a fail-open)."""
    return 0 <= v <= policy.DESTRUCTIVE


def _head(b):
    """SHA-384 over a body -- a 48-octet chain head."""
    return hashlib.sha384(bytes(b)).digest()


def _content_id(b):
    """The T1 framing multihash(0x20, SHA-384(body)) = 0x20 0x30 || SHA-384(body) (50 octets)."""
    return cbor.content_id(bytes(b))


# ---- FlowOpen: the one full signature fixing the flow's authority (design.md §20.2) -----------

class FlowOpen:
    """Fixes a flow's identity, effect ceiling, and approval bindings. Signed with a full ML-DSA
    signature (sign_flow_open); its authority is reconstructable from its bytes alone."""

    __slots__ = ("flow_id", "effect_ceiling", "approvals")

    def __init__(self, flow_id, effect_ceiling, approvals):
        self.flow_id = bytes(flow_id)
        self.effect_ceiling = int(effect_ceiling)
        self.approvals = [bytes(a) for a in approvals]

    def bytes(self):
        """Deterministic-CBOR encoding {1: flow_id, 2: effect_ceiling, 3: approvals[]}."""
        return cbor.encode(M([
            (U(1), B(self.flow_id)),
            (U(2), U(self.effect_ceiling)),
            (U(3), A([B(a) for a in self.approvals])),
        ]))

    def head(self):
        """The FlowOpen's SHA-384 head -- the genesis prev that anchors the continuation chain."""
        return _head(self.bytes())

    def id(self):
        """The FlowOpen's content-id -- carried by every child object."""
        return _content_id(self.bytes())


def parse_flow_open(b):
    """Reconstruct a FlowOpen from its body bytes ALONE (the bearer-authority property). An
    out-of-lattice effect_ceiling is rejected RangeError on decode, never normalized. Fail-closed
    (ContMalformed) on any malformed shape."""
    m = _decode_map(b)
    fid = _bstr_field(m, 1)
    ceil = _uint_field(m, 2)
    apps_v = _field(m, 3)
    if fid is None or ceil is None or apps_v is None or not isinstance(apps_v, A):
        raise ContError("ContMalformed", "object is not a well-formed FlowOpen body")
    if not _in_lattice(ceil):
        raise ContError("RangeError", "effect_ceiling is outside the closed 0..3 lattice")
    apps = []
    for e in apps_v.items:
        if not isinstance(e, B):
            raise ContError("ContMalformed", "approval is not a bstr")
        apps.append(e.v)
    return FlowOpen(fid, ceil, apps)


# ---- Continuation: the cheap hash-chain link (design.md §20.3) --------------------------------

class Continuation:
    """One cheap link in a flow's chain. NOT individually signed; its authenticity derives from the
    FlowOpen signature plus the hash chain plus the FlowCommit signature."""

    __slots__ = ("flow_open_id", "seq", "effect", "payload_id", "prev")

    def __init__(self, flow_open_id, seq, effect, payload_id, prev):
        self.flow_open_id = bytes(flow_open_id)
        self.seq = int(seq)
        self.effect = int(effect)
        self.payload_id = bytes(payload_id)
        self.prev = bytes(prev)

    def bytes(self):
        """Deterministic-CBOR encoding {1: flow_open_id, 2: seq, 3: effect, 4: payload_id, 5: prev}."""
        return cbor.encode(M([
            (U(1), B(self.flow_open_id)),
            (U(2), U(self.seq)),
            (U(3), U(self.effect)),
            (U(4), B(self.payload_id)),
            (U(5), B(self.prev)),
        ]))

    def head(self):
        """This link's SHA-384 head -- the prev of the next link."""
        return _head(self.bytes())


def parse_continuation(b):
    """The single audited decode path for untrusted Continuation wire bytes. Reconstructs the
    5-field body and range-checks the effect against the closed lattice (0..3): an out-of-lattice
    effect is rejected RangeError, never carried as an unknown value. Fail-closed (ContMalformed)."""
    m = _decode_map(b)
    fid = _bstr_field(m, 1)
    seq = _uint_field(m, 2)
    effect = _uint_field(m, 3)
    pid = _bstr_field(m, 4)
    prev = _bstr_field(m, 5)
    if fid is None or seq is None or effect is None or pid is None or prev is None:
        raise ContError("ContMalformed", "object is not a well-formed Continuation body")
    if not _in_lattice(effect):
        raise ContError("RangeError", "effect is outside the closed 0..3 lattice")
    return Continuation(fid, seq, effect, pid, prev)


def verify_continuation(c, flow_open_id, prev_head, expected_seq, ceiling):
    """The CHEAP-path check of a single link against the flow's fixed authority: same flow
    (WrongFlow), next seq (SeqGap), effect within the ceiling (AboveCeiling), and prev chaining to
    the previous head (ChainBroken). Performs no signature verification -- that is what makes it
    cheap. Both the ceiling and the link effect are closed effects; an out-of-lattice value is
    RangeError, never normalized (fail-closed). Returns None on success."""
    if not _in_lattice(ceiling):
        raise ContError("RangeError", "ceiling is outside the closed 0..3 lattice")
    if not _in_lattice(c.effect):
        raise ContError("RangeError", "effect is outside the closed 0..3 lattice")
    if bytes(c.flow_open_id) != bytes(flow_open_id):
        raise ContError("WrongFlow", "object's flow_open_id does not match the FlowOpen")
    if c.seq != expected_seq:
        raise ContError("SeqGap", "continuation seq is not the next expected value")
    if not policy.authorizes(ceiling, c.effect):
        raise ContError("AboveCeiling", "continuation effect exceeds the FlowOpen effect ceiling")
    if bytes(c.prev) != bytes(prev_head):
        raise ContError("ChainBroken", "continuation prev does not chain to the previous head")
    return None


def verify_chain(open_, conts):
    """Verify a whole ordered continuation sequence starting from the FlowOpen and return the final
    chain head. The ceiling comes from the FlowOpen, so the cheap path can never exceed what the one
    full signature authorized."""
    if not _in_lattice(open_.effect_ceiling):
        raise ContError("RangeError", "effect_ceiling is outside the closed 0..3 lattice")
    fid = open_.id()
    prev = open_.head()
    ceiling = open_.effect_ceiling
    for i, c in enumerate(conts):
        verify_continuation(c, fid, prev, i, ceiling)
        prev = c.head()
    return prev


# ---- Checkpoint: confirm a prefix, detect a gap (design.md §20.4) -----------------------------

class Checkpoint:
    """Asserts the chain head after a contiguous prefix of continuations (seq 0..through_seq)."""

    __slots__ = ("flow_open_id", "through_seq", "head")

    def __init__(self, flow_open_id, through_seq, head):
        self.flow_open_id = bytes(flow_open_id)
        self.through_seq = int(through_seq)
        self.head = bytes(head)

    def bytes(self):
        """Deterministic-CBOR encoding {1: flow_open_id, 2: through_seq, 3: head}."""
        return cbor.encode(M([
            (U(1), B(self.flow_open_id)),
            (U(2), U(self.through_seq)),
            (U(3), B(self.head)),
        ]))


def parse_checkpoint(b):
    """The single audited decode path for untrusted Checkpoint wire bytes: the 3-field body (field 3
    a bstr head). A 2-field FlowCommit look-alike is rejected here (missing field 3). Fail-closed
    (ContMalformed)."""
    m = _decode_map(b)
    fid = _bstr_field(m, 1)
    through = _uint_field(m, 2)
    h = _bstr_field(m, 3)
    if fid is None or through is None or h is None:
        raise ContError("ContMalformed", "object is not a well-formed Checkpoint body")
    return Checkpoint(fid, through, h)


def verify_checkpoint(cp, open_, prefix):
    """Confirm the prefix is exactly the contiguous sequence seq 0..through_seq and that its
    recomputed head matches the checkpoint. A dropped or reordered link -- a missing seq, a broken
    prev, or the wrong count -- is reported GapDetected. Returns None on a clean confirmation."""
    if bytes(cp.flow_open_id) != bytes(open_.id()):
        raise ContError("WrongFlow", "checkpoint flow_open_id does not match the FlowOpen")
    # through_seq is a 0-based index, so the prefix length is through_seq+1. At through_seq == u64::MAX
    # that addition would wrap and false-accept an EMPTY prefix as covering the whole counter space --
    # reject it as a gap instead (there can be no MAX+1 contiguous links).
    if cp.through_seq == _MAX_U64:
        raise ContError("GapDetected", "through_seq at u64::MAX admits no contiguous prefix")
    if len(prefix) != cp.through_seq + 1:
        raise ContError("GapDetected", "wrong count: a link is missing or extra")
    try:
        h = verify_chain(open_, prefix)
    except ContError:
        raise ContError("GapDetected", "a seq/prev break inside the prefix is a gap")
    if bytes(cp.head) != bytes(h):
        raise ContError("GapDetected", "recomputed prefix head does not match the checkpoint")
    return None


# ---- FlowCommit: the second full signature binding the whole sequence (design.md §20.5) --------

class FlowCommit:
    """Binds a completed flow's final chain head under one full ML-DSA signature."""

    __slots__ = ("flow_open_id", "final_head")

    def __init__(self, flow_open_id, final_head):
        self.flow_open_id = bytes(flow_open_id)
        self.final_head = bytes(final_head)

    def bytes(self):
        """Deterministic-CBOR encoding {1: flow_open_id, 2: final_head} -- the 2-field shape that
        distinguishes it from the 3-field Checkpoint."""
        return cbor.encode(M([
            (U(1), B(self.flow_open_id)),
            (U(2), B(self.final_head)),
        ]))


# ---- full-signature helpers (FlowOpen / FlowCommit) — real ML-DSA, isolation ------------------

def _protected_header(alg):
    """The COSE protected header {1: alg} as deterministic CBOR (alg is a negative int)."""
    return cbor.encode(M([(U(1), N(alg))]))


def sign_flow_open(o, alg, seed):
    """The tagged COSE_Sign1 over the FlowOpen body (the one full signature that opens the flow)."""
    return cose.cose_sign1(alg, seed, _protected_header(alg), o.bytes())


def sign_flow_commit(c, alg, seed):
    """The tagged COSE_Sign1 over the FlowCommit body."""
    return cose.cose_sign1(alg, seed, _protected_header(alg), c.bytes())


def verify_flow_open(obj, profile, alg, pubkey):
    """Verify the FlowOpen's full signature, then reconstruct the authority from the signed body
    bytes (fail-closed BadSignature)."""
    prot, payload, sig = cose.parse_sign1_raw(obj)
    tbs = cose.to_be_signed_raw(prot, payload)
    if not cose.cose_verify1_raw(alg, pubkey, tbs, sig):
        raise ContError("BadSignature", "flow-open signature does not verify")
    return parse_flow_open(payload)


def verify_flow_commit(obj, profile, alg, pubkey, open_, conts):
    """Verify the FlowCommit's full signature, that it binds this FlowOpen, and that its final_head
    equals the chain recomputed over the delivered continuations (CommitMismatch otherwise)."""
    prot, payload, sig = cose.parse_sign1_raw(obj)
    tbs = cose.to_be_signed_raw(prot, payload)
    if not cose.cose_verify1_raw(alg, pubkey, tbs, sig):
        raise ContError("BadSignature", "flow-commit signature does not verify")
    m = _decode_map(payload)
    fid = _bstr_field(m, 1)
    fh = _bstr_field(m, 2)
    if fid is None or fh is None:
        raise ContError("ContMalformed", "object is not a well-formed FlowCommit body")
    fc = FlowCommit(fid, fh)
    if bytes(fc.flow_open_id) != bytes(open_.id()):
        raise ContError("WrongFlow", "flow-commit does not bind this FlowOpen")
    final = verify_chain(open_, conts)
    if bytes(fc.final_head) != bytes(final):
        raise ContError("CommitMismatch", "flow commit final_head does not match the recomputed chain")
    return fc


# ---- small deterministic-CBOR field accessors ------------------------------------------------

def _decode_map(b):
    v = cbor.decode(bytes(b))   # strict decoder: raises cbor.NonCanonical on a non-canonical body
    if not isinstance(v, M):
        raise ContError("ContMalformed", "object is not a map")
    return v


def _field(m, k):
    for key, val in m.pairs:
        if isinstance(key, U) and key.v == k:
            return val
    return None


def _bstr_field(m, k):
    v = _field(m, k)
    return v.v if isinstance(v, B) else None


def _uint_field(m, k):
    v = _field(m, k)
    return v.v if isinstance(v, U) else None
