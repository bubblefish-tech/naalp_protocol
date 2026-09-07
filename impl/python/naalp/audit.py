# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""C7 audit for the Python SDK -- the signed hash-chained receipt (the baseline single-authority
ordering tier), the equivocation auditor and its non-repudiable fork proof, and the
offline-checkable causal graph (design.md §8; R-8.1..8.6, R-12.2, R-12.3).

An ordering authority records each accepted object by appending a signed Receipt
{1: prev, 2: obj, 3: seq, 4: at}; the chain is tamper-evident because reordering, omission, or
substitution breaks a `prev` link or a `seq`. The authority never mutates the origin object to
order it -- ordering is an outer signed layer. The causal graph is the authority-independent
foundation: an edge "A causes B" is proven by B's signature over A's content id and is checkable
offline; a total order is a policy layered over this partial order. An auditor detects
equivocation -- two receipts by one authority at one seq naming different objects -- from the
signed receipts alone, and mints a non-repudiable ForkProof carrying BOTH of the accused's
signatures and an external monotonic counter (draft-01 finding #70).

Ported from impl/go/audit. Receipt/fork-proof signatures are a RAW deterministic ML-DSA
signature over the record body (cose.mldsa_sign / cose.mldsa_verify), exactly as the reference's
cose.Signer/Verifier sign the receipt body directly. The causal partial order is checked by the
shared naalp.graph (the same foundation the reference reuses). Graded against the shared
vectors/audit/cases.json.
"""
import hashlib
from dataclasses import dataclass

from . import cbor, cose, graph
from .cbor import U, B, M

# The width of a chain head / prev link (SHA-384 = 48 bytes); genesis is zero.
HEAD_SIZE = 48


class AuditError(ValueError):
    """A named, fail-closed audit error; .kind is the stable error kind (design §8.6)."""

    def __init__(self, kind, msg=""):
        super().__init__("%s: %s" % (kind, msg) if msg else kind)
        self.kind = kind


@dataclass(frozen=True)
class Receipt:
    """One signed append to an ordering authority's chain (design §8.1)."""

    prev: bytes   # hash of the previous receipt body (HEAD_SIZE bytes; genesis is zero)
    obj: bytes    # content id of the accepted object (never the object itself -- §8.2)
    seq: int      # monotonic sequence position within this authority's chain
    at: int       # the authority's time anchor, epoch ms (independent of the signer's clock)

    def bytes(self):
        """Deterministic-CBOR encoding of the receipt body {1: prev, 2: obj, 3: seq, 4: at}."""
        return cbor.encode(M([
            (U(1), B(self.prev)), (U(2), B(self.obj)), (U(3), U(self.seq)), (U(4), U(self.at)),
        ]))

    def head(self):
        """The chain head after this receipt: SHA-384 of the receipt body. Because the body carries
        prev, editing any receipt breaks the next receipt's linkage."""
        return hashlib.sha384(self.bytes()).digest()


class Authority:
    """A baseline single ordering authority (§8.4). It appends monotonic signed receipts over
    object content ids; it holds no object bodies and mutates none. Signs with a real deterministic
    ML-DSA key derived from `seed` (a RAW signature over each receipt body)."""

    def __init__(self, alg, seed):
        self._alg = alg
        self._seed = bytes(seed)
        self._head = bytes(HEAD_SIZE)
        self._seq = 0

    def append(self, obj, at):
        """Record acceptance of the object named by content id obj at time at, returning
        (receipt, signature). Seq increases by one per append (monotonic)."""
        r = Receipt(self._head, bytes(obj), self._seq, at)
        sig = cose.mldsa_sign(self._alg, self._seed, r.bytes())
        self._head = r.head()
        self._seq += 1
        return r, sig


def verify_chain(receipts, sigs, alg, pubkey):
    """Check a receipt chain offline against the authority's key: each receipt's seq is the next
    expected value, its prev links to the previous receipt's head (genesis is zero), and its raw
    signature verifies. A broken link or a seq gap is ChainBroken; a bad signature is
    ReceiptUnsigned. Detects any reorder, omission, or substitution (§8.1). Returns None on success."""
    if len(receipts) != len(sigs):
        raise AuditError("ChainBroken", "receipt/signature count mismatch")
    head = bytes(HEAD_SIZE)
    for i, r in enumerate(receipts):
        if r.seq != i or r.prev != head:
            raise AuditError("ChainBroken", "receipt prev/seq does not chain to the previous receipt")
        if not cose.mldsa_verify(alg, pubkey, r.bytes(), sigs[i]):
            raise AuditError("ReceiptUnsigned", "receipt signature does not verify")
        head = r.head()
    return None


def consistent_with_anchor(created, at):
    """An object cannot be created after the authority ordered it, so created MUST NOT exceed at
    (R-8.4). The receipt's `at` is signed and chained, so it is evidence a verifier checks
    independently of the signer's clock."""
    return created <= at


@dataclass(frozen=True)
class ForkProof:
    """Non-repudiable evidence of equivocation (draft-01 §8.5, R-8.3): two validly-signed receipts
    by ONE authority at the SAME seq naming DIFFERENT objects, with the accused's OWN two signatures
    and an external monotonic counter -- self-contained, so any third party verifies both signatures
    against the accused key with no further evidence and no repudiation."""

    signer: bytes      # accused authority signer id; both sigs verify under its key
    ext_counter: int   # external monotonic counter bound into the proof (fixes replay/reorder)
    a: Receipt         # first receipt (a.bytes() is the signed input for sig_a)
    sig_a: bytes       # the accused authority's signature over a.bytes()
    b: Receipt         # second receipt at the same seq naming a different object
    sig_b: bytes       # the accused authority's signature over b.bytes()

    def bytes(self):
        """Deterministic-CBOR fork-proof body {1: signer, 2: ext_counter, 3: body_a, 4: sig_a,
        5: body_b, 6: sig_b}. The two receipt bodies are embedded as the exact bytes each signature
        covers."""
        return cbor.encode(M([
            (U(1), B(self.signer)), (U(2), U(self.ext_counter)),
            (U(3), B(self.a.bytes())), (U(4), B(self.sig_a)),
            (U(5), B(self.b.bytes())), (U(6), B(self.sig_b)),
        ]))

    def preimage(self):
        """The deterministic-CBOR framing witness: the fork-proof body with the two signature
        byte-strings elided to empty. It is the structural authority the independent oracle
        reproduces byte-for-byte; the two ML-DSA signatures are graded by cross-implementation
        byte-parity elsewhere. This is not a wire object; it exists only to grade the framing."""
        return cbor.encode(M([
            (U(1), B(self.signer)), (U(2), U(self.ext_counter)),
            (U(3), B(self.a.bytes())), (U(4), B(b"")),
            (U(5), B(self.b.bytes())), (U(6), B(b"")),
        ]))

    def verify(self, alg, pubkey):
        """Accept iff ALL hold: (1) the signer id is present; (2) the two receipts share one seq;
        (3) they name DIFFERENT objects; and (4) BOTH signatures verify under the accused key. Any
        failure rejects the whole proof (fail-closed): a same-object / seq-mismatch / unnamed-signer
        proof is ForkProofInvalid, and a signature that does not verify is ReceiptUnsigned. Returns
        None on a valid, non-repudiable proof of Equivocation."""
        if len(self.signer) == 0:
            raise AuditError("ForkProofInvalid", "an unnamed accused is not evidence")
        if self.a.seq != self.b.seq:
            raise AuditError("ForkProofInvalid", "receipts at different sequence positions")
        if self.a.obj == self.b.obj:
            raise AuditError("ForkProofInvalid", "same object named twice -- no equivocation")
        if not cose.mldsa_verify(alg, pubkey, self.a.bytes(), self.sig_a) or \
                not cose.mldsa_verify(alg, pubkey, self.b.bytes(), self.sig_b):
            raise AuditError("ReceiptUnsigned", "a signature does not verify under the accused key")
        return None


def new_fork_proof(signer, a, sig_a, b, sig_b, ext_counter):
    """Assemble a fork proof from two conflicting signed receipts, the accused signer id, and an
    external monotonic counter. Performs no checks -- verify is the fail-closed gate; this is the
    pure constructor (A9). Copies the byte slices so the proof owns its evidence."""
    return ForkProof(bytes(signer), ext_counter, a, bytes(sig_a), b, bytes(sig_b))


class Auditor:
    """Observes an authority's receipts and detects equivocation from the signed receipts alone
    (§8.5). On a conflict it mints a non-repudiable ForkProof carrying the accused signer id, both
    conflicting signatures, and an external monotonic counter."""

    def __init__(self, alg, pubkey, signer, ext_base=0):
        self._alg = alg
        self._pk = bytes(pubkey)
        self._signer = bytes(signer)
        self._ext = ext_base
        self._seen = {}  # seq -> (Receipt, signature)

    def observe(self, r, sig):
        """Record a signed receipt. Raises AuditError(ReceiptUnsigned) on a bad signature. Returns a
        ForkProof (Equivocation) if a previously-seen receipt at the same seq named a different
        object -- the proof carries the accused signer id, both signatures, and the auditor's current
        external counter, which then advances. Returns None otherwise (including a benign exact
        duplicate)."""
        if not cose.mldsa_verify(self._alg, self._pk, r.bytes(), sig):
            raise AuditError("ReceiptUnsigned", "receipt signature does not verify")
        prev = self._seen.get(r.seq)
        if prev is not None:
            prev_r, prev_sig = prev
            if prev_r.obj != r.obj:
                fp = new_fork_proof(self._signer, prev_r, prev_sig, r, sig, self._ext)
                self._ext += 1
                return fp
            return None
        self._seen[r.seq] = (r, bytes(sig))
        return None


@dataclass(frozen=True)
class CausalNode:
    """An object's place in the causal graph: its content id, the content ids of its causes
    (envelope field 8), and its ordering position (authority seq, or `created` absent a receipt)."""

    id: bytes
    causes: list
    position: int


def verify_causal(nodes):
    """Check the signed partial order (§8.2, §8.3): no object names a present cause whose position
    exceeds its own (a future cause it could not have seen), and the graph is acyclic. Either fault
    is CausalViolation. Edges to causes not present in the set are ignored (external references).
    Runs with no ordering authority present (R-8.5). Delegates to the shared naalp.graph, which
    implements exactly this partial order. Returns None on success."""
    graph.verify_causal([(n.id, list(n.causes), n.position) for n in nodes])
    return None


def topo_order(nodes):
    """Return the causal nodes' content ids in a deterministic topological order (a cause before its
    effects). Ties among ready nodes break by (position, input index), so the order is reproducible.
    Raises CausalViolation if the graph does not verify. NOTE: the audit tie-break is by POSITION --
    distinct from the federation reconcile, whose tie-break is the content id (naalp.graph.reconcile)."""
    verify_causal(nodes)
    idx = {bytes(n.id): i for i, n in enumerate(nodes)}
    indeg = [0] * len(nodes)
    effects = [[] for _ in nodes]  # cause index -> effect indices
    for i, n in enumerate(nodes):
        for c in n.causes:
            j = idx.get(bytes(c))
            if j is not None:
                effects[j].append(i)
                indeg[i] += 1
    done = [False] * len(nodes)
    order = []
    while len(order) < len(nodes):
        pick = -1
        for i, n in enumerate(nodes):
            if done[i] or indeg[i] != 0:
                continue
            if pick == -1 or n.position < nodes[pick].position:
                pick = i  # lowest position wins; equal positions keep the lower index (first seen)
        if pick == -1:
            raise graph.CausalViolation("no ready node (unreachable after verify_causal)")
        done[pick] = True
        order.append(bytes(nodes[pick].id))
        for e in effects[pick]:
            indeg[e] -= 1
    return order
