# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""C6 approval object + single-use consume ledger for the Python SDK (design.md §7; R-7.1..7.4).

An ApprovalRecord binds, under signature, the content id of the exact canonical argument object it
approves (§7.1); because the args are named by content id, mutating any argument changes the id and
the approval no longer matches (ApprovalMismatch). The consume ledger is a durable compare-and-set
set keyed by approval content id: the FIRST consumer of an id wins and every later consume of the
same id is rejected AlreadyConsumed (§7.2). Atomicity is honest, not decorative -- the membership
check AND the append run inside ONE lock-held critical section (the single-writer discipline, as the
Go single mutex), so there is no read-then-write TOCTOU window and a race spends an approval exactly
once. Each winning consume is written and fsynced to the write-ahead log before it returns
(persist-before-ack). A held outcome is a distinct signed non-success result (HeldResult, §7.4).
Every rejection is fail-closed and causes no ledger append.

Ported from impl/go/approval; graded against the shared vectors/approval/cases.json. The approval
SIGNATURE is real deterministic ML-DSA-65 over the body bytes directly (as the reference
cose.Signer.Sign -- NOT a COSE Sig_structure); the corpus carries no signed vector, so sign/verify
is demonstrated in isolation only.

Also ported (T1.5, NAALP-REQ-121; design.md §25, C22 R-TDCS-2/3/4/5): the ledger-signed
ConsumeReceipt / ConsumeForkEvidence / ReceiptSet double-spend-evidence surface (approval.go
§7.5), graded against the SEPARATE independent corpus vectors/consume_receipt/cases.json; the
R-TDCS-5 audience binding and R-TDCS-3 party-visible coarse Refusal object, graded against
vectors/trust_decision/cases.json; and R-TDCS-4 freshness-independence
(verify_fresh_independent). Each ordering-authority signature here is real deterministic
ML-DSA-65 over the receipt body bytes directly, exactly as the approval signature above.

NOT A PER-PORT SURFACE (honest status F2/F4): vectors/partition/consume_partition_cases.json
(NAALP-REQ-103, "a baseline executor SHALL deny the spend when it cannot reach the consume
ledger") is a behavioral-transcript conformance case graded by the language-agnostic
scripts/partition_case.py directly against its fixture -- it exercises no impl/<lang> code path
and defines no encode/decode surface, so there is nothing for this port (or any port) to
implement or grade independently; it is not omitted, it has no per-port shape.
"""
import hashlib
import os
import threading
from dataclasses import dataclass

from . import cbor, cose, envelope, policy, records
from .cbor import U, B, T, M

# HeadSize is the width of a chain head (SHA-384 = 48 bytes). Genesis is all-zero.
HEAD_SIZE = 48


class ApprovalError(ValueError):
    """A named, fail-closed approval error; .kind is the stable error kind (§7, §15)."""

    def __init__(self, kind, msg=""):
        super().__init__("%s: %s" % (kind, msg) if msg else kind)
        self.kind = kind


def _chain_next(entry_bytes):
    """The chain head after an entry: SHA-384 over the entry's deterministic-CBOR bytes (48 octets).
    Because the entry body carries Prev, editing any entry breaks the next entry's linkage."""
    return hashlib.sha384(bytes(entry_bytes)).digest()


# ---- §7.1 the approval object body -------------------------------------------------------------

@dataclass(frozen=True)
class ApprovalRecord:
    """The body of an Approval object (§7.1). Signed over its deterministic-CBOR bytes. `approves`
    is the content id of the exact canonical args object; a changed argument changes the id and the
    approval no longer matches (ApprovalMismatch)."""

    approves: bytes    # content id of the exact canonical args object (§7.1)
    approver: str      # approver signer id
    grant: int         # granted effect class (0..3), the C5 effect
    nonce: bytes       # anti-replay nonce (§7.3)
    not_after: int     # expiry, epoch ms (§7.3)
    audience: str = "" # OPTIONAL valid-context (R-TDCS-5); "" == absent (field 6 omitted, unrestricted)

    def bytes(self):
        """Deterministic-CBOR encoding of the approval body {1..5, ?6:audience}. Field 6 is OMITTED
        when `audience` is "" -- an empty string is not a distinct value, so an approval that names no
        audience encodes byte-identically to a 5-field approval (R-TDCS-5, additive by design)."""
        pairs = [
            (U(1), B(self.approves)), (U(2), T(self.approver)), (U(3), U(self.grant)),
            (U(4), B(self.nonce)), (U(5), U(self.not_after)),
        ]
        if self.audience:
            pairs.append((U(6), T(self.audience)))
        return cbor.encode(M(pairs))

    def id(self):
        """The approval content id (the ledger key): multihash(0x20, SHA-384(body)) (50 octets)."""
        return cbor.content_id(self.bytes())


def sign_approval(a, alg, seed):
    """Sign the approval body with a real deterministic ML-DSA key derived from seed. The signed
    input is the approval body bytes DIRECTLY (matching the reference cose.Signer.Sign: raw message,
    empty context, rnd=0 -- there is NO COSE Sig_structure wrapping here)."""
    return cose.mldsa_sign(alg, seed, a.bytes())


def verify_approval(a, alg, pubkey, sig, args_content_id, pos_time):
    """Verify an approval: (1) signed by the approver's key over its body bytes, (2) binds the exact
    args by content id, (3) not expired at pos_time. Returns None only if all three hold; otherwise
    raises the specific named error and authorizes nothing. Check order is fail-closed: BadSignature
    -> ApprovalMismatch -> ApprovalExpired. It does NOT consume -- consumption is the separate atomic
    ledger step (§7.2)."""
    if not cose.cose_verify1_raw(alg, pubkey, a.bytes(), sig):
        raise ApprovalError("BadSignature", "approval signature does not verify")
    if bytes(a.approves) != bytes(args_content_id):
        raise ApprovalError("ApprovalMismatch", "approval does not bind these arguments' content id")
    if pos_time > a.not_after:
        raise ApprovalError("ApprovalExpired", "approval is past its not_after")
    return None


def verify_audience(a, use_context):
    """(R-TDCS-5) Enforce the OPTIONAL audience binding. An approval that NAMES an audience
    (a.audience != "") is valid only in that context: a relying party checks it at use and raises
    AudienceMismatch on a mismatch. An approval that names NO audience is unrestricted by the
    issuer's explicit choice and passes for any use context -- a deployment MAY require an audience
    by local policy above this check. The check is mandatory WHEN a context is present, never
    mandatory-presence (the JWT `aud` present-optional / check-mandatory shape)."""
    if a.audience and a.audience != use_context:
        raise ApprovalError("AudienceMismatch", "approval names an audience other than the use context")
    return None


def consume_approval(a, alg, pubkey, sig, args_content_id, pos_time, required_effect, ledger, by):
    """The composed, single-call consume choke point for the approval state machine (draft
    "## Approval state machine"). Runs the table's precedence in ONE impl-owned place -- the exact
    sequence the conformance suite drives -- rather than re-deriving the ordering at each call site:

      1. verify_approval checks the signature, then the args-content-id binding (ApprovalMismatch,
         which the draft says takes precedence over every cell), then expiry (ApprovalExpired) --
         all BEFORE the ledger is consulted. So a request both past not_after AND already in the
         ledger is refused ApprovalExpired, never AlreadyConsumed (the draft's expiry-over-consume
         rule), and the ledger is left untouched by the rejected request.
      2. the granted effect must be a valid class (0..3) and must cover the action's required
         effect; a grant outside the closed vocabulary, or one below the required effect,
         authorizes nothing and is refused ApprovalRequired (fail-closed; the grant-range guard is
         stricter than the raw callers).
      3. the atomic single-use consume through the §7 ledger: the first consumer of the id wins, a
         second raises AlreadyConsumed, and neither a rejected earlier step nor a losing race
         appends.

    Every rejection is fail-closed and appends nothing; it consumes only when every check holds,
    returning the ledger entry. It does NOT enforce object audience -- that is consume_object's
    binding (design.md §2.5.3); consume_approval is the args-content-id/effect/single-use choke
    point. Mirrors impl/go/approval.ConsumeApproval / impl/rust/src/approval.rs consume_approval."""
    verify_approval(a, alg, pubkey, sig, args_content_id, pos_time)  # BadSignature / ApprovalMismatch / ApprovalExpired
    if a.grant > policy.DESTRUCTIVE:
        raise ApprovalError("ApprovalRequired", "grant is outside the closed 0..3 effect vocabulary")
    if not policy.authorizes(a.grant, required_effect):
        raise ApprovalError("ApprovalRequired", "approval's granted effect does not cover this action")
    return ledger.consume(a.id(), by)


# ---- §7.4 the held (not-yet-granted) outcome ---------------------------------------------------

@dataclass(frozen=True)
class HeldResult:
    """The distinct, signed, non-success result returned when an action requires an approval that has
    not been granted (§7.4). It is never a silent success or a silent denial."""

    approves: bytes    # content id of the args whose approval is pending
    reason: str

    def bytes(self):
        """Deterministic-CBOR encoding {1: approves, 2: reason}."""
        return cbor.encode(M([(U(1), B(self.approves)), (U(2), T(self.reason))]))


def sign_held(h, alg, seed):
    """Sign a held result so the 'not yet granted' outcome is itself attributable (real ML-DSA)."""
    return cose.mldsa_sign(alg, seed, h.bytes())


# ---- R-TDCS-3 the party-visible coarse refusal (design.md §25, C22) ----------------------------
#
# A refusal returned to the authenticated party carries ONLY a single value from a closed
# vocabulary and the content id of the full signed record that carries the discriminating detail --
# a reference, not the reason. The detail exists, is signed, and is auditor-resolvable through the
# record channel, but never reaches the adversary-facing surface, so repeated refusals cannot serve
# an adaptive party as an oracle. A party-visible refusal that carries discriminating detail, or
# omits the record content id, is RefusalDetailLeak; an outcome outside the closed set is
# UnknownRefusalOutcome.

REFUSAL_DENIED = 0        # the action is refused
REFUSAL_HELD = 1          # the action requires a further step not yet taken
REFUSAL_UNVERIFIABLE = 2  # required evidence did not verify

_REFUSAL_OUTCOME_NAME = {
    REFUSAL_DENIED: "denied", REFUSAL_HELD: "held", REFUSAL_UNVERIFIABLE: "unverifiable",
}


def is_known_refusal_outcome(code):
    """Whether code is in the closed refusal-outcome set (denied/held/unverifiable)."""
    return code in _REFUSAL_OUTCOME_NAME


@dataclass(frozen=True)
class Refusal:
    """The party-visible coarse refusal body {1: outcome, 2: record}. `outcome` is the closed-set
    coarse outcome; `record` is the T1 content id of the full signed record carrying the detail."""

    outcome: int   # denied / held / unverifiable (closed set)
    record: bytes  # content id of the full signed record carrying the discriminating detail

    def bytes(self):
        """Deterministic-CBOR encoding {1: outcome, 2: record}."""
        return cbor.encode(M([(U(1), U(self.outcome)), (U(2), B(self.record))]))


def refusal_from_record(outcome, full_record):
    """Build the party-visible refusal for a full signed record: it carries the coarse outcome and
    the content id of full_record, and NOTHING drawn from inside full_record -- the discriminating
    detail stays in the record, referenced only by its id. This is the coarse-to-party split the
    closure property requires (R-TDCS-3)."""
    return Refusal(outcome, cbor.content_id(full_record))


def parse_refusal(b):
    """Reconstruct a Refusal from its body bytes, enforcing that a party-visible refusal carries
    ONLY {outcome, record} and nothing more (R-TDCS-3). Rejects, fail-closed: a malformed body, any
    key other than 1 and 2, a missing or empty record id (RefusalDetailLeak -- discriminating detail
    leaked, or the auditor reference dropped), and an outcome outside the closed set
    (UnknownRefusalOutcome). Authorizes nothing."""
    try:
        v = cbor.decode(b)
    except ValueError:  # cbor.NonCanonical (and any other malformed-body decode fault)
        raise ApprovalError("RefusalDetailLeak", "malformed refusal body")
    if not isinstance(v, M):
        raise ApprovalError("RefusalDetailLeak", "refusal body is not a map")
    outcome, record = None, None
    have_outcome, have_record = False, False
    for k, val in v.pairs:
        if not isinstance(k, U):
            raise ApprovalError("RefusalDetailLeak", "non-uint refusal key")
        if k.v == 1 and isinstance(val, U):
            outcome, have_outcome = val.v, True
        elif k.v == 2 and isinstance(val, B):
            record, have_record = bytes(val.v), True
        else:
            raise ApprovalError("RefusalDetailLeak", "field beyond {1,2} is leaked detail")
    if not have_outcome or not have_record or len(record) == 0:
        raise ApprovalError("RefusalDetailLeak", "a refusal must carry the full-record content id")
    if not is_known_refusal_outcome(outcome):
        raise ApprovalError("UnknownRefusalOutcome",
                             "refusal outcome is outside the closed set denied/held/unverifiable")
    return Refusal(outcome, record)


# ---- §7.2 the consume ledger entry -------------------------------------------------------------

@dataclass(frozen=True)
class LedgerEntry:
    """One append to the consume ledger (§7.2)."""

    seq: int            # ledger sequence position
    prev: bytes         # prior chain head (HEAD_SIZE bytes; genesis is all-zero)
    approval_id: bytes  # the approval content id being consumed
    by: str             # consumer signer id

    def bytes(self):
        """Deterministic-CBOR encoding {1: seq, 2: prev, 3: approval-id, 4: by} (reuses the spine
        records builder). The head after this entry is SHA-384(bytes())."""
        return records.ledger_entry(self.seq, self.prev, self.approval_id, self.by)

    def head(self):
        """This entry's chain head -- the prev of the next entry."""
        return _chain_next(self.bytes())


def _parse_entry(rec):
    """Decode a ledger entry from its deterministic-CBOR bytes. A malformed shape, a non-uint key,
    a mistyped field, an unknown field, or a missing field is a corrupt log (LedgerCorrupt)."""
    v = cbor.decode(rec)   # strict decoder: raises cbor.NonCanonical on a non-canonical body
    if not isinstance(v, M):
        raise ApprovalError("LedgerCorrupt", "ledger entry is not a map")
    seq = prev = aid = by = None
    for k, val in v.pairs:
        if not isinstance(k, U):
            raise ApprovalError("LedgerCorrupt", "non-uint ledger entry key")
        if k.v == 1 and isinstance(val, U):
            seq = val.v
        elif k.v == 2 and isinstance(val, B):
            prev = val.v
        elif k.v == 3 and isinstance(val, B):
            aid = val.v
        elif k.v == 4 and isinstance(val, T):
            by = val.v
        else:
            raise ApprovalError("LedgerCorrupt", "unknown or mistyped ledger entry field %r" % (k.v,))
    if seq is None or prev is None or aid is None or by is None:
        raise ApprovalError("LedgerCorrupt", "ledger entry missing a mandatory field")
    return LedgerEntry(seq, prev, aid, by)


def open_ledger(path, authority=""):
    """Open (creating if needed) a WAL-backed consume ledger at path and replay any existing log to
    rebuild the consumed set and chain head. A log that does not hash-chain cleanly is refused
    (LedgerCorrupt) rather than trusted.

    `authority` is this ledger's consuming-authority NAME only -- the §2.5.3 audience target that
    consume_object() enforces. It is an identity string, NOT the T1.5 ledger-SIGNING surface (the
    receipt/fork/receipt-set double-spend-evidence layer) -- open_ledger_signed() opens THAT."""
    led = Ledger(path, authority)
    led._replay()
    return led


def open_ledger_signed(path, ledger_id, alg, seed):
    """Open a WAL-backed ledger (as open_ledger) and bind it to its own ordering-authority identity
    (`ledger_id`, T1.5's ConsumeReceipt.ledger bytes) and signing key (`alg`/`seed`), so it can mint
    ledger-signed consume receipts through consume_with_receipt (design.md §7.5; T1.5,
    NAALP-REQ-121). An empty `ledger_id` is refused fail-closed: an unnamed ordering authority
    cannot sign the anti-double-spend position, so consume_with_receipt would have nothing
    accountable to emit.

    This T1.5 signing identity is deliberately DISTINCT from the §2.5.3 `authority` string
    open_ledger() takes for consume_object()'s audience check: one is a signed-receipt identity
    (bytes, judged by the ledger's own key), the other is a plain audience-match name (a string
    compared against envelope.Object.audience). A ledger opened here does not gain a
    consume_object() audience; a ledger opened via open_ledger() does not gain a receipt-signing
    key. Nothing in the ten-port surface requires the two to be the same ledger instance."""
    if not ledger_id or seed is None:
        raise ApprovalError("LedgerUnsigned", "ledger requires a named ordering authority and a signing key")
    led = Ledger(path)
    led._replay()
    led._receipt_ledger_id = bytes(ledger_id)
    led._receipt_alg = alg
    led._receipt_seed = bytes(seed)
    return led


class Ledger:
    """The durable, hash-chained, single-use consume set (§7.2). All state mutation goes through
    consume() under a single lock (the single-writer discipline), and each winning consume is written
    and fsynced to the WAL before it returns. Use open_ledger() to construct one.

    T1.5 (NAALP-REQ-121): a ledger opened with open_ledger_signed() also carries its own
    ordering-authority identity (`_receipt_ledger_id`) and signing key (`_receipt_alg`/
    `_receipt_seed`), so consume_with_receipt() can mint a ledger-signed consume receipt binding the
    approval id to the ledger's forward-only position. A plain open_ledger() leaves these unset and
    offers consume() only."""

    def __init__(self, path, authority=""):
        self._lock = threading.Lock()
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        self._f = os.fdopen(fd, "r+b")
        self._consumed = {}                    # approval-id bytes -> seq
        self._head = bytes(HEAD_SIZE)          # current chain head (genesis is all-zero)
        self._seq = 0                          # next sequence number
        self._ledger_id = authority            # consuming-authority NAME (§2.5.3 audience target); identity only, NOT a signed-ledger id
        # T1.5 receipt-signing identity (unset unless opened via open_ledger_signed()).
        self._receipt_ledger_id = b""          # the consuming ledger's signer id (the ordering authority; REQ-121)
        self._receipt_alg = None
        self._receipt_seed = None

    def _replay(self):
        """Read the WAL from the start, rebuilding state and verifying the chain. Each record is
        length-prefixed (uint32 big-endian) so the log is self-framing. An out-of-order seq or a
        broken prev linkage is refused LedgerCorrupt."""
        self._f.seek(0)
        head = bytes(HEAD_SIZE)
        seq = 0
        while True:
            lb = self._f.read(4)
            if len(lb) == 0:
                break
            if len(lb) != 4:
                raise ApprovalError("LedgerCorrupt", "truncated length prefix")
            n = int.from_bytes(lb, "big")
            rec = self._f.read(n)
            if len(rec) != n:
                raise ApprovalError("LedgerCorrupt", "truncated record")
            e = _parse_entry(rec)
            if e.seq != seq or bytes(e.prev) != head:
                raise ApprovalError("LedgerCorrupt", "out-of-order seq or broken chain linkage")
            self._consumed[bytes(e.approval_id)] = e.seq
            head = _chain_next(rec)
            seq += 1
        self._head = head
        self._seq = seq

    def consume(self, approval_id, by):
        """Atomically consume an approval id exactly once (§7.2). The first caller for a given id
        appends a ledger entry (written and fsynced before returning) and returns it; every later
        caller for the same id raises AlreadyConsumed with no append. The single lock serialises the
        compare-and-set, so under a race exactly one caller wins."""
        aid = bytes(approval_id)
        with self._lock:
            if aid in self._consumed:
                raise ApprovalError("AlreadyConsumed", "approval already consumed")
            e = LedgerEntry(self._seq, bytes(self._head), aid, by)
            rec = e.bytes()
            framed = len(rec).to_bytes(4, "big") + rec
            self._f.seek(0, os.SEEK_END)
            self._f.write(framed)
            self._f.flush()
            os.fsync(self._f.fileno())         # persist-before-ack (R-7.2 durability)
            self._consumed[aid] = e.seq
            self._head = _chain_next(rec)
            self._seq += 1
            return e

    def consume_object(self, o, approval_id, by):
        """Consume the approval for a consume-once OBJECT, enforcing the §2.5.3 audience binding at
        the choke point BEFORE the compare-and-set: the object's audience MUST name this ledger's
        consuming authority, or the object is rejected WrongAudience with no ledger append. An
        unnamed ledger (no authority) refuses LedgerUnsigned -- it cannot be the audience of any
        object. This is the unbypassable point-of-use gate (design.md §2.5.3); the audience check is
        NEVER inside envelope.verify() (a relay/auditor legitimately verifies objects addressed to
        others). Mirrors Go/Rust Ledger.ConsumeObject -- the authority is this port's ledger NAME."""
        if not self._ledger_id:
            raise ApprovalError("LedgerUnsigned", "ledger has no consuming authority")
        # fail-closed, before the CAS: raises envelope.EnvelopeError('WrongAudience') and appends nothing
        envelope.check_audience(o, self._ledger_id, True)
        return self.consume(approval_id, by)

    def consume_with_receipt(self, approval_id, by):
        """Perform the first-append-wins compare-and-set (exactly as consume()) AND, on the winning
        append, return a ledger-signed ConsumeReceipt binding the approval id to the entry's
        forward-only position (its ledger seq) (T1.5, NAALP-REQ-121). The ledger must have been
        opened with open_ledger_signed(); a plain ledger raises LedgerUnsigned (fail-closed). A
        second consume of the same approval id raises AlreadyConsumed and signs nothing -- the first
        receipt stands (first-append-wins). The receipt is signed before the WAL write, so a signing
        failure records nothing. The single lock serialises concurrent callers, so under a race
        exactly one wins and exactly one receipt is minted.

        Returns (LedgerEntry, ConsumeReceipt, sig)."""
        with self._lock:
            if not self._receipt_ledger_id or self._receipt_seed is None:
                raise ApprovalError("LedgerUnsigned", "ledger was not opened with a signing key")
            aid = bytes(approval_id)
            if aid in self._consumed:
                raise ApprovalError("AlreadyConsumed", "approval already consumed")  # first-append-wins: no second receipt
            e = LedgerEntry(self._seq, bytes(self._head), aid, by)
            # The receipt binds the approval id to THIS consume's forward-only position (the entry
            # seq), signed by the ledger key. Sign before touching the WAL so a signing failure
            # records nothing.
            receipt = ConsumeReceipt(bytes(self._receipt_ledger_id), aid, e.seq)
            sig = cose.mldsa_sign(self._receipt_alg, self._receipt_seed, receipt.bytes())
            rec = e.bytes()
            framed = len(rec).to_bytes(4, "big") + rec
            self._f.seek(0, os.SEEK_END)
            self._f.write(framed)
            self._f.flush()
            os.fsync(self._f.fileno())         # persist-before-ack (R-7.2 durability)
            self._consumed[aid] = e.seq
            self._head = _chain_next(rec)
            self._seq += 1
            return e, receipt, sig

    def is_consumed(self, approval_id):
        """Whether an approval id has been consumed."""
        with self._lock:
            return bytes(approval_id) in self._consumed

    def head(self):
        """The current chain head (a copy)."""
        with self._lock:
            return bytes(self._head)

    def __len__(self):
        """The number of consumed approvals."""
        with self._lock:
            return len(self._consumed)

    def close(self):
        """Flush and close the WAL file."""
        with self._lock:
            self._f.close()


# ---- T1.5 (NAALP-REQ-121): ledger-signed consume receipt with forward-only position ------------
#
# A ConsumeReceipt is the draft-01 ledger-signed evidence that a consuming ledger -- the ORDERING
# AUTHORITY -- bound an approval content id to its own forward-only position. The anti-double-spend
# counter (position) rides under the LEDGER's signature, never the requester's: the requester cannot
# forge the ledger's position or its signature. A partition that spends one approval twice therefore
# leaves two ledger-signed receipts against one approval id, each carrying a position drawn from
# forked state -- a contradiction authored by neither the requester nor a thief, provable the
# instant the two receipts are compared (see ConsumeForkEvidence). It does not PREVENT the second
# spend; it makes the double-spend detectable in bytes neither party could repudiate.

@dataclass(frozen=True)
class ConsumeReceipt:
    """The ledger-signed evidence body {1: ledger, 2: approval_id, 3: position} -- the exact bytes
    the ledger signs (T1.5)."""

    ledger: bytes       # the consuming ledger's signer id (the ordering authority; REQ-121)
    approval_id: bytes  # the approval content id consumed (the compare-and-set key)
    position: int       # the ledger's forward-only position bound to this consume

    def bytes(self):
        """Deterministic-CBOR encoding of the receipt body {1: ledger, 2: approval_id, 3: position}."""
        return cbor.encode(M([
            (U(1), B(self.ledger)), (U(2), B(self.approval_id)), (U(3), U(self.position)),
        ]))


def sign_consume_receipt(r, alg, seed):
    """Sign a consume receipt with the LEDGER's key (REQ-121: the anti-double-spend counter is
    under the ordering authority's signature, never the requester's). The signed input is the
    receipt bytes() directly (as sign_approval / sign_held -- no COSE Sig_structure wrapping)."""
    return cose.mldsa_sign(alg, seed, r.bytes())


def verify_consume_receipt(r, alg, pubkey, sig):
    """Check that a consume receipt is a valid ledger-signed statement: the ledger id is present
    (an unnamed ordering authority is not evidence) and the signature verifies under the ledger's
    key. Fail-closed: either fault raises ConsumeReceiptUnsigned and authorizes nothing. `pubkey`
    MUST be the key resolved for r.ledger."""
    if not r.ledger:
        raise ApprovalError("ConsumeReceiptUnsigned", "an unnamed ordering authority is not evidence")
    if not cose.cose_verify1_raw(alg, pubkey, r.bytes(), sig):
        raise ApprovalError("ConsumeReceiptUnsigned", "consume receipt signature does not verify")
    return None


def verify_fresh_independent(a, approver_alg, approver_pk, a_sig, args_content_id, pos_time,
                              r, ledger_alg, ledger_pk, r_sig, party_id):
    """(R-TDCS-4, design.md §25, C22) Judge an approval's present-moment validity using time drawn
    from an ordering authority STRUCTURALLY DISTINCT from the party being authenticated. It is the
    named realization of the §18.2 seam -- "validity judged on the ordering position, never the
    signer's clock" -- composing the existing verifiers and adding the distinctness check a relying
    party runs so a party can never be the source of the time against which its own credential's
    expiry is judged. It (1) verifies the approval binds args_content_id, is signed by the approver,
    and is unexpired at pos_time, where pos_time is the ORDERING AUTHORITY's forward-only position
    (never a clock the approver supplies); (2) verifies the consume receipt is ledger-signed (the
    position rides under the ordering authority's key, never the requester's); and (3) rejects
    FreshnessSelfAsserted when the ordering authority r.ledger IS the authenticated party party_id.
    Fail-closed: any fault raises its named error and authorizes nothing."""
    verify_approval(a, approver_alg, approver_pk, a_sig, args_content_id, pos_time)
    verify_consume_receipt(r, ledger_alg, ledger_pk, r_sig)
    if bytes(r.ledger) == bytes(party_id):
        raise ApprovalError("FreshnessSelfAsserted",
                             "the ordering authority that stamps freshness is the authenticated party itself")
    return None


@dataclass(frozen=True)
class ConsumeForkEvidence:
    """The non-repudiable evidence (T1.5, NAALP-REQ-121) that ONE approval content id received TWO
    conflicting ledger-signed consume receipts -- a double spend made provable on comparison. It
    carries both receipts and both ledger signatures; because a verifier checks each signature under
    the key its receipt names, the contradiction is authored by neither the requester nor a thief."""

    approval_id: bytes    # the one approval content id spent twice
    a: ConsumeReceipt      # first receipt
    sig_a: bytes           # ledger A's signature over a.bytes()
    b: ConsumeReceipt      # second receipt (same approval id; different position and/or ledger)
    sig_b: bytes           # ledger B's signature over b.bytes()

    def verify(self, resolve):
        """Check that this is a genuine fork: (1) the disputed approval id is present and BOTH
        receipts name it; (2) the two receipts actually conflict -- they are NOT byte-identical (a
        byte-identical re-emission is a benign duplicate, not a fork); and (3) BOTH ledger signatures
        verify under the keys their receipts name, resolved through `resolve(ledger_id) ->
        (alg, pubkey) | None`. Any failure rejects the whole thing (fail-closed): a mismatched/absent
        approval id or a byte-identical pair raises ConsumeForkInvalid, and an unnamed/unresolvable
        ledger or a signature that does not verify raises ConsumeReceiptUnsigned. On a clean pass the
        double spend is proven and non-repudiable. Returns None."""
        if not self.approval_id:
            raise ApprovalError("ConsumeForkInvalid", "no disputed approval id")
        if bytes(self.a.approval_id) != bytes(self.approval_id) or bytes(self.b.approval_id) != bytes(self.approval_id):
            raise ApprovalError("ConsumeForkInvalid", "both receipts must name the one disputed approval id")
        if self.a.bytes() == self.b.bytes():
            raise ApprovalError("ConsumeForkInvalid", "byte-identical receipts are a benign duplicate, not a fork")
        if not self.a.ledger:
            raise ApprovalError("ConsumeReceiptUnsigned", "receipt A names no ledger")
        ra = resolve(bytes(self.a.ledger))
        if ra is None:
            raise ApprovalError("ConsumeReceiptUnsigned", "receipt A's ledger does not resolve")
        if not self.b.ledger:
            raise ApprovalError("ConsumeReceiptUnsigned", "receipt B names no ledger")
        rb = resolve(bytes(self.b.ledger))
        if rb is None:
            raise ApprovalError("ConsumeReceiptUnsigned", "receipt B's ledger does not resolve")
        alg_a, pk_a = ra
        alg_b, pk_b = rb
        if not cose.cose_verify1_raw(alg_a, pk_a, self.a.bytes(), self.sig_a) or \
                not cose.cose_verify1_raw(alg_b, pk_b, self.b.bytes(), self.sig_b):
            raise ApprovalError("ConsumeReceiptUnsigned", "a ledger signature does not verify")
        return None  # a valid, non-repudiable double-spend proof


class ReceiptSet:
    """Observes ledger-signed consume receipts, keyed by approval content id, and detects a fork (a
    double spend) from the signed receipts alone (T1.5, NAALP-REQ-121) -- the consume-layer analogue
    of the audit.Auditor equivocation detector. It resolves each receipt's ledger to (alg, pubkey)
    through `resolve`, rejects any receipt whose ledger signature does not verify, and on a
    conflicting second receipt for one approval id mints a non-repudiable ConsumeForkEvidence. Use
    new_receipt_set() to construct one."""

    def __init__(self, resolve):
        self._resolve = resolve                # ledger_id bytes -> (alg, pubkey) | None
        self._lock = threading.Lock()
        self._seen = {}                        # approval-id bytes -> (ConsumeReceipt, sig bytes)

    def observe(self, r, sig):
        """Record a ledger-signed consume receipt. Raises ApprovalError(ConsumeReceiptUnsigned) if
        the ledger is unnamed/unresolvable or the signature does not verify. Returns a
        ConsumeForkEvidence when a previously-seen receipt for the same approval id conflicts
        (different position and/or ledger); returns None otherwise (including a benign
        byte-identical duplicate) -- mirroring audit.Auditor.observe (a fork is information the
        caller inspects, not itself a raised fault)."""
        with self._lock:
            resolved = self._resolve(bytes(r.ledger)) if r.ledger else None
            if resolved is None:
                raise ApprovalError("ConsumeReceiptUnsigned", "ledger unnamed or unresolvable")
            alg, pk = resolved
            if not cose.cose_verify1_raw(alg, pk, r.bytes(), sig):
                raise ApprovalError("ConsumeReceiptUnsigned", "receipt signature does not verify")
            key = bytes(r.approval_id)
            prev = self._seen.get(key)
            if prev is not None:
                prev_r, prev_sig = prev
                if prev_r.bytes() == r.bytes():
                    return None  # benign byte-identical duplicate
                fe = ConsumeForkEvidence(bytes(r.approval_id), prev_r, prev_sig, r, bytes(sig))
                return fe
            self._seen[key] = (r, bytes(sig))
            return None


def new_receipt_set(resolve):
    """Make a fork detector that resolves a ledger id to (alg, pubkey) via
    resolve(ledger_id) -> (alg, pubkey) | None (returns None for an unknown ledger id)."""
    return ReceiptSet(resolve)
