# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""The N-AALP offline proof bundle (Part-2 E6.5, requirement R12.5).

Packages a signed N-AALP object with the approval that authorized it and the ledger-signed
consume receipt that proves the approval was consumed exactly once, into ONE self-contained
byte string that a third party can verify LATER, OFFLINE, with no live service reachable --
using only the bundle and keys the verifier already holds. Concretely, this proves a chain of
three signed facts:

    Object (signed by the object's own signer)
      <- approved-by --  ApprovalRecord (signed by the approver; approves == Object content id)
      <- consumed-by  --  ConsumeReceipt (signed by the ordering-authority ledger;
                                           approval_id == the ApprovalRecord's own content id)

Every cryptographic and encoding operation is delegated to the real Part-1 primitives -- this
module performs NO signing, NO signature verification math, and NO CBOR encode/decode of its
own. Object assembly and verification is `naalp.envelope` (sign/verify); the approval and the
ledger-signed receipt are `naalp.approval` (ApprovalRecord/ConsumeReceipt, sign_approval/
verify_approval, sign_consume_receipt/verify_consume_receipt, Ledger.consume_with_receipt); the
bundle's own wire format is `naalp.cbor` (the same deterministic-CBOR codec naalp_codec binds --
imported directly here per the task's "or reuse naalp.cbor directly" option, so this package
carries no runtime dependency on the sibling naalp-codec package). The only code this module
adds is glue: field-numbered assembly/parsing of the bundle's OWN wire shape (the same pattern
`naalp.approval._parse_entry` and `naalp.envelope._object_from_map` use to interpret an
already-decoded CBOR map's known fields) and the independent-anchor verification choke point.

THE CRUCIAL F3 PROPERTY (non-circular verification): `verify_bundle` NEVER trusts a key the
bundle carries about itself. A bundle names, by REFERENCE only (a signer/approver/ledger id plus
an algorithm number -- never key material), which independently-held verifying keys a verifier
needs; the caller resolves those references against a `TrustAnchor` it builds from its OWN,
out-of-band source (a keystore, a certificate, an operator's trust list). A bundle whose only
source of a verifying key is itself is CIRCULAR and `verify_bundle` REFUSES it outright
(`BundleError("CircularAnchor", ...)`) -- see `TrustAnchor.from_bundle_self_asserted` below,
which exists ONLY to make that forbidden shape constructible so it can be tested and refused.
"""
from . import _bootstrap  # noqa: F401  (repo-relative sys.path setup; must run before `naalp` imports)

import time
from dataclasses import dataclass, field
from typing import Optional, Tuple

from naalp import approval, cbor, cose, envelope
from naalp.cbor import U, N, B, T, A, M


class BundleError(ValueError):
    """A named, fail-closed proof-bundle error; .kind is the stable error kind. Most failure
    kinds are the reused Part-1 errors (BadSignature, ApprovalMismatch, ApprovalExpired,
    ContentIdMismatch, ConsumeReceiptUnsigned, ...) raised directly by naalp.envelope /
    naalp.approval and never re-wrapped; this class exists only for the outcomes that have no
    Part-1 analogue: AnchorRequired, CircularAnchor, UnresolvedAnchor, IncompleteBundle,
    ApprovalObjectMismatch, ReceiptApprovalMismatch, and Malformed (a corrupt bundle wire
    shape)."""

    def __init__(self, kind, msg=""):
        super().__init__("%s: %s" % (kind, msg) if msg else kind)
        self.kind = kind


def default_clock_ms() -> int:
    """The wall clock in epoch milliseconds -- the unit ApprovalRecord.not_after uses. A real
    offline verifier (no network) still has a local clock; this is that clock, never a value the
    bundle itself supplies."""
    return int(time.time() * 1000)


# --- glue: interpret an already-decoded CBOR map's known fields (never a second encoder) -------
#
# ApprovalRecord and ConsumeReceipt are Part-1 dataclasses whose OWN `.bytes()` is the real,
# deterministic encoding (naalp.cbor underneath); neither Part-1 module exposes a decode-from-
# bytes for its record type (approval.py decodes ledger ENTRIES and refusals; envelope.py
# decodes objects; neither decodes a bare ApprovalRecord/ConsumeReceipt body). These two
# functions fill that gap the same way Part-1's own `_parse_entry` / `_object_from_map` do:
# `naalp.cbor.decode` does the real byte-level work; this only reads the resulting map's known
# field numbers back into the dataclass's constructor arguments.

def _parse_approval_body(body: bytes) -> approval.ApprovalRecord:
    v = cbor.decode(body)
    if not isinstance(v, M):
        raise BundleError("Malformed", "approval body is not a map")
    approves = approver = grant = nonce = not_after = None
    audience = ""
    for k, val in v.pairs:
        if not isinstance(k, U):
            raise BundleError("Malformed", "non-uint approval field key")
        if k.v == 1 and isinstance(val, B):
            approves = bytes(val.v)
        elif k.v == 2 and isinstance(val, T):
            approver = val.v
        elif k.v == 3 and isinstance(val, U):
            grant = val.v
        elif k.v == 4 and isinstance(val, B):
            nonce = bytes(val.v)
        elif k.v == 5 and isinstance(val, U):
            not_after = val.v
        elif k.v == 6 and isinstance(val, T):
            audience = val.v
        else:
            raise BundleError("Malformed", "unknown or mistyped approval field %r" % (k.v,))
    if approves is None or approver is None or grant is None or nonce is None or not_after is None:
        raise BundleError("Malformed", "approval body missing a mandatory field")
    return approval.ApprovalRecord(approves, approver, grant, nonce, not_after, audience)


def _parse_receipt_body(body: bytes) -> approval.ConsumeReceipt:
    v = cbor.decode(body)
    if not isinstance(v, M):
        raise BundleError("Malformed", "receipt body is not a map")
    ledger = approval_id = position = None
    for k, val in v.pairs:
        if not isinstance(k, U):
            raise BundleError("Malformed", "non-uint receipt field key")
        if k.v == 1 and isinstance(val, B):
            ledger = bytes(val.v)
        elif k.v == 2 and isinstance(val, B):
            approval_id = bytes(val.v)
        elif k.v == 3 and isinstance(val, U):
            position = val.v
        else:
            raise BundleError("Malformed", "unknown or mistyped receipt field %r" % (k.v,))
    if ledger is None or approval_id is None or position is None:
        raise BundleError("Malformed", "receipt body missing a mandatory field")
    return approval.ConsumeReceipt(ledger, approval_id, position)


def _peek_object_signer(object_bytes: bytes) -> bytes:
    """Read the CLAIMED signer id straight off an (as yet unverified) object's payload, so a
    verifier can pick which candidate key to fetch from its trust anchor BEFORE the object's
    signature is checked -- `envelope.verify` needs the pubkey as an input, so something must
    name which key to try first. This peek trusts nothing on its own: it is used only to select
    a candidate; `envelope.verify` independently re-derives and cross-checks the SAME field from
    the SIGNED body afterward (a lie here fails closed downstream as HeaderBodyMismatch or
    BadSignature, never silently accepted)."""
    _, payload, _ = cose.parse_sign1_raw(object_bytes)
    bv = cbor.decode_bounded(payload, envelope.MAX_NESTING_DEPTH)
    if not isinstance(bv, M):
        raise BundleError("Malformed", "object body is not a map")
    for k, v in bv.pairs:
        if isinstance(k, U) and k.v == envelope.FIELD_SIGNER and isinstance(v, B):
            return bytes(v.v)
    raise BundleError("Malformed", "object body carries no signer field")


def _object_alg(object_bytes: bytes) -> int:
    """Read the alg the object's protected header declares (`naalp.cose.alg_from_protected`,
    unchanged) -- the real signature-verification dispatch inside `envelope.verify` always uses
    this SAME field re-derived from the signed bytes; this is only read early so a verifier
    knows what kind of key to fetch from its trust anchor."""
    prot, _, _ = cose.parse_sign1_raw(object_bytes)
    return cose.alg_from_protected(prot)


# --- the trust anchor: the ONLY legitimate source of verifying-key material ---------------------

class TrustAnchor:
    """An INDEPENDENT source of verifying-key material, supplied by the verifier out-of-band --
    never derived from the bundle under test (F3 non-circular; this is the whole discipline this
    module exists to enforce). Build one from keys the caller already holds:

        anchor = TrustAnchor({
            ("object", object_signer_id): object_pubkey,
            ("approval", approver_id.encode("utf-8")): approver_pubkey,
            ("receipt", ledger_id): ledger_pubkey,
        })

    `resolve(role, id_bytes)` returns the pubkey bytes for that (role, id) pair, or None if this
    anchor does not hold one -- `verify_bundle` refuses (UnresolvedAnchor) rather than guess."""

    def __init__(self, known_keys: Optional[dict] = None):
        self._known = {(role, bytes(id_)): pk for (role, id_), pk in (known_keys or {}).items()}
        self._self_derived = False  # set only by from_bundle_self_asserted below

    def resolve(self, role: str, id_bytes: bytes) -> Optional[bytes]:
        return self._known.get((role, bytes(id_bytes)))

    @classmethod
    def from_bundle_self_asserted(cls, bundle: "ProofBundle") -> "TrustAnchor":
        """Build an anchor by reading the key material the BUNDLE ITSELF optionally carries in
        its `self_asserted_keys` hint field (see ProofBundle). THIS IS THE FORBIDDEN SHAPE
        (F3): a trust anchor sourced from the artifact under verification is circular, and
        `verify_bundle` REFUSES any anchor built this way outright, unconditionally, before
        resolving a single key. This constructor exists ONLY so that forbidden shape can be
        built and exercised by a negative conformance test. Production verification code MUST
        build a `TrustAnchor` from an independent source (see the class docstring above) and
        MUST NOT call this constructor."""
        known = {}
        for role, id_bytes, pk in (bundle.self_asserted_keys or ()):
            known[(role, bytes(id_bytes))] = bytes(pk)
        anchor = cls(known)
        anchor._self_derived = True
        return anchor


# --- the proof bundle itself ---------------------------------------------------------------------

@dataclass(frozen=True)
class ProofBundle:
    """The offline-verifiable package (R12.5): a signed N-AALP object, the ApprovalRecord that
    authorized it, and the ConsumeReceipt proving that approval was consumed exactly once --
    plus, OPTIONALLY, `self_asserted_keys`: a producer-supplied convenience hint (NEVER trusted
    by `verify_bundle`'s real verification path -- see `TrustAnchor.from_bundle_self_asserted`
    and the module docstring's F3 discussion). Construct with `build_bundle`, not directly."""

    object_bytes: bytes
    profile: int
    approval: approval.ApprovalRecord
    approval_sig: bytes
    approval_alg: int
    receipt: approval.ConsumeReceipt
    receipt_sig: bytes
    receipt_alg: int
    self_asserted_keys: Tuple[Tuple[str, bytes, bytes], ...] = field(default_factory=tuple)

    def key_refs(self):
        """The (role, id_bytes, alg) triples naming which independently-held verifying keys
        this bundle needs -- REFERENCES only, never key material (the "verifying-key
        references" R12.5 asks the bundle to carry). A verifier resolves each against its OWN
        trust store to build the `TrustAnchor` that `verify_bundle` requires."""
        return (
            ("object", _peek_object_signer(self.object_bytes), _object_alg(self.object_bytes)),
            ("approval", self.approval.approver.encode("utf-8"), self.approval_alg),
            ("receipt", bytes(self.receipt.ledger), self.receipt_alg),
        )

    def _body_map(self) -> M:
        pairs = [
            (U(1), B(self.object_bytes)),
            (U(2), U(self.profile)),
            (U(3), B(self.approval.bytes())),  # ApprovalRecord's OWN deterministic encoding
            (U(4), B(self.approval_sig)),
            (U(5), N(self.approval_alg)),
            (U(6), B(self.receipt.bytes())),   # ConsumeReceipt's OWN deterministic encoding
            (U(7), B(self.receipt_sig)),
            (U(8), N(self.receipt_alg)),
        ]
        if self.self_asserted_keys:
            pairs.append((U(9), A([A([T(role), B(id_), B(pk)]) for (role, id_, pk) in self.self_asserted_keys])))
        return M(pairs)

    def content_id(self) -> bytes:
        """The bundle's own content id (multihash(0x20, SHA-384(body)), `naalp.cbor.content_id`
        unchanged) -- a re-serialized bundle with the same fields reproduces the SAME id, because
        `naalp.cbor.encode` has exactly one output per logical value (property (d))."""
        return cbor.content_id(self._body_map())

    def to_bytes(self) -> bytes:
        """The bundle's canonical wire bytes -- `naalp.cbor.encode`, unchanged."""
        return cbor.encode(self._body_map())

    @staticmethod
    def from_bytes(data: bytes) -> "ProofBundle":
        """Decode a bundle from its canonical wire bytes (`naalp.cbor.decode`, unchanged --
        rejects any non-canonical encoding fail-closed, as it does everywhere else this decoder
        is used). Reconstructs the ApprovalRecord/ConsumeReceipt instances via the glue parsers
        above; since both `.bytes()` are deterministic, a bundle round-tripped through
        `to_bytes()` -> `from_bytes()` -> `to_bytes()` reproduces byte-identical output."""
        v = cbor.decode(data)
        if not isinstance(v, M):
            raise BundleError("Malformed", "bundle is not a map")
        fields = {}
        for k, val in v.pairs:
            if not isinstance(k, U):
                raise BundleError("Malformed", "non-uint bundle field key")
            fields[k.v] = val

        def need(n, typ):
            val = fields.get(n)
            if not isinstance(val, typ):
                raise BundleError("Malformed", "field %d wrong type or absent" % n)
            return val

        object_bytes = bytes(need(1, B).v)
        prof = need(2, U).v
        approval_rec = _parse_approval_body(bytes(need(3, B).v))
        approval_sig = bytes(need(4, B).v)
        approval_alg = need(5, N).v
        receipt = _parse_receipt_body(bytes(need(6, B).v))
        receipt_sig = bytes(need(7, B).v)
        receipt_alg = need(8, N).v

        self_asserted = []
        if 9 in fields:
            arr = fields[9]
            if not isinstance(arr, A):
                raise BundleError("Malformed", "field 9 (self_asserted_keys) not an array")
            for item in arr.items:
                if not isinstance(item, A) or len(item.items) != 3:
                    raise BundleError("Malformed", "self-asserted key entry malformed")
                role_v, id_v, pk_v = item.items
                if not (isinstance(role_v, T) and isinstance(id_v, B) and isinstance(pk_v, B)):
                    raise BundleError("Malformed", "self-asserted key entry field types")
                self_asserted.append((role_v.v, bytes(id_v.v), bytes(pk_v.v)))

        return ProofBundle(object_bytes, prof, approval_rec, approval_sig, approval_alg,
                            receipt, receipt_sig, receipt_alg, tuple(self_asserted))


def build_bundle(object_bytes: bytes, profile: int,
                  approval_record: approval.ApprovalRecord, approval_sig: bytes, approval_alg: int,
                  receipt: approval.ConsumeReceipt, receipt_sig: bytes, receipt_alg: int,
                  self_asserted_keys=()) -> ProofBundle:
    """Package already-signed pieces into one ProofBundle. Performs NO cryptography itself --
    every signed input is the caller's own output from `naalp.envelope.sign` /
    `naalp.approval.sign_approval` / `naalp.approval.Ledger.consume_with_receipt` (or
    `sign_consume_receipt`); this only assembles them. Refuses, fail-closed, to package an
    internally-inconsistent chain: if the approval does not actually bind THIS object's content
    id (`ApprovalObjectMismatch`), or the receipt does not name THIS approval's own content id
    (`ReceiptApprovalMismatch`), nothing is returned -- a bundle that could never verify later is
    never produced in the first place. The object's content id is recomputed straight from
    `object_bytes` the same way `envelope.verify` does (§2.3: decode the signed payload, drop
    field 1, hash what remains) -- never trusted from a caller-supplied value."""
    obj_cid = cbor.content_id(_object_body_without_id(object_bytes))
    if bytes(approval_record.approves) != bytes(obj_cid):
        raise BundleError("ApprovalObjectMismatch", "the approval does not bind this object's content id")
    if bytes(receipt.approval_id) != bytes(approval_record.id()):
        raise BundleError("ReceiptApprovalMismatch", "the consume receipt does not name this approval")
    return ProofBundle(bytes(object_bytes), profile, approval_record, bytes(approval_sig), approval_alg,
                        receipt, bytes(receipt_sig), receipt_alg, tuple(self_asserted_keys))


def _object_body_without_id(object_bytes: bytes) -> M:
    """Recompute the object's content id the SAME way `envelope.verify` does: decode the signed
    payload and drop field 1 (the claimed id) before hashing (§2.3). Used only by `build_bundle`
    as an up-front sanity cross-check; `verify_bundle` gets the authoritative id from
    `envelope.verify`'s own return value instead (never trusts this pre-check alone)."""
    _, payload, _ = cose.parse_sign1_raw(object_bytes)
    bv = cbor.decode_bounded(payload, envelope.MAX_NESTING_DEPTH)
    if not isinstance(bv, M):
        raise BundleError("Malformed", "object body is not a map")
    return M([(k, v) for k, v in bv.pairs if not (isinstance(k, U) and k.v == envelope.FIELD_ID)])


_NAMED_ERROR_TYPES = (envelope.EnvelopeError, approval.ApprovalError, cbor.NonCanonical, cbor.DepthExceeded)


def _call_named(fn, *args, **kwargs):
    """Call a Part-1 verification primitive, letting its OWN named errors (EnvelopeError,
    ApprovalError, NonCanonical, DepthExceeded) propagate unchanged. `approval_alg`/`receipt_alg`
    are plain bundle metadata, not covered by any signature, so a corrupted algorithm number
    (e.g. from a tampered wire bundle) can drive the underlying crypto call into an
    alg/pubkey-length combination that its OWN library raises a bare ValueError/TypeError for
    (naalp.cose.cose_verify1_raw: "unknown alg %d"; a mis-sized key handed to the Ed25519/ML-DSA
    verifier) rather than cleanly returning False. That mismatch can never turn a rejection into
    an acceptance -- the signature still does not verify -- but left unwrapped it would force
    every caller of verify_bundle to catch an unbounded exception type just to stay fail-closed.
    Any exception outside the named set is therefore wrapped into a named
    BundleError('MalformedSignatureInput', ...): this only tightens the SHAPE of a failure that
    was already going to be a failure, never the outcome."""
    try:
        return fn(*args, **kwargs)
    except _NAMED_ERROR_TYPES:
        raise
    except Exception as e:  # noqa: BLE001 -- deliberately broad: see docstring
        raise BundleError("MalformedSignatureInput", "%s: %s" % (getattr(fn, "__name__", fn), e))


def verify_bundle(bundle: ProofBundle, anchor: Optional[TrustAnchor], kind_validator,
                   pos_time: Optional[int] = None, known_cext: Optional[dict] = None):
    """Verify a proof bundle end-to-end, OFFLINE: no network call is made anywhere in this
    function or anything it calls. Returns the verified `naalp.envelope.Object` on success;
    raises a named error and authorizes nothing on the first failure. Check order (fail-closed):

      1. `anchor` must be supplied (AnchorRequired) and must NOT be self-derived from this
         bundle (CircularAnchor -- the F3 non-circular refusal; checked before anything else is
         even looked at).
      2. the bundle must carry a complete chain (IncompleteBundle).
      3. the OBJECT verifies against an anchor-resolved key (`envelope.verify`, unchanged: content
         id, critical extensions, field ranges, header/body consistency, signature).
      4. the APPROVAL verifies against an anchor-resolved key AND binds the object's own,
         JUST-VERIFIED content id (`naalp.approval.verify_approval`, unchanged: BadSignature ->
         ApprovalMismatch -> ApprovalExpired).
      5. the RECEIPT names THIS approval's own content id (`ReceiptApprovalMismatch` -- a bundle-
         level cross-check with no Part-1 analogue: naming a different, validly-signed approval
         would otherwise pass receipt verification alone).
      6. the RECEIPT verifies as a genuine ledger-signed statement against an anchor-resolved key
         (`naalp.approval.verify_consume_receipt`, unchanged).

    Any UNRESOLVED anchor reference at steps 3/4/6 refuses `UnresolvedAnchor` rather than guess a
    key. `pos_time` defaults to this verifier's own local clock (never a time the bundle
    supplies); pass it explicitly for deterministic verification."""
    if anchor is None:
        raise BundleError("AnchorRequired", "verification requires an independently-supplied trust anchor")
    if getattr(anchor, "_self_derived", False):
        raise BundleError(
            "CircularAnchor",
            "the anchor was derived from key material the bundle itself carries; refused -- "
            "F3 non-circular verification requires a trust anchor from an independent source")
    if bundle.approval is None or bundle.receipt is None:
        raise BundleError("IncompleteBundle", "a proof bundle must carry both an approval and a consume receipt")

    pos_time = default_clock_ms() if pos_time is None else pos_time
    obj_ref, approval_ref, receipt_ref = bundle.key_refs()

    obj_role, obj_signer, obj_alg = obj_ref
    object_pk = anchor.resolve(obj_role, obj_signer)
    if object_pk is None:
        raise BundleError("UnresolvedAnchor", "no independently-supplied key for object signer %s" % obj_signer.hex())
    obj = _call_named(envelope.verify, bundle.profile, obj_alg, object_pk, kind_validator,
                       bundle.object_bytes, known_cext)

    appr_role, appr_id, appr_alg = approval_ref
    approval_pk = anchor.resolve(appr_role, appr_id)
    if approval_pk is None:
        raise BundleError("UnresolvedAnchor", "no independently-supplied key for approver %s" % appr_id.hex())
    _call_named(approval.verify_approval, bundle.approval, appr_alg, approval_pk, bundle.approval_sig,
                obj.content_id(), pos_time)

    if bytes(bundle.receipt.approval_id) != bytes(bundle.approval.id()):
        raise BundleError("ReceiptApprovalMismatch", "the consume receipt does not name this bundle's approval")

    rcpt_role, rcpt_id, rcpt_alg = receipt_ref
    receipt_pk = anchor.resolve(rcpt_role, rcpt_id)
    if receipt_pk is None:
        raise BundleError("UnresolvedAnchor", "no independently-supplied key for ledger %s" % rcpt_id.hex())
    _call_named(approval.verify_consume_receipt, bundle.receipt, rcpt_alg, receipt_pk, bundle.receipt_sig)

    return obj
