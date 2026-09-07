# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""C21 (task 5B.1) NAALP-PAY payment import for the Python SDK (design.md §24; R-PAY-1..6).

NAALP-PAY imports a foreign payment payload -- an AP2 mandate, an Agentic Commerce Protocol
delegated token, an x402 payload -- octet-for-octet as OPAQUE foreign bytes (carriage, not
adoption): the foreign bytes are never re-serialized, canonicalized, or rewritten, and a foreign
identity inside them never becomes an N-AALP authorization identity. It introduces NO new envelope,
encoding, signature, identity, effect, or ledger mechanism: the imported payload becomes a
value-bearing charge that N-AALP governs with its OWN added guarantees, reusing the closed C5 effect
lattice (naalp.policy). There is NO fifth effect and NO payment-specific ledger.

The added guarantees over the imported formats:

  - PaymentImport {1: format, 2: amount, 3: currency, 4: payee, 5: not_after, 6: foreign} is the
    wrapper body. `format` selects the imported FORMAT from the closed payment-format registry;
    `foreign` carries the imported payload octet-for-octet. An unknown format is rejected
    (UnknownPaymentFormat).
  - THE CHARGE IS BOUND. ChargeBinding {1: format, 2: amount, 3: currency, 4: payee, 5: not_after,
    6: foreign_id} names the exact value a §7 approval binds by content id -- including the foreign
    payload's content id (the carriage binding). A wrong-amount, wrong-payee, wrong-currency, or
    substituted-payload charge yields a different content id and no longer matches the approval.

Every check is fail-closed (§15): a failing charge is rejected whole and returns its named error.

Ported from impl/go/payment. The PaymentImport SIGNATURE is a bare-{1:alg} COSE_Sign1 (as the
reference's cose.Sign1) with real deterministic ML-DSA. Graded against vectors/payment/cases.json.

THE PER-CHARGE APPROVAL GATE (STEP-2 parity, ported from impl/go/payment/payment.go:241
AuthorizeCharge): authorize_charge() reuses the §7 approval object, its VerifyApproval binding
check, and the §7 single-use consume ledger UNCHANGED (naalp.approval), plus the closed C5 effect
lattice (naalp.policy.authorizes) -- exactly as the Go/Rust reference. It introduces no new
approval or ledger mechanism of its own. Check order (fail-closed, no state change on any failure
until the ledger consume): unknown/unregistered format -> UnknownPaymentFormat (no ledger append);
verify_approval -> BadSignature / ApprovalMismatch / ApprovalExpired (the approval must bind the
EXACT charge-binding content id -- a wrong amount, wrong payee, wrong currency, or substituted
foreign payload fails this, per test_charge_binding_mismatch_ids); the approval's granted effect
must cover CHARGE_EFFECT (a non_idempotent_write) -> ApprovalRequired; ledger.consume is the ONLY
state change, single-use (AlreadyConsumed on replay, no double-spend); success returns the
LedgerEntry.
"""
import hashlib
from dataclasses import dataclass

from . import approval, cbor, cose, policy
from .cbor import U, N, B, T, M

# The width of a head / content-id digest (SHA-384 = 48 bytes), matching the C7 audit chain.
HEAD_SIZE = 48

# The C5 effect a payment spend carries: a non_idempotent_write. A charge is value-bearing and not
# safely repeatable, which is why it is spent single-use through the §7 ledger.
CHARGE_EFFECT = policy.NON_IDEMPOTENT_WRITE

# Payment format codes (design §24; the closed payment-format registry). A code outside the closed
# set is rejected (UnknownPaymentFormat).
FORMAT_AP2_MANDATE = 1   # AP2 mandate
FORMAT_ACP_TOKEN = 2     # Agentic Commerce Protocol delegated token
FORMAT_X402 = 3          # x402 payload

_FORMAT_NAMES = {
    FORMAT_AP2_MANDATE: "ap2-mandate",
    FORMAT_ACP_TOKEN: "acp-delegated-token",
    FORMAT_X402: "x402-payload",
}


def is_registered_format(code):
    """Whether code is one of the closed payment formats."""
    return code in _FORMAT_NAMES


def format_name(code):
    """The registry name of a format code, or 'unknown'."""
    return _FORMAT_NAMES.get(code, "unknown")


class PayError(ValueError):
    """A named, fail-closed payment error; .kind is the stable error kind (§15)."""

    def __init__(self, kind, msg=""):
        super().__init__("%s: %s" % (kind, msg) if msg else kind)
        self.kind = kind


def _head(b):
    """SHA-384 over a body -- a 48-octet digest."""
    return hashlib.sha384(bytes(b)).digest()


@dataclass(frozen=True)
class PaymentImport:
    """Wraps a foreign payment payload as a value-bearing charge. Format selects the imported format
    (closed registry); Amount/Currency/Payee/NotAfter are the bound charge terms; Foreign is the
    imported payload carried octet-for-octet (carriage, not adoption)."""

    format: int
    amount: int
    currency: str
    payee: bytes
    not_after: int
    foreign: bytes

    def bytes(self):
        """Deterministic-CBOR encoding {1: format, 2: amount, 3: currency, 4: payee, 5: not_after,
        6: foreign}."""
        return cbor.encode(M([
            (U(1), U(self.format)), (U(2), U(self.amount)), (U(3), T(self.currency)),
            (U(4), B(self.payee)), (U(5), U(self.not_after)), (U(6), B(self.foreign)),
        ]))

    def head(self):
        """The SHA-384 head (48 octets)."""
        return _head(self.bytes())

    def id(self):
        """The T1 content-id (50 octets): multihash(0x20, SHA-384(body))."""
        return cbor.content_id(self.bytes())

    def foreign_id(self):
        """The T1 content-id of the carried foreign payload -- the hash the charge binding binds (the
        carriage binding). A substituted payload yields a different foreign_id."""
        return cbor.content_id(bytes(self.foreign))

    def charge_binding(self):
        """The exact charge value an approval binds for this import (amount + currency + payee +
        expiry + the foreign payload's content id). A change to any bound term -- including the
        foreign payload -- changes the binding's content id."""
        return ChargeBinding(self.format, self.amount, self.currency, self.payee,
                             self.not_after, self.foreign_id())


@dataclass(frozen=True)
class ChargeBinding:
    """Names the exact charge by value: format, amount, currency, payee, expiry, and the foreign
    payload's content id. A §7 approval binds THIS binding's content id, so a change to any bound term
    invalidates a prior approval (ApprovalMismatch)."""

    format: int
    amount: int
    currency: str
    payee: bytes
    not_after: int
    foreign_id: bytes  # content-id of the foreign payload: multihash(0x20, SHA-384(foreign))

    def bytes(self):
        """Deterministic-CBOR encoding {1: format, 2: amount, 3: currency, 4: payee, 5: not_after,
        6: foreign_id}."""
        return cbor.encode(M([
            (U(1), U(self.format)), (U(2), U(self.amount)), (U(3), T(self.currency)),
            (U(4), B(self.payee)), (U(5), U(self.not_after)), (U(6), B(self.foreign_id)),
        ]))

    def head(self):
        """The SHA-384 head (48 octets)."""
        return _head(self.bytes())

    def content_id(self):
        """The charge content id an approval binds: multihash(0x20, SHA-384(binding))."""
        return cbor.content_id(self.bytes())


def _field(m, k, typ):
    """Return the value of map key k if it is present with type typ, else None."""
    for key, val in m.pairs:
        if isinstance(key, U) and key.v == k:
            return val if isinstance(val, typ) else None
    return None


def parse_payment_import(b):
    """Reconstruct a PaymentImport from its body bytes alone. Does NOT validate the format against
    the closed set (that is verify_payment_import's job), so an import carrying an unknown format can
    be represented (then rejected). Fail-closed on a malformed shape or a non-canonical encoding."""
    try:
        v = cbor.decode(b)  # the strict decoder rejects a non-canonical body (NonCanonical)
    except cbor.NonCanonical as e:
        raise PayError("PayMalformed", "non-canonical payment-import body: %s" % e)
    if not isinstance(v, M):
        raise PayError("PayMalformed", "payment import is not a map")
    fmt = _field(v, 1, U)
    amt = _field(v, 2, U)
    cur = _field(v, 3, T)
    payee = _field(v, 4, B)
    na = _field(v, 5, U)
    foreign = _field(v, 6, B)
    if None in (fmt, amt, cur, payee, na, foreign):
        raise PayError("PayMalformed", "object is not a well-formed N-AALP payment-import body")
    return PaymentImport(fmt.v, amt.v, cur.v, payee.v, na.v, foreign.v)


# ---- signed import (bare {1:alg} COSE_Sign1, as the reference's cose.Sign1) --------------------

def _protected_header(alg):
    """The COSE protected header {1: alg} as deterministic CBOR (alg is a negative int)."""
    return cbor.encode(M([(U(1), N(alg))]))


def _alg_from_protected(prot):
    v = cbor.decode(prot)
    if not isinstance(v, M):
        raise PayError("PayMalformed", "protected header is not a map")
    for k, val in v.pairs:
        if isinstance(k, U) and k.v == 1:
            if isinstance(val, N):
                return val.v
            if isinstance(val, U):
                return val.v
    raise PayError("PayMalformed", "protected header has no alg")


def sign_payment_import(p, alg, seed):
    """Produce the tagged COSE_Sign1 object over the PaymentImport body with a real deterministic
    ML-DSA key derived from seed."""
    prot = _protected_header(alg)
    payload = p.bytes()
    tbs = cose.to_be_signed_raw(prot, payload)
    sig = cose.mldsa_sign(alg, seed, tbs)
    return cose.assemble_sign1_raw(prot, payload, sig)


def verify_payment_import(obj, profile, alg, pubkey):
    """Verify the import's full signature under the profile, reconstruct it from the signed body
    bytes, and validate the format against the closed registry. Check order (fail-closed):
    Malformed -> UnknownAlg -> ProfileDowngrade -> KeyAlgMismatch -> BadSignature -> parse ->
    UnknownPaymentFormat. Returns the PaymentImport on success."""
    try:
        prot, payload, sig = cose.parse_sign1_raw(obj)
    except ValueError as e:
        raise PayError("PayMalformed", "not a tagged COSE_Sign1: %s" % e)
    halg = _alg_from_protected(prot)
    level, known = cose.alg_level(halg)
    if not known:
        raise PayError("UnknownAlg", "algorithm id not in the N-AALP registry")
    if level < cose.profile_min_level(profile):
        raise PayError("ProfileDowngrade", "signature level below the profile minimum")
    if halg != alg:
        raise PayError("KeyAlgMismatch", "key algorithm does not match object header")
    tbs = cose.to_be_signed_raw(prot, payload)
    if not cose.cose_verify1_raw(halg, pubkey, tbs, sig):
        raise PayError("BadSignature", "signature verification failed")
    p = parse_payment_import(payload)
    if not is_registered_format(p.format):
        raise PayError("UnknownPaymentFormat",
                       "payment import selects a format outside the closed payment-format registry")
    return p


# ---- the per-charge approval gate (reuses §7 approval + consume ledger) -------------------------

def authorize_charge(p, appr, alg, approver_pk, appr_sig, by, now, ledger):
    """Enforce the value-bearing rule for an imported payment (ported from
    impl/go/payment/payment.go:241 AuthorizeCharge), reusing the §7 approval and single-use consume
    ledger UNCHANGED. The approval MUST bind the EXACT charge binding content id (format + amount +
    currency + payee + expiry + foreign_id) -- so it satisfies neither a different amount/payee/
    currency nor a substituted foreign payload (ApprovalMismatch, from naalp.approval) -- its granted
    effect must cover the charge's CHARGE_EFFECT (a non_idempotent_write), it must be unexpired at
    `now`, and it is consumed single-use by `by` through the §7 ledger. Precedence and fail-closed
    behaviour mirror the spine: a non-matching or under-granting approval denies with no ledger
    append; an already-spent approval denies AlreadyConsumed; the consume (the single state change)
    happens only when every check holds. Returns the ledger entry on success.

    p: PaymentImport. appr: approval.ApprovalRecord. alg/approver_pk: the approver's key. appr_sig:
    the approval's signature bytes. by: the consumer signer id. now: the current position (epoch ms).
    ledger: an approval.Ledger (open_ledger()). Raises PayError('UnknownPaymentFormat' /
    'ApprovalRequired') or approval.ApprovalError ('BadSignature' / 'ApprovalMismatch' /
    'ApprovalExpired' / 'AlreadyConsumed')."""
    if not is_registered_format(p.format):
        raise PayError("UnknownPaymentFormat",
                       "payment import selects a format outside the closed payment-format registry")
    charge_cid = p.charge_binding().content_id()
    # Raises BadSignature / ApprovalMismatch (wrong amount/payee/currency/payload) / ApprovalExpired.
    approval.verify_approval(appr, alg, approver_pk, appr_sig, charge_cid, now)
    if not policy.authorizes(appr.grant, CHARGE_EFFECT):
        raise PayError("ApprovalRequired", "the approval's granted effect does not cover the charge")
    return ledger.consume(appr.id(), by)  # AlreadyConsumed on replay (or IO) -- single-use, no double-spend
