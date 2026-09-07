# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""The N-AALP evidentiality primitive (Part-2 ecosystem task E6.4, requirement R12.4;
evidence-layer primitives).

An audit/receipt record makes assertions ("this happened", "this identity is who it claims to
be", "this value is correct"). A bare assertion -- a claim with no stated derivation -- cannot
be trusted merely because it is present in an otherwise-signed record: the record's own
signature proves who WROTE the assertion, never that the assertion is TRUE. R12.4 requires that
every assertion instead carry HOW IT IS KNOWN: which signature verified it, which oracle/
authority established it, or which input it was computed from -- "the record states how it
knows" -- and that a bare assertion (or one whose stated basis does not actually hold when
re-run) be REFUSED, fail-closed.

evidentiality is therefore a RE-CHECKABLE annotation, not a new signed wire object: the
derivation tag needs no signature of its own because its integrity comes from the VERIFIER
RE-RUNNING the named basis check against real evidence and refusing any assertion whose stated
basis does not actually hold right now. This mirrors two patterns already established in this
codebase:
  * naalp's `recheck` closed-registry pattern (design §2.5 / vectors/registry/recheck.csv):
    a small closed set of named re-derivation procedures, each checked by literally re-running
    the real primitive it names, never by trusting the label.
  * naalp_hitl.nonrepudiation's R-TDCS-3 closed outcome mapping: a bounded vocabulary that a
    verifier enforces by membership, with an explicit "everything else is refused" default.

Closed basis registry (4 codes -- see BASIS_* below and _BASIS_NAMES):
    0  signature-verified   -- a COSE signature verifies under the named signer over the named
                                content (naalp.identity.signer_id + naalp.cose.cose_verify1_raw).
    1  oracle-established   -- a named, REGISTERED oracle re-derives the asserted value from the
                                named input (an external computation this module does not itself
                                perform; the caller supplies the OracleRegistry).
    2  authority-attested   -- a named audit authority's receipt chain, re-verified offline
                                (naalp.audit.verify_chain), places the asserted content id at the
                                named sequence position.
    3  input-computed       -- the asserted value re-computes deterministically from the named
                                input by RE-RUNNING recheck procedure 1, "recompute-content-id"
                                (design §2.3, vectors/registry/recheck.csv row 1): the SAME real
                                naalp.cbor.content_id function every other recheck consumer in
                                this codebase already uses, named here rather than reinvented.

This module performs NO cryptography, NO CBOR encoding, and NO chain bookkeeping itself. Every
check is delegated to the real Part-1 primitives:
  * naalp.identity.signer_id (the real self-certifying signer id, C4/§5.1)
  * naalp.cose.cose_verify1_raw (the real raw COSE signature verify)
  * naalp.cbor.content_id (the real deterministic-CBOR content id, §2.3 -- the SAME function
    recheck procedure 1 names)
  * naalp.audit.verify_chain (the real offline hash-chain re-verify, §8.1)
Nothing here re-derives or re-approximates any of them. What IS this module's own logic -- and
therefore the only logic its own mutation tests target -- is the basis-registry DISPATCH (which
procedure a given basis code runs) and the fail-closed REFUSAL CHOICES (exactly which named error
each mismatch produces).
"""
from . import _bootstrap  # noqa: F401  (repo-relative sys.path setup; must run before `naalp` imports)

from dataclasses import dataclass
from typing import Callable, Dict, Optional

from naalp import audit, cbor, cose, identity  # noqa: F401 (re-exported for callers)

# ---- the closed basis registry (R12.4) -----------------------------------------------------

BASIS_SIGNATURE_VERIFIED = 0
BASIS_ORACLE_ESTABLISHED = 1
BASIS_AUTHORITY_ATTESTED = 2
BASIS_INPUT_COMPUTED = 3

_BASIS_NAMES = {
    BASIS_SIGNATURE_VERIFIED: "signature-verified",
    BASIS_ORACLE_ESTABLISHED: "oracle-established",
    BASIS_AUTHORITY_ATTESTED: "authority-attested",
    BASIS_INPUT_COMPUTED: "input-computed",
}


def basis_name(code: Optional[int]) -> str:
    """The registry's human-readable name for a basis code, or "unknown" for anything outside
    the closed set (including None). Never raises -- this is a label lookup for logging/audit
    display, not a validity check (verify_and_admit is the validity check)."""
    if code is None:
        return "unknown"
    return _BASIS_NAMES.get(code, "unknown")


class EvidentialityError(ValueError):
    """A named, fail-closed evidentiality error; .kind is the stable error kind."""

    def __init__(self, kind, msg=""):
        super().__init__("%s: %s" % (kind, msg) if msg else kind)
        self.kind = kind


@dataclass(frozen=True)
class BasisRef:
    """WHICH signer/oracle/authority/input a basis code names (design table, R12.4). Only the
    fields relevant to the assertion's own basis_code are populated by a well-formed caller; the
    re-check functions below read only the fields their own basis needs and never trust an
    unrelated field left at its default."""

    signer_id: str = ""              # basis 0: the signer id the signature is claimed to verify under
    oracle_id: str = ""              # basis 1: the registered oracle id claimed to have established the value
    authority_signer_id: str = ""    # basis 2: the audit authority's signer id
    receipt_seq: int = -1            # basis 2: the receipt sequence position the value is claimed to be at
    input_content_id: bytes = b""    # basis 1 and 3: the content id of the input the value derives from


@dataclass(frozen=True)
class EvidencedAssertion:
    """One assertion in an audit/receipt record, annotated with HOW IT IS KNOWN (R12.4).
    `what` is a free-form label naming the fact (e.g. "audit.chain.head", "identity.rotation.new
    -key"); `value_content_id` is the naalp.cbor.content_id of the fact's own canonical-CBOR
    encoding -- the thing whose provenance is being asserted. `basis_code`/`basis_ref` are
    Optional and default to None/None: a bare assertion (both None) is exactly the case R12.4
    requires this module to refuse."""

    what: str
    value_content_id: bytes
    basis_code: Optional[int] = None
    basis_ref: Optional[BasisRef] = None


# ---- evidence: the real, re-derivable material each basis re-check runs against -------------
#
# An EvidencedAssertion is deliberately NOT self-contained (it carries only content ids and
# labels, not raw bytes/signatures) -- exactly like naalp's own recheck registry, which also
# re-derives from real objects supplied at verify time rather than from a value baked into the
# thing being checked. Evidence is supplied SEPARATELY, at verify time, so a forger who controls
# only the assertion's basis_code/basis_ref cannot manufacture a pass: admission requires REAL
# evidence that actually verifies/chains/recomputes, which is exactly as hard to forge as the
# real Part-1 primitive it re-runs (a signature that verifies, a chain that is intact, a SHA-384
# preimage that lands on the claimed digest).

@dataclass(frozen=True)
class SignatureEvidence:
    """Basis 0 evidence: the actual signed bytes and signature, re-verified for real."""

    alg: int
    pubkey: bytes
    signed_bytes: bytes
    sig: bytes


@dataclass(frozen=True)
class OracleEvidence:
    """Basis 1 evidence: the actual input bytes the named oracle is re-run against."""

    input_bytes: bytes


@dataclass(frozen=True)
class AuthorityEvidence:
    """Basis 2 evidence: the actual receipt chain (from genesis) the authority is re-verified
    against. `receipts`/`sigs` are naalp.audit.Receipt / raw-signature lists, in chain order."""

    receipts: object   # list[naalp.audit.Receipt]
    sigs: object        # list[bytes]
    authority_alg: int
    authority_pubkey: bytes


@dataclass(frozen=True)
class InputEvidence:
    """Basis 3 evidence: the actual input bytes recheck procedure 1 recomputes a content id
    from."""

    input_bytes: bytes


# ---- pluggable oracle registry (basis 1) -----------------------------------------------------

class Oracle:
    """The pluggable contract for a basis-1 "oracle-established" authority: given the exact
    input bytes, deterministically re-derive the fact's own canonical-CBOR-encodable value.
    A concrete oracle MUST be deterministic (same input -> same output, always) -- a
    non-deterministic "oracle" cannot be re-run to confirm an assertion, which defeats the whole
    point of naming it as a basis."""

    def establish(self, input_bytes: bytes) -> bytes:
        raise NotImplementedError


class OracleRegistry:
    """The closed set of oracles a verifier is willing to trust for basis 1, keyed by oracle id.
    An unregistered oracle id is refused (OracleUnregistered) -- a basis-1 assertion can never be
    admitted on the strength of an oracle id nobody configured this verifier to trust."""

    def __init__(self):
        self._oracles: Dict[str, Oracle] = {}

    def register(self, oracle_id: str, oracle: Oracle) -> None:
        self._oracles[oracle_id] = oracle

    def get(self, oracle_id: str) -> Optional[Oracle]:
        return self._oracles.get(oracle_id)


# ---- the re-check dispatch (this module's own logic; mutation-tested) -----------------------

def verify_and_admit(
    assertion: EvidencedAssertion,
    evidence,
    oracle_registry: Optional[OracleRegistry] = None,
) -> None:
    """Re-run the assertion's STATED basis for real, against real evidence, admitting it only
    if the basis demonstrably holds RIGHT NOW. Raises a named EvidentialityError and admits
    nothing on ANY failure (fail-closed: no partial admission, no state change). Returns None on
    success -- the caller's own code proceeds only past this call, mirroring
    naalp_verify_at_use.VerifyAtUseGuard.execute's RESUME-only-past-this-line discipline."""
    if assertion.basis_code is None or assertion.basis_ref is None:
        raise EvidentialityError("NoBasis", "assertion carries no derivation basis (%r)" % (assertion.what,))
    if assertion.basis_code not in _BASIS_NAMES:
        raise EvidentialityError(
            "UnknownBasis", "basis code %r is outside the closed registry" % (assertion.basis_code,)
        )
    if evidence is None:
        raise EvidentialityError("EvidenceMissing", "no evidence supplied to re-run the stated basis")

    if assertion.basis_code == BASIS_SIGNATURE_VERIFIED:
        _recheck_signature_verified(assertion, evidence)
    elif assertion.basis_code == BASIS_ORACLE_ESTABLISHED:
        _recheck_oracle_established(assertion, evidence, oracle_registry)
    elif assertion.basis_code == BASIS_AUTHORITY_ATTESTED:
        _recheck_authority_attested(assertion, evidence)
    elif assertion.basis_code == BASIS_INPUT_COMPUTED:
        _recheck_input_computed(assertion, evidence)
    else:
        # Unreachable given the registry-membership check above; kept as an explicit
        # fail-closed backstop rather than an implicit fall-through admit.
        raise EvidentialityError("UnknownBasis", "basis code %r has no re-check procedure" % (assertion.basis_code,))


def _recheck_signature_verified(assertion: EvidencedAssertion, evidence) -> None:
    """Basis 0: re-run the REAL COSE verify (naalp.cose.cose_verify1_raw) under the REAL
    signer id (naalp.identity.signer_id) named in basis_ref, over the exact bytes whose content
    id is the asserted value."""
    if not isinstance(evidence, SignatureEvidence):
        raise EvidentialityError("EvidenceMissing", "signature-verified basis requires SignatureEvidence")
    signer = identity.signer_id(evidence.alg, evidence.pubkey)
    if signer != assertion.basis_ref.signer_id:
        raise EvidentialityError("SignerMismatch", "evidence key does not match the named signer id")
    signed_id = cbor.content_id(evidence.signed_bytes)
    if signed_id != assertion.value_content_id:
        raise EvidentialityError(
            "SignedContentMismatch", "evidence signed bytes do not match the asserted content id"
        )
    if not cose.cose_verify1_raw(evidence.alg, evidence.pubkey, evidence.signed_bytes, evidence.sig):
        raise EvidentialityError("SignatureInvalid", "signature does not verify under the named signer")


def _recheck_oracle_established(assertion: EvidencedAssertion, evidence, oracle_registry) -> None:
    """Basis 1: bind the evidence to the named input, then re-run the named REGISTERED oracle
    for real and confirm it re-derives the exact asserted value."""
    if not isinstance(evidence, OracleEvidence):
        raise EvidentialityError("EvidenceMissing", "oracle-established basis requires OracleEvidence")
    input_id = cbor.content_id(evidence.input_bytes)
    if input_id != assertion.basis_ref.input_content_id:
        raise EvidentialityError("OracleInputMismatch", "evidence input does not match the named input content id")
    oracle = oracle_registry.get(assertion.basis_ref.oracle_id) if oracle_registry is not None else None
    if oracle is None:
        raise EvidentialityError(
            "OracleUnregistered", "oracle id %r is not registered with this verifier" % (assertion.basis_ref.oracle_id,)
        )
    derived = oracle.establish(evidence.input_bytes)
    if cbor.content_id(derived) != assertion.value_content_id:
        raise EvidentialityError(
            "OracleValueMismatch", "the named oracle does not re-derive the asserted value from this input"
        )


def _recheck_authority_attested(assertion: EvidencedAssertion, evidence) -> None:
    """Basis 2: re-verify the REAL receipt chain offline (naalp.audit.verify_chain) under the
    REAL authority signer id, then confirm the receipt AT the named sequence position orders
    exactly the asserted content id."""
    if not isinstance(evidence, AuthorityEvidence):
        raise EvidentialityError("EvidenceMissing", "authority-attested basis requires AuthorityEvidence")
    authority_id = identity.signer_id(evidence.authority_alg, evidence.authority_pubkey)
    if authority_id != assertion.basis_ref.authority_signer_id:
        raise EvidentialityError(
            "AuthorityMismatch", "evidence authority key does not match the named authority signer id"
        )
    seq = assertion.basis_ref.receipt_seq
    if seq < 0 or seq >= len(evidence.receipts):
        raise EvidentialityError("ReceiptNotAtSeq", "no receipt exists at the named sequence position")
    try:
        audit.verify_chain(evidence.receipts, evidence.sigs, evidence.authority_alg, evidence.authority_pubkey)
    except audit.AuditError as e:
        raise EvidentialityError("ChainInvalid", "receipt chain does not verify: %s" % (e.kind,))
    if evidence.receipts[seq].obj != assertion.value_content_id:
        raise EvidentialityError(
            "ReceiptNotAtSeq", "the receipt at the named sequence does not order the asserted content id"
        )


def _recheck_input_computed(assertion: EvidencedAssertion, evidence) -> None:
    """Basis 3: RE-RUN recheck procedure 1, "recompute-content-id" (design §2.3,
    vectors/registry/recheck.csv row 1) -- the SAME real naalp.cbor.content_id function --
    confirming the evidence is genuinely the named input AND that the asserted value is
    genuinely that input's own recomputed content id. Two independent equality checks against
    two independently-populated fields (basis_ref.input_content_id and
    assertion.value_content_id): a forger who controls only one of the two cannot pass both."""
    if not isinstance(evidence, InputEvidence):
        raise EvidentialityError("EvidenceMissing", "input-computed basis requires InputEvidence")
    recomputed = cbor.content_id(evidence.input_bytes)
    if recomputed != assertion.basis_ref.input_content_id:
        raise EvidentialityError("InputMismatch", "evidence input does not match the named input content id")
    if recomputed != assertion.value_content_id:
        raise EvidentialityError("RecomputeMismatch", "recomputed content id does not match the asserted value")
