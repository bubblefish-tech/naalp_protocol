# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""The per-effect PQ-signed offline-verifiable receipt (Group 6, AC-6.1.1(c)/6.2; design.md
Sec.2.7 "emit PQ-signed receipt per effect"; MCP-VERIFIED F1.5: "PQ-signed receipts per effect:
parameters, principal, decision, result hash -- the NSA logging recommendation made
cryptographically evidenced").

Core MCP defines no receipt, no message-signing, and no logging object of its own (NSA CSI: "the
protocol ... is unaware of message integrity"); this module therefore mints a NEW, small record
type -- there is no existing N-AALP object shape for "one signed statement about one MCP effect
attempt" to reuse. It re-implements NO cryptography and NO encoding: the record is a plain
deterministic-CBOR map (the same `naalp.cbor` primitive `naalp.approval.ConsumeReceipt` and
`naalp_hitl.nonrepudiation.RefusalDecisionRecord` already use), signed and verified with the
SAME idiom those two use -- `naalp.cose.mldsa_sign`/`cose_verify1_raw` directly over the body
bytes (no COSE Sig_structure wrapping, matching `sign_approval`/`sign_held`/
`sign_consume_receipt`/`sign_refusal_record`). Nothing here re-derives ML-DSA, CBOR encoding, or
content-id framing.

MCP-VERIFIED's own honest caveat applies unchanged: "receipts are non-repudiable only relative to
the guard's key; when guard and server share one operator, receipts are self-attested" -- this
module produces exactly that kind of evidence, never a peer-verified or third-party-anchored
claim (F1.6's "receipted, not peer-verified" applies here too)."""
from . import _bootstrap  # noqa: F401  (repo-relative sys.path setup; must run before `naalp` imports)

import json
import os
from dataclasses import dataclass

from naalp import cbor, cose
from naalp.cbor import U, B, T, M

# The receipt's decision is a closed two-value vocabulary: the effect was either forwarded to the
# wrapped server ("executed", with or without approval) or it was refused before reaching the
# server ("denied"). There is no third value -- a receipt is minted on EVERY gated attempt, never
# only on success (F1.5: an audit trail that only records successes is not an audit trail).
DECISION_EXECUTED = "executed"
DECISION_DENIED = "denied"
_DECISIONS = frozenset({DECISION_EXECUTED, DECISION_DENIED})

RECEIPT_FILE_VERSION = 1


class ReceiptError(ValueError):
    """A named, fail-closed receipt-layer error; .kind is the stable error kind."""

    def __init__(self, kind, msg=""):
        super().__init__("%s: %s" % (kind, msg) if msg else kind)
        self.kind = kind


@dataclass(frozen=True)
class EffectReceipt:
    """The body of one per-effect receipt (Group 6). `tool_id`/`args_id` are the T1 content ids
    of the exact foreign tool-definition and call-argument octets the guard carried (the same ids
    `naalp.mcp.CallBinding` names); `call_id` is that binding's own content id -- the SAME value
    an approval for this call bound (§19.5) -- so a receipt is independently traceable to the
    exact approval that authorized it, without re-deriving anything. `effect` is the guard's
    ENFORCED (more-severe) effect classification, never a value the caller merely claimed.
    `decision`/`reason` record the outcome (F1.5); `result_hash` is the content id of the exact
    forwarded result bytes (empty when the effect was denied, since nothing was forwarded) --
    the NSA-recommended "cryptographic hash of the result" made concrete. `principal` is the
    requesting party the guard was told about ("" when none was supplied -- an honest absence,
    never a fabricated identity, matching naalp_hitl.PendingAction.principal's own convention)."""

    tool_id: bytes
    args_id: bytes
    call_id: bytes
    effect: int
    decision: str
    reason: str
    result_hash: bytes
    principal: str
    tool_name: str
    guard_identity: str
    created_ms: int

    def to_map(self):
        if self.decision not in _DECISIONS:
            raise ReceiptError("MalformedReceipt", "decision must be 'executed' or 'denied'")
        if not (0 <= self.effect <= 3):
            raise ReceiptError("MalformedReceipt", "effect is outside the closed 0..3 lattice")
        return M([
            (U(1), B(bytes(self.tool_id))),
            (U(2), B(bytes(self.args_id))),
            (U(3), B(bytes(self.call_id))),
            (U(4), U(self.effect)),
            (U(5), T(self.decision)),
            (U(6), T(self.reason)),
            (U(7), B(bytes(self.result_hash))),
            (U(8), T(self.principal)),
            (U(9), T(self.tool_name)),
            (U(10), T(self.guard_identity)),
            (U(11), U(self.created_ms)),
        ])

    def bytes(self):
        """Deterministic-CBOR encoding of the receipt body {1..11} -- what gets signed."""
        return cbor.encode(self.to_map())

    def content_id(self):
        """The receipt's own content id (T1 framing over `bytes()`)."""
        return cbor.content_id(self.bytes())


def sign_effect_receipt(r: EffectReceipt, alg: int, seed: bytes) -> bytes:
    """Sign the receipt body with a real deterministic ML-DSA key -- the exact signing idiom
    naalp.approval already uses (raw body bytes, no COSE Sig_structure wrapping). Delegates
    entirely to naalp.cose; performs no cryptography of its own."""
    return cose.mldsa_sign(alg, seed, r.bytes())


def verify_effect_receipt(r: EffectReceipt, alg: int, pubkey: bytes, sig: bytes) -> bool:
    """Check a receipt's signature against a public key the caller ALREADY holds (an in-process
    check, e.g. for a test or a caller that separately trusts the key). Delegates entirely to
    naalp.cose.cose_verify1_raw -- the same primitive `naalp_hitl.nonrepudiation.
    verify_refusal_record` uses."""
    return cose.cose_verify1_raw(alg, pubkey, r.bytes(), sig)


# ---- the self-contained, offline-verifiable receipt FILE format (AC-6.2.1) ---------------------
#
# `naalp-mcp-guard verify <receipt>` must PASS/FAIL with NO network access and ONLY the public
# key -- so the artifact a receipt is handed out as must carry its own verification key alongside
# the signed body and signature (MCP-VERIFIED's own scoping: "receipts are non-repudiable only
# relative to the guard's key"). This is a plain, self-describing JSON envelope: a version tag,
# the algorithm, the public key, the exact signed body bytes, and the signature -- all hex-encoded
# for a human-readable artifact. Verification NEVER recomputes the body from separate fields (a
# tamper to ANY hex field changes what gets checked): the signature is checked against the
# `body` field literally as recorded, so a single flipped hex character anywhere fails closed.

def receipt_file_dict(r: EffectReceipt, alg: int, pubkey: bytes, sig: bytes) -> dict:
    """The plain dict a receipt file serializes as (exposed for callers that want the dict form
    without touching a filesystem, e.g. tests)."""
    return {
        "naalp_mcp_guard_receipt": RECEIPT_FILE_VERSION,
        "alg": alg,
        "pubkey": bytes(pubkey).hex(),
        "body": r.bytes().hex(),
        "sig": bytes(sig).hex(),
    }


def write_receipt_file(path: str, r: EffectReceipt, alg: int, pubkey: bytes, sig: bytes) -> None:
    """Write the self-contained receipt file to `path` (created 0600, JSON, newline-terminated).
    Deterministic given identical inputs -- sorted keys, no incidental whitespace variance."""
    obj = receipt_file_dict(r, alg, pubkey, sig)
    data = (json.dumps(obj, sort_keys=True, indent=2) + "\n").encode("utf-8")
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    f = os.fdopen(fd, "wb")
    try:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    finally:
        f.close()


def verify_receipt_bytes(data: bytes) -> bool:
    """THE OFFLINE VERIFIER (Group 6, AC-6.2.1): given the raw bytes of a receipt FILE, return
    True iff it is a well-formed naalp-mcp-guard receipt whose embedded signature verifies
    against its embedded public key over its embedded body bytes EXACTLY as recorded -- False on
    ANY parse failure, unrecognized version, malformed hex, unregistered algorithm, or signature
    mismatch (a single-bit tamper anywhere in `body`, `sig`, `alg`, or `pubkey` changes what is
    checked and therefore fails this check -- fail-closed, never an exception escaping to the
    caller as a false PASS). Performs NO network access and no filesystem access -- offline by
    construction, the property AC-6.2.1 requires; the CLI's `verify` command is the only piece
    that touches a file, by reading it before calling this function.

    This function is the guard's SOLE trust boundary for "is this receipt real": a receipt whose
    JSON is syntactically perfect but whose signature does not check is treated identically to one
    that fails to parse at all -- both return False."""
    try:
        obj = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    if not isinstance(obj, dict) or obj.get("naalp_mcp_guard_receipt") != RECEIPT_FILE_VERSION:
        return False
    try:
        alg = int(obj["alg"])
        pubkey = bytes.fromhex(obj["pubkey"])
        body = bytes.fromhex(obj["body"])
        sig = bytes.fromhex(obj["sig"])
    except (KeyError, ValueError, TypeError):
        return False
    try:
        return bool(cose.cose_verify1_raw(alg, pubkey, body, sig))
    except (ValueError, TypeError):
        return False


__all__ = [
    "EffectReceipt", "ReceiptError", "DECISION_EXECUTED", "DECISION_DENIED",
    "sign_effect_receipt", "verify_effect_receipt",
    "receipt_file_dict", "write_receipt_file", "verify_receipt_bytes",
    "RECEIPT_FILE_VERSION",
]
