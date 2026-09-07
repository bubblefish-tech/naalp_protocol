# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""A9 isolation demonstration for the N-AALP offline proof bundle (E6.5/R12.5): build a real,
fully-signed object -> approval -> ledger-signed-receipt chain with real ML-DSA-65 keys and a
real durable consume ledger, package it into ONE self-contained ProofBundle, then verify it
LATER, standing in a fresh Python process's worth of state, OFFLINE -- no socket is opened, no
module that could reach a network is even imported -- against an INDEPENDENTLY-supplied trust
anchor. Then shows the two failure modes the whole module exists to enforce: a tampered
signature fails closed with a named error, and a "helpfully" self-anchored bundle (a verifier
who reads the verifying keys OUT OF the bundle instead of an independent source) is refused
outright before a single signature is even checked.

Run (from ecosystem/naalp-bundle/, using the real Python on this machine, not the Microsoft
Store `python` stub):
    python examples/isolation_demo.py
"""
import os
import sys
import tempfile

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PKG_ROOT = os.path.dirname(_THIS_DIR)  # ecosystem/naalp-bundle
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

from naalp_bundle import BundleError, ProofBundle, TrustAnchor, build_bundle, verify_bundle  # noqa: E402
from naalp import approval, cose, envelope, policy  # noqa: E402
from naalp.cbor import U, T, M  # noqa: E402


def _seed(b):
    return bytes([b]) * 32


def main() -> int:
    print("=" * 72)
    print("PASS 1: build a real object -> approval -> ledger-signed-receipt chain")
    print("=" * 72)

    obj_seed = _seed(0xA1)
    obj_pk = cose.mldsa_keygen("ML-DSA-65", obj_seed)
    approver_seed = _seed(0xA2)
    approver_pk = cose.mldsa_keygen("ML-DSA-65", approver_seed)
    ledger_seed = _seed(0xA3)
    ledger_pk = cose.mldsa_keygen("ML-DSA-65", ledger_seed)
    approver_id = "approver-demo-1"
    ledger_id = b"ordering-authority-demo-1"

    obj = envelope.Object(
        kind=1, channel=4, signer=obj_pk, created=1_785_000_000_000, effect=policy.DESTRUCTIVE,
        body=M([(U(1), T("wire 500000 (cents) from treasury to acct-778-441"))]),
        profile=cose.PROFILE_PUBLIC,
    )
    object_bytes = envelope.sign(obj, cose.ALG_MLDSA65, obj_seed)
    print("signed object content id: %s" % obj.id.hex())

    rec = approval.ApprovalRecord(
        obj.id, approver_id, policy.DESTRUCTIVE, b"\x07" * 8, 9_999_999_999_999, "",
    )
    approval_sig = approval.sign_approval(rec, cose.ALG_MLDSA65, approver_seed)
    print("signed approval id: %s (binds the object's content id)" % rec.id().hex())

    with tempfile.TemporaryDirectory() as d:
        ledger = approval.open_ledger_signed(
            os.path.join(d, "consume.wal"), ledger_id, cose.ALG_MLDSA65, ledger_seed)
        try:
            _entry, receipt, receipt_sig = ledger.consume_with_receipt(rec.id(), "requester-demo-1")
            print("ledger-signed consume receipt: ledger=%s position=%d" % (
                receipt.ledger, receipt.position))

            bundle = build_bundle(
                object_bytes, cose.PROFILE_PUBLIC, rec, approval_sig, cose.ALG_MLDSA65,
                receipt, receipt_sig, cose.ALG_MLDSA65,
            )
            wire_bytes = bundle.to_bytes()
            print("packaged bundle: %d bytes, content id %s" % (len(wire_bytes), bundle.content_id().hex()))

            print()
            print("=" * 72)
            print("PASS 2: verify the bundle OFFLINE, against an INDEPENDENTLY-supplied trust anchor")
            print("=" * 72)

            # This anchor is built directly from keys THIS verifier already holds -- never from
            # the bundle under verification. No network module is imported anywhere in this
            # file or in naalp_bundle itself; "offline" here means exactly that: verification
            # succeeds with nothing reachable but the bundle bytes and this local anchor.
            anchor = TrustAnchor({
                ("object", obj_pk): obj_pk,
                ("approval", approver_id.encode("utf-8")): approver_pk,
                ("receipt", ledger_id): ledger_pk,
            })

            # Simulate "later, offline, standing alone": rebuild the bundle from ONLY its wire
            # bytes, as a third party who received the bundle would.
            received = ProofBundle.from_bytes(wire_bytes)
            verified_obj = verify_bundle(received, anchor, lambda ch, k: True)
            print("VERIFIED offline: object content id matches: %r" % (
                verified_obj.content_id() == obj.id))
            assert verified_obj.content_id() == obj.id

            print()
            print("=" * 72)
            print("PASS 3: flip one signature byte -> fails closed with a named error")
            print("=" * 72)
            # object_bytes is a tagged COSE_Sign1 array [protected, {}, payload, signature]; the
            # signature is its final element, so its LAST byte is genuinely the ML-DSA
            # signature's own last byte (not, e.g., a length header or an unrelated field --
            # flipping the raw serialized BUNDLE's last byte instead would corrupt whichever
            # bundle-wire field happens to land there, which is a real but different failure
            # mode from "one signature byte is wrong").
            tampered_object = bytearray(object_bytes)
            tampered_object[-1] ^= 0xFF
            tampered_bundle = build_bundle(
                bytes(tampered_object), cose.PROFILE_PUBLIC, rec, approval_sig, cose.ALG_MLDSA65,
                receipt, receipt_sig, cose.ALG_MLDSA65,
            )
            try:
                verify_bundle(tampered_bundle, anchor, lambda ch, k: True)
                print("FAIL: a tampered signature verified -- this would be a security bug")
                return 1
            except (envelope.EnvelopeError, approval.ApprovalError, BundleError) as e:
                print("tampered signature correctly rejected fail-closed: kind=%s" % e.kind)
                assert e.kind == "BadSignature"

            print()
            print("=" * 72)
            print("PASS 4: a SELF-ANCHORED bundle (F3 circular verification) is REFUSED")
            print("=" * 72)
            # A "helpful" producer embeds the same keys that signed the bundle as a convenience
            # hint -- and a verifier who (wrongly) builds its anchor FROM the bundle instead of
            # an independent source. verify_bundle refuses this outright.
            self_asserted = (
                ("object", obj_pk, obj_pk),
                ("approval", approver_id.encode("utf-8"), approver_pk),
                ("receipt", ledger_id, ledger_pk),
            )
            circular_bundle = ProofBundle(
                received.object_bytes, received.profile, received.approval, received.approval_sig,
                received.approval_alg, received.receipt, received.receipt_sig, received.receipt_alg,
                self_asserted,
            )
            circular_anchor = TrustAnchor.from_bundle_self_asserted(circular_bundle)
            try:
                verify_bundle(circular_bundle, circular_anchor, lambda ch, k: True)
                print("FAIL: a self-anchored (circular) bundle verified -- this would be a security bug")
                return 1
            except BundleError as e:
                print("self-anchored bundle correctly refused: kind=%s" % e.kind)
                assert e.kind == "CircularAnchor"

            print()
            print("ISOLATION DEMO: PASS")
            return 0
        finally:
            ledger.close()


if __name__ == "__main__":
    raise SystemExit(main())
