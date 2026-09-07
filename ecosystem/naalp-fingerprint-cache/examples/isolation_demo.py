# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""A9 isolation demonstration for the N-AALP signer-id fingerprint cache (E6.2/R12.2): a
concrete first-use pin -> repeat-use -> authorized rotation (re-pin) -> unauthorized key-swap
(refused) -> forged rotation proof (refused) run, with real ML-DSA-65 keys, a real tag-98
Rotation object built and signed by the Part-1 SDK, and a real signer-id fingerprint computed by
the Part-1 SDK -- nothing in this script is mocked or hand-waved.

Run (from ecosystem/naalp-fingerprint-cache/, using the real Python on this machine, not the
Microsoft Store `python` stub):
    python examples/isolation_demo.py
"""
import os
import sys

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PKG_ROOT = os.path.dirname(_THIS_DIR)  # ecosystem/naalp-fingerprint-cache
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

from naalp_fingerprint_cache import FingerprintCache, FingerprintCacheError  # noqa: E402
from naalp import cbor, cose, envelope  # noqa: E402
from naalp.cbor import U, T, M  # noqa: E402


def _rotation_record(old_id, new_id, not_before):
    """The naalp-rotation body {1: old, 2: new, 3: not_before} (design.md sec 5.2 CDDL) -- built
    with the real naalp.cbor primitives, never a hand-rolled encoding."""
    return M([(U(1), T(old_id)), (U(2), T(new_id)), (U(3), U(not_before))])


def main() -> int:
    partner_id = "svc:payments-partner-legacy-erp"
    profile = cose.PROFILE_PUBLIC

    # Three real ML-DSA-65 keypairs: the partner's original key, its legitimate rotated
    # successor, and a completely unrelated (attacker-controlled) key.
    original_seed = bytes([0x51]) * 32
    rotated_seed = bytes([0x52]) * 32
    attacker_seed = bytes([0x99]) * 32
    original_pk = cose.mldsa_keygen("ML-DSA-65", original_seed)
    rotated_pk = cose.mldsa_keygen("ML-DSA-65", rotated_seed)
    attacker_pk = cose.mldsa_keygen("ML-DSA-65", attacker_seed)

    cache = FingerprintCache(profile=profile)

    print("=" * 72)
    print("STEP 1: first authenticated use of the partner's key -> pin")
    print("=" * 72)
    entry1 = cache.check_and_pin(partner_id, cose.ALG_MLDSA65, original_pk)
    print("pinned fingerprint: %s" % entry1.fingerprint)
    assert cache.get(partner_id) == entry1

    print()
    print("=" * 72)
    print("STEP 2: the SAME key presented again -> allowed silently, no state change")
    print("=" * 72)
    entry2 = cache.check_and_pin(partner_id, cose.ALG_MLDSA65, original_pk)
    print("still pinned to: %s (unchanged: %s)" % (entry2.fingerprint, entry2 == entry1))
    assert entry2 == entry1

    print()
    print("=" * 72)
    print("STEP 3: legitimate rotation -- build a real tag-98 Rotation object co-signed by the")
    print("        OLD and NEW keys, present it, and confirm the cache RE-PINS")
    print("=" * 72)
    rotation_obj_body = envelope.Object(
        kind=0, channel=3, signer=b"SIGNER_NEW", created=1_800_000_000_000, effect=2,
        body=_rotation_record("signer-old", "signer-new", 1_800_000_000_000), tier=0, profile=profile,
    )
    rotation_object = envelope.sign_rotation_object(
        rotation_obj_body, cose.ALG_MLDSA65, original_seed, cose.ALG_MLDSA65, rotated_seed
    )
    print("real tag-98 rotation object: %d bytes" % len(rotation_object))
    entry3 = cache.check_and_pin(
        partner_id, cose.ALG_MLDSA65, rotated_pk, rotation_object=rotation_object
    )
    print("re-pinned fingerprint: %s" % entry3.fingerprint)
    assert entry3.fingerprint != entry1.fingerprint
    assert cache.get(partner_id) == entry3

    print()
    print("=" * 72)
    print("STEP 4: an unrelated key presented with NO rotation proof -> refused, cache unchanged")
    print("=" * 72)
    try:
        cache.check_and_pin(partner_id, cose.ALG_MLDSA65, attacker_pk)
        print("FAIL: the key swap was NOT rejected -- this would be a security bug")
        return 1
    except FingerprintCacheError as e:
        print("key swap correctly rejected fail-closed: kind=%s" % e.kind)
        assert e.kind == "KeyPinViolation"
    assert cache.get(partner_id) == entry3, "an unauthorized key swap must not change the pin"

    print()
    print("=" * 72)
    print("STEP 5: a FORGED rotation object (both legs signed by the attacker's own key) ->")
    print("        refused, cache unchanged")
    print("=" * 72)
    forged_body = envelope.Object(
        kind=0, channel=3, signer=b"SIGNER_NEW", created=1_800_000_100_000, effect=2,
        body=_rotation_record("signer-old", "signer-attacker", 1_800_000_100_000), tier=0, profile=profile,
    )
    forged_rotation_object = envelope.sign_rotation_object(
        forged_body, cose.ALG_MLDSA65, attacker_seed, cose.ALG_MLDSA65, attacker_seed
    )
    try:
        cache.check_and_pin(
            partner_id, cose.ALG_MLDSA65, attacker_pk, rotation_object=forged_rotation_object
        )
        print("FAIL: the forged rotation proof was NOT rejected -- this would be a security bug")
        return 1
    except envelope.EnvelopeError as e:
        print("forged rotation proof correctly rejected fail-closed: kind=%s" % e.kind)
        assert e.kind == "RotationUnauthorized"
    assert cache.get(partner_id) == entry3, "a forged rotation proof must not change the pin"

    print()
    print("ISOLATION DEMO: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
