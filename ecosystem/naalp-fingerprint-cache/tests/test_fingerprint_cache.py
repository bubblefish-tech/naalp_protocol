# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""Conformance + mutation-surviving tests for the N-AALP signer-id fingerprint cache (E6.2/R12.2).

Every test here exercises the REAL Part-1 primitives -- naalp.identity.signer_id (the
self-certifying signer id) and naalp.envelope.verify_rotation_object (the tag-98 Rotation-object
co-signature verifier) -- through the cache's thin pin/compare wrapper; no cryptography is faked.

F3 non-circularity, two independent sources, both used below:
  1. `_independent_signer_id` -- a from-scratch reimplementation of design.md sec 5.1's formula
     (multibase(base32, multihash(0x12 sha2-256, SHA-256(multicodec(mc) || pubkey)))), built
     directly from the multiformats registry + RFC 4648, over the RFC 8032 sec 7.1 TEST-1 Ed25519
     public key. Shares no code with naalp.identity or with naalp_fingerprint_cache (the code
     under test).
  2. vectors/rotation/cases.json -- the existing top-level, independently-generated (by
     tools/rotation_oracle.py) tag-98 Rotation-object corpus, already cross-validated
     byte-for-byte against impl/go and impl/rust. Read-only: loaded here, never written.

The five required fail-closed / accept cases (task bar, R12.2) are:
  - test_first_use_pins                            (a) first authenticated use pins
  - test_same_fingerprint_allowed_silently          (b) same fingerprint later -> allowed silently
  - test_key_swap_without_proof_fails_closed        (c) changed + no proof -> KeyPinViolation
  - test_valid_rotation_proof_repins                (d) changed + valid proof -> accepted, re-pins
  - test_forged_rotation_proof_fails_closed         (e) changed + invalid proof -> named error, no re-pin

(c) and (e) are the two recorded red-evidence mutation targets (see ../RED-EVIDENCE.md).

Run (from ecosystem/naalp-fingerprint-cache/, PYTHONDONTWRITEBYTECODE=1, using the real Python on
this machine -- not the Microsoft Store `python` stub):
    python -m unittest -v tests.test_fingerprint_cache
"""
import base64
import hashlib
import json
import os
import sys
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PKG_ROOT = os.path.dirname(_THIS_DIR)  # ecosystem/naalp-fingerprint-cache
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

from naalp_fingerprint_cache import (  # noqa: E402
    FingerprintCache,
    FingerprintCacheError,
    PinnedIdentity,
)
from naalp import cose, envelope, identity  # noqa: E402


# --- F3 vector source 1: a from-scratch, independent signer-id constructor --------------------
#
# Shares no code with naalp.identity.signer_id or naalp_fingerprint_cache.fingerprint_cache.
# Formula and constants are design.md sec 5.1 / the multiformats registry / RFC 4648, not a copy
# of any implementation file in this tree.

_ED25519_MULTICODEC = 0xED           # multiformats key-type code, ed25519-pub
_SHA256_MULTIHASH_CODE = 0x12        # multiformats hash-function code, sha2-256

# RFC 8032 sec 7.1 TEST-1 Ed25519 public key (the well-known primary-source constant; the same
# one tools/signerid_oracle.py cites for the identical reason -- a fixed, external, independently
# checkable key, not one this test suite minted).
_RFC8032_TEST1_ED25519_PK = bytes.fromhex(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
)

# The signer id independently recomputed for the key above, pinned as a golden value BEFORE this
# file imports naalp.identity or naalp_fingerprint_cache (see test_independent_constructor_
# matches_golden_rfc8032_value, which asserts _independent_signer_id reproduces exactly this
# string with zero dependency on naalp.identity).
_RFC8032_TEST1_SIGNER_ID = "bciqn3e4opqx2aihkydyc7c6uif5vn3odubjjhe6rsc5fpdltyr4aizy"


def _uvarint(n):
    """Unsigned LEB128 varint (the multiformats varint spec)."""
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _independent_signer_id(multicodec, pubkey):
    """multibase(base32, multihash(0x12 sha2-256, SHA-256(multicodec(mc) || pubkey))) --
    design.md sec 5.1, built from first principles (hashlib + base64 only)."""
    tagged = _uvarint(multicodec) + bytes(pubkey)
    digest = hashlib.sha256(tagged).digest()
    mh = _uvarint(_SHA256_MULTIHASH_CODE) + _uvarint(len(digest)) + digest
    return "b" + base64.b32encode(mh).decode("ascii").lower().rstrip("=")


# --- F3 vector source 2: the existing top-level rotation oracle (read-only) -------------------

_ROTATION_ORACLE_PATH = os.path.normpath(
    os.path.join(_THIS_DIR, "..", "..", "..", "vectors", "rotation", "cases.json")
)


def _load_rotation_oracle():
    with open(_ROTATION_ORACLE_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def _oracle_verify_case(name):
    doc = _load_rotation_oracle()
    for case in doc["verify"]:
        if case["name"] == name:
            return case
    raise KeyError("no oracle verify case named %r in %s" % (name, _ROTATION_ORACLE_PATH))


class IndependentFingerprintVectorTests(unittest.TestCase):
    """F3: fingerprint values are checked against an independent constructor, never inferred from
    naalp_fingerprint_cache itself."""

    def test_independent_constructor_matches_golden_rfc8032_value(self):
        got = _independent_signer_id(_ED25519_MULTICODEC, _RFC8032_TEST1_ED25519_PK)
        self.assertEqual(got, _RFC8032_TEST1_SIGNER_ID)

    def test_reference_signer_id_matches_the_independent_constructor(self):
        # naalp.identity.signer_id (the Part-1 primitive the cache reuses) must agree with the
        # from-scratch constructor above -- confirming the fingerprint the cache pins really is
        # the design.md sec 5.1 self-certifying signer id, not some other derivation.
        ref = identity.signer_id(cose.ALG_ED25519, _RFC8032_TEST1_ED25519_PK)
        self.assertEqual(ref, _RFC8032_TEST1_SIGNER_ID)

    def test_cache_first_pin_uses_the_independently_verified_fingerprint(self):
        cache = FingerprintCache()
        entry = cache.check_and_pin("peer:rfc8032-test1", cose.ALG_ED25519, _RFC8032_TEST1_ED25519_PK)
        self.assertIsInstance(entry, PinnedIdentity)
        self.assertEqual(entry.fingerprint, _RFC8032_TEST1_SIGNER_ID)


class FingerprintCacheDecisionTableTests(unittest.TestCase):
    """(a)-(e): the full R12.2 decision table, driven by the real tag-98 Rotation-object
    verifier (naalp.envelope.verify_rotation_object) over the independent top-level oracle's
    'good' fixture -- an actual co-signed rotation object, not a hand-built stand-in."""

    def setUp(self):
        good = _oracle_verify_case("good")
        self.old_alg = good["old_alg"]
        self.new_alg = good["new_alg"]
        self.old_pk = bytes.fromhex(good["old_pubkey_hex"])
        self.new_pk = bytes.fromhex(good["new_pubkey_hex"])
        self.good_rotation_object = bytes.fromhex(good["obj_hex"])
        self.profile = good["profile"]
        self.logical_id = "svc:payments-partner"

    # (a) the FIRST authenticated use of a signer pins its fingerprint.
    def test_first_use_pins(self):
        cache = FingerprintCache(profile=self.profile)
        self.assertIsNone(cache.get(self.logical_id))
        entry = cache.check_and_pin(self.logical_id, self.old_alg, self.old_pk)
        self.assertEqual(entry.alg, self.old_alg)
        self.assertEqual(entry.pubkey, self.old_pk)
        self.assertEqual(entry.fingerprint, identity.signer_id(self.old_alg, self.old_pk))
        self.assertEqual(cache.get(self.logical_id), entry)

    # (b) the SAME fingerprint presented again is allowed silently; cache state is unchanged.
    def test_same_fingerprint_allowed_silently(self):
        cache = FingerprintCache(profile=self.profile)
        first = cache.check_and_pin(self.logical_id, self.old_alg, self.old_pk)
        second = cache.check_and_pin(self.logical_id, self.old_alg, self.old_pk)
        self.assertEqual(first, second)
        self.assertEqual(cache.get(self.logical_id), first)

    # (c) a CHANGED fingerprint with NO rotation proof at all -> named error, no re-pin.
    # Mutation target M1 (see ../RED-EVIDENCE.md): removing this check's fail-closed branch
    # flips this test red.
    def test_key_swap_without_proof_fails_closed(self):
        cache = FingerprintCache(profile=self.profile)
        pinned = cache.check_and_pin(self.logical_id, self.old_alg, self.old_pk)
        with self.assertRaises(FingerprintCacheError) as cm:
            cache.check_and_pin(self.logical_id, self.new_alg, self.new_pk)  # no rotation_object
        self.assertEqual(cm.exception.kind, "KeyPinViolation")
        self.assertEqual(
            cache.get(self.logical_id), pinned, "an unauthorized key swap must not change the pin"
        )

    # (d) a CHANGED fingerprint with a VALID tag-98 rotation object (co-signed by the pinned OLD
    # key and the presented NEW key) -> accepted, the cache re-pins to the new fingerprint.
    def test_valid_rotation_proof_repins(self):
        cache = FingerprintCache(profile=self.profile)
        cache.check_and_pin(self.logical_id, self.old_alg, self.old_pk)
        entry = cache.check_and_pin(
            self.logical_id, self.new_alg, self.new_pk, rotation_object=self.good_rotation_object
        )
        self.assertEqual(entry.pubkey, self.new_pk)
        self.assertEqual(entry.fingerprint, identity.signer_id(self.new_alg, self.new_pk))
        self.assertNotEqual(entry.fingerprint, identity.signer_id(self.old_alg, self.old_pk))
        self.assertEqual(cache.get(self.logical_id), entry, "a valid rotation must re-pin the cache")

    # (e) a CHANGED fingerprint with an INVALID/forged rotation object -> the real
    # naalp.envelope.EnvelopeError propagates, and the cache does NOT re-pin.
    # Mutation target M2 (see ../RED-EVIDENCE.md): swallowing verify_rotation_object's error and
    # re-pinning anyway flips this test red.
    def test_forged_rotation_proof_fails_closed(self):
        bad = _oracle_verify_case("old_leg_wrong_key")  # both legs signed by the NEW key
        cache = FingerprintCache(profile=bad["profile"])
        old_pk = bytes.fromhex(bad["old_pubkey_hex"])
        new_pk = bytes.fromhex(bad["new_pubkey_hex"])
        forged_object = bytes.fromhex(bad["obj_hex"])
        pinned = cache.check_and_pin(self.logical_id, bad["old_alg"], old_pk)

        with self.assertRaises(envelope.EnvelopeError) as cm:
            cache.check_and_pin(self.logical_id, bad["new_alg"], new_pk, rotation_object=forged_object)
        self.assertEqual(cm.exception.kind, bad["expect_error"])  # "RotationUnauthorized"
        self.assertEqual(
            cache.get(self.logical_id), pinned, "a forged rotation proof must not change the pin"
        )

    # A rotation object minted for a DIFFERENT (old, new) key pair entirely -- its OLD leg cannot
    # verify against THIS logical_id's actually-pinned key -- must also fail closed, no re-pin.
    def test_rotation_object_for_a_different_pin_is_rejected(self):
        cache = FingerprintCache(profile=self.profile)
        pinned = cache.check_and_pin(self.logical_id, self.old_alg, self.old_pk)
        unrelated = _oracle_verify_case("sovereign_old_leg_floor")
        unrelated_new_pk = bytes.fromhex(unrelated["new_pubkey_hex"])
        unrelated_object = bytes.fromhex(unrelated["obj_hex"])

        with self.assertRaises(envelope.EnvelopeError):
            cache.check_and_pin(
                self.logical_id, unrelated["new_alg"], unrelated_new_pk, rotation_object=unrelated_object
            )
        self.assertEqual(cache.get(self.logical_id), pinned)

    # A tag-18 single-signature "rotation" (missing the old-key co-signature) is exactly the
    # single-Sign1 rotation-gap the tag-98 verifier exists to close. verify_rotation_object
    # requires tag-98 framing structurally, so a tag-18 object offered as `rotation_object` fails
    # while parsing (naalp.cose.parse_sign_raw raises a plain ValueError, "not a tagged
    # COSE_Sign", never an EnvelopeError) -- still a real exception, propagated unwrapped, with
    # no cache mutation. This is the boundary case: the general envelope.verify() path rejects the
    # SAME tag-18 rotation object RotationUnauthorized (impl/python/tests/test_rotation.py's
    # test_tag18_single_sig_rejected covers that path; it is Part-1 surface, out of scope here).
    def test_single_signature_rotation_rejected(self):
        bad = _oracle_verify_case("tag18_single_sig")
        cache = FingerprintCache(profile=bad["profile"])
        old_pk = bytes.fromhex(bad["old_pubkey_hex"])
        new_pk = bytes.fromhex(bad["new_pubkey_hex"])
        single_sig_object = bytes.fromhex(bad["obj_hex"])
        pinned = cache.check_and_pin(self.logical_id, bad["old_alg"], old_pk)

        with self.assertRaises(ValueError):
            cache.check_and_pin(self.logical_id, bad["new_alg"], new_pk, rotation_object=single_sig_object)
        self.assertEqual(cache.get(self.logical_id), pinned)

    def test_new_logical_identity_is_independent_of_an_existing_pin(self):
        # Two different logical ids never interfere with each other's pin, including when they
        # happen to present the SAME underlying key.
        cache = FingerprintCache(profile=self.profile)
        entry_a = cache.check_and_pin("peer-a", self.old_alg, self.old_pk)
        entry_b = cache.check_and_pin("peer-b", self.old_alg, self.old_pk)
        self.assertEqual(entry_a.fingerprint, entry_b.fingerprint)
        self.assertEqual(cache.get("peer-a"), entry_a)
        self.assertEqual(cache.get("peer-b"), entry_b)


if __name__ == "__main__":
    unittest.main()
