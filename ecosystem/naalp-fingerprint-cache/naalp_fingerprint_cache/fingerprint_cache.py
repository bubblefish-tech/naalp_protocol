# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""The N-AALP signer-id fingerprint cache (Part-2 ecosystem task E6.2, requirement R12.2).

Trust-on-first-use (TOFU) pinning of signer-id fingerprints (design.md sec 5.1's self-certifying
signer id -- the multihash over the multicodec-tagged public key). On the FIRST authenticated use
of a signer under a given logical identity, PIN its fingerprint. On a LATER use presenting a
CHANGED fingerprint for that SAME logical identity, refuse with a named error UNLESS a valid
rotation proof -- the real Part-1 sec 5.2 tag-98 Rotation object, co-signed by the OLD pinned key
AND the NEW presented key -- authorizes the change, in which case the cache accepts and RE-PINS to
the new fingerprint. This detects a key-swap / impersonation attempt against a pinned identity.

This module performs NO cryptography and NO multihash computation of its own. The fingerprint is
computed by the real Part-1 primitive `naalp.identity.signer_id` (the exact self-certifying-id
formula, sec 5.1), and a rotation proof is checked entirely by the real Part-1 primitive
`naalp.envelope.verify_rotation_object` (the tag-98 co-signature verifier, sec 5.2, already graded
against vectors/rotation/cases.json in impl/python/tests/test_rotation.py). This package adds
exactly one thing neither of those primitives has any reason to know about: a caller-side PIN
STORE that remembers which fingerprint was last seen for a logical identity, and the
first-use/same/changed-with-proof/changed-without-proof decision table around it.
"""
from . import _bootstrap  # noqa: F401  (repo-relative sys.path setup; must run before `naalp` imports)

from dataclasses import dataclass
from typing import Dict, Optional

from naalp import cose, envelope, identity


class FingerprintCacheError(ValueError):
    """A named, fail-closed fingerprint-cache error; .kind is the stable error kind.

    The single kind defined here -- KeyPinViolation -- is this package's own: a changed
    fingerprint presented with NO rotation proof offered at all has no Part-1 analogue (neither
    naalp.identity nor naalp.envelope has any concept of a caller-side pin store to violate).
    Every OTHER rejection this module can raise -- an INVALID, forged, or wrongly-shaped rotation
    proof -- is the real naalp.envelope.EnvelopeError the Part-1 tag-98 Rotation-object verifier
    already raises (RotationUnauthorized, BadSignature, KeyAlgMismatch, ProfileDowngrade, ...) and
    is left to propagate UNWRAPPED, exactly as naalp_hitl lets naalp.approval.ApprovalError
    propagate unwrapped for every check that already has a Part-1 name."""

    def __init__(self, kind: str, msg: str = ""):
        super().__init__("%s: %s" % (kind, msg) if msg else kind)
        self.kind = kind


def _is_identity_rotation_kind(channel: int, kind: int) -> bool:
    """The Identity-channel Rotation object selector (channel 3, kind 0; design.md sec 5.2) --
    the exact (channel, kind) pair naalp.envelope.sign_rotation_object / verify_rotation_object
    restrict tag-98 to. This is a one-line kind_validator closure, the same shape every caller of
    verify_rotation_object supplies (see impl/python/tests/test_rotation.py's `_kind_ok`); it is
    not a re-implementation of envelope's own (private) `_is_rotation_object` check -- the real
    check that a tag-98 object is ONLY accepted for (3, 0) still runs inside verify_rotation_object
    itself and rejects UnknownKind independently of what this closure returns."""
    return channel == 3 and kind == 0


@dataclass(frozen=True)
class PinnedIdentity:
    """One pinned entry: the algorithm, public key, and derived signer-id fingerprint currently
    trusted for a logical identity."""

    alg: int
    pubkey: bytes
    fingerprint: str


class FingerprintCache:
    """R12.2: a cache of known-good signer-id fingerprints, TOFU-pinned per logical identity.

    `logical_id` is the caller's own stable name for the identity being authenticated (a peer id,
    a service name, a room member, ...) -- deliberately distinct from the fingerprint, which is
    exactly the value a legitimate rotation changes. The cache never invents or verifies THIS
    identity binding; it only remembers, per logical_id, which (alg, pubkey, fingerprint) was last
    accepted, so a later use can be compared against it.

    Decision table for `check_and_pin(logical_id, alg, pubkey, rotation_object=None)`:
      (a) never pinned before               -> PIN it now (first authenticated use), no error.
      (b) same fingerprint as pinned         -> accepted silently, cache unchanged.
      (c) changed fingerprint, no proof      -> FingerprintCacheError('KeyPinViolation'),
                                                 cache unchanged (fail-closed).
      (d) changed fingerprint, VALID proof   -> accepted, cache RE-PINS to the new fingerprint.
      (e) changed fingerprint, INVALID proof -> the real naalp.envelope.EnvelopeError propagates
                                                 (its own .kind), cache unchanged (fail-closed).

    "VALID proof" (d) means: `rotation_object` is a tag-98 Rotation object (naalp.envelope
    sec 5.2) whose OLD leg verifies under the key currently pinned for `logical_id` and whose NEW
    leg verifies under the `pubkey` presented on this call -- checked entirely by
    naalp.envelope.verify_rotation_object, which this class calls with the pinned entry's own
    (alg, pubkey) as the trusted OLD key and the presented (alg, pubkey) as the trusted NEW key.
    No cryptographic check in this class is re-derived; only the pin/compare bookkeeping is."""

    def __init__(self, profile: int = cose.PROFILE_PUBLIC):
        self._profile = profile
        self._pins: Dict[str, PinnedIdentity] = {}

    def get(self, logical_id: str) -> Optional[PinnedIdentity]:
        """Return the currently pinned identity for logical_id, or None if never pinned."""
        return self._pins.get(logical_id)

    def check_and_pin(
        self,
        logical_id: str,
        alg: int,
        pubkey: bytes,
        rotation_object: Optional[bytes] = None,
    ) -> PinnedIdentity:
        """Authenticate a continuity claim for `logical_id` against this cache's pin, per the
        decision table in the class docstring. `alg`/`pubkey` are the key ACTUALLY presented on
        this authenticated use (already verified by the caller's own object/handshake signature
        check -- this cache authenticates identity CONTINUITY across uses, not the current
        message). `rotation_object` is the tag-98 Rotation-object bytes offered to justify a
        fingerprint change; omit it (None) when none is offered.

        Returns the (possibly newly pinned) PinnedIdentity on success. Raises
        FingerprintCacheError('KeyPinViolation') when the fingerprint changed and no rotation
        object was offered at all. Raises the real naalp.envelope.EnvelopeError, UNWRAPPED, when
        a rotation object WAS offered but does not verify. Neither rejection changes cache
        state -- the pin is updated on exactly one path: a successful first-use or a successfully
        verified rotation."""
        new_fingerprint = identity.signer_id(alg, pubkey)
        pinned = self._pins.get(logical_id)

        if pinned is None:
            entry = PinnedIdentity(alg=alg, pubkey=bytes(pubkey), fingerprint=new_fingerprint)
            self._pins[logical_id] = entry
            return entry

        if pinned.fingerprint == new_fingerprint:
            return pinned

        if rotation_object is None:
            raise FingerprintCacheError(
                "KeyPinViolation",
                "fingerprint changed for %r with no rotation proof offered "
                "(pinned=%s, presented=%s)" % (logical_id, pinned.fingerprint, new_fingerprint),
            )

        # The real Part-1 tag-98 Rotation-object verifier: both legs MUST verify, the OLD leg
        # under exactly the key we have pinned for logical_id and the NEW leg under exactly the
        # key presented on this call. A forged/invalid/wrongly-shaped rotation object raises
        # naalp.envelope.EnvelopeError here and this call never reaches the re-pin below
        # (fail-closed, no state change -- property (e)).
        envelope.verify_rotation_object(
            self._profile,
            pinned.alg, pinned.pubkey,
            alg, pubkey,
            _is_identity_rotation_kind,
            rotation_object,
        )

        entry = PinnedIdentity(alg=alg, pubkey=bytes(pubkey), fingerprint=new_fingerprint)
        self._pins[logical_id] = entry
        return entry
