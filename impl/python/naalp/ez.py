# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
naalp.ez — an ergonomic convenience surface over the N-AALP object SDK.

This module adds NO new cryptography and NO new encoding. It is a thin, well-named layer
that delegates every byte-producing and byte-checking step to the reference primitives:

    Signer.sign(...)  ->  channels.lookup + envelope.Object + envelope.sign  (ML-DSA / COSE / CBOR)
    verify(...)       ->  envelope.verify                                    (the full offline check)

It exists to collapse the two most common paths — "sign a message on a channel" and "verify
an object I received" — each to a single call, while keeping the exact same wire bytes the raw
SDK, the Go/Rust references, and the shared conformance corpus produce.
"""
import os
import time

from . import channels, cose, envelope, identity

# The convenience surface signs with the profile-compliant post-quantum algorithms only.
# envelope.sign() produces the signature through cose.mldsa_sign(), which is defined for
# ML-DSA-65 and ML-DSA-87; Ed25519 is a level-0 hybrid leg and cannot stand alone here, so
# a Signer built on any other algorithm is refused up front (fail-closed) rather than failing
# opaquely deep inside the sign call.
_KEYGEN_PARAM = {
    cose.ALG_MLDSA65: "ML-DSA-65",
    cose.ALG_MLDSA87: "ML-DSA-87",
}


class Signer:
    """An N-AALP identity plus its sign path.

    A Signer holds a 32-byte ML-DSA key seed and derives, once, the public key and the
    self-certifying signer id from it. `sign()` then builds and signs a full N-AALP object.
    Nothing here is a copy of the crypto — the public key comes from cose.mldsa_keygen, the
    signer id from identity.signer_id, and the signature from envelope.sign.
    """

    def __init__(self, seed, alg=cose.ALG_MLDSA65, profile=cose.PROFILE_PUBLIC):
        param = _KEYGEN_PARAM.get(alg)
        if param is None:
            raise ValueError(
                "naalp.ez.Signer supports ML-DSA-65 (%d) and ML-DSA-87 (%d), not alg %d"
                % (cose.ALG_MLDSA65, cose.ALG_MLDSA87, alg)
            )
        seed = bytes(seed)
        if len(seed) != 32:
            raise ValueError("ML-DSA key seed must be exactly 32 bytes, got %d" % len(seed))
        self._seed = seed
        self.alg = alg
        self.profile = profile
        self.public_key = cose.mldsa_keygen(param, seed)      # derive pk from the seed (ACVP keyGen)
        self.signer_id = identity.signer_id(alg, self.public_key)  # multiformats self-certifying id

    @classmethod
    def generate(cls, alg=cose.ALG_MLDSA65, profile=cose.PROFILE_PUBLIC):
        """Create a Signer on a fresh 32-byte seed drawn from the OS CSPRNG (os.urandom)."""
        param = _KEYGEN_PARAM.get(alg)
        if param is None:
            raise ValueError("naalp.ez.Signer.generate: unsupported alg %d" % alg)
        return cls(os.urandom(32), alg=alg, profile=profile)

    def sign(self, channel, kind, payload, effect=None, created=None, causes=None):
        """Build, content-id-bind, and sign one N-AALP object; return the self-describing bytes.

        `channel`/`kind` are looked up in the real twenty-channel registry (raising
        channels.UnknownKind for an unregistered surface), which also supplies the declared
        effect so the caller does not have to. A fixed-effect kind whose caller passes a
        mismatching `effect` is refused (channels.check_effect), and a variable-effect kind
        requires the caller to state the effect. `payload` is a naalp.cbor value (e.g. a
        cbor.M) that becomes the object body verbatim.
        """
        _name, declared, variable = channels.lookup(channel, kind)  # validates the surface + gets effect
        if effect is None:
            if variable:
                raise ValueError(
                    "channel 0x%04x kind %d has a variable effect; pass effect=0..3" % (channel, kind)
                )
            effect = declared
        channels.check_effect(channel, kind, effect)  # fail-closed: reject a mislabeled fixed effect
        if created is None:
            created = int(time.time() * 1000)          # epoch milliseconds
        obj = envelope.Object(
            kind=kind, channel=channel, signer=self.signer_id.encode("utf-8"),
            created=created, effect=effect, profile=self.profile, body=payload,
            causes=causes,
        )
        return envelope.sign(obj, self.alg, self._seed)


def _registered(channel, kind):
    """True iff (channel, kind) resolves in the real twenty-channel registry."""
    try:
        channels.lookup(channel, kind)
        return True
    except channels.UnknownKind:
        return False


def verify(public_key, envelope_bytes, profile=cose.PROFILE_PUBLIC):
    """Verify a received N-AALP object offline and return the decoded envelope.Object.

    This delegates the entire check to envelope.verify — canonical decode, content-id rebind,
    field-range check, protected-header/body agreement, critical-extension gate, kind dispatch
    against the real registry, profile-floor check, and the COSE/ML-DSA signature — and raises
    envelope.EnvelopeError (with a stable .kind) on the first failure. Nothing is accepted that
    the SDK would not accept; a tampered object raises "BadSignature" and returns no object.
    """
    # envelope.verify derives the actual algorithm from the object's own protected header; the
    # positional alg argument below is not consulted by the SDK, so any registered value serves.
    return envelope.verify(profile, cose.ALG_MLDSA65, bytes(public_key), _registered, bytes(envelope_bytes))
