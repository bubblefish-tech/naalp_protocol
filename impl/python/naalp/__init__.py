# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
naalp — the Python reference SDK for N-AALP (draft-bubblefish-naalp-00).

N-AALP makes the *object*, not the connection, the unit of security: every message is a
deterministically-encoded CBOR structure signed with COSE that carries, under one signature,
its content identity, its signer, a closed effect label, optional approval/audit bindings, and
its causal derivation — verifiable offline, over any transport.

Quick start (sign and verify a full object):

    from naalp import cose, identity, envelope
    from naalp.cbor import U, B, T, M

    seed = bytes(32)                                   # a real 32-byte key seed in production
    alg  = cose.ALG_MLDSA65
    pk   = cose.mldsa_keygen("ML-DSA-65", seed)
    sid  = identity.signer_id(alg, pk)

    body = M([(U(1), T("hello"))])
    obj  = envelope.Object(kind=1, channel=4, signer=sid.encode(),
                           created=1785000000000, effect=2, profile=cose.PROFILE_PUBLIC, body=body)
    signed = envelope.sign(obj, alg, seed)             # bytes: a self-describing signed object
    got    = envelope.verify(cose.PROFILE_PUBLIC, alg, pk, lambda c, k: True, signed)

The independent, byte-level primitives live in submodules: `cbor` (deterministic CBOR + content
id), `cose` (COSE_Sign1 + deterministic ML-DSA / Ed25519), `identity` (self-certifying signer id),
`policy` (effect + authorization), `records` (approval/receipt/delivery/stream/carriage bodies +
the transport boundary), `graph` (causal verify + federation reconcile), `channels` (the twenty
channel registry), and `envelope` (the full object). Every construction is graded byte-for-byte
against the shared conformance corpus (== Go == Rust).
"""
from . import cbor, channels, cose, envelope, graph, identity, policy, records  # noqa: F401
from .envelope import Object, sign, verify  # noqa: F401  (the ergonomic surface)

__all__ = [
    "cbor", "cose", "identity", "policy", "records", "graph", "channels", "envelope",
    "Object", "sign", "verify",
]
__version__ = "0.1.0"
