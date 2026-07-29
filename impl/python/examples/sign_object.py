# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
examples/sign_object.py — build, sign, and verify a full N-AALP object.

Run:  python examples/sign_object.py
Expected output:
    signer   bciq...
    signed   <N> bytes, verifies=True
    tampered rejected: BadSignature
"""
import os
import sys

# run in-tree without an install (a pip-installed `naalp` takes precedence if present)
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from naalp import cose, identity, envelope  # noqa: E402
from naalp.cbor import U, B, T, M  # noqa: E402


def main():
    # a deterministic 32-byte key seed (use a real random seed in production)
    seed = bytes([0x2a]) * 32
    alg = cose.ALG_MLDSA65
    pk = cose.mldsa_keygen("ML-DSA-65", seed)
    signer_id = identity.signer_id(alg, pk)
    print("signer  ", signer_id)

    # a Governance Approval object (channel 0x0004, kind 1) on the Public profile
    args_id = envelope.Object(
        kind=0, channel=0, signer=b"", created=0, effect=0, body=M([(U(1), T("the-args"))])
    ).content_id()
    approval = M([
        (U(1), B(args_id)),
        (U(2), T(signer_id)),
        (U(3), U(2)),                                    # granted effect: non_idempotent_write
        (U(4), B(bytes([1, 2, 3, 4, 5, 6, 7, 8]))),      # nonce
        (U(5), U(1785000000000)),                        # not_after (epoch ms)
    ])
    obj = envelope.Object(
        kind=1, channel=4, tier=0, signer=signer_id.encode("utf-8"),
        created=1785000000000, effect=2, profile=cose.PROFILE_PUBLIC, body=approval,
    )

    signed = envelope.sign(obj, alg, seed)
    got = envelope.verify(cose.PROFILE_PUBLIC, alg, pk, lambda c, k: (c, k) == (4, 1), signed)
    print("signed  ", len(signed), "bytes, verifies=%s" % (got.kind == 1 and got.channel == 4))

    tampered = bytearray(signed)
    tampered[-1] ^= 1
    try:
        envelope.verify(cose.PROFILE_PUBLIC, alg, pk, lambda c, k: True, bytes(tampered))
        print("tampered NOT rejected (bug)")
    except Exception as e:
        print("tampered rejected:", getattr(e, "kind", type(e).__name__))


if __name__ == "__main__":
    main()
