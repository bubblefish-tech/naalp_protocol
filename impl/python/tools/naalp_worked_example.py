# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""Emit the worked-example N-AALP object as one line of lowercase hex.

The whole COSE_Sign1 the reference produces from the fixed 0x2a seed for the
Governance Approval object (channel 0x0004, kind 1) -- the same construction the
Go cmd/naalp-worked-example emitter and tests/test_worked_example.py build.
scripts/record_cross_port_objects.py runs this and records the bytes; the
cross-port object gate compares them to vectors/worked/example.json. Prints ONLY
the hex so the recorder reads it unambiguously.

    python tools/naalp_worked_example.py        (from impl/python/)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # impl/python on path

from naalp import cose, identity, envelope  # noqa: E402
from naalp.cbor import U, B, T, M  # noqa: E402

_SEED = bytes([0x2A]) * 32
_ALG = cose.ALG_MLDSA65
_ARGS_ID = bytes.fromhex(
    "20304e8abef02897dcc39231d926feb79b34534c6d474cd49a5b4dec2cc2cce90d251eef7418782006d829bd7f30ae8626ff"
)


def main():
    pk = cose.mldsa_keygen("ML-DSA-65", _SEED)
    signer_id = identity.signer_id(_ALG, pk)
    body = M([
        (U(1), B(_ARGS_ID)),
        (U(2), T(signer_id)),
        (U(3), U(2)),
        (U(4), B(bytes([1, 2, 3, 4, 5, 6, 7, 8]))),
        (U(5), U(1785000000000)),
    ])
    obj = envelope.Object(
        kind=1, channel=4, tier=0, signer=signer_id.encode("utf-8"),
        created=1785000000000, effect=2, profile=cose.PROFILE_PUBLIC, body=body,
    )
    sys.stdout.write(envelope.sign(obj, _ALG, _SEED).hex() + "\n")


if __name__ == "__main__":
    main()
