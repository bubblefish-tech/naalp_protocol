# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
naalp_codec -- the N-AALP blessed deterministic-CBOR codec binding (Part-2 ecosystem E0.3, R7).

    from naalp_codec import encode, decode, content_id, U, T, M

    value = M([(U(2), U(0)), (U(10), T("hello"))])
    wire_bytes = encode(value)
    cid = content_id(value)

See `codec.py` for the full API and rationale. Reuses the Part-1 Python reference SDK
(`impl/python/naalp.cbor`) for every byte-level operation; defines no second codec.
"""
from .codec import (  # noqa: F401
    A, B, DepthExceeded, M, N, NonCanonical, T, Tag, U,
    canonical_bytes, content_id, decode, decode_bounded, encode, verify_roundtrip,
)

__all__ = [
    "U", "N", "B", "T", "A", "M", "Tag", "NonCanonical", "DepthExceeded",
    "encode", "decode", "decode_bounded", "content_id",
    "canonical_bytes", "verify_roundtrip",
]

__version__ = "0.1.0"
