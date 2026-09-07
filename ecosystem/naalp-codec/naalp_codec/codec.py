# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
N-AALP blessed deterministic-CBOR codec binding (Part-2 ecosystem task E0.3, requirement R7).

    from naalp_codec import encode, decode, U, T, M

    value = M([(U(2), U(0)), (U(10), T("hello"))])
    wire_bytes = encode(value)
    assert decode(wire_bytes).pairs == value.pairs

Requirement R7 ("Serialization/codec parity for agents"): "Each SDK SHALL use the
language's blessed deterministic-CBOR codec... never a hand-rolled encoder... so a
third-party SDK produces the same content-id as the reference." This module performs NO
CBOR encoding or decoding of its own: every byte-level operation (shortest-form integer
heads, canonical map-key ordering, duplicate-key rejection, the nesting-depth-bounded
decode, and the content-id multihash) is the Part-1 reference implementation's own
`naalp.cbor` code (RFC 8949 sec.4.2.1 core-deterministic profile), imported and called
directly. Reimplementing the codec here -- even partially -- would reintroduce the
"second encoder" this repository's non-negotiable discipline forbids (CLAUDE.md: "never...
introduce a second object encoding"); a third-party SDK that used a hand-rolled encoder
instead of this binding could silently produce a DIFFERENT content-id for a logically
identical object, breaking R7's whole point.

The one piece of behaviour this module adds on top of the raw Part-1 codec is
`_reject_bare_float`, used by `encode()`. `naalp.cbor`'s value model (U/N/B/T/A/M/Tag) has
no wrapper for a floating-point value at all -- the wire forbids floats entirely
(vectors/registry/error-codes.csv, NonCanonical: "...a float, or the 0x41A0 empty
header"), so there is no float TYPE to encode in the first place. Without this guard, a
caller who embeds a raw Python `float` inside a body/ext/cext map (an "LLM hallucinated a
numeric score as a float" shape) would hit `naalp.cbor`'s generic
`TypeError("not a cbor value")` -- fail-closed, but under the wrong name. This guard walks
the value BEFORE delegating to the real encoder and raises the SAME `cbor.NonCanonical`
exception class the registry assigns to a float, so a caller dispatching on the error name
gets the correct, registered verdict. It adds no new encoding, coerces no value into a
wire form, and turns no previously-rejected input into accepted bytes -- it only sharpens
an already-fail-closed rejection's error identity.
"""
from . import _bootstrap  # noqa: F401  (side-effecting import: puts impl/python on sys.path)

from naalp import cbor
from naalp.cbor import A, B, DepthExceeded, M, N, NonCanonical, T, Tag, U

__all__ = [
    "U", "N", "B", "T", "A", "M", "Tag", "NonCanonical", "DepthExceeded",
    "encode", "decode", "decode_bounded", "content_id",
    "canonical_bytes", "verify_roundtrip",
]


def _reject_bare_float(value):
    """Recursively refuse a raw Python float anywhere inside `value` (top level, or nested
    in an A/M/Tag), raising cbor.NonCanonical -- the registered error name for a float on
    the wire (vectors/registry/error-codes.csv) -- BEFORE naalp.cbor.encode ever sees it.
    See the module docstring for why this exists and why it is not a second codec.

    NOTE: Python's `bool` is an `int` subclass but never a `float` subclass, so this check
    cannot be confused by a bare bool (which the wire's uint/int fields already reject
    elsewhere, e.g. naalp_validator's `_uint_field`); it is scoped purely to `float`."""
    if isinstance(value, float):
        raise NonCanonical(
            "floats are forbidden on the N-AALP wire (RFC 8949 sec.4.2.1 core-deterministic "
            "profile; registered as NonCanonical, vectors/registry/error-codes.csv): got %r"
            % (value,))
    if isinstance(value, A):
        for item in value.items:
            _reject_bare_float(item)
    elif isinstance(value, M):
        for k, v in value.pairs:
            _reject_bare_float(k)
            _reject_bare_float(v)
    elif isinstance(value, Tag):
        _reject_bare_float(value.content)


def encode(value):
    """Deterministic-CBOR encode `value` (one of U/N/B/T/A/M/Tag) to its unique canonical
    byte string -- `naalp.cbor.encode`, unchanged, after `_reject_bare_float` refuses any
    bare float nested anywhere inside it. Raises `NonCanonical` for a float or a duplicate
    map key (naalp.cbor.encode's own sort-then-dedupe check, unmodified), and `TypeError`
    for any Python value that is not one of the seven recognised wrapper types. Never
    returns a "sanitized" partial result: on any rejection, no bytes are returned at all."""
    _reject_bare_float(value)
    return cbor.encode(value)


def decode(data):
    """Strict canonical decode of `data` back to a U/N/B/T/A/M/Tag value -- `naalp.cbor.decode`,
    unchanged. Rejects (`NonCanonical`) any non-canonical encoding: non-shortest-form
    integers, indefinite lengths, out-of-order or duplicate map keys, a float (there is no
    float variant in the value model, so a float head is an "unsupported major type"), or
    trailing bytes after the top-level item. Does not bound nesting depth; for untrusted
    input use `decode_bounded`."""
    return cbor.decode(data)


def decode_bounded(data, max_depth):
    """`decode()` with a maximum CBOR nesting depth (`naalp.cbor.decode_bounded`, unchanged):
    an item at depth `max_depth + 1` is rejected with `DepthExceeded` before it is
    materialized. Use this, not `decode`, for any object arriving over the wire."""
    return cbor.decode_bounded(data, max_depth)


def content_id(value_or_bytes):
    """The N-AALP content id (`naalp.cbor.content_id`, unchanged): multihash(0x20 [sha2-384],
    0x30 [48], SHA-384(deterministic-body-bytes)). Accepts either a value (U/N/B/T/A/M/Tag --
    encoded first via the `encode()` above, so the float guard applies here too) or
    already-encoded bytes. This is the literal proof R7 asks for: two independently-built
    SDKs that both call THIS function on the same logical body produce the same content id,
    because both ultimately call the one blessed `naalp.cbor` encoder underneath."""
    if isinstance(value_or_bytes, (U, N, B, T, A, M, Tag)):
        value_or_bytes = encode(value_or_bytes)
    return cbor.content_id(value_or_bytes)


def canonical_bytes(value):
    """Alias for `encode(value)`, named for the guarantee it documents: deterministic CBOR
    (RFC 8949 sec.4.2.1) defines exactly ONE valid encoding per logical value, so there is
    exactly one "canonical bytes" answer for any `value` this function accepts -- never a
    choice of equally-valid encodings, and never a configuration knob that could produce a
    second one (this module intentionally exposes no such knob)."""
    return encode(value)


def verify_roundtrip(value):
    """Encode `value`, decode the result, and re-encode the decoded value; return True iff
    the two encodings are byte-identical. Because `decode()` accepts only already-canonical
    bytes (anything else raises `NonCanonical`/`DepthExceeded` before a value is even
    produced) and `encode()` has exactly one output per logical value, this holds for every
    `value` this function does not raise on -- it is a runnable proof of the determinism
    guarantee `canonical_bytes` documents, not a conditional check with a real False branch
    for well-formed input. It propagates every exception `encode()`/`decode()` raise (a
    bare non-value input, a bare float, a duplicate key) -- it never swallows a rejection to
    report an "always safe" verdict."""
    first = encode(value)
    decoded = decode(first)
    second = encode(decoded)
    return first == second
