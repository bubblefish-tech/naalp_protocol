# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
N-AALP body builders for the Python SDK — the deterministic-CBOR bodies of the spine records:
approval + consume ledger (C6, §7), audit receipt (C7, §8), delivery update (C8, §9), stream
open/commit/checkpoint + rolling commitment (C9, §10), foreign carriage (C12, §13), and the
transport confidentiality boundary (C11, §12). Each body is exactly what the Go and Rust
reference implementations encode, so the bytes are byte-identical.
"""
import hashlib

from . import cbor
from .cbor import U, B, T


# --- C6 approval + consume ledger (§7) ---

def approval_body(approves: bytes, approver: str, grant: int, nonce: bytes, not_after: int) -> bytes:
    return cbor.encode(cbor.M([
        (U(1), B(approves)), (U(2), T(approver)), (U(3), U(grant)),
        (U(4), B(nonce)), (U(5), U(not_after)),
    ]))


def approval_id(approves: bytes, approver: str, grant: int, nonce: bytes, not_after: int) -> bytes:
    return cbor.content_id(approval_body(approves, approver, grant, nonce, not_after))


def ledger_entry(seq: int, prev: bytes, approval_id_bytes: bytes, by: str) -> bytes:
    return cbor.encode(cbor.M([
        (U(1), U(seq)), (U(2), B(prev)), (U(3), B(approval_id_bytes)), (U(4), T(by)),
    ]))


# --- C7 audit receipt (§8) ---

def receipt_body(prev: bytes, obj: bytes, seq: int, at: int) -> bytes:
    return cbor.encode(cbor.M([
        (U(1), B(prev)), (U(2), B(obj)), (U(3), U(seq)), (U(4), U(at)),
    ]))


def receipt_head(body: bytes) -> bytes:
    return hashlib.sha384(bytes(body)).digest()


# --- C8 delivery (§9) ---

def delivery_update(obj: bytes, stage: int, at: int) -> bytes:
    return cbor.encode(cbor.M([(U(1), B(obj)), (U(2), U(stage)), (U(3), U(at))]))


# --- C9 streaming (§10) ---

def stream_digest(chunks) -> bytes:
    """Rolling SHA-384 over the chunk data in absolute-offset order (R-10.2)."""
    h = hashlib.sha384()
    for offset, data in sorted(chunks, key=lambda c: c[0]):
        h.update(bytes(data))
    return h.digest()


def stream_open_body(stream_id: bytes, effect: int, approval: bytes, substream: int) -> bytes:
    pairs = [(U(1), B(stream_id)), (U(2), U(effect)), (U(4), U(substream))]
    if approval:  # field 3 present only when an approval binding exists
        pairs.append((U(3), B(approval)))
    return cbor.encode(cbor.M(pairs))


def stream_commit_body(stream_id: bytes, digest: bytes) -> bytes:
    return cbor.encode(cbor.M([(U(1), B(stream_id)), (U(2), B(digest))]))


def stream_checkpoint_body(stream_id: bytes, through_offset: int, digest_so_far: bytes) -> bytes:
    return cbor.encode(cbor.M([
        (U(1), B(stream_id)), (U(2), U(through_offset)), (U(3), B(digest_so_far)),
    ]))


# --- C12 foreign carriage (§13) ---

CLASS_JSONRPC, CLASS_HTTP, CLASS_MSG, CLASS_STREAM, CLASS_DOC, CLASS_OPAQUE = range(6)


class MappingError(ValueError):
    kind = "MappingError"


def carriage_body(protocol_id: int, cls: int, content_type: int,
                  correlation: bytes, method: str, foreign: bytes) -> bytes:
    if cls > CLASS_OPAQUE:
        raise MappingError("carriage class %d is not defined" % cls)
    return cbor.encode(cbor.M([
        (U(1), U(protocol_id)), (U(2), U(cls)), (U(3), U(content_type)),
        (U(4), B(correlation)), (U(5), T(method)), (U(6), B(foreign)),
    ]))


# --- C11 transport confidentiality boundary (§12) ---

_TRANSPORTS = {
    "npamp": (True, True),
    "quic": (True, True),
    "websocket+wss": (True, False),
    "websocket+ws": (False, False),
    "https": (True, False),
    "http": (False, False),
}


class UnknownTransport(ValueError):
    kind = "UnknownTransport"


def transport_emit(name: str, sensitive: bool, require_peer_auth: bool) -> str:
    """Apply the §12.3 confidentiality boundary + §12.4 peer-auth rule; returns the result label."""
    t = _TRANSPORTS.get(name)
    if t is None:
        raise UnknownTransport("unknown transport %r" % name)
    confidential, peer_authenticated = t
    if sensitive and not confidential:
        return "ConfidentialTransportRequired"
    if require_peer_auth and not peer_authenticated:
        return "PeerUnauthenticated"
    return "ok"
