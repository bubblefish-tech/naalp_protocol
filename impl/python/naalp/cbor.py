# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Deterministic CBOR (RFC 8949 §4.2.1) for N-AALP — the C1 codec.

An independent Python implementation of the same deterministic profile the Go and Rust
reference implementations produce: shortest-form integer heads, no indefinite lengths,
canonical (bytewise-ascending, by encoded key) map ordering, no duplicate keys. The
content id is multihash(0x20, SHA-384(body)) over the deterministic body bytes (§2.3).
"""
import hashlib


class NonCanonical(ValueError):
    kind = "NonCanonical"


# --- value model (mirrors the Go/Rust cbor.Value variants) ---

class U:
    """CBOR unsigned integer (major 0)."""
    __slots__ = ("v")
    def __init__(self, v): self.v = int(v)

class N:
    """CBOR negative integer (major 1); v is the negative value itself."""
    __slots__ = ("v")
    def __init__(self, v): self.v = int(v)

class B:
    """CBOR byte string (major 2)."""
    __slots__ = ("v")
    def __init__(self, v): self.v = bytes(v)

class T:
    """CBOR text string (major 3)."""
    __slots__ = ("v")
    def __init__(self, v): self.v = str(v)

class A:
    """CBOR array (major 4)."""
    __slots__ = ("items")
    def __init__(self, items): self.items = list(items)

class M:
    """CBOR map (major 5); pairs is a list of (key_value, value)."""
    __slots__ = ("pairs")
    def __init__(self, pairs): self.pairs = list(pairs)

class Tag:
    """CBOR tag (major 6)."""
    __slots__ = ("n", "content")
    def __init__(self, n, content): self.n = int(n); self.content = content


def _head(major, n):
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 256:
        return bytes([(major << 5) | 24, n])
    if n < 65536:
        return bytes([(major << 5) | 25]) + n.to_bytes(2, "big")
    if n < 2 ** 32:
        return bytes([(major << 5) | 26]) + n.to_bytes(4, "big")
    return bytes([(major << 5) | 27]) + n.to_bytes(8, "big")


def encode(v):
    """Deterministic-CBOR encode a value; map keys are emitted in canonical order."""
    if isinstance(v, U):
        if v.v < 0:
            raise NonCanonical("uint is negative")
        return _head(0, v.v)
    if isinstance(v, N):
        return _head(1, -1 - v.v)
    if isinstance(v, B):
        return _head(2, len(v.v)) + v.v
    if isinstance(v, T):
        b = v.v.encode("utf-8")
        return _head(3, len(b)) + b
    if isinstance(v, A):
        return _head(4, len(v.items)) + b"".join(encode(i) for i in v.items)
    if isinstance(v, M):
        enc = [(encode(k), encode(val)) for k, val in v.pairs]
        enc.sort(key=lambda kv: kv[0])
        keys = [k for k, _ in enc]
        if len(set(keys)) != len(keys):
            raise NonCanonical("duplicate map key")
        return _head(5, len(enc)) + b"".join(k + val for k, val in enc)
    if isinstance(v, Tag):
        return _head(6, v.n) + encode(v.content)
    raise TypeError("not a cbor value: %r" % (v,))


def _dec(data):
    if not data:
        raise NonCanonical("truncated")
    ib = data[0]
    major = ib >> 5
    ai = ib & 0x1F
    if ai == 31:
        raise NonCanonical("indefinite length")
    if ai < 24:
        arg, rest = ai, data[1:]
    elif ai == 24:
        if len(data) < 2:
            raise NonCanonical("truncated head")
        arg, rest = data[1], data[2:]
        if arg < 24:
            raise NonCanonical("non-shortest integer")
    elif ai == 25:
        if len(data) < 3:
            raise NonCanonical("truncated head")
        arg, rest = int.from_bytes(data[1:3], "big"), data[3:]
        if arg < 256:
            raise NonCanonical("non-shortest integer")
    elif ai == 26:
        if len(data) < 5:
            raise NonCanonical("truncated head")
        arg, rest = int.from_bytes(data[1:5], "big"), data[5:]
        if arg < 65536:
            raise NonCanonical("non-shortest integer")
    elif ai == 27:
        if len(data) < 9:
            raise NonCanonical("truncated head")
        arg, rest = int.from_bytes(data[1:9], "big"), data[9:]
        if arg < 2 ** 32:
            raise NonCanonical("non-shortest integer")
    else:
        raise NonCanonical("reserved additional-info")

    if major == 0:
        return U(arg), rest
    if major == 1:
        return N(-1 - arg), rest
    if major == 2:
        if len(rest) < arg:
            raise NonCanonical("truncated byte string")
        return B(rest[:arg]), rest[arg:]
    if major == 3:
        if len(rest) < arg:
            raise NonCanonical("truncated text string")
        return T(rest[:arg].decode("utf-8")), rest[arg:]
    if major == 4:
        items, cur = [], rest
        for _ in range(arg):
            it, cur = _dec(cur)
            items.append(it)
        return A(items), cur
    if major == 5:
        pairs, cur, prev = [], rest, None
        for _ in range(arg):
            before = cur
            k, cur = _dec(cur)
            kbytes = before[: len(before) - len(cur)]
            val, cur = _dec(cur)
            if prev is not None and kbytes <= prev:
                raise NonCanonical("map keys out of order or duplicate")
            prev = kbytes
            pairs.append((k, val))
        return M(pairs), cur
    if major == 6:
        content, rest2 = _dec(rest)
        return Tag(arg, content), rest2
    raise NonCanonical("unsupported major type %d" % major)


def decode(data):
    """Strict canonical decode: rejects any non-canonical encoding with NonCanonical."""
    v, rest = _dec(bytes(data))
    if rest:
        raise NonCanonical("trailing bytes after top-level item")
    return v


def content_id(body):
    """Content id = multihash(0x20 [sha2-384], 0x30 [48], SHA-384(body-bytes)) (§2.3)."""
    if isinstance(body, (U, N, B, T, A, M, Tag)):
        body = encode(body)
    return bytes([0x20, 0x30]) + hashlib.sha384(bytes(body)).digest()
