# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
N-AALP C1 independent oracle: deterministic CBOR (RFC 8949 §4.2.1) + content-id
(design.md §2.3: multihash(0x20, SHA-384(canonical-body-without-field-1))).

This constructor is written from scratch against the RFC and FIPS text and shares
no code with impl/go or impl/rust. It is the independent expected-value source
required by R-16.1 / CLAUDE.md (non-circular oracle). Go and Rust are graded by
matching the bytes this file emits into vectors/cbor/cases.json.

Authorities used:
  - RFC 8949 §4.2.1  deterministic encoding (shortest head, sorted unique map keys,
    no indefinite lengths).
  - FIPS 180-4       SHA-384 (via hashlib; a KAT case is emitted so impls prove the
    digest is real, not a constant).
  - multiformats     sha2-384 multihash code = 0x20, digest length 48 = 0x30.
"""
import hashlib
import json
import os


# ---- deterministic CBOR encoder (RFC 8949 §4.2.1) --------------------------------

def enc_head(major, n):
    """Shortest-form head for a major type and argument n (RFC 8949 §3, §4.2.1)."""
    mt = major << 5
    if n < 0:
        raise ValueError("negative argument")
    if n < 24:
        return bytes([mt | n])
    if n < (1 << 8):
        return bytes([mt | 24, n])
    if n < (1 << 16):
        return bytes([mt | 25]) + n.to_bytes(2, "big")
    if n < (1 << 32):
        return bytes([mt | 26]) + n.to_bytes(4, "big")
    if n < (1 << 64):
        return bytes([mt | 27]) + n.to_bytes(8, "big")
    raise ValueError("argument exceeds 64-bit range")


# Value model (matches the tagged form written into cases.json so Go/Rust rebuild the
# identical logical value):
#   int  >= 0                  -> uint      (major 0)
#   bytes                      -> bstr      (major 2)
#   str                        -> tstr      (major 3, UTF-8)
#   list                       -> array     (major 4)
#   ("map", [(k, v), ...])     -> map       (major 5), canonical key order
def encode(v):
    if isinstance(v, bool):
        raise ValueError("booleans are not used in the N-AALP spine")
    if isinstance(v, int):
        if v < 0:
            # Negative integer, major type 1 (RFC 8949 §3): argument = -1 - v. Used by
            # the COSE protected header's algorithm ids (e.g. -49); the object body
            # itself uses no negatives (a surface rule, not a codec rule).
            return enc_head(1, -1 - v)
        return enc_head(0, v)
    if isinstance(v, bytes):
        return enc_head(2, len(v)) + v
    if isinstance(v, str):
        b = v.encode("utf-8")
        return enc_head(3, len(b)) + b
    if isinstance(v, list):
        out = enc_head(4, len(v))
        for it in v:
            out += encode(it)
        return out
    if isinstance(v, tuple) and len(v) == 3 and v[0] == "tag":
        # CBOR tag (major type 6): ("tag", number, content) — COSE_Sign1 = 18, COSE_Sign = 98.
        return enc_head(6, v[1]) + encode(v[2])
    if isinstance(v, tuple) and len(v) == 2 and v[0] == "map":
        pairs = v[1]
        enc_pairs = [(encode(k), encode(val)) for (k, val) in pairs]
        keys = [ek for (ek, _) in enc_pairs]
        if len(set(keys)) != len(keys):
            raise ValueError("duplicate map key")
        enc_pairs.sort(key=lambda p: p[0])  # bytewise ascending on the encoded key
        out = enc_head(5, len(pairs))
        for (ek, ev) in enc_pairs:
            out += ek + ev
        return out
    raise ValueError("unencodable value: %r" % (v,))


# ---- N-AALP object body + content-id (design.md §2.1, §2.3) ----------------------

def body_map(fields, include_id):
    pairs = []
    for k in sorted(fields.keys()):
        if k == 1 and not include_id:
            continue
        pairs.append((k, fields[k]))
    return ("map", pairs)


def content_id(fields_without_id):
    """multihash(0x20, SHA-384(canonical-body-without-field-1))."""
    body = body_map(fields_without_id, include_id=False)
    digest = hashlib.sha384(encode(body)).digest()   # 48 bytes
    assert len(digest) == 48
    return b"\x20\x30" + digest                        # code 0x20, length 0x30(48)


def hx(b):
    return b.hex()


# ---- cases -----------------------------------------------------------------------

def positive_case(name, fields_without_id):
    cid = content_id(fields_without_id)
    full = dict(fields_without_id)
    full[1] = cid
    body_no1_hex = hx(encode(body_map(fields_without_id, include_id=False)))
    full_hex = hx(encode(body_map(full, include_id=True)))
    # tagged, language-neutral description of the logical object for Go/Rust to rebuild
    def tag(v):
        if isinstance(v, int):
            return ["u", v]
        if isinstance(v, bytes):
            return ["b", v.hex()]
        if isinstance(v, str):
            return ["s", v]
        if isinstance(v, list):
            return ["arr", [tag(x) for x in v]]
        if isinstance(v, tuple) and v[0] == "map":
            return ["map", [[tag(k), tag(val)] for (k, val) in v[1]]]
        raise ValueError(v)
    obj = {str(k): tag(v) for k, v in fields_without_id.items()}
    return {
        "name": name,
        "obj_without_id": obj,      # fields 2..12; id is computed by the impl
        "body_no1_hex": body_no1_hex,
        "id_hex": hx(cid),
        "full_hex": full_hex,
    }


def build():
    minimal_fields = {
        2: 0,                                   # kind
        3: 0,                                   # channel Control 0x0000
        4: 0,                                   # tier baseline
        5: bytes.fromhex("5349474e45525f41"),   # signer "SIGNER_A" (opaque bstr; real id is C4)
        6: 1785000000000,                       # created (epoch ms)
        7: 0,                                    # effect read_only
        8: [],                                   # causes (empty)
        9: 1,                                    # profile Public
        10: "hello",                             # body (tstr)
    }
    minimal = positive_case("minimal", minimal_fields)

    nested_fields = {
        2: 1,
        3: 4,                                    # channel Governance 0x0004
        4: 0,
        5: bytes.fromhex("5349474e45525f42"),    # "SIGNER_B"
        6: 1785000123456,
        7: 2,                                    # effect non_idempotent_write
        8: [bytes.fromhex(minimal["id_hex"])],   # causes -> minimal.id (a real derivation edge)
        9: 3,                                    # profile Sovereign
        10: ("map", [(1, "world"), (2, 42)]),    # body is a nested map {1:"world", 2:42}
        11: ("map", [(100, 7)]),                 # ext {100:7} (non-critical)
    }
    nested = positive_case("nested", nested_fields)

    # Empty-vs-absent optional field (design.md §3.3, R-3.3): two objects identical
    # except for the optional ext field (11) being present-but-empty versus absent MUST
    # encode to different bytes and different content ids. "absent != empty; both
    # defined." The pair isolates that single variable over a shared base.
    ea_base = {
        2: 0,                                    # kind
        3: 0,                                    # channel Control 0x0000
        4: 0,                                    # tier baseline
        5: bytes.fromhex("5349474e45525f43"),    # signer "SIGNER_C"
        6: 1785000200000,                        # created (epoch ms)
        7: 0,                                    # effect read_only
        8: [],                                   # causes (empty array — a *present* empty)
        9: 1,                                    # profile Public
        10: "x",                                 # body
    }
    absent_ext = positive_case("absent_ext", dict(ea_base))   # field 11 omitted
    empty_ext_fields = dict(ea_base)
    empty_ext_fields[11] = ("map", [])                        # field 11 present, empty map
    empty_ext = positive_case("empty_ext", empty_ext_fields)
    assert absent_ext["id_hex"] != empty_ext["id_hex"], \
        "empty-vs-absent must produce distinct content ids"

    # Negative byte blobs: hand-crafted non-canonical CBOR a strict decoder MUST reject.
    negatives = [
        {"name": "key_order",     "bytes_hex": "a2020001 00".replace(" ", ""), "expect": "NonCanonical"},
        {"name": "int_notshortest","bytes_hex": "1800",                         "expect": "NonCanonical"},
        {"name": "indefinite_arr", "bytes_hex": "9f00ff",                       "expect": "NonCanonical"},
        {"name": "duplicate_key",  "bytes_hex": "a2010001 01".replace(" ", ""), "expect": "NonCanonical"},
    ]

    sha_kat = {
        "input_utf8": "abc",
        "digest_hex": hashlib.sha384(b"abc").hexdigest(),  # FIPS 180-4 known answer
    }

    return {
        "note": "Independent oracle output for N-AALP C1 (deterministic CBOR + content-id). "
                "Go and Rust MUST reproduce every *_hex and reject every negative. "
                "Generated by tools/cbor_oracle.py; do not hand-edit.",
        "positives": [minimal, nested, absent_ext, empty_ext],
        "negatives": negatives,
        "sha384_kat": sha_kat,
    }


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    out_dir = os.path.join(here, "..", "vectors", "cbor")
    out_dir = os.path.normpath(out_dir)
    os.makedirs(out_dir, exist_ok=True)
    data = build()
    path = os.path.join(out_dir, "cases.json")
    # newline="\n" forces LF on every platform: Python text mode would otherwise
    # translate "\n" to CRLF on Windows, making the worktree vector diverge from the
    # LF-normalized git blob and breaking any hash-pinned vector gate (T14 / CI).
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2, sort_keys=False)
        f.write("\n")
    # human-visible confirmation
    for p in data["positives"]:
        print(p["name"], "id=", p["id_hex"][:16], "... full", len(p["full_hex"]) // 2, "bytes")
    print("SHA-384('abc') =", data["sha384_kat"]["digest_hex"])
    print("wrote", path)


if __name__ == "__main__":
    main()
