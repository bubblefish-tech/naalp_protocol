# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Independent oracle for C12 — foreign carriage by class (T11).

Non-circular authority (NOT the code under test):
  * Each carriage class carries a real foreign message as its OWN bytes (a JSON-RPC/MCP
    request, a raw HTTP request, a FIPA-ACL performative, an SSE event, an agent-card JSON, an
    arbitrary binary blob). The independent authority is the foreign protocol's own bytes plus
    a round-trip identity check: the carried-and-recovered foreign message MUST be byte-identical
    to the input (design §13.6, R-14.7). The foreign bytes deliberately include non-canonical
    whitespace so re-serialization would be detectable.
  * The carriage body is built by the shared deterministic-CBOR constructor (cbor_oracle, graded
    against RFC 8949 in T1): {1:protocol_id, 2:class, 3:content_type, 4:correlation, 5:method,
    6:foreign}.

Emits vectors/carriage/{jsonrpc,http,msg,stream,doc,opaque}/cases.json (LF-normalized).
"""
import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cbor_oracle  # shared RFC-8949 deterministic-CBOR constructor (graded in T1)

# class codes (design §13.2)
JSONRPC, HTTP, MSG, STREAM, DOC, OPAQUE = 0, 1, 2, 3, 4, 5

# One worked case per class: (dir, protocol_id, class, content_type, correlation, method, foreign)
CASES = [
    ("jsonrpc", 0x01, JSONRPC, 0, b"\x00\x00\x00\x01", "tools/call",
     b'{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "search"}}'),
    ("http", 0x03, HTTP, 2, b"\x00\x00\x00\x02", "GET",
     b"GET /agent HTTP/1.1\r\nHost: example.test\r\nAccept: */*\r\n\r\n"),
    ("msg", 0x10, MSG, 2, b"\x00\x00\x00\x03", "request",
     b'(request :sender agent-1 :receiver agent-2 :content "do-x")'),
    ("stream", 0x04, STREAM, 2, b"\x00\x00\x00\x04", "event",
     b'data: {"event": "tick", "seq": 7}\n\n'),
    ("doc", 0x02, DOC, 0, b"\x00\x00\x00\x05", "AgentCard",
     b'{"name": "MyAgent", "skills": ["search", "summarize"]}'),
    ("opaque", 0x11, OPAQUE, 1, b"\x00\x00\x00\x06", "",
     bytes([0x00, 0x01, 0x02, 0xFF, 0xFE, 0x7F, 0x80])),
]


def carriage_body(protocol_id, cls, content_type, correlation, method, foreign):
    return cbor_oracle.encode(("map", [
        (1, protocol_id),
        (2, cls),
        (3, content_type),
        (4, correlation),
        (5, method),
        (6, foreign),
    ]))


def write_case(dir_name, protocol_id, cls, content_type, correlation, method, foreign):
    body = carriage_body(protocol_id, cls, content_type, correlation, method, foreign)
    data = {
        "source": ("design §13; carriage body {1:protocol_id,2:class,3:content_type,"
                   "4:correlation,5:method,6:foreign}; foreign carried octet-for-octet (R-14.4); "
                   "round-trip identity is the independent authority (R-14.7)."),
        "protocol_id": protocol_id,
        "class": cls,
        "content_type": content_type,
        "correlation_hex": correlation.hex(),
        "method": method,
        "foreign_hex": foreign.hex(),
        "body_hex": body.hex(),
    }
    out = os.path.join(HERE, "..", "vectors", "carriage", dir_name, "cases.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with io.open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    return os.path.relpath(out, os.path.join(HERE, ".."))


def main():
    for c in CASES:
        p = write_case(*c)
        print("wrote", p)


if __name__ == "__main__":
    main()
