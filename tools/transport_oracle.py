# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Independent oracle for C11 — the four transport bindings (T10).

Non-circular authority (NOT the code under test):
  * design §12: one signed object = one message unit across N-PAMP / QUIC / WebSocket / HTTP,
    with identical object semantics; the binding adds ONLY framing (the object is self-secured
    by C2..C8), so the transport-independent object is its own cross-binding oracle — the SAME
    signed object must verify identically over every binding (graded in Go/Rust with real
    crypto, since signing needs ML-DSA).
  * The confidentiality boundary (§12.3/§12.4) is a decision matrix computed here independently:
    a sensitive object over a non-confidential transport is refused (ConfidentialTransportRequired);
    a transport lacking peer authentication where policy requires it is PeerUnauthenticated.
  * The media type is application/naalp+cbor (§12.1).

Emits vectors/transport/cases.json (LF-normalized).
"""
import io
import json
import os

# The four binding types; WebSocket and HTTP have a confidential (wss/https) and a cleartext
# (ws/http) variant — confidentiality is the property the §12.3 boundary turns on.
TRANSPORTS = [
    ("npamp", True, True),           # PQ AEAD + PQ handshake / PeerHandle
    ("quic", True, True),            # TLS 1.3 + cert / raw public key
    ("websocket+wss", True, False),  # TLS (wss); connection auth out of band
    ("websocket+ws", False, False),  # cleartext ws
    ("https", True, False),          # TLS (https); connection auth out of band
    ("http", False, False),          # cleartext http
]


def decide(confidential, peer_authenticated, sensitive, require_peer_auth):
    """The §12.3 confidentiality boundary + §12.4 peer-auth rule (checked in that order)."""
    if sensitive and not confidential:
        return "ConfidentialTransportRequired"
    if require_peer_auth and not peer_authenticated:
        return "PeerUnauthenticated"
    return "ok"


def build():
    transports = [
        {"name": n, "confidential": c, "peer_authenticated": a}
        for (n, c, a) in TRANSPORTS
    ]
    matrix = []
    for (n, c, a) in TRANSPORTS:
        for sensitive in (False, True):
            for require_peer_auth in (False, True):
                matrix.append({
                    "transport": n, "sensitive": sensitive, "require_peer_auth": require_peer_auth,
                    "result": decide(c, a, sensitive, require_peer_auth),
                })
    return {
        "source": ("design §12; one signed object = one message unit across N-PAMP/QUIC/"
                   "WebSocket/HTTP; binding adds only framing; sensitive object over a "
                   "non-confidential transport => ConfidentialTransportRequired; missing peer "
                   "auth where required => PeerUnauthenticated; media type application/naalp+cbor."),
        "media_type": "application/naalp+cbor",
        "transports": transports,
        "emit_matrix": matrix,
    }


def main():
    data = build()
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "vectors", "transport", "cases.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with io.open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    print("wrote", os.path.relpath(out, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")))
    print("  transports=%d matrix=%d" % (len(data["transports"]), len(data["emit_matrix"])))


if __name__ == "__main__":
    main()
