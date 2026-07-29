# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Independent oracle for C5 — effect + safety vocabulary + effect-to-authorization (T5).

Non-circular authority (NOT the code under test):
  * The four-value effect set and its fail-safe rule are taken from the N-PAMP
    substrate spec, witnessed this session:
      N-PAMP draft-01, spec/companion/10_bridge_framework.md §7 (SafetyLabel TLV 0x0013):
        effect u8 = 0x00 read_only, 0x01 idempotent_write,
                    0x02 non_idempotent_write, 0x03 destructive
        "A receiver MUST NOT treat the absence of a SafetyLabel on a state-mutating
         operation as read_only; absence ... MUST be treated as destructive (fail-safe).
         The label describes intent and does not replace authorization."
    N-AALP design §6.1 aligns 1:1 with this set (identity Bridge map) and §6.3 CLOSES the
    authorization hole N-PAMP leaves open.
  * The authorize/deny matrix is computed here from the effect LATTICE
    (read_only < idempotent_write < non_idempotent_write < destructive), independently of
    the Go/Rust policy code: an object is authorized iff object.effect <= granted capability.
  * The safety-label canonical bytes are built by the shared deterministic-CBOR constructor
    (cbor_oracle), which is itself graded against RFC 8949 in T1 — not by the policy code.

Emits vectors/effect/cases.json (LF-normalized). Go and Rust read it and assert equality;
Go == oracle and Rust == oracle jointly imply Go == Rust.
"""
import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cbor_oracle  # shared RFC-8949 deterministic-CBOR constructor (graded in T1)

# The closed effect set (N-PAMP Bridge SafetyLabel §7 = N-AALP design §6.1). The lattice
# order IS the numeric order; "destructive" is the top. authorizes/denies text is the
# design §6.1 table verbatim.
EFFECTS = [
    (0, "read_only",            "observation, no state change",       "any write"),
    (1, "idempotent_write",     "a write safe to repeat",             "non-idempotent or destructive change"),
    (2, "non_idempotent_write", "a write not safe to repeat",         "destruction"),
    (3, "destructive",          "irreversible change / deletion",     "nothing further (top of lattice)"),
]
DESTRUCTIVE = 3  # fail-closed target for any unrecognized effect (R-6.2)


def normalize(v):
    """R-6.2: an effect the evaluator does not recognize is treated as the most dangerous
    class (destructive) and never fails open."""
    return v if 0 <= v <= 3 else DESTRUCTIVE


def authorize(granted, effect):
    """R-6.3: an object whose (normalized) effect exceeds the granted capability is denied.
    Pure lattice comparison, computed independently of the implementation under test."""
    return normalize(effect) <= granted


def build():
    effects = [
        {"value": v, "safety_label": name, "authorizes": auth, "denies": deny}
        for (v, name, auth, deny) in EFFECTS
    ]

    # N-AALP effect <-> N-PAMP Bridge SafetyLabel u8: identity map (design §6.1, no
    # translation), so carriage over the Bridge is loss-free.
    bridge_mapping = [{"effect": v, "npamp_u8": v, "safety_label": name}
                      for (v, name, _, _) in EFFECTS]

    # The full 4x4 authorize/deny matrix (granted capability x object effect).
    matrix = [{"granted": g, "effect": e, "allow": authorize(g, e)}
              for g in range(4) for e in range(4)]

    # Unrecognized effect values fail closed to destructive (R-6.2).
    unknown = [{"input": v, "effect": normalize(v)} for v in (4, 5, 99, 255, 256, 65535)]

    # An authorization principal is ONLY a signature-derived identity (R-6.5): transport
    # metadata, a foreign header, and a client-supplied name are NOT authorization identities.
    principal_sources = [
        {"source": "signature",         "accepted": True},
        {"source": "transport_metadata", "accepted": False},
        {"source": "foreign_header",     "accepted": False},
        {"source": "client_name",        "accepted": False},
    ]

    # Optional signed safety label (R-6.4): a non-critical ext entry {1: risk, 2: scope};
    # an accountable claim, not a guarantee. Canonical CBOR built by the T1-graded encoder.
    risk, scope = "elevated", "billing-records"
    label_bytes = cbor_oracle.encode(("map", [(1, risk), (2, scope)]))
    safety_label = {"risk": risk, "scope": scope, "ext_key": 1, "cbor_hex": label_bytes.hex()}

    return {
        "source": ("N-PAMP draft-01 spec/companion/10_bridge_framework.md §7 (SafetyLabel "
                   "TLV 0x0013): effect u8 0x00..0x03; absence on a state-mutating op => "
                   "destructive (fail-safe); 'describes intent and does not replace "
                   "authorization'. N-AALP design §6 closes the authorization hole."),
        "effects": effects,
        "bridge_mapping": bridge_mapping,
        "authorization_matrix": matrix,
        "unknown_normalization": unknown,
        "principal_sources": principal_sources,
        "safety_label": safety_label,
    }


def main():
    data = build()
    out = os.path.join(HERE, "..", "vectors", "effect", "cases.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with io.open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    print("wrote", os.path.relpath(out, os.path.join(HERE, "..")))
    print("  effects=%d matrix=%d unknown=%d label_bytes=%d"
          % (len(data["effects"]), len(data["authorization_matrix"]),
             len(data["unknown_normalization"]), len(data["safety_label"]["cbor_hex"]) // 2))


if __name__ == "__main__":
    main()
