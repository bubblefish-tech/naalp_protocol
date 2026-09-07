# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Independent oracle for T1.3 — the `recheck` checkable-minimum field (NAALP-REQ-110/111;
coding-instructions §1.2). It is the non-circular authority the two reference implementations
(impl/go/envelope, impl/rust/src/envelope.rs) are graded against: Go == Rust == oracle on every
recheck-bearing object body, AND Go == Rust == oracle on every accept/reject verdict.

WHAT recheck IS (design.md §2.5; NAALP-REQ-111(c)). A signature makes a body's claim
ATTRIBUTABLE to a signer. A claim is CHECKABLE only if a stranger can re-derive it without
trusting the speaker, which requires the object to (c) NAME the procedure a verifier runs to
re-check it. `recheck` is that naming: a procedure id into a small CLOSED registry —

    1 recompute-content-id   2 verify-cose-sign1   3 walk-causes   4 replay-consume-check

carried as extension key 13 in the object body's extension maps (design.md §2.1, §2.5):
  * in the NON-CRITICAL ext map (envelope field 11) it is MAY-IGNORE: a verifier that does not
    recognize the procedure id ignores it and the object still verifies;
  * in the CRITICAL cext map (envelope field 12) it is MUST-UNDERSTAND: a verifier that does not
    recognize the procedure id REJECTS the whole object (UnknownCriticalExt), fail-closed — the
    exact C3 critical-extension rule (§2.5, R-2.5), now reaching the re-check procedure it names.
A known procedure id verifies in either map. Placement (ext vs cext) is the criticality signal;
there is no boolean on the wire (the N-AALP spine carries no CBOR booleans).

NON-CIRCULARITY (CLAUDE.md standing rule; F3). This file is written from the -01 spec text and
shares NO code with impl/go or impl/rust. Object bytes are built by the shared deterministic-CBOR
constructor (cbor_oracle, itself graded against RFC 8949 §4.2.1 in T1); the content id is the T1
framing multihash(0x20, SHA-384(body-without-field-1)) (design.md §2.3). The accept/reject VERDICT
for each (procedure id, placement) comes from the from-scratch model `verdict()` below, read
directly from the requirement text — never from the code under test. The impls build each case as
a REAL signed COSE_Sign1 object (real ML-DSA-65) and MUST reproduce both the body bytes and the
verdict.

Emits vectors/recheck/cases.json (LF-normalized).
"""
import hashlib
import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cbor_oracle  # shared RFC-8949 deterministic-CBOR constructor (graded in T1)

enc = cbor_oracle.encode

# ---- the closed re-check procedure registry (coding-instructions §1.2 T1.3) ------------------
# ids are assigned here from the spec's named set; the CDDL `recheck-procedure` enum and
# vectors/registry/recheck.csv mirror this exact table (registry_drift cross-checks all three).
PROCEDURES = [
    (1, "recompute-content-id"),
    (2, "verify-cose-sign1"),
    (3, "walk-causes"),
    (4, "replay-consume-check"),
]
KNOWN_IDS = {pid for pid, _ in PROCEDURES}
PROC_NAME = {pid: name for pid, name in PROCEDURES}

# The extension key under which a re-check procedure is named, in ext (field 11) or cext
# (field 12). 13 is free: safety-label occupies ext key 1 (design.md §6.4); it does not collide.
RECHECK_KEY = 13

# Object body field numbers (design.md §2.1); recheck rides the ext/cext maps, not a new field.
FIELD_EXT = 11   # non-critical extensions — unknown keys ignored (may-ignore, R-2.5)
FIELD_CEXT = 12  # critical extensions — an unknown key/procedure rejects (must-understand, R-2.5)


def content_id(body_no_id_pairs):
    """multihash(0x20, SHA-384(canonical-body-without-field-1)) (design.md §2.3)."""
    digest = hashlib.sha384(enc(("map", body_no_id_pairs))).digest()  # 48 bytes
    assert len(digest) == 48
    return b"\x20\x30" + digest


# A fixed base object (a Governance object, mirroring the envelope oracle's worked object) over
# which the ONLY variable is the recheck placement, so a constant/field-ignoring encoder diverges.
BASE = {
    2: 2,                                    # kind
    3: 4,                                    # channel Governance 0x0004
    4: 0,                                    # tier baseline
    5: bytes.fromhex("5349474e45525f41"),    # signer "SIGNER_A" (opaque bstr; real id is C4/T4)
    6: 1785000000000,                        # created (epoch ms)
    7: 2,                                    # effect non_idempotent_write
    8: [],                                   # causes (empty)
    9: 1,                                    # profile Public
    10: "hello",                             # body (tstr) — the claim recheck names a procedure for
}


def build_body(placement, proc_id):
    """Return the body-without-field-1 pairs (fields 2..12, ascending) for a recheck placement.
       placement: 'cext' (critical), 'ext' (non-critical), 'ext_empty' (present-but-empty ext,
       no procedure), or 'absent' (no ext/cext)."""
    fields = dict(BASE)
    if placement == "cext":
        fields[FIELD_CEXT] = ("map", [(RECHECK_KEY, proc_id)])
    elif placement == "ext":
        fields[FIELD_EXT] = ("map", [(RECHECK_KEY, proc_id)])
    elif placement == "ext_empty":
        fields[FIELD_EXT] = ("map", [])      # present but empty — carries no recheck
    elif placement == "absent":
        pass                                  # no ext, no cext
    else:
        raise ValueError("bad placement: %r" % placement)
    return [(k, fields[k]) for k in sorted(fields)]


def verdict(placement, proc_id):
    """The independent accept/reject model, read from NAALP-REQ-111 + the C3 critical-extension
       rule (design.md §2.5). Returns 'accept' or the named fail-closed error.
         - no recheck named            -> accept (the claim is attributable-only; §2.5).
         - known procedure id          -> accept (recognized, in either map).
         - unknown id, CRITICAL (cext) -> UnknownCriticalExt (must-understand, fail-closed).
         - unknown id, NON-CRIT (ext)  -> accept (may-ignore; unknown non-critical ext ignored)."""
    if placement in ("absent", "ext_empty"):
        return "accept"
    if proc_id in KNOWN_IDS:
        return "accept"
    if placement == "cext":
        return "UnknownCriticalExt"
    return "accept"  # placement == 'ext', unknown -> ignored


def positive_case(name, placement, proc_id, note):
    body_no_id = build_body(placement, proc_id)
    cid = content_id(body_no_id)
    full = [(1, cid)] + body_no_id
    return {
        "name": name,
        "note": note,
        "placement": placement,                     # cext | ext | ext_empty | absent
        "critical": placement == "cext",
        "present": placement in ("cext", "ext"),
        "procedure_id": proc_id,
        "procedure_name": PROC_NAME.get(proc_id),   # null for an unknown id / no recheck
        "body_no_id_hex": enc(("map", body_no_id)).hex(),
        "content_id_hex": cid.hex(),
        "full_hex": enc(("map", full)).hex(),
        "expect": verdict(placement, proc_id),
    }


def build_cases():
    cases = [
        # known procedures, CRITICAL (cext) — must-understand, all recognized -> accept.
        positive_case("critical_known_recompute", "cext", 1,
                      "cext[13]=1 recompute-content-id (known, critical) -> accept"),
        positive_case("critical_known_cose", "cext", 2,
                      "cext[13]=2 verify-cose-sign1 (known, critical) -> accept"),
        positive_case("critical_known_walk", "cext", 3,
                      "cext[13]=3 walk-causes (known, critical) -> accept"),
        positive_case("critical_known_replay_max", "cext", 4,
                      "cext[13]=4 replay-consume-check (known, critical; the registry's top id) -> accept"),
        # known procedure, NON-CRITICAL (ext) -> accept (recognized, advisory).
        positive_case("noncritical_known_walk", "ext", 3,
                      "ext[13]=3 walk-causes (known, non-critical) -> accept"),
        # unknown procedure, CRITICAL -> the reject path (UnknownCriticalExt).
        positive_case("critical_unknown", "cext", 99,
                      "cext[13]=99 (unknown, critical) -> UnknownCriticalExt, fail-closed"),
        # unknown procedure, CRITICAL, boundaries around the closed registry {1..4}.
        positive_case("critical_unknown_zero", "cext", 0,
                      "cext[13]=0 (just below the registry, unknown, critical) -> UnknownCriticalExt"),
        positive_case("critical_unknown_five", "cext", 5,
                      "cext[13]=5 (just above the registry top 4, unknown, critical) -> UnknownCriticalExt"),
        positive_case("critical_unknown_large", "cext", 4294967296,
                      "cext[13]=2^32 (a procedure-id value beyond 32 bits, unknown, critical) -> "
                      "UnknownCriticalExt; also exercises 64-bit uint decode of the recheck value"),
        # unknown procedure, NON-CRITICAL -> ignored (may-ignore).
        positive_case("noncritical_unknown", "ext", 99,
                      "ext[13]=99 (unknown, non-critical) -> ignored, accept (may-ignore rule)"),
        # empty vs absent recheck carrier: both name no procedure but encode to DISTINCT bytes
        # and DISTINCT content ids (empty != absent; design.md §3.3, R-3.3). Both accept.
        positive_case("recheck_absent", "absent", None,
                      "no ext, no cext: the claim is attributable-only -> accept"),
        positive_case("ext_present_empty", "ext_empty", None,
                      "ext={} present-but-empty (no key 13): names no recheck -> accept; bytes/id "
                      "differ from recheck_absent (empty != absent)"),
    ]
    # empty != absent invariant (the pair isolates the single variable).
    absent = next(c for c in cases if c["name"] == "recheck_absent")
    empty = next(c for c in cases if c["name"] == "ext_present_empty")
    assert absent["content_id_hex"] != empty["content_id_hex"], "empty must differ from absent"
    return cases


def build_negatives():
    """Hand-crafted non-canonical recheck bodies a strict decoder MUST reject BEFORE the recheck
       rule runs (design.md §2.6, R-3.1). Proves keys-out-of-order in a recheck object is caught
       at the CBOR layer (NonCanonical), not silently honored."""
    # A body whose CRITICAL map (field 12) carries two keys {13, 100} in NON-canonical order
    # (100 before 13). Deterministic CBOR requires map keys ascending by encoded bytes, so 13
    # (0x0d) must precede 100 (0x1864). We build the full body with cbor_oracle (canonical) then
    # splice a non-canonical field-12 inner map in place of the canonical one.
    body_no_id = build_body("cext", 2)                       # cext={13:2}
    # canonical two-key cext {13:2, 100:7}
    canon_cext_pairs = [(13, 2), (100, 7)]
    canon_body = [(k, v) for (k, v) in body_no_id if k != FIELD_CEXT]
    canon_body.append((FIELD_CEXT, ("map", canon_cext_pairs)))
    canon_body_sorted = sorted(canon_body, key=lambda kv: kv[0])
    cid = content_id(canon_body_sorted)
    full_pairs = [(1, cid)] + canon_body_sorted
    canonical_full = enc(("map", full_pairs))
    # non-canonical variant: build the field-12 inner map bytes by hand with the two keys in
    # NON-canonical order (100 then 13); everything else stays canonical.
    inner = cbor_oracle.enc_head(5, 2) + enc(100) + enc(7) + enc(13) + enc(2)
    # reconstruct the full payload swapping only the field-12 value bytes.
    # encode every top-level pair, replacing field 12's value with the non-canonical inner map.
    out = cbor_oracle.enc_head(5, len(full_pairs))
    for (k, v) in sorted(full_pairs, key=lambda kv: enc(kv[0])):
        out += enc(k)
        if k == FIELD_CEXT:
            out += inner
        else:
            out += enc(v)
    return [{
        "name": "cext_keys_out_of_order",
        "note": "field-12 critical map {100:7,13:2} with keys in NON-canonical order (100 before "
                "13) -> the decoder rejects NonCanonical before the recheck rule is reached",
        "payload_hex": out.hex(),
        "canonical_payload_hex": canonical_full.hex(),
        "expect": "NonCanonical",
    }]


def build():
    return {
        "note": ("Independent oracle for T1.3 recheck (NAALP-REQ-110/111; coding-instructions §1.2). "
                 "recheck names the body claim's re-check procedure by id (1 recompute-content-id, "
                 "2 verify-cose-sign1, 3 walk-causes, 4 replay-consume-check) as extension key 13: "
                 "in cext (field 12) it is critical/must-understand (unknown id -> UnknownCriticalExt), "
                 "in ext (field 11) non-critical/may-ignore (unknown id ignored); a known id verifies "
                 "in either. Go and Rust reproduce every body_no_id_hex, content_id_hex, full_hex AND "
                 "every accept/reject verdict over REAL ML-DSA-65 signed objects, so Go==Rust==oracle. "
                 "Verdicts come from the from-scratch model in this file, NOT impl/go or impl/rust. "
                 "Generated by tools/recheck_oracle.py; do not hand-edit."),
        "recheck_key": RECHECK_KEY,
        "reject_error": "UnknownCriticalExt",
        "procedures": [{"id": pid, "name": name} for pid, name in PROCEDURES],
        "base_object": {
            "kind": BASE[2], "channel": BASE[3], "tier": BASE[4],
            "signer_hex": BASE[5].hex(), "created": BASE[6], "effect": BASE[7],
            "causes_hex": [], "profile": BASE[9], "body_str": BASE[10],
        },
        "cases": build_cases(),
        "negatives": build_negatives(),
    }


def main():
    data = build()
    out = os.path.normpath(os.path.join(HERE, "..", "vectors", "recheck", "cases.json"))
    os.makedirs(os.path.dirname(out), exist_ok=True)
    # newline="\n" forces LF on every platform (Python text mode would emit CRLF on Windows,
    # diverging the worktree vector from the LF-normalized git blob and breaking a pinned gate).
    with io.open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print("wrote", os.path.relpath(out, os.path.join(HERE, "..")))
    for p in data["procedures"]:
        print("  procedure %d = %s" % (p["id"], p["name"]))
    for c in data["cases"]:
        print("  case %-26s [%-9s id=%-10s] -> %s"
              % (c["name"], c["placement"], c["procedure_id"], c["expect"]))
    for n in data["negatives"]:
        print("  negative %-24s -> %s" % (n["name"], n["expect"]))


if __name__ == "__main__":
    main()
