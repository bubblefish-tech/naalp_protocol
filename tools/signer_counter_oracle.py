# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Independent oracle for T1.6 — the OPTIONAL per-signer forward-only counter (NAALP-REQ-120;
coding-instructions §1.3). It is the non-circular authority the two reference implementations
(impl/go/envelope, impl/rust/src/envelope.rs) are graded against: Go == Rust == oracle on every
counter-bearing object body, AND Go == Rust == oracle on every accept/reject verdict AND on every
duplication-detection verdict.

WHAT the per-signer counter IS (coding-instructions §1.3, NAALP-REQ-120; design.md §2.5.2). A signer
MAY carry a forward-only counter that it increments on each object. Its purpose is DETECTION of key
duplication, NOT prevention (# Security Considerations). It is carried as extension key 14 in the
object body's NON-CRITICAL ext map (envelope field 11) — may-ignore: a verifier that does not do
duplication-detection ignores it and the object still verifies. Because ext (field 11) is part of the
signed body/payload, the counter is covered by the SIGNER's own COSE_Sign1 signature (the deliberate
contrast with T1.5, whose consume-receipt position is signed by the LEDGER key, not the signer). The
field is OPTIONAL: an absent counter is valid; a present counter is a forward-only per-signer id
position. The counter is NON-CRITICAL only — placing it in the critical cext map (field 12) is an
unrecognized critical extension and is rejected fail-closed (UnknownCriticalExt), the same C3 §2.5
critical-extension rule; the counter is a detection aid, never a must-understand verification gate.

WHAT IT IS NOT (the honest-design limit, stated as a limit — NAALP-REQ-120 + the §0/§5 non-goals).
A single sequence from a signer proves NOTHING. Once a key is duplicated, the legitimate holder and
the thief each emit locally-consistent, monotonic sequences, and neither contradicts the other in
isolation. Duplication is DETECTABLE only when two conflicting sequences bearing the SAME signer id
physically MEET where the attacker cannot suppress one of them. This oracle therefore models detection
as a function over a SET of PRESENTED objects, never a per-object boolean: it flags a signer id iff
two DISTINCT objects (distinct content ids) from that signer carry the SAME counter value in the
presented set. Given only one object per value it flags nothing. The counter does not prevent the
second signing and does not resolve the never-signs-again case; those limits are stated in the draft's
Security Considerations, not papered over here.

THE DETECTION VERDICT (independent model, from the §1.3 text — `detect()` below). Group the presented
objects by signer id, then by counter value; a (signer, counter) that binds >= 2 DISTINCT content ids
is a detected duplication, surfacing every conflicting content id. A forward-only counter binds each
value to at most one object, so a reused value across two distinct objects is the observable
fingerprint of the key incrementing in two places. A byte-identical re-presentation (one content id
twice) is benign, not a conflict. Different signers at the same value are two independent counters,
not a conflict (the counter is PER-signer). This verdict comes from this file, never from the code
under test.

NON-CIRCULARITY (project standing rule; F3). This file is written from the -01 spec text and shares
NO code with impl/go or impl/rust (it does not import them). Object bytes are built by the shared
deterministic-CBOR constructor (cbor_oracle, itself graded against RFC 8949 §4.2.1 in T1); the content
id is the T1 framing multihash(0x20, SHA-384(body-without-field-1)) (design.md §2.3). The accept/reject
verdict for each placement, and the detection verdict for each presented set, come from the from-scratch
models below, read directly from the requirement text. The impls build each case as a REAL signed
ML-DSA-65 object and MUST reproduce both the bytes and the verdicts.

Emits vectors/signer_counter/cases.json (LF-normalized).
"""
import hashlib
import io
import json
import os
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cbor_oracle  # shared RFC-8949 deterministic-CBOR constructor (graded in T1)

enc = cbor_oracle.encode

# The extension key under which a forward-only per-signer counter is carried, in the NON-CRITICAL
# ext map (field 11). 14 is the next free ext/cext key: safety-label is ext key 1 (design.md §6.4),
# recheck is ext/cext key 13 (T1.3); 14 collides with neither. Mirrors impl/go + impl/rust +
# vectors/registry/signer_counter.csv + the CDDL signer-counter production (registry_drift gate).
COUNTER_KEY = 14

# Object body field numbers (design.md §2.1); the counter rides the ext/cext maps, not a new field.
FIELD_EXT = 11   # non-critical extensions — unknown keys ignored (may-ignore, R-2.5)
FIELD_CEXT = 12  # critical extensions — an unknown key rejects (must-understand, R-2.5)

# Worked signer ids — opaque authority ids in the envelope field-5 form (the real key is C4/T4).
SIGNER_A = bytes.fromhex("5349474e45525f41")  # "SIGNER_A"
SIGNER_B = bytes.fromhex("5349474e45525f42")  # "SIGNER_B" — a distinct signer id


def content_id(body_no_id_pairs):
    """multihash(0x20, SHA-384(canonical-body-without-field-1)) (design.md §2.3)."""
    digest = hashlib.sha384(enc(("map", body_no_id_pairs))).digest()  # 48 bytes
    assert len(digest) == 48
    return b"\x20\x30" + digest


# A fixed base object (a Governance object, channel 0x0004 / kind 2, verifiable by the test's
# acceptKind) over which the ONLY variables are the body claim and the counter placement, so a
# constant / field-ignoring encoder diverges from the pinned bytes.
BASE = {
    2: 2,                                    # kind
    3: 4,                                    # channel Governance 0x0004
    4: 0,                                    # tier baseline
    5: SIGNER_A,                             # signer (opaque bstr; real id is C4/T4)
    6: 1785000000000,                        # created (epoch ms)
    7: 2,                                    # effect non_idempotent_write
    8: [],                                   # causes (empty)
    9: 1,                                    # profile Public
    10: "hello",                             # body (tstr) — the claim the object carries
}


def build_body(placement, counter, signer=None, body_str=None):
    """Return the body-without-field-1 pairs (fields 2..12, ascending) for a counter placement.
       placement: 'ext' (non-critical, the specified home), 'cext' (critical — an unrecognized
       critical extension), 'ext_empty' (present-but-empty ext, no counter), or 'absent'."""
    fields = dict(BASE)
    if signer is not None:
        fields[5] = signer
    if body_str is not None:
        fields[10] = body_str
    if placement == "ext":
        fields[FIELD_EXT] = ("map", [(COUNTER_KEY, counter)])
    elif placement == "cext":
        fields[FIELD_CEXT] = ("map", [(COUNTER_KEY, counter)])
    elif placement == "ext_empty":
        fields[FIELD_EXT] = ("map", [])      # present but empty — carries no counter
    elif placement == "absent":
        pass                                  # no ext, no cext
    else:
        raise ValueError("bad placement: %r" % placement)
    return [(k, fields[k]) for k in sorted(fields)]


def verdict(placement):
    """The independent accept/reject model, read from NAALP-REQ-120 + the C3 critical-extension
       rule (design.md §2.5). Returns 'accept' or the named fail-closed error.
         - counter absent / ext present-but-empty -> accept (the field is OPTIONAL).
         - counter in ext (non-critical)          -> accept (may-ignore; the specified home).
         - counter in cext (critical)             -> UnknownCriticalExt (the counter is non-critical;
             placing it in the critical map is an unrecognized critical extension, fail-closed)."""
    if placement == "cext":
        return "UnknownCriticalExt"
    return "accept"


def object_case(name, placement, counter, note, signer=None, body_str=None):
    body_no_id = build_body(placement, counter, signer=signer, body_str=body_str)
    cid = content_id(body_no_id)
    full = [(1, cid)] + body_no_id
    return {
        "name": name,
        "note": note,
        "placement": placement,                     # ext | cext | ext_empty | absent
        "present": placement in ("ext", "cext"),
        "counter": counter,                          # null for ext_empty / absent
        "signer_hex": (signer if signer is not None else BASE[5]).hex(),
        "body_str": body_str if body_str is not None else BASE[10],
        "body_no_id_hex": enc(("map", body_no_id)).hex(),
        "content_id_hex": cid.hex(),
        "full_hex": enc(("map", full)).hex(),
        "expect": verdict(placement),
    }


def build_cases():
    """Single-object byte-parity + accept/reject cases, INCLUDING the section-4 standard wire cases:
       minimal object with the field, empty-value vs absent-value, an unknown-critical placement,
       and a counter value too large for a receiving language's normal integer."""
    cases = [
        # minimal object carrying the counter in the non-critical ext map (the specified home).
        object_case("minimal_ext", "ext", 1,
                    "ext[14]=1 minimal forward-only position (non-critical, the specified home) -> accept"),
        # OPTIONAL: an absent counter is valid.
        object_case("counter_absent", "absent", None,
                    "no ext, no cext: the counter is OPTIONAL; its absence is valid -> accept"),
        # empty value vs absent value (empty != absent; design.md §3.3, R-3.3), TWO renderings:
        #  (a) value-level: a present counter with value 0 is NOT the same as an absent counter.
        object_case("counter_zero", "ext", 0,
                    "ext[14]=0 a present zero position: bytes/id differ from counter_absent "
                    "(present-zero != absent)"),
        #  (b) carrier-level: a present-but-empty ext map names no counter; bytes differ from absent.
        object_case("ext_present_empty", "ext_empty", None,
                    "ext={} present-but-empty (no key 14): names no counter -> accept; bytes/id "
                    "differ from counter_absent (empty != absent)"),
        # counter value too large for a receiving language's normal integer: 2^53 (beyond a JS/
        # float64-safe integer) and 2^64-1 (max uint64). MUST decode as a 64-bit uint, not round.
        object_case("counter_2_53", "ext", 1 << 53,
                    "ext[14]=2^53 (beyond a JS/float64-safe integer): decodes as a 64-bit uint -> accept"),
        object_case("counter_uint64_max", "ext", (1 << 64) - 1,
                    "ext[14]=2^64-1 (max uint64): decodes without overflow/round -> accept"),
        # the STANDARD "unknown critical" wire case, rendered for a field with no procedure registry:
        # the counter placed in the CRITICAL cext map is an unrecognized critical extension (key 14 is
        # non-critical; the envelope does not recognize it as must-understand) -> UnknownCriticalExt.
        object_case("cext_counter_unknown_critical", "cext", 5,
                    "cext[14]=5 the counter placed in the critical map is an unrecognized critical "
                    "extension (the counter is non-critical) -> UnknownCriticalExt, fail-closed"),
    ]
    # empty/present-zero/absent triple: all three distinct content ids (isolates the single variable).
    absent = next(c for c in cases if c["name"] == "counter_absent")
    zero = next(c for c in cases if c["name"] == "counter_zero")
    empty = next(c for c in cases if c["name"] == "ext_present_empty")
    assert absent["content_id_hex"] != zero["content_id_hex"], "present-zero must differ from absent"
    assert absent["content_id_hex"] != empty["content_id_hex"], "empty must differ from absent"
    assert zero["content_id_hex"] != empty["content_id_hex"], "present-zero must differ from empty"
    return cases


def build_negatives():
    """Hand-crafted non-canonical counter bodies a strict decoder MUST reject BEFORE any counter
       rule runs (design.md §2.6, R-3.1). Proves keys-out-of-order in a counter object is caught at
       the CBOR layer (NonCanonical), not silently honored — even though ext is may-ignore."""
    # A body whose non-critical ext map (field 11) carries two keys {14, 100} in NON-canonical order
    # (100 before 14). Deterministic CBOR requires map keys ascending by encoded bytes, so 14 (0x0e)
    # must precede 100 (0x1864). Build the canonical body with cbor_oracle, then splice a
    # non-canonical field-11 inner map in place of the canonical one.
    canon_ext_pairs = [(COUNTER_KEY, 7), (100, 9)]
    canon_body = [(k, v) for (k, v) in build_body("absent", None)]
    canon_body.append((FIELD_EXT, ("map", canon_ext_pairs)))
    canon_body_sorted = sorted(canon_body, key=lambda kv: kv[0])
    cid = content_id(canon_body_sorted)
    full_pairs = [(1, cid)] + canon_body_sorted
    canonical_full = enc(("map", full_pairs))
    # non-canonical variant: build the field-11 inner map by hand with keys in NON-canonical order
    # (100 then 14); everything else stays canonical.
    inner = cbor_oracle.enc_head(5, 2) + enc(100) + enc(9) + enc(COUNTER_KEY) + enc(7)
    out = cbor_oracle.enc_head(5, len(full_pairs))
    for (k, v) in sorted(full_pairs, key=lambda kv: enc(kv[0])):
        out += enc(k)
        out += inner if k == FIELD_EXT else enc(v)
    return [{
        "name": "ext_keys_out_of_order",
        "note": "field-11 ext map {100:9,14:7} with keys in NON-canonical order (100 before 14) -> "
                "the decoder rejects NonCanonical before any counter rule runs (even though ext is "
                "may-ignore, the codec is strict)",
        "payload_hex": out.hex(),
        "canonical_payload_hex": canonical_full.hex(),
        "expect": "NonCanonical",
    }]


# ---- detection over a SET of presented objects (the whole point: not a per-object boolean) --------

def obj_ref(signer, counter, body_str):
    """A presented object's (signer, counter, content_id): the impl reconstructs the same object from
       (signer, counter, body_str) over the shared BASE and MUST recompute this content id."""
    placement = "ext" if counter is not None else "absent"
    body_no_id = build_body(placement, counter, signer=signer, body_str=body_str)
    return {"signer_hex": signer.hex(), "counter": counter, "body_str": body_str,
            "content_id_hex": content_id(body_no_id).hex()}


def detect(objects):
    """The independent duplication-detection model (from the §1.3 text). `objects` is a list of the
       presented-object dicts obj_ref() produces. Group by signer id, then counter value; a (signer,
       counter) binding >= 2 DISTINCT content ids is a detected duplication surfacing every id.
       Objects with no counter do not participate. A single object per value flags NOTHING — the
       asymmetry that makes this detection (needs both), not prevention."""
    groups = defaultdict(lambda: defaultdict(set))
    for o in objects:
        if o["counter"] is None:
            continue
        groups[o["signer_hex"]][o["counter"]].add(o["content_id_hex"])
    findings = []
    for signer in sorted(groups):
        for counter in sorted(groups[signer]):
            ids = sorted(groups[signer][counter])
            if len(ids) >= 2:
                findings.append({"signer_hex": signer, "counter": counter, "ids_hex": ids})
    return findings


def scenario(name, note, objects):
    return {"name": name, "note": note, "objects": objects, "expect": detect(objects)}


def build_detection():
    A, B = SIGNER_A, SIGNER_B
    # the two conflicting objects at the fork point (position 5): same signer, same counter, DISTINCT
    # bodies -> distinct content ids. These are the holder's and the thief's objects.
    holder5 = obj_ref(A, 5, "holder")
    thief5 = obj_ref(A, 5, "thief")
    thief5b = obj_ref(A, 5, "thief2")
    scenarios = [
        # (a) one sequence alone -> NOT flagged. Detection requires two conflicting sequences to meet.
        scenario("one_sequence_alone",
                 "a single object at position 5 presented alone -> NOT flagged (one sequence proves "
                 "nothing; detection requires both conflicting sequences to physically meet)",
                 [holder5]),
        # one signer's honest forward-only sequence (1,2,3): distinct values, distinct objects -> none.
        scenario("forward_only_sequence",
                 "one signer's honest monotonic sequence (positions 1,2,3) -> NOT flagged "
                 "(each value binds exactly one object)",
                 [obj_ref(A, 1, "s1"), obj_ref(A, 2, "s2"), obj_ref(A, 3, "s3")]),
        # (b) two conflicting sequences, SAME signer id, SAME position, presented TOGETHER -> FLAGGED,
        # both content ids surfaced. This is the duplication fingerprint.
        scenario("conflict_same_signer_same_position",
                 "the holder's and the thief's objects, both signer SIGNER_A at position 5, presented "
                 "together -> FLAGGED once, surfacing BOTH content ids (the duplication is now provable)",
                 [holder5, thief5]),
        # a three-way collision surfaces all three ids.
        scenario("three_way_conflict",
                 "three distinct objects from one signer all at position 5 -> FLAGGED, surfacing all "
                 "three content ids",
                 [holder5, thief5, thief5b]),
        # (c) two NON-conflicting (forward-only consistent) sequences -> NOT flagged.
        scenario("non_conflicting_two",
                 "two objects from one signer at DIFFERENT positions (5 and 6) -> NOT flagged "
                 "(forward-only consistent; no value reused)",
                 [holder5, obj_ref(A, 6, "next")]),
        # a byte-identical re-presentation is benign (same content id twice, not two distinct objects).
        scenario("benign_rerepresentation",
                 "the SAME object presented twice (byte-identical, one content id) -> NOT flagged "
                 "(a re-presentation is benign, not a duplication)",
                 [holder5, obj_ref(A, 5, "holder")]),
        # different signers at the same position are two independent counters (per-signer), not a fork.
        scenario("cross_signer_same_position",
                 "SIGNER_A and SIGNER_B each at position 5 -> NOT flagged (the counter is PER-signer; "
                 "different signers at one value are two independent counters)",
                 [holder5, obj_ref(B, 5, "other")]),
        # an object with NO counter does not participate; mixed with one counter-bearing object -> none.
        scenario("absent_does_not_participate",
                 "an object with no counter presented with one counter-bearing object -> NOT flagged "
                 "(a counter-less object does not participate in detection)",
                 [obj_ref(A, None, "no_counter"), holder5]),
    ]
    return {
        "note": ("Detection over a SET of presented objects (NAALP-REQ-120): flagged iff two DISTINCT "
                 "objects from the SAME signer id carry the SAME counter value in the presented set; a "
                 "single sequence flags nothing. Each object is rebuilt by the impl from (signer, "
                 "counter, body_str) over the shared base; the impl runs DetectSignerDuplication and "
                 "MUST reproduce the expect findings (signer, counter, and the SET of content ids). "
                 "Verdicts come from the from-scratch detect() model in this file, NOT the code under test."),
        "signers": {"a_hex": SIGNER_A.hex(), "b_hex": SIGNER_B.hex()},
        "scenarios": scenarios,
    }


def build():
    return {
        "note": ("Independent oracle for T1.6 the OPTIONAL per-signer forward-only counter "
                 "(NAALP-REQ-120; coding-instructions §1.3). The counter is carried as extension key "
                 "14 in the object body's NON-CRITICAL ext map (field 11), covered by the SIGNER's "
                 "COSE_Sign1 signature (contrast T1.5: the consume-receipt position is signed by the "
                 "LEDGER key). It is OPTIONAL (absent -> valid) and DETECTION-only: it flags key "
                 "duplication ONLY when two conflicting sequences from one signer id physically meet, "
                 "never from one alone, and never prevents the second signing. Placing it in the "
                 "critical cext map is an unrecognized critical extension -> UnknownCriticalExt. Go and "
                 "Rust reproduce every body_no_id_hex/content_id_hex/full_hex, every accept/reject "
                 "verdict over REAL ML-DSA-65 signed objects, and every duplication-detection finding, "
                 "so Go==Rust==oracle. Verdicts come from the from-scratch models in this file, NOT "
                 "impl/go or impl/rust. Generated by tools/signer_counter_oracle.py; do not hand-edit."),
        "counter_key": COUNTER_KEY,
        "reject_error_cext": "UnknownCriticalExt",
        "base_object": {
            "kind": BASE[2], "channel": BASE[3], "tier": BASE[4],
            "signer_hex": BASE[5].hex(), "created": BASE[6], "effect": BASE[7],
            "causes_hex": [], "profile": BASE[9], "body_str": BASE[10],
        },
        "cases": build_cases(),
        "negatives": build_negatives(),
        "detection": build_detection(),
    }


def _r12_stringify(node):
    # R12 (NAALP-01-03): carry any 64-bit counter/position > 2^53-1 as a decimal STRING so a
    # float64 JSON decoder (JS Number, Go interface{}, and the shared runner's own decode+re-marshal
    # step) cannot silently round the low octets before an adapter's string-tolerant u64 parses it.
    # Representation-only: the signed CBOR bytes (full_hex / content_id_hex / body_no_id_hex) are
    # computed from the integer BEFORE this walk and are unchanged.
    if isinstance(node, bool):
        return node
    if isinstance(node, int):
        return str(node) if abs(node) > (1 << 53) - 1 else node
    if isinstance(node, dict):
        return {k: _r12_stringify(v) for k, v in node.items()}
    if isinstance(node, list):
        return [_r12_stringify(v) for v in node]
    return node


def main():
    data = _r12_stringify(build())
    out = os.path.normpath(os.path.join(HERE, "..", "vectors", "signer_counter", "cases.json"))
    os.makedirs(os.path.dirname(out), exist_ok=True)
    # newline="\n" forces LF on every platform (Python text mode would emit CRLF on Windows,
    # diverging the worktree vector from the LF-normalized git blob and breaking a pinned gate).
    with io.open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print("wrote", os.path.relpath(out, os.path.join(HERE, "..")))
    print("  counter_key =", data["counter_key"])
    for c in data["cases"]:
        print("  case %-30s [%-9s counter=%-20s] -> %s"
              % (c["name"], c["placement"], c["counter"], c["expect"]))
    for n in data["negatives"]:
        print("  negative %-24s -> %s" % (n["name"], n["expect"]))
    for s in data["detection"]["scenarios"]:
        print("  detection %-34s objects=%d -> %d finding(s)"
              % (s["name"], len(s["objects"]), len(s["expect"])))


if __name__ == "__main__":
    main()
