# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Independent oracle for NA-IETF-1 — the OPTIONAL producing-boundary disclosure (design.md §2.5.4).
It is the non-circular authority the two reference implementations (impl/go/envelope,
impl/rust/src/envelope.rs) are graded against: Go == Rust == oracle on every disclosure-bearing
object body, on every accept/reject verdict, AND on every parsed disclosure (present, kind,
boundary, reporting-boundary).

WHAT the producing-boundary disclosure IS (design.md §2.5.4; NA-IETF-1). A signer MAY carry a
per-object disclosure of the trust boundary that PRODUCED the object and whether that boundary
OBSERVED the event it describes first-hand or is RELAYING a report of it. It is carried as extension
key 15 in the object body's NON-CRITICAL ext map (envelope field 11) — may-ignore: a verifier that
does not understand it, or that reads a malformed value, ignores the entry and the object still
verifies. Because ext (field 11) is part of the signed body/payload, the disclosure is covered by
the SIGNER's own COSE_Sign1 signature, so it is SELF-ASSERTED. The value is a small map:
  1 boundary (bstr, the emitting boundary, same party-id form as the object signer, field 5),
  2 kind     (1 observed = witnessed first-hand / 2 reported = relaying a report), and
  3 reporting-boundary (bstr, OPTIONAL) present ONLY when kind = reported, naming the report origin.
For observed, reporting-boundary MUST be absent (an observer relays from no one).

WHAT IT IS NOT (the honest-design limit — design.md §2.5.4 "correspondence is not precedence").
The causal graph (causes, §8.2) and parent-by-content-id establish RECORD ORDER within a two-party
construction ("existed no later than"), NOT cross-trust-boundary EVENT PRECEDENCE: each boundary's
observational domain is authoritative only within itself. This disclosure makes the one fact the
object CAN honestly assert explicit (whose domain, first-hand or relayed); it does not establish that
the named boundary is honest. Placing it in the critical cext map is an unrecognized critical
extension -> UnknownCriticalExt (fail-closed); a malformed value in ext is IGNORED, not fatal.

THE PARSE + ACCEPT/REJECT VERDICTS (independent models, from the §2.5.4 text — verdict() + parse()
below). accept for every ext/absent placement; UnknownCriticalExt for a cext placement. A disclosure
is SURFACED (present) iff the ext[15] value is well-formed: a non-empty boundary (key 1), a kind
(key 2) in {1,2}, and reporting-boundary (key 3) absent unless kind = reported. Any malformed value
is surfaced as absent (present = false) and the object still verifies. These verdicts come from this
file, never from the code under test.

NON-CIRCULARITY (project standing rule; F3). This file is written from the §2.5.4 spec text and
shares NO code with impl/go or impl/rust. Object bytes are built by the shared deterministic-CBOR
constructor (cbor_oracle, graded against RFC 8949 §4.2.1 in T1); the content id is the framing
multihash(0x20, SHA-384(body-without-field-1)) (design.md §2.3). The impls build each case as a REAL
signed ML-DSA-65 object and MUST reproduce both the bytes and the verdicts.

Emits vectors/producing_boundary/cases.json (LF-normalized).
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

# The extension key under which the producing-boundary disclosure is carried, in the NON-CRITICAL
# ext map (field 11). 15 is the next free ext/cext key: safety-label is ext key 1 (design.md §6.4),
# recheck is ext/cext key 13 (§2.5.1), signer-counter is ext key 14 (§2.5.2); 15 collides with none.
# Mirrors impl/go + impl/rust + vectors/registry/producing_boundary.csv + the CDDL
# naalp-producing-boundary production (registry_drift gate).
PB_KEY = 15

# Object body field numbers (design.md §2.1); the disclosure rides the ext/cext maps, not a new field.
FIELD_EXT = 11   # non-critical extensions — unknown keys ignored (may-ignore, R-2.5)
FIELD_CEXT = 12  # critical extensions — an unknown key rejects (must-understand, R-2.5)

# The producing-boundary value sub-map keys (design.md §2.5.4).
PB_BOUNDARY = 1   # bstr — the emitting trust boundary (party id)
PB_KIND = 2       # 1 observed / 2 reported
PB_REPORTING = 3  # bstr — report origin; present iff kind = reported

# The closed kind enum (design.md §2.5.4).
OBSERVED = 1
REPORTED = 2

# Worked boundary ids — opaque authority ids in the envelope field-5 (signer) party-id form.
BOUNDARY_X = bytes.fromhex("424f554e444152595f58")  # "BOUNDARY_X"
ORIGIN_Y = bytes.fromhex("4f524947494e5f59")        # "ORIGIN_Y" — a distinct origin boundary


def content_id(body_no_id_pairs):
    """multihash(0x20, SHA-384(canonical-body-without-field-1)) (design.md §2.3)."""
    digest = hashlib.sha384(enc(("map", body_no_id_pairs))).digest()  # 48 bytes
    assert len(digest) == 48
    return b"\x20\x30" + digest


# A fixed base object (a Governance object, channel 0x0004 / kind 2, verifiable by the test's
# acceptKind) over which the ONLY variable is the producing-boundary placement + value, so a
# constant / field-ignoring encoder diverges from the pinned bytes.
BASE = {
    2: 2,                                    # kind
    3: 4,                                    # channel Governance 0x0004
    4: 0,                                    # tier baseline
    5: BOUNDARY_X,                           # signer (opaque bstr; real id is C4/T4)
    6: 1785000000000,                        # created (epoch ms)
    7: 2,                                    # effect non_idempotent_write
    8: [],                                   # causes (empty)
    9: 1,                                    # profile Public
    10: "hello",                             # body (tstr) — the claim the object carries
}


def pb_value(boundary, kind, reporting):
    """The producing-boundary sub-map value (ascending keys). A field is omitted when None, so a
       'malformed' shape (e.g. no boundary) is a real distinct byte string, not a defaulted one."""
    pairs = []
    if boundary is not None:
        pairs.append((PB_BOUNDARY, boundary))
    if kind is not None:
        pairs.append((PB_KIND, kind))
    if reporting is not None:
        pairs.append((PB_REPORTING, reporting))
    return ("map", pairs)


def build_body(placement, boundary, kind, reporting):
    """Return the body-without-field-1 pairs (fields 2..12, ascending) for a placement.
       placement: 'ext' (non-critical, the specified home), 'cext' (critical — an unrecognized
       critical extension), or 'absent'."""
    fields = dict(BASE)
    if placement == "ext":
        fields[FIELD_EXT] = ("map", [(PB_KEY, pb_value(boundary, kind, reporting))])
    elif placement == "cext":
        fields[FIELD_CEXT] = ("map", [(PB_KEY, pb_value(boundary, kind, reporting))])
    elif placement == "absent":
        pass
    else:
        raise ValueError("bad placement: %r" % placement)
    return [(k, fields[k]) for k in sorted(fields)]


def verdict(placement):
    """The independent accept/reject model, read from §2.5.4 + the C3 critical-extension rule.
         - absent / any ext placement (well-formed OR malformed) -> accept (non-critical, may-ignore);
         - the disclosure in cext (critical)                     -> UnknownCriticalExt (fail-closed,
             the disclosure is non-critical; placing it in the critical map is unrecognized)."""
    if placement == "cext":
        return "UnknownCriticalExt"
    return "accept"


def parse(placement, boundary, kind, reporting):
    """The independent PARSE model (from §2.5.4). Returns the SURFACED disclosure or None.
       A disclosure is surfaced only when the ext[15] value is well-formed:
         - key 1 boundary present and non-empty,
         - key 2 kind in {observed, reported},
         - key 3 reporting-boundary absent unless kind = reported.
       cext is rejected before parse; absent carries no disclosure; a malformed ext value -> None
       (may-ignore: the entry is ignored and the object still verifies)."""
    if placement != "ext":
        return None
    if boundary is None or len(boundary) == 0:
        return None
    if kind not in (OBSERVED, REPORTED):
        return None
    if reporting is not None and kind != REPORTED:
        return None
    return {
        "kind": kind,
        "boundary_hex": boundary.hex(),
        "reporting_hex": (reporting.hex() if reporting is not None else None),
    }


def object_case(name, placement, boundary, kind, reporting, note):
    body_no_id = build_body(placement, boundary, kind, reporting)
    cid = content_id(body_no_id)
    full = [(1, cid)] + body_no_id
    surfaced = parse(placement, boundary, kind, reporting)
    return {
        "name": name,
        "note": note,
        "placement": placement,                      # ext | cext | absent
        "boundary_hex": (boundary.hex() if boundary is not None else None),
        "kind": kind,                                # 1 observed / 2 reported / other for malformed
        "reporting_hex": (reporting.hex() if reporting is not None else None),
        "present": surfaced is not None,             # is a well-formed disclosure surfaced?
        "surfaced": surfaced,                        # the parsed disclosure, or null
        "body_no_id_hex": enc(("map", body_no_id)).hex(),
        "content_id_hex": cid.hex(),
        "full_hex": enc(("map", full)).hex(),
        "expect": verdict(placement),
    }


def build_cases():
    cases = [
        # the two well-formed disclosures (the specified home, non-critical ext).
        object_case("observed", "ext", BOUNDARY_X, OBSERVED, None,
                    "ext[15]={1:X,2:observed} first-hand disclosure -> accept, surfaced "
                    "(kind observed, boundary X, no reporting)"),
        object_case("reported_with_origin", "ext", BOUNDARY_X, REPORTED, ORIGIN_Y,
                    "ext[15]={1:X,2:reported,3:Y} relayed disclosure naming origin Y -> accept, "
                    "surfaced (kind reported, boundary X, reporting Y)"),
        object_case("reported_no_origin", "ext", BOUNDARY_X, REPORTED, None,
                    "ext[15]={1:X,2:reported} relayed without disclosing the origin -> accept, "
                    "surfaced (kind reported, boundary X, no reporting): reporting is OPTIONAL"),
        # OPTIONAL: an absent disclosure is valid.
        object_case("absent", "absent", None, None, None,
                    "no ext, no cext: the disclosure is OPTIONAL; its absence is valid -> accept, "
                    "not surfaced"),
        # the STANDARD "unknown critical" wire case: the disclosure placed in the CRITICAL cext map
        # is an unrecognized critical extension (key 15 is non-critical) -> UnknownCriticalExt.
        object_case("cext_producing_boundary_unknown_critical", "cext", BOUNDARY_X, OBSERVED, None,
                    "cext[15]={1:X,2:observed} the disclosure placed in the critical map is an "
                    "unrecognized critical extension (it is non-critical) -> UnknownCriticalExt, "
                    "fail-closed"),
        # malformed ext values: the object VERIFIES (may-ignore) but the disclosure is NOT surfaced.
        object_case("malformed_observed_with_reporting", "ext", BOUNDARY_X, OBSERVED, ORIGIN_Y,
                    "ext[15]={1:X,2:observed,3:Y} a reporting-boundary under observed is malformed "
                    "(an observer relays from no one) -> accept, NOT surfaced (ignored, may-ignore)"),
        object_case("malformed_unknown_kind", "ext", BOUNDARY_X, 9, None,
                    "ext[15]={1:X,2:9} kind outside {observed,reported} is malformed -> accept, "
                    "NOT surfaced (ignored, may-ignore)"),
        object_case("malformed_missing_boundary", "ext", None, OBSERVED, None,
                    "ext[15]={2:observed} no boundary (key 1) is malformed -> accept, NOT surfaced "
                    "(ignored, may-ignore)"),
    ]
    # well-formed disclosures must have DISTINCT content ids from the absent object and each other
    # (isolates the placement/value as the single variable).
    absent = next(c for c in cases if c["name"] == "absent")
    observed = next(c for c in cases if c["name"] == "observed")
    reported = next(c for c in cases if c["name"] == "reported_with_origin")
    assert observed["content_id_hex"] != absent["content_id_hex"], "observed must differ from absent"
    assert observed["content_id_hex"] != reported["content_id_hex"], "observed must differ from reported"
    return cases


def build_negatives():
    """A hand-crafted non-canonical producing-boundary body a strict decoder MUST reject BEFORE any
       disclosure rule runs (design.md §2.6, R-3.1): the ext[15] sub-map with keys {2,1} in
       NON-canonical order (2 before 1). Deterministic CBOR requires map keys ascending by encoded
       bytes, so 1 (0x01) must precede 2 (0x02). Proves the sub-map ordering is caught at the CBOR
       layer (NonCanonical), not silently honored — even though ext is may-ignore."""
    # canonical variant: ext[15] = {1:X, 2:observed} in ascending order.
    canon_body = build_body("ext", BOUNDARY_X, OBSERVED, None)
    cid = content_id(canon_body)
    full_pairs = [(1, cid)] + canon_body
    canonical_full = enc(("map", full_pairs))
    # non-canonical: build the ext[15] inner sub-map by hand with keys 2 then 1 (2 before 1);
    # everything else stays canonical.
    bad_submap = cbor_oracle.enc_head(5, 2) + enc(PB_KIND) + enc(OBSERVED) + enc(PB_BOUNDARY) + enc(BOUNDARY_X)
    ext_map = cbor_oracle.enc_head(5, 1) + enc(PB_KEY) + bad_submap
    out = cbor_oracle.enc_head(5, len(full_pairs))
    for (k, v) in sorted(full_pairs, key=lambda kv: enc(kv[0])):
        out += enc(k)
        out += ext_map if k == FIELD_EXT else enc(v)
    return [{
        "name": "pb_submap_keys_out_of_order",
        "note": "ext[15] sub-map {2:observed,1:X} with keys in NON-canonical order (2 before 1) -> "
                "the decoder rejects NonCanonical before any disclosure rule runs (even though ext "
                "is may-ignore, the codec is strict)",
        "payload_hex": out.hex(),
        "canonical_payload_hex": canonical_full.hex(),
        "expect": "NonCanonical",
    }]


def build():
    return {
        "note": ("Independent oracle for NA-IETF-1 the OPTIONAL producing-boundary disclosure "
                 "(design.md §2.5.4). The disclosure is carried as extension key 15 in the object "
                 "body's NON-CRITICAL ext map (field 11), covered by the SIGNER's COSE_Sign1 "
                 "signature (self-asserted). It names the emitting trust boundary and whether the "
                 "boundary observed the event first-hand (kind 1) or relayed a report (kind 2, with "
                 "an OPTIONAL reporting-boundary naming the origin). It is OPTIONAL (absent -> valid). "
                 "It establishes record-order / observational domain, NOT cross-boundary event "
                 "precedence. Placing it in the critical cext map is an unrecognized critical "
                 "extension -> UnknownCriticalExt; a malformed ext value is IGNORED (may-ignore), not "
                 "rejected. Go and Rust reproduce every body_no_id_hex/content_id_hex/full_hex, every "
                 "accept/reject verdict over REAL ML-DSA-65 signed objects, and every parsed "
                 "disclosure (present/kind/boundary/reporting), so Go==Rust==oracle. Verdicts come "
                 "from the from-scratch verdict()/parse() models in this file, NOT impl/go or "
                 "impl/rust. Generated by tools/producing_boundary_oracle.py; do not hand-edit."),
        "producing_boundary_key": PB_KEY,
        "kind_observed": OBSERVED,
        "kind_reported": REPORTED,
        "reject_error_cext": "UnknownCriticalExt",
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
    out = os.path.normpath(os.path.join(HERE, "..", "vectors", "producing_boundary", "cases.json"))
    os.makedirs(os.path.dirname(out), exist_ok=True)
    # newline="\n" forces LF on every platform (Python text mode would emit CRLF on Windows,
    # diverging the worktree vector from the LF-normalized git blob and breaking a pinned gate).
    with io.open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print("wrote", os.path.relpath(out, os.path.join(HERE, "..")))
    print("  producing_boundary_key =", data["producing_boundary_key"])
    for c in data["cases"]:
        print("  case %-42s [%-6s present=%-5s] -> %s"
              % (c["name"], c["placement"], c["present"], c["expect"]))
    for n in data["negatives"]:
        print("  negative %-30s -> %s" % (n["name"], n["expect"]))


if __name__ == "__main__":
    main()
