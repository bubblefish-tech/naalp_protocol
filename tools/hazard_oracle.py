# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Independent oracle for Manufacturing Add-ons Component F -- the physical-hazard
authorization extension (design.md addendum,
the hazard design addendum; requirements F1-F5; wire
authority spec/naalp-draft-01.cddl, the frozen MANUFACTURING PHYSICAL-HAZARD productions
+ cext key 16 + Governance kind 7). FROZEN 2026-09-01 (Shawn-approved wire bytes): the
naalp-hazard-claim / naalp-hazard-authorization productions are merged into the normative
CDDL; this oracle grades impl/rust/naalp-hazard against the frozen vectors/hazard corpus
(non-circular, F3), independent of the crate it grades.

It grades three independent things, written from scratch against spec/hazard.cddl and
the design addendum -- sharing no code with impl/rust/naalp-hazard/src/lib.rs -- so a
defect shared between the oracle and the crate cannot hide behind agreement (F3):

  1. FAIL-CLOSED CLASS DECODE (F2). hazard-class is a closed 0..4 enum; an absent or
     unrecognized raw code normalizes to the highest class (4,
     motion-in-shared-space), never to a weaker one.

  2. WIRE BYTES (byte-identical against naalp-hazard). naalp-hazard-claim and
     naalp-hazard-authorization share one shape {1:class,2:envelope}; envelope is
     {1:spatial-bounds,2:speed_bound_mm_s,3:hazard-window}; spatial-bounds is
     {1:frame,2:axes}; hazard-window is {1:not_before,2:not_after}. Every field is
     1-based (a deliberate departure from the 0-based OneDrive source-triple sketch,
     recorded in spec/hazard.cddl's header comment) and every numeric bound is a
     signed/unsigned CBOR integer (a deliberate departure from the sketch's `float`,
     since naalp's own CBOR subset carries no floats). Built with the SAME shared
     deterministic-CBOR constructor (cbor_oracle, graded in T1 against RFC 8949
     Section 4.2.1) every other N-AALP oracle uses, so a shared codec defect is not
     masked as agreement between this file and the Rust codec it independently mirrors.

  3. GRANT-COVERAGE VERDICTS (F3). A from-scratch containment check -- exact class
     match plus full envelope containment (same frame, same axis count and order,
     every claim axis inside the matching grant axis, claim speed <= grant speed,
     claim window a sub-interval of the grant window) -- run over a matrix that
     includes one vector per hazard class (F4), one absent-hazard fail-closed vector,
     and one unknown-hazard fail-closed vector, plus dedicated single-dimension
     denial cases (frame, axis, speed, window, axis-count) so a constant-Ok or
     constant-Err coverage function fails half the matrix (mutation-surviving).

Emits vectors/hazard/cases.json (LF-normalized).
"""
import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cbor_oracle  # shared RFC-8949 deterministic-CBOR constructor (graded in T1)

CLASS_NAME = {
    0: "none",
    1: "tool_actuation",
    2: "thermal",
    3: "energy_release",
    4: "motion_in_shared_space",
}
FAIL_CLOSED_CLASS = 4  # motion_in_shared_space -- F2's fail-closed default


# ---- 1. fail-closed class decode (F2) ---------------------------------------------

def from_code(code):
    """code is an int 0..4, or None for "absent". Any other value (out of range) is
    "unrecognized". Both absent and unrecognized normalize to FAIL_CLOSED_CLASS."""
    if code is None:
        return FAIL_CLOSED_CLASS
    if isinstance(code, int) and 0 <= code <= 4:
        return code
    return FAIL_CLOSED_CLASS


def build_from_code_vectors():
    cases = [None, 0, 1, 2, 3, 4, 5, 9, 99, 2**32, 2**63]
    out = []
    for code in cases:
        cls = from_code(code)
        # A code exceeding JS's 2^53 safe-integer range is emitted as a STRING so a
        # float64-based JSON decoder (JS Number, Go interface{}) cannot silently round
        # it before a port's own from_code runs. Small codes stay ints (a stringified
        # "0" would mis-normalize to the fail-closed class). [conformance-vector, 2026-07-16]
        code_out = str(code) if isinstance(code, int) and code > 2**53 else code
        out.append({"code": code_out, "class": cls, "class_name": CLASS_NAME[cls]})
    return out


# ---- 2. wire bytes: naalp-hazard-claim / naalp-hazard-authorization ----------------

def spatial_bounds_value(frame, axes):
    """{1:frame(tstr), 2:axes([+[min,max]])} -- axes is a list of (min,max) int pairs."""
    return ("map", [
        (1, frame),
        (2, [[a[0], a[1]] for a in axes]),
    ])


def hazard_window_value(not_before, not_after):
    """{1:not_before(uint), 2:not_after(uint)}."""
    return ("map", [(1, not_before), (2, not_after)])


def hazard_envelope_value(frame, axes, speed_bound_mm_s, not_before, not_after):
    """{1:spatial-bounds, 2:speed_bound_mm_s(uint), 3:hazard-window}."""
    return ("map", [
        (1, spatial_bounds_value(frame, axes)),
        (2, speed_bound_mm_s),
        (3, hazard_window_value(not_before, not_after)),
    ])


def hazard_body_value(cls, frame, axes, speed_bound_mm_s, not_before, not_after):
    """{1:class(uint 0..4), 2:envelope} -- the shared naalp-hazard-claim /
    naalp-hazard-authorization shape (spec/hazard.cddl)."""
    return ("map", [
        (1, cls),
        (2, hazard_envelope_value(frame, axes, speed_bound_mm_s, not_before, not_after)),
    ])


def build_body_vectors():
    # Representative bodies varying every field, so a constant/field-ignoring encoder
    # diverges from the pinned hex (mutation-surviving byte grading). One per hazard
    # class (F4) plus a signed-axis and a large-uint case to exercise both CBOR
    # integer major types.
    specs = [
        ("class0_none", 0, "cell-1/world", [(0, 100), (0, 100), (0, 50)], 0, 0, 1000),
        ("class1_tool", 1, "cell-2/world", [(-50, 50), (-50, 50), (0, 200)], 250, 100, 2000),
        ("class2_thermal", 2, "cell-3/world", [(0, 1000), (0, 1000), (0, 1000)], 0, 0, 3_600_000),
        ("class3_energy", 3, "cell-4/world", [(-1000, 1000)], 1500, 0, 999_999_999),
        ("class4_motion", 4, "cell-5/world", [(-2000, 2000), (-2000, 2000), (0, 3000)], 4000, 500, 987_654_321_000),
        ("unicode_frame", 1, "cellule-café/monde", [(0, 10)], 10, 0, 10),
        ("negative_only_axis", 2, "cell-6/world", [(-500, -100)], 5, 0, 1),
    ]
    out = []
    for name, cls, frame, axes, speed, nb, na in specs:
        body = hazard_body_value(cls, frame, axes, speed, nb, na)
        b = cbor_oracle.encode(body)
        # Content id: T1 framing over the FULL body (no field-1-to-exclude here -- this
        # is a body production, not a naalp-object envelope; matches
        # naalp::cbor::content_id's contract of "the value passed in, digested whole").
        import hashlib
        digest = hashlib.sha384(b).digest()
        cid = b"\x20\x30" + digest
        out.append({
            "name": name,
            "class": cls,
            "class_name": CLASS_NAME[cls],
            "frame": frame,
            "axes": [[a[0], a[1]] for a in axes],
            "speed_bound_mm_s": speed,
            "not_before": nb,
            "not_after": na,
            "body_hex": cbor_oracle.hx(b),
            "content_id_hex": cbor_oracle.hx(cid),
        })
    return out


# ---- 3. grant-coverage verdicts (F3, from-scratch containment) --------------------

def spatial_contained(claim, grant):
    if claim["frame"] != grant["frame"]:
        return False
    ca, ga = claim["axes"], grant["axes"]
    if len(ca) != len(ga):
        return False
    for (cmin, cmax), (gmin, gmax) in zip(ca, ga):
        if cmin < gmin or cmax > gmax:
            return False
    return True


def envelope_contained(claim, grant):
    return (
        spatial_contained(claim, grant)
        and claim["speed_bound_mm_s"] <= grant["speed_bound_mm_s"]
        and grant["not_before"] <= claim["not_before"]
        and claim["not_after"] <= grant["not_after"]
    )


def hazard_authorized(claim_class, claim_env, grant_class, grant_env):
    """F3: exact class match AND full envelope containment. Any single failing
    dimension denies the whole claim -- no partial authorization."""
    if claim_class != grant_class:
        return False
    return envelope_contained(claim_env, grant_env)


def env(frame, axes, speed, nb, na):
    return {"frame": frame, "axes": [list(a) for a in axes], "speed_bound_mm_s": speed, "not_before": nb, "not_after": na}


def build_coverage_vectors():
    full_grant_env = env("cell-9/world", [(-1000, 1000), (-1000, 1000), (0, 2000)], 1000, 0, 10_000_000)
    contained_claim_env = env("cell-9/world", [(-500, 500), (-500, 500), (100, 1900)], 500, 100, 9_000_000)
    exact_edges_env = env("cell-9/world", [(-1000, 1000), (-1000, 1000), (0, 2000)], 1000, 0, 10_000_000)

    rows = []

    # F4: one vector per hazard class, fully covered by a same-class grant.
    for cls in range(5):
        rows.append({
            "name": "class%d_%s_authorized" % (cls, CLASS_NAME[cls]),
            "claim_class_code": cls,
            "grant_class_code": cls,
            "claim_envelope": contained_claim_env,
            "grant_envelope": full_grant_env,
            "authorized": hazard_authorized(from_code(cls), contained_claim_env, from_code(cls), full_grant_env),
        })

    # F4: absent-hazard fail-closed vector (claim class code is None -> normalizes to
    # 4; grant is class 1 -> class mismatch -> denied).
    rows.append({
        "name": "absent_fail_closed",
        "claim_class_code": None,
        "grant_class_code": 1,
        "claim_envelope": contained_claim_env,
        "grant_envelope": full_grant_env,
        "authorized": hazard_authorized(from_code(None), contained_claim_env, from_code(1), full_grant_env),
    })

    # F4: unknown-hazard fail-closed vector (claim class code is 9, out of range ->
    # normalizes to 4; grant is class 1 -> denied).
    rows.append({
        "name": "unknown_fail_closed",
        "claim_class_code": 9,
        "grant_class_code": 1,
        "claim_envelope": contained_claim_env,
        "grant_envelope": full_grant_env,
        "authorized": hazard_authorized(from_code(9), contained_claim_env, from_code(1), full_grant_env),
    })

    # Exact edges (closed interval) -- authorized (not an off-by-one denial).
    rows.append({
        "name": "exact_edges_authorized",
        "claim_class_code": 4,
        "grant_class_code": 4,
        "claim_envelope": exact_edges_env,
        "grant_envelope": full_grant_env,
        "authorized": hazard_authorized(from_code(4), exact_edges_env, from_code(4), full_grant_env),
    })

    # Single-dimension denials: each row is otherwise fully covered so it isolates
    # exactly one failing dimension (mutation-surviving: a coverage function that
    # ignores any one dimension passes this row incorrectly).
    frame_mismatch = dict(contained_claim_env)
    frame_mismatch["frame"] = "cell-9/OTHER-FRAME"
    rows.append({
        "name": "frame_mismatch_denied",
        "claim_class_code": 2, "grant_class_code": 2,
        "claim_envelope": frame_mismatch, "grant_envelope": full_grant_env,
        "authorized": hazard_authorized(from_code(2), frame_mismatch, from_code(2), full_grant_env),
    })

    axis_outside = env("cell-9/world", [(-1000, 1000), (-1000, 1000), (0, 2001)], 500, 100, 9_000_000)
    rows.append({
        "name": "spatial_axis_outside_denied",
        "claim_class_code": 3, "grant_class_code": 3,
        "claim_envelope": axis_outside, "grant_envelope": full_grant_env,
        "authorized": hazard_authorized(from_code(3), axis_outside, from_code(3), full_grant_env),
    })

    axis_count_mismatch = env("cell-9/world", [(-500, 500), (-500, 500)], 500, 100, 9_000_000)
    rows.append({
        "name": "axis_count_mismatch_denied",
        "claim_class_code": 1, "grant_class_code": 1,
        "claim_envelope": axis_count_mismatch, "grant_envelope": full_grant_env,
        "authorized": hazard_authorized(from_code(1), axis_count_mismatch, from_code(1), full_grant_env),
    })

    speed_exceeds = env("cell-9/world", [(-500, 500), (-500, 500), (100, 1900)], 1001, 100, 9_000_000)
    rows.append({
        "name": "speed_exceeds_denied",
        "claim_class_code": 4, "grant_class_code": 4,
        "claim_envelope": speed_exceeds, "grant_envelope": full_grant_env,
        "authorized": hazard_authorized(from_code(4), speed_exceeds, from_code(4), full_grant_env),
    })

    # not_after past the grant's own not_after (10_000_000) -- window not contained.
    window_ends_late = env("cell-9/world", [(-500, 500), (-500, 500), (100, 1900)], 500, 100, 10_000_001)
    rows.append({
        "name": "window_ends_after_grant_denied",
        "claim_class_code": 2, "grant_class_code": 2,
        "claim_envelope": window_ends_late, "grant_envelope": full_grant_env,
        "authorized": hazard_authorized(from_code(2), window_ends_late, from_code(2), full_grant_env),
    })

    narrow_grant = env("cell-9/world", [(-1000, 1000), (-1000, 1000), (500, 2000)], 1000, 500, 10_000_000)
    window_starts_before_grant = env("cell-9/world", [(-500, 500), (-500, 500), (600, 1900)], 500, 400, 9_000_000)
    rows.append({
        "name": "window_starts_before_grant_denied",
        "claim_class_code": 1, "grant_class_code": 1,
        "claim_envelope": window_starts_before_grant, "grant_envelope": narrow_grant,
        "authorized": hazard_authorized(from_code(1), window_starts_before_grant, from_code(1), narrow_grant),
    })

    class_mismatch = dict(contained_claim_env)
    rows.append({
        "name": "class_mismatch_denied",
        "claim_class_code": 1, "grant_class_code": 2,
        "claim_envelope": class_mismatch, "grant_envelope": full_grant_env,
        "authorized": hazard_authorized(from_code(1), class_mismatch, from_code(2), full_grant_env),
    })

    return rows


def build():
    return {
        "from_code": build_from_code_vectors(),
        "bodies": build_body_vectors(),
        "coverage": build_coverage_vectors(),
    }


def main():
    out_dir = os.path.join(HERE, "..", "vectors", "hazard")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "cases.json")
    data = build()
    buf = io.StringIO()
    json.dump(data, buf, indent=2, sort_keys=False)
    text = buf.getvalue().replace("\r\n", "\n")
    if not text.endswith("\n"):
        text += "\n"
    with open(out_path, "w", newline="\n", encoding="utf-8") as f:
        f.write(text)
    print("wrote %s (%d from_code, %d bodies, %d coverage rows)" % (
        out_path, len(data["from_code"]), len(data["bodies"]), len(data["coverage"])
    ))


if __name__ == "__main__":
    main()
