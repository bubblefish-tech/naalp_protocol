# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Independent oracle for C15 — multi-hop AGENT delegation (design.md §18; R-DEL-1..8),
a Phase-3 draft-01 addition over the frozen spine. It is the non-circular authority the
two reference implementations (impl/go/delegation, impl/rust/src/delegation.rs) are graded
against: Go == Rust == oracle on every grant byte, AND Go == Rust == oracle on every chain
verdict.

It grades two independent things:

  1. WIRE BYTES (byte-identical Go == Rust == oracle). The DelegationGrant body is the new
     draft-01 production {1:subject, 2:effect_cap, 3:max_depth, 4:not_before, 5:not_after,
     ?6:scope} (design.md §18.5). Each byte vector is built by the shared deterministic-CBOR
     constructor (cbor_oracle, graded against RFC 8949 §4.2.1 in T1); a grant body content id
     is multihash(0x20, SHA-384(body)) — the T1 framing (design §2.3), computed here over the
     FULL grant body (there is no field-1-to-exclude in a body production). scope="" means the
     field is ABSENT (unconstrained), so key 6 is omitted for an empty scope.

  2. CHAIN VERDICTS (Go == Rust == oracle on the algorithm). This file carries a SECOND,
     from-scratch implementation of the D3 12-step leaf->root walk (§18.2) — written directly
     from the design prose, sharing no code with impl/go or impl/rust — plus the D2 scope
     containment rule and the D4 depth attenuation. It runs that model over a set of logical
     chain scenarios and emits the expected verdict for each. The two reference impls build
     the SAME logical scenario as a REAL signed COSE_Sign1 grant chain (real ML-DSA-65 keys,
     real envelope content ids wired into `causes`) and must reproduce the verdict. Three
     independent implementations of D3 (this oracle + Go + Rust) agreeing over the 6 named
     chain errors + attenuation + depth + window + revocation + root-trust is the F3
     non-circular conformance guarantee. (Object/grant SIGNATURES are not modelled here —
     Python has no ML-DSA — they are graded by the deterministic-signature byte parity the
     cose layer already establishes; the chain WALK is what this file grades.)

Emits vectors/delegation/cases.json (LF-normalized).
"""
import hashlib
import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cbor_oracle  # shared RFC-8949 deterministic-CBOR constructor (graded in T1)

# Effect lattice (design.md §6.1): read_only < idempotent_write < non_idempotent_write < destructive.
READ_ONLY, IDEMPOTENT_WRITE, NON_IDEMPOTENT_WRITE, DESTRUCTIVE = 0, 1, 2, 3
EFFECT_NAME = {0: "read_only", 1: "idempotent_write", 2: "non_idempotent_write", 3: "destructive"}


# ---- 1. wire bytes: the DelegationGrant body + its content id --------------------------------

def grant_body(subject, effect_cap, max_depth, not_before, not_after, scope=None):
    """Deterministic CBOR of a naalp-delegation-grant body (design.md §18.5):
       {1:subject, 2:effect_cap, 3:max_depth, 4:not_before, 5:not_after, ?6:scope}.
       scope=None or "" omits field 6 (an absent scope is unconstrained)."""
    pairs = [
        (1, subject),
        (2, effect_cap),
        (3, max_depth),
        (4, not_before),
        (5, not_after),
    ]
    if scope:  # non-empty scope only; "" / None => field 6 absent (unconstrained)
        pairs.append((6, scope))
    return cbor_oracle.encode(("map", pairs))


def cid(body):
    """Grant-body content id (T1 framing): multihash(0x20, SHA-384(body))."""
    return b"\x20\x30" + hashlib.sha384(body).digest()


def build_grant_vectors():
    # Representative grant bodies varying every field, so a constant/field-ignoring encoder
    # in either impl diverges from the pinned hex (mutation-surviving byte grading).
    specs = [
        # name,            subject,     eff, depth, nb,     na,               scope
        ("full_scope",     "agent:b",   NON_IDEMPOTENT_WRITE, 2, 1000, 2000,            "billing/reports"),
        ("no_scope",       "agent:m",   DESTRUCTIVE,          1, 0,    9999999999999,   None),
        ("read_only_leaf", "reader",    READ_ONLY,            0, 100,  200,             "docs"),
        ("deep_root",      "ops",       DESTRUCTIVE,          5, 1,    2,               None),
        ("unicode_scope",  "délégué",   IDEMPOTENT_WRITE,     3, 42,   43,              "café/notes"),
    ]
    out = []
    for name, subject, eff, depth, nb, na, scope in specs:
        body = grant_body(subject, eff, depth, nb, na, scope)
        out.append({
            "name": name,
            "subject": subject,
            "effect_cap": eff,
            "effect_cap_name": EFFECT_NAME[eff],
            "max_depth": depth,
            "not_before": nb,
            "not_after": na,
            "scope": scope if scope else "",  # "" == absent (field 6 omitted)
            "has_scope": bool(scope),
            "body_hex": body.hex(),
            "content_id_hex": cid(body).hex(),
        })
    return out


# ---- 2. the D2 scope-containment rule (independent) ------------------------------------------

def scope_contained(child, parent):
    """S_child is contained in S_parent iff (design.md §18.1 D2, §18.2 step 6):
         - S_parent is absent (""): unconstrained -> any child (incl. "") is contained; OR
         - S_child == S_parent; OR
         - S_child begins with S_parent + "/".
       A missing child scope ("") under a scoped parent WIDENS authority -> NOT contained."""
    if parent == "":
        return True
    if child == "":
        return False
    if child == parent:
        return True
    return child.startswith(parent + "/")


def build_scope_table():
    # (child, parent) -> contained. Both allows and denies, so a constant scope predicate fails.
    pairs = [
        ("billing/reports", "billing",          True),   # strict prefix on a boundary
        ("billing",         "billing",          True),   # equal
        ("billing",         "",                 True),   # unconstrained parent
        ("",                "",                 True),   # both unconstrained
        ("billingreports",  "billing",          False),  # prefix but NOT on a "/" boundary
        ("",                "billing",          False),  # missing child under a scoped parent
        ("billing/a/b",     "billing/a",        True),   # deep prefix
        ("other",           "billing",          False),  # disjoint
        ("café/notes",      "café",             True),   # NFC unicode prefix
    ]
    return [{"child": c, "parent": p, "contained": r} for (c, p, r) in pairs]


# ---- 3. the D3 chain-verification model (independent, from design.md §18.2) ------------------

def _resolve(cands):
    """0 candidates -> None; 1 -> that index; >1 -> "AMBIGUOUS"."""
    if len(cands) == 0:
        return None
    if len(cands) > 1:
        return "AMBIGUOUS"
    return cands[0]


def verify_chain(grants, action, anchors, revoked, now):
    """From-scratch D3 (design.md §18.2). `grants` is a list of logical grant dicts each with
    issuer/subject (labels) + effect_cap/max_depth/not_before/not_after/scope + causes (indices
    wired as envelope `causes`). Returns "authorized" or the named error a fail-closed verifier
    returns. Parent resolution mirrors the wire (a cause resolves to a parent iff that grant's
    subject == this grant's issuer), computed independently here."""
    # step 2 — locate the unique leaf grant among the action's causes whose subject == B.
    leaf_cands = [j for j in action["causes"] if grants[j]["subject"] == action["signer"]]
    r = _resolve(leaf_cands)
    if r is None:
        return "EffectNotAuthorized"   # no delegation authorizes this action (existing error)
    if r == "AMBIGUOUS":
        return "ChainBroken"           # two authorizing grants -> ambiguous (step 2)
    gi = r
    child_effect = action["effect"]
    child_scope = action["scope"]
    pos = 0                            # realized delegation hops beneath the current grant
    visited = set()
    while True:
        if gi in visited:              # a content-id cycle (infeasible for a real hash chain)
            return "ChainBroken"
        visited.add(gi)
        g = grants[gi]
        # step 3 (integrity: signature + content-id pointer) is graded by real crypto in Go/Rust.
        # step 4 — validity window at `now` (the action's authoritative ordering position).
        if now < g["not_before"]:
            return "GrantNotYetValid"
        if now > g["not_after"]:
            return "GrantExpired"
        # step 5 — revocation at `now`.
        if gi in revoked and revoked[gi] <= now:
            return "GrantRevoked"
        # step 6 — attenuation: child effect + scope may not exceed this grant.
        if child_effect > g["effect_cap"]:
            return "CapExceedsParent"
        if not scope_contained(child_scope, g["scope"]):
            return "CapExceedsParent"
        # step 9 — realized-depth bound: `pos` grants sit beneath G, so pos <= G.max_depth.
        if pos > g["max_depth"]:
            return "DelegationDepthExceeded"
        # step 7 — resolve G's delegation parent (unique cause whose subject == G's issuer).
        parent_cands = [j for j in g["causes"] if grants[j]["subject"] == g["issuer"]]
        pr = _resolve(parent_cands)
        if pr == "AMBIGUOUS":
            return "ChainBroken"
        if pr is None:
            # step 10 / 11 — root test: G has no parent.
            if g["issuer"] in anchors:
                return "authorized"    # terminated at a trusted root (steps 10, 12)
            return "UntrustedChainRoot"
        p = grants[pr]
        # step 8 — declared depth attenuation: G.max_depth <= P.max_depth - 1
        #   (a parent with max_depth 0 admits no child grant; no unsigned underflow).
        if p["max_depth"] == 0 or g["max_depth"] >= p["max_depth"]:
            return "DelegationDepthExceeded"
        child_effect = g["effect_cap"]
        child_scope = g["scope"]
        gi = pr
        pos += 1


def build_scenarios():
    """Logical chain scenarios + the independently-computed expected verdict. Each grant carries
    issuer/subject as SEED LABELS; the impls map each label to a deterministic ML-DSA-65 key ->
    real signer id, sign each grant by its issuer, wire the parent's real envelope content id into
    `causes`, and run the real verifier. The verdict here (from the model above) is the oracle."""
    scenarios = []

    def add(name, grants, action, anchors, revoked=None, now=500, note=""):
        revoked = revoked or {}
        verdict = verify_chain(grants, action, set(anchors), revoked, now)
        scenarios.append({
            "name": name,
            "note": note,
            "grants": grants,
            "action": action,
            "anchors": anchors,
            "revoked": [{"grant": gi, "pos": p} for gi, p in sorted(revoked.items())],
            "now": now,
            "expect": verdict,
        })

    W = {"not_before": 100, "not_after": 900}  # an open window at now=500

    # 1 — a direct 1-hop grant issued by the trust anchor A to the actor B.
    add("valid_1hop",
        [{"issuer": "A", "subject": "B", "effect_cap": NON_IDEMPOTENT_WRITE, "max_depth": 0, "scope": "", "causes": [], **W}],
        {"signer": "B", "effect": NON_IDEMPOTENT_WRITE, "scope": "", "causes": [0]},
        ["A"], note="A->B, A trusted, in-window; the minimal valid chain.")

    # 2 — a 2-hop chain A -> M -> B.
    g2 = [
        {"issuer": "A", "subject": "M", "effect_cap": NON_IDEMPOTENT_WRITE, "max_depth": 2, "scope": "", "causes": [], **W},
        {"issuer": "M", "subject": "B", "effect_cap": NON_IDEMPOTENT_WRITE, "max_depth": 1, "scope": "", "causes": [0], **W},
    ]
    add("valid_2hop", g2, {"signer": "B", "effect": NON_IDEMPOTENT_WRITE, "scope": "", "causes": [1]}, ["A"],
        note="A->M->B, effects equal, depths attenuating (2 then 1); authorized.")

    # 3 — a 3-hop chain A -> M1 -> M2 -> B, effects attenuating destructive>niw>iw>ro isn't needed; keep equal.
    g3 = [
        {"issuer": "A",  "subject": "M1", "effect_cap": DESTRUCTIVE,          "max_depth": 3, "scope": "", "causes": [], **W},
        {"issuer": "M1", "subject": "M2", "effect_cap": NON_IDEMPOTENT_WRITE, "max_depth": 2, "scope": "", "causes": [0], **W},
        {"issuer": "M2", "subject": "B",  "effect_cap": IDEMPOTENT_WRITE,     "max_depth": 1, "scope": "", "causes": [1], **W},
    ]
    add("valid_3hop", g3, {"signer": "B", "effect": IDEMPOTENT_WRITE, "scope": "", "causes": [2]}, ["A"],
        note="A->M1->M2->B, effect attenuates de>niw>iw, depth 3->2->1; authorized.")

    # 4 — the root is not in the trust-anchor set.
    add("untrusted_root", [dict(g) for g in g2], {"signer": "B", "effect": NON_IDEMPOTENT_WRITE, "scope": "", "causes": [1]},
        ["X"], note="A->M->B but only X is trusted; the root A is untrusted -> UntrustedChainRoot.")

    # 5 — the leaf grant is expired at now.
    exp = [
        {"issuer": "A", "subject": "M", "effect_cap": NON_IDEMPOTENT_WRITE, "max_depth": 2, "scope": "", "causes": [], **W},
        {"issuer": "M", "subject": "B", "effect_cap": NON_IDEMPOTENT_WRITE, "max_depth": 1, "scope": "", "causes": [0],
         "not_before": 100, "not_after": 400},  # expired at now=500
    ]
    add("leaf_expired", exp, {"signer": "B", "effect": NON_IDEMPOTENT_WRITE, "scope": "", "causes": [1]}, ["A"],
        note="leaf not_after=400 < now=500 -> GrantExpired.")

    # 6 — a mid grant is not yet valid at now.
    nyv = [
        {"issuer": "A", "subject": "M", "effect_cap": NON_IDEMPOTENT_WRITE, "max_depth": 2, "scope": "",
         "causes": [], "not_before": 600, "not_after": 900},  # not valid until 600
        {"issuer": "M", "subject": "B", "effect_cap": NON_IDEMPOTENT_WRITE, "max_depth": 1, "scope": "", "causes": [0], **W},
    ]
    add("mid_not_yet_valid", nyv, {"signer": "B", "effect": NON_IDEMPOTENT_WRITE, "scope": "", "causes": [1]}, ["A"],
        note="parent grant not_before=600 > now=500 -> GrantNotYetValid.")

    # 7 — the leaf grant is revoked at or before now.
    add("leaf_revoked", [dict(g) for g in g2], {"signer": "B", "effect": NON_IDEMPOTENT_WRITE, "scope": "", "causes": [1]},
        ["A"], revoked={1: 300}, note="leaf grant revoked at pos 300 <= now 500 -> GrantRevoked.")

    # 8 — the root grant is revoked.
    add("root_revoked", [dict(g) for g in g2], {"signer": "B", "effect": NON_IDEMPOTENT_WRITE, "scope": "", "causes": [1]},
        ["A"], revoked={0: 500}, note="root grant revoked at pos 500 == now 500 (inclusive) -> GrantRevoked.")

    # 9 — the action's effect exceeds the leaf grant's effect_cap.
    add("effect_exceeds_leaf",
        [
            {"issuer": "A", "subject": "M", "effect_cap": NON_IDEMPOTENT_WRITE, "max_depth": 2, "scope": "", "causes": [], **W},
            {"issuer": "M", "subject": "B", "effect_cap": NON_IDEMPOTENT_WRITE, "max_depth": 1, "scope": "", "causes": [0], **W},
        ],
        {"signer": "B", "effect": DESTRUCTIVE, "scope": "", "causes": [1]}, ["A"],
        note="action effect=destructive > leaf effect_cap=non_idempotent_write -> CapExceedsParent.")

    # 10 — a mid grant conveys MORE effect than its parent (attenuation across a grant edge).
    add("grant_effect_exceeds_parent",
        [
            {"issuer": "A", "subject": "M", "effect_cap": IDEMPOTENT_WRITE,     "max_depth": 2, "scope": "", "causes": [], **W},
            {"issuer": "M", "subject": "B", "effect_cap": NON_IDEMPOTENT_WRITE, "max_depth": 1, "scope": "", "causes": [0], **W},
        ],
        {"signer": "B", "effect": IDEMPOTENT_WRITE, "scope": "", "causes": [1]}, ["A"],
        note="leaf effect_cap=niw exceeds parent effect_cap=iw -> CapExceedsParent (across the grant edge).")

    # 11 — the leaf scope is not contained in the parent's scope.
    add("scope_not_contained",
        [
            {"issuer": "A", "subject": "M", "effect_cap": NON_IDEMPOTENT_WRITE, "max_depth": 2, "scope": "billing", "causes": [], **W},
            {"issuer": "M", "subject": "B", "effect_cap": NON_IDEMPOTENT_WRITE, "max_depth": 1, "scope": "payroll", "causes": [0], **W},
        ],
        {"signer": "B", "effect": NON_IDEMPOTENT_WRITE, "scope": "payroll", "causes": [1]}, ["A"],
        note="leaf scope 'payroll' not contained in parent scope 'billing' -> CapExceedsParent.")

    # 12 — a scoped parent with a missing (unconstrained) child scope widens authority.
    add("missing_child_scope",
        [
            {"issuer": "A", "subject": "M", "effect_cap": NON_IDEMPOTENT_WRITE, "max_depth": 2, "scope": "billing", "causes": [], **W},
            {"issuer": "M", "subject": "B", "effect_cap": NON_IDEMPOTENT_WRITE, "max_depth": 1, "scope": "", "causes": [0], **W},
        ],
        {"signer": "B", "effect": NON_IDEMPOTENT_WRITE, "scope": "billing/reports", "causes": [1]}, ["A"],
        note="child grant has no scope under a scoped parent 'billing' -> widens -> CapExceedsParent.")

    # 13 — declared depth attenuation: a parent with max_depth 0 admits no child grant.
    add("depth_declared_exceeded",
        [
            {"issuer": "A", "subject": "M", "effect_cap": NON_IDEMPOTENT_WRITE, "max_depth": 0, "scope": "", "causes": [], **W},
            {"issuer": "M", "subject": "B", "effect_cap": NON_IDEMPOTENT_WRITE, "max_depth": 0, "scope": "", "causes": [0], **W},
        ],
        {"signer": "B", "effect": NON_IDEMPOTENT_WRITE, "scope": "", "causes": [1]}, ["A"],
        note="parent max_depth=0 but a child grant exists -> DelegationDepthExceeded (step 8).")

    # 14 — boundary: root max_depth exactly admits the one hop below it.
    add("depth_boundary_ok",
        [
            {"issuer": "A", "subject": "M", "effect_cap": NON_IDEMPOTENT_WRITE, "max_depth": 1, "scope": "", "causes": [], **W},
            {"issuer": "M", "subject": "B", "effect_cap": NON_IDEMPOTENT_WRITE, "max_depth": 0, "scope": "", "causes": [0], **W},
        ],
        {"signer": "B", "effect": NON_IDEMPOTENT_WRITE, "scope": "", "causes": [1]}, ["A"],
        note="root max_depth=1 admits exactly one further hop (leaf max_depth=0, acts); authorized boundary.")

    # 15 — no grant in the action's causes authorizes B.
    add("no_grant_for_B",
        [{"issuer": "A", "subject": "someone-else", "effect_cap": NON_IDEMPOTENT_WRITE, "max_depth": 1, "scope": "", "causes": [], **W}],
        {"signer": "B", "effect": NON_IDEMPOTENT_WRITE, "scope": "", "causes": [0]}, ["A"],
        note="the only grant in causes delegates to someone-else, not B -> EffectNotAuthorized.")

    # 16 — two grants in the action's causes both delegate to B (ambiguous leaf).
    add("ambiguous_leaf",
        [
            {"issuer": "A", "subject": "B", "effect_cap": NON_IDEMPOTENT_WRITE, "max_depth": 0, "scope": "", "causes": [], **W},
            {"issuer": "A", "subject": "B", "effect_cap": DESTRUCTIVE,          "max_depth": 0, "scope": "", "causes": [], **W},
        ],
        {"signer": "B", "effect": NON_IDEMPOTENT_WRITE, "scope": "", "causes": [0, 1]}, ["A"],
        note="two distinct grants both name subject=B in the action's causes -> ChainBroken (step 2).")

    # 17 — a grant whose causes resolve to two parents (both delegate to M): ambiguous parent.
    add("ambiguous_parent",
        [
            {"issuer": "A", "subject": "M", "effect_cap": DESTRUCTIVE,          "max_depth": 3, "scope": "", "causes": [], **W},
            {"issuer": "A", "subject": "M", "effect_cap": DESTRUCTIVE,          "max_depth": 3, "scope": "billing", "causes": [], **W},
            {"issuer": "M", "subject": "B", "effect_cap": NON_IDEMPOTENT_WRITE, "max_depth": 1, "scope": "", "causes": [0, 1], **W},
        ],
        {"signer": "B", "effect": NON_IDEMPOTENT_WRITE, "scope": "", "causes": [2]}, ["A"],
        note="the leaf grant names two causes both delegating to its issuer M -> ChainBroken (step 7).")

    # 18 — a valid scoped chain where the leaf scope is a strict prefix child of the root scope.
    add("valid_scope_prefix",
        [
            {"issuer": "A", "subject": "M", "effect_cap": NON_IDEMPOTENT_WRITE, "max_depth": 2, "scope": "billing", "causes": [], **W},
            {"issuer": "M", "subject": "B", "effect_cap": NON_IDEMPOTENT_WRITE, "max_depth": 1, "scope": "billing/reports", "causes": [0], **W},
        ],
        {"signer": "B", "effect": NON_IDEMPOTENT_WRITE, "scope": "billing/reports/q3", "causes": [1]}, ["A"],
        note="scopes nest billing >= billing/reports >= billing/reports/q3; authorized.")

    return scenarios


def build():
    return {
        "note": ("Independent oracle for C15 multi-hop agent delegation (design.md §18; R-DEL-1..8). "
                 "grant body {1:subject,2:effect_cap,3:max_depth,4:not_before,5:not_after,?6:scope}; "
                 "content id = multihash(0x20, SHA-384(body)); scope='' => field 6 absent (unconstrained). "
                 "The chain verdicts come from a from-scratch D3 (design §18.2) model in this file, NOT "
                 "from impl/go or impl/rust. Go and Rust reproduce every grant byte AND every verdict "
                 "(with real ML-DSA-65 signed chains), so Go==Rust==oracle. Do not hand-edit."),
        "effects": [{"value": v, "name": n} for v, n in EFFECT_NAME.items()],
        "grants": build_grant_vectors(),
        "scope_containment": build_scope_table(),
        "scenarios": build_scenarios(),
    }


def main():
    data = build()
    out = os.path.normpath(os.path.join(HERE, "..", "vectors", "delegation", "cases.json"))
    os.makedirs(os.path.dirname(out), exist_ok=True)
    # newline="\n" forces LF on every platform (Python text mode would emit CRLF on Windows,
    # diverging the worktree vector from the LF-normalized git blob and breaking a pinned gate).
    with io.open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print("wrote", os.path.relpath(out, os.path.join(HERE, "..")))
    for g in data["grants"]:
        print("  grant %-14s body %3dB  id=%s..." % (g["name"], len(g["body_hex"]) // 2, g["content_id_hex"][:16]))
    for s in data["scenarios"]:
        print("  scenario %-26s -> %s" % (s["name"], s["expect"]))


if __name__ == "__main__":
    main()
