# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Independent oracle for the NAALP-MCP binding profile (design.md §19;
Companion-Spec Program Requirement 6.1). It is the non-circular authority the two reference implementations (impl/go/mcp,
impl/rust/src/mcp.rs) are graded against: Go == Rust == oracle on every wrapper byte, every
annotation->effect mapping, every more-severe resolution, and every call-binding content id.

It grades four independent things, none of them derived from the code under test (F3):

  1. THE ANNOTATION->EFFECT MAPPING TABLE. The expected effect for every MCP tool-annotation set
     comes from the CURRENT Model Context Protocol ToolAnnotations contract, read from the MCP
     specification THIS SESSION (modelcontextprotocol.io, spec revision 2025-11-25; the same
     ToolAnnotations shape as 2025-03-26 and 2025-06-18), cross-checked against the MCP schema on
     context7 and the MCP blog "Tool Annotations as Risk Vocabulary" (2026-03-16). The field names,
     types, and DEFAULTS are quoted verbatim in mcp_annotation_contract below. The mapping is
     computed here directly from those documented semantics and the closed four-effect lattice
     (design.md §6.1) — never by reading impl/go or impl/rust.

  2. WIRE BYTES (byte-identical Go == Rust == oracle). The wrapper body is the draft-01 production
     naalp-mcp-tool-call {1:tool, 2:args, 3:annotations}; the call binding is naalp-mcp-call-binding
     {1:tool_id, 2:args_id}. Each byte vector is built by the shared deterministic-CBOR constructor
     (cbor_oracle, graded against RFC 8949 §4.2.1 in T1); content ids are multihash(0x20,
     SHA-384(bytes)) — the T1 framing (design §2.3). The N-AALP SPINE CARRIES NO CBOR BOOLEAN
     (design §3.1): a JSON hint's true/false is transcribed as the uint 1/0 (an absent hint is the
     MCP default, applied by the mapping, and is a DISTINCT wire encoding from a present 0).

  3. THE MORE-SEVERE RESOLUTION (the attenuator). When the annotation-derived effect and the
     wrapping signer's DECLARED envelope effect disagree, the enforced effect is the MORE SEVERE of
     the two, and the disagreement is a mismatch attributable to the wrapping signer's key. A signer
     that DECLARES BELOW the tool's own annotations (under-declaration) is rejected fail-closed
     (EffectUnderDeclared) — the wrapper's declared effect can never sit under the effect its own
     carried annotations map to. This model is written from the profile prose, not from the impl.

  4. OUT-OF-LATTICE REJECTION. An annotation set that would map outside the closed lattice (a hint
     value outside {0,1}, or an annotation key the closed mapping does not define) is REJECTED
     (MalformedAnnotation), never defaulted to benign.

Emits vectors/mcp/cases.json (LF-normalized). Do not hand-edit.
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

# ---- the MCP annotation contract, WITNESSED from the MCP spec this session -------------------
# The four behavioural hints, their exact field names, CBOR-key transcription, MCP default values,
# and documented meaning. Quoted from the Model Context Protocol ToolAnnotations interface
# (modelcontextprotocol.io/specification/2025-11-25; unchanged from 2025-03-26/2025-06-18) and the
# MCP schema (github.com/modelcontextprotocol/modelcontextprotocol schema.ts). The trust posture is
# the MCP spec's own words on the tools page: "clients MUST consider tool annotations to be
# untrusted unless they come from trusted servers." That is the hole this profile closes: an
# unenforced, untrusted hint becomes a signed effect claim by a named key.
ANNOTATION_KEY = {
    "read_only_hint": 1,   # MCP readOnlyHint
    "destructive_hint": 2,  # MCP destructiveHint
    "idempotent_hint": 3,   # MCP idempotentHint
    "open_world_hint": 4,   # MCP openWorldHint (ADVISORY — not an effect determinant)
}
MCP_ANNOTATION_CONTRACT = {
    "source": ("Model Context Protocol ToolAnnotations, read this session from "
               "modelcontextprotocol.io/specification/2025-11-25 (same shape as 2025-03-26 and "
               "2025-06-18), the MCP schema.ts on context7, and the MCP blog "
               "'Tool Annotations as Risk Vocabulary' (2026-03-16)."),
    "trust_posture": ("MCP tools page (2025-06-18 and 2025-11-25), verbatim: 'For trust & safety "
                      "and security, clients MUST consider tool annotations to be untrusted unless "
                      "they come from trusted servers.' Annotations are hints a malicious server "
                      "can lie about; they are not authorization constructs."),
    "spine_note": ("The N-AALP spine carries NO CBOR boolean (design §3.1); each JSON boolean hint "
                   "is transcribed as the uint 1 (true) / 0 (false). An absent hint is the MCP "
                   "default, applied by the mapping."),
    "fields": [
        {"name": "readOnlyHint", "cbor_key": 1, "type": "boolean-as-uint(0|1)", "default": "false",
         "meaning": "If true, the tool does not modify its environment."},
        {"name": "destructiveHint", "cbor_key": 2, "type": "boolean-as-uint(0|1)", "default": "true",
         "meaning": ("If true, the tool may perform destructive updates to its environment; if "
                     "false, the tool performs only additive updates. Meaningful only when "
                     "readOnlyHint == false.")},
        {"name": "idempotentHint", "cbor_key": 3, "type": "boolean-as-uint(0|1)", "default": "false",
         "meaning": ("If true, calling the tool repeatedly with the same arguments has no "
                     "additional effect on its environment. Meaningful only when "
                     "readOnlyHint == false.")},
        {"name": "openWorldHint", "cbor_key": 4, "type": "boolean-as-uint(0|1)", "default": "true",
         "meaning": ("If true, the tool may interact with an open world of external entities; if "
                     "false, its domain of interaction is closed. ADVISORY risk signal ONLY — it "
                     "does NOT enter the effect lattice (design §5: risk dimensions ride as "
                     "advisory labels, never as effects).")},
    ],
}

# MCP defaults for absent hints, as uint (0=false, 1=true) — the documented defaults above.
DEFAULT_READ_ONLY = 0    # readOnlyHint default false
DEFAULT_DESTRUCTIVE = 1  # destructiveHint default true  (the fail-closed default: an un-annotated
                         # write is treated as potentially destructive — aligned 1:1 with N-AALP's
                         # "absent effect on a state-changing object => destructive")
DEFAULT_IDEMPOTENT = 0   # idempotentHint default false


# ---- 1. the annotation -> effect mapping (independent, from the MCP semantics + the lattice) --

def map_annotations_to_effect(hints):
    """The published mapping table. `hints` is a dict of PRESENT annotation cbor-keys (1..4) -> uint
    (0/1); an absent hint takes its MCP default. Returns the annotation-derived effect (0..3), or
    raises ValueError for an annotation set that maps OUTSIDE the closed lattice (rejected, never
    defaulted to benign). openWorldHint (key 4) is advisory and never consulted for the effect."""
    for k, v in hints.items():
        if k not in (1, 2, 3, 4):
            raise ValueError("unknown annotation key %r (outside the closed mapping)" % (k,))
        if v not in (0, 1):
            raise ValueError("hint %r value %r outside {0,1} (maps outside the lattice)" % (k, v))
    ro = hints.get(1, DEFAULT_READ_ONLY)
    de = hints.get(2, DEFAULT_DESTRUCTIVE)
    idem = hints.get(3, DEFAULT_IDEMPOTENT)
    if ro == 1:
        return READ_ONLY                 # "the tool does not modify its environment"
    # readOnlyHint false => a state-changing write; destructive/idempotent hints now meaningful.
    if de == 1:
        return DESTRUCTIVE               # "may perform destructive updates"
    # additive (non-destructive) write.
    if idem == 1:
        return IDEMPOTENT_WRITE          # "repeated calls have no additional effect"
    return NON_IDEMPOTENT_WRITE


def resolve_enforced_effect(annotation_mapped, declared):
    """The attenuator (the good-regulator collapse to the most-severe). When the annotation-derived
    effect and the wrapping signer's DECLARED effect disagree, the enforced effect is the MORE
    SEVERE. A signer that declares BELOW the tool's own annotations is rejected fail-closed. Returns
    (verdict, enforced_or_None, mismatch): verdict is "accept" or "EffectUnderDeclared"."""
    if declared not in (0, 1, 2, 3):
        return ("EffectOutsideLattice", None, declared != annotation_mapped)
    if declared < annotation_mapped:
        # under-declaration: the wrapper's own effect sits below the effect its carried annotations
        # map to. Resolving to the more-severe would require declared >= annotation_mapped; a wrapper
        # that violates that is rejected (never silently corrected).
        return ("EffectUnderDeclared", None, True)
    return ("accept", max(annotation_mapped, declared), declared != annotation_mapped)


# ---- 2. wire bytes: the annotation map, the wrapper body, the call binding --------------------

def annotations_cbor(hints):
    """Deterministic CBOR of a naalp-mcp-annotations map: present hints only, uint keys 1..4 -> uint
    0/1 (the spine carries no boolean, design §3.1). An empty dict encodes the empty map 0xa0."""
    pairs = [(k, hints[k]) for k in sorted(hints.keys())]
    return cbor_oracle.encode(("map", pairs))


def tool_call_body(tool, args, hints):
    """Deterministic CBOR of a naalp-mcp-tool-call body {1:tool(bstr), 2:args(bstr),
    3:annotations(map)}. `tool` and `args` are the foreign MCP bytes, carried octet-for-octet."""
    return cbor_oracle.encode(("map", [
        (1, tool),
        (2, args),
        (3, ("map", [(k, hints[k]) for k in sorted(hints.keys())])),
    ]))


def call_binding_body(tool, args):
    """Deterministic CBOR of a naalp-mcp-call-binding {1:tool_id, 2:args_id}. The approval binds the
    content id of THIS binding, so a changed tool description (new tool_id) OR changed arguments (new
    args_id) yields a new call content id and invalidates a prior approval (Requirement 6.1)."""
    return cbor_oracle.encode(("map", [(1, cid(tool)), (2, cid(args))]))


def cid(b):
    """Content id (T1 framing, design §2.3): multihash(0x20, SHA-384(b))."""
    return b"\x20\x30" + hashlib.sha384(b).digest()


def noncanon_map(pairs):
    """Hand-build a CBOR map carrying the SAME pairs but with the top-level keys emitted in DESCENDING
    order — non-canonical per RFC 8949 §4.2.1, which the strict shared decoder rejects (NonCanonical).
    `pairs` is the canonical ascending list [(k, v), ...]; each value is encoded canonically (only the
    top-level key order is wrong). Built by hand, NOT via cbor_oracle.encode (which always sorts)."""
    n = len(pairs)
    assert n < 24
    out = bytes([0xA0 | n])
    for (k, v) in reversed(pairs):
        out += cbor_oracle.encode(k) + cbor_oracle.encode(v)
    return out


# ---- 3. build the vectors --------------------------------------------------------------------

def hint_label(hints):
    parts = []
    names = {1: "ro", 2: "de", 3: "idem", 4: "ow"}
    for k in sorted(hints.keys()):
        parts.append("%s=%d" % (names[k], hints[k]))
    return "{" + ",".join(parts) + "}" if parts else "{}"


def build_mapping_table():
    """The four canonical mapping rows, using RESOLVED hint values (true/false/any). 'any' means the
    hint is not consulted for that row. This is the published contract mirrored in
    vectors/registry/mcp.csv; registry_drift asserts CSV == this table."""
    return [
        {"read_only_hint": "true", "destructive_hint": "any", "idempotent_hint": "any",
         "effect": "read_only", "effect_value": READ_ONLY},
        {"read_only_hint": "false", "destructive_hint": "true", "idempotent_hint": "any",
         "effect": "destructive", "effect_value": DESTRUCTIVE},
        {"read_only_hint": "false", "destructive_hint": "false", "idempotent_hint": "true",
         "effect": "idempotent_write", "effect_value": IDEMPOTENT_WRITE},
        {"read_only_hint": "false", "destructive_hint": "false", "idempotent_hint": "false",
         "effect": "non_idempotent_write", "effect_value": NON_IDEMPOTENT_WRITE},
    ]


def build_annotation_vectors():
    # (name, hints) pairs covering: the empty (all-default) set => destructive (the fail-closed crown
    # jewel, 1:1 with "absent effect on a state-changing object => destructive"); readOnlyHint
    # precedence; the destructive/idempotent distinction on the write path; MCP defaults applied to
    # absent hints; present-0 vs absent (distinct bytes, same effect); openWorldHint proven advisory
    # (never changes the effect). Both allows and all four effect values appear, so a constant mapper
    # (always read_only, or always destructive) diverges (mutation-surviving).
    specs = [
        ("empty_all_absent", {}),                         # ro def F, de def T -> destructive
        ("read_only_true", {1: 1}),                       # ro T -> read_only
        ("read_only_false_only", {1: 0}),                 # ro F, de def T -> destructive
        ("write_destructive", {1: 0, 2: 1}),              # ro F, de T -> destructive
        ("write_additive_nonidem", {1: 0, 2: 0}),         # ro F, de F, idem def F -> non_idempotent
        ("write_additive_idem", {1: 0, 2: 0, 3: 1}),      # ro F, de F, idem T -> idempotent_write
        ("write_additive_nonidem_explicit", {1: 0, 2: 0, 3: 0}),  # -> non_idempotent_write
        ("read_only_wins_over_writes", {1: 1, 2: 1, 3: 0}),  # ro T short-circuits -> read_only
        ("idem_without_readonly", {2: 0, 3: 1}),          # ro def F, de F, idem T -> idempotent_write
        ("idem_true_but_destructive_default", {3: 1}),    # ro def F, de def T -> destructive (de wins)
        ("openworld_does_not_change_ro", {1: 1, 4: 1}),   # ow present -> still read_only
        ("openworld_false_does_not_change_ro", {1: 1, 4: 0}),  # -> read_only
        ("openworld_only", {4: 1}),                       # ow only; ro def F, de def T -> destructive
        ("openworld_does_not_change_idem", {1: 0, 2: 0, 3: 1, 4: 1}),  # -> idempotent_write
    ]
    out = []
    for name, hints in specs:
        eff = map_annotations_to_effect(hints)
        ah = annotations_cbor(hints)
        out.append({
            "name": name,
            "label": hint_label(hints),
            "hints": {str(k): hints[k] for k in sorted(hints.keys())},
            "annotations_hex": ah.hex(),
            "mapped_effect": eff,
            "mapped_effect_name": EFFECT_NAME[eff],
        })
    return out


def build_malformed_annotations():
    # Annotation sets that map OUTSIDE the closed lattice -> rejected (never defaulted to benign).
    # These are byte blobs a strict parser must reject; the impls parse them and MUST return
    # MalformedAnnotation. (Both are structurally valid CBOR maps, so the rejection is a profile
    # rule, not a CBOR-codec rule.)
    return [
        {"name": "hint_value_two", "annotations_hex": cbor_oracle.encode(("map", [(1, 2)])).hex(),
         "reason": "readOnlyHint value 2 is outside {0,1} — no boolean it could transcribe",
         "expect": "MalformedAnnotation"},
        {"name": "hint_value_large", "annotations_hex": cbor_oracle.encode(("map", [(2, 99)])).hex(),
         "reason": "destructiveHint value 99 is outside {0,1}", "expect": "MalformedAnnotation"},
        {"name": "unknown_key", "annotations_hex": cbor_oracle.encode(("map", [(5, 1)])).hex(),
         "reason": "annotation key 5 is not in the closed mapping {1,2,3,4}",
         "expect": "MalformedAnnotation"},
    ]


# Realistic foreign MCP bytes, carried OCTET-FOR-OCTET (carriage, not adoption). The exact bytes are
# not parsed on the signing path; they are what the tool_id / args_id content ids are taken over.
def jb(s):
    return s.encode("utf-8")


def build_tool_calls():
    specs = [
        ("read_weather",
         jb('{"name":"get_weather","description":"Get current weather for a location",'
            '"annotations":{"readOnlyHint":true}}'),
         jb('{"location":"New York"}'),
         {1: 1}),
        ("append_note",
         jb('{"name":"append_note","description":"Append a note (additive)",'
            '"annotations":{"readOnlyHint":false,"destructiveHint":false,"idempotentHint":false}}'),
         jb('{"text":"remember the milk"}'),
         {1: 0, 2: 0, 3: 0}),
        ("set_config_idempotent",
         jb('{"name":"set_config","annotations":{"readOnlyHint":false,"destructiveHint":false,'
            '"idempotentHint":true}}'),
         jb('{"key":"theme","value":"dark"}'),
         {1: 0, 2: 0, 3: 1}),
        ("delete_file_destructive",
         jb('{"name":"delete_file","annotations":{"readOnlyHint":false,"destructiveHint":true}}'),
         jb('{"path":"reports/q3.pdf"}'),
         {1: 0, 2: 1}),
        ("unannotated_tool",
         jb('{"name":"do_thing","description":"no annotations at all"}'),
         jb('{"arg":1}'),
         {}),  # empty annotation set -> destructive (fail-closed)
    ]
    out = []
    for name, tool, args, hints in specs:
        body = tool_call_body(tool, args, hints)
        eff = map_annotations_to_effect(hints)
        binding = call_binding_body(tool, args)
        out.append({
            "name": name,
            "tool_hex": tool.hex(),
            "args_hex": args.hex(),
            "hints": {str(k): hints[k] for k in sorted(hints.keys())},
            "annotations_hex": annotations_cbor(hints).hex(),
            "body_hex": body.hex(),
            "content_id_hex": cid(body).hex(),
            "tool_id_hex": cid(tool).hex(),
            "args_id_hex": cid(args).hex(),
            "annotation_mapped_effect": eff,
            "annotation_mapped_effect_name": EFFECT_NAME[eff],
            "call_binding_hex": binding.hex(),
            "call_content_id_hex": cid(binding).hex(),
        })
    return out


def build_resolution():
    # (name, annotation_mapped, declared, note). The oracle computes verdict/enforced/mismatch.
    specs = [
        ("agree_read_only", READ_ONLY, READ_ONLY, "tool and signer agree read_only"),
        ("agree_destructive", DESTRUCTIVE, DESTRUCTIVE, "tool and signer agree destructive"),
        ("lying_tool_benign_annotation_severe_declared", READ_ONLY, DESTRUCTIVE,
         "the tool's annotation lies read_only; the wrapping signer, accountable, declares "
         "destructive; enforced = destructive (the more severe); mismatch attributable to the signer"),
        ("over_declare_idem_to_niw", IDEMPOTENT_WRITE, NON_IDEMPOTENT_WRITE,
         "signer declares more severe than the annotations map; enforced = non_idempotent_write"),
        ("over_declare_niw_to_destructive", NON_IDEMPOTENT_WRITE, DESTRUCTIVE,
         "signer escalates a write to destructive; enforced = destructive; mismatch"),
        ("under_declare_severe_annotation_benign_signer", DESTRUCTIVE, READ_ONLY,
         "signer under-declares below the tool's own destructive annotations -> EffectUnderDeclared "
         "(a wrapper's declared effect can never sit under its carried annotations' mapping)"),
        ("under_declare_niw_to_idem", NON_IDEMPOTENT_WRITE, IDEMPOTENT_WRITE,
         "signer under-declares a non_idempotent_write as idempotent_write -> EffectUnderDeclared"),
    ]
    out = []
    for name, mapped, declared, note in specs:
        verdict, enforced, mismatch = resolve_enforced_effect(mapped, declared)
        out.append({
            "name": name,
            "note": note,
            "annotation_mapped": mapped,
            "annotation_mapped_name": EFFECT_NAME[mapped],
            "declared": declared,
            "declared_name": EFFECT_NAME[declared],
            "verdict": verdict,
            "enforced": enforced,
            "enforced_name": EFFECT_NAME[enforced] if enforced is not None else None,
            "mismatch": mismatch,
        })
    return out


def build_approval_binding():
    # One base call (tool T, args A) and two single-variable perturbations proving the approval
    # binding covers BOTH the tool description and the arguments: a changed tool DESCRIPTION yields a
    # new call content id (Requirement 6.1 / AC-6.1.3), and changed ARGUMENTS yield a new call
    # content id (AC-6.1.2). An approval bound to the base call satisfies neither perturbed call.
    tool_T = jb('{"name":"transfer","description":"Transfer funds",'
                '"annotations":{"readOnlyHint":false,"destructiveHint":true}}')
    tool_T2 = jb('{"name":"transfer","description":"Transfer funds (updated wording)",'
                 '"annotations":{"readOnlyHint":false,"destructiveHint":true}}')
    args_A = jb('{"to":"acct-1","amount":100}')
    args_B = jb('{"to":"acct-2","amount":100}')

    def entry(name, tool, args, note):
        binding = call_binding_body(tool, args)
        return {
            "name": name, "note": note,
            "tool_hex": tool.hex(), "args_hex": args.hex(),
            "tool_id_hex": cid(tool).hex(), "args_id_hex": cid(args).hex(),
            "call_binding_hex": binding.hex(), "call_content_id_hex": cid(binding).hex(),
        }

    base = entry("base_T_A", tool_T, args_A, "the approved call: tool T, args A")
    changed_args = entry("changed_args_T_B", tool_T, args_B,
                         "same tool T, DIFFERENT args B -> different call content id (AC-6.1.2)")
    changed_tool = entry("changed_tool_desc_T2_A", tool_T2, args_A,
                         "changed tool DESCRIPTION T2, same args A -> different call content id "
                         "(AC-6.1.3)")
    # Independently assert the perturbations differ from the base (the oracle's own sanity check).
    assert changed_args["call_content_id_hex"] != base["call_content_id_hex"]
    assert changed_tool["call_content_id_hex"] != base["call_content_id_hex"]
    return [base, changed_args, changed_tool]


def build_edge_cases():
    """Standard wire-format edge cases (Part 1), mirroring the C17 continuation family:
      #1 keys-out-of-order: a tool-call body whose top-level keys are DESCENDING (3,2,1) — rejected
         NonCanonical by the strict shared decoder the verify path routes through.
      #2 empty-vs-absent (the annotations map): an empty annotations map is PRESENT and valid (all MCP
         defaults -> destructive, the fail-closed crown jewel), and is a DISTINCT wire body from a
         tool-call whose annotations field is ABSENT (field 3 omitted), which is rejected.
      #4 minimal tool-call: the smallest valid tool-call (empty tool, empty args, empty annotations).
      #5 look-alike: a naalp-mcp-call-binding {1:tool_id,2:args_id} (2 fields, a SIBLING kind) fed to
         the tool-call parser is rejected — a tool-call is 3 fields (annotations required).
      #3 (oversized >2^53 counter) is N/A: the NAALP-MCP bodies carry no 64-bit counter field."""
    et_tool = jb('{"name":"t"}')
    et_args = jb('{}')

    # #1 keys-out-of-order over a {1:tool,2:args,3:annotations} tool-call (annotations {readOnlyHint=1}).
    koo_hints = {1: 1}
    koo_pairs = [(1, et_tool), (2, et_args), (3, ("map", [(1, 1)]))]
    koo_canon = tool_call_body(et_tool, et_args, koo_hints)
    koo_noncanon = noncanon_map(koo_pairs)
    assert koo_noncanon != koo_canon and len(koo_noncanon) == len(koo_canon)
    keys_out_of_order = {
        "canonical_body_hex": koo_canon.hex(),
        "noncanonical_body_hex": koo_noncanon.hex(),
        "reject": "NonCanonical",
        "note": "same content, top-level keys emitted descending (3,2,1) — the strict decoder rejects NonCanonical.",
    }

    # #2 empty-vs-absent: empty annotations map present (valid, -> destructive) vs annotations absent.
    empty_ann_body = tool_call_body(et_tool, et_args, {})           # field 3 present = empty map (0xa0)
    absent_ann_body = cbor_oracle.encode(("map", [(1, et_tool), (2, et_args)]))  # field 3 OMITTED
    assert empty_ann_body != absent_ann_body
    empty_vs_absent = {
        "empty_annotations": {
            "body_hex": empty_ann_body.hex(),
            "content_id_hex": cid(empty_ann_body).hex(),
            "mapped_effect": map_annotations_to_effect({}),        # 3 (destructive: all MCP defaults)
            "mapped_effect_name": EFFECT_NAME[map_annotations_to_effect({})],
        },
        "absent_annotations": {"body_hex": absent_ann_body.hex(), "reject": "ToolCallMalformed"},
        "note": ("an empty annotations map is PRESENT and valid (all MCP defaults -> destructive) and is "
                 "a distinct wire body from a tool-call whose annotations field is absent (rejected)."),
    }

    # #4 minimal tool-call: empty tool, empty args, empty annotations -> destructive default.
    min_body = tool_call_body(b"", b"", {})
    minimal = {
        "tool_hex": "", "args_hex": "",
        "body_hex": min_body.hex(),
        "content_id_hex": cid(min_body).hex(),
        "mapped_effect": map_annotations_to_effect({}),
        "mapped_effect_name": EFFECT_NAME[map_annotations_to_effect({})],
        "note": "smallest valid tool-call: empty tool, empty args, empty annotations (-> destructive default).",
    }

    # #5 look-alike: a call-binding {1:tool_id,2:args_id} (a sibling kind) fed to the tool-call parser.
    la_binding = call_binding_body(et_tool, et_args)
    look_alike = {
        "call_binding_body_hex": la_binding.hex(),
        "tool_hex": et_tool.hex(), "args_hex": et_args.hex(),
        "reject": "ToolCallMalformed",
        "note": "a 2-field call-binding fed to the tool-call parser is rejected — a tool-call is 3 fields.",
    }

    return {
        "keys_out_of_order": keys_out_of_order,
        "empty_vs_absent": empty_vs_absent,
        "minimal": minimal,
        "look_alike": look_alike,
        "oversized_note": "edge case #3 (oversized >2^53 counter) is N/A: NAALP-MCP bodies carry no 64-bit counter.",
    }


def build():
    return {
        "note": ("Independent oracle for the NAALP-MCP binding profile (Requirement 6.1). Go and "
                 "Rust MUST reproduce every *_hex, every mapped_effect, every resolution verdict, "
                 "and reject every malformed annotation set. The annotation->effect mapping is "
                 "derived from the MCP ToolAnnotations contract read this session (see "
                 "mcp_annotation_contract) + the closed effect lattice, NEVER from impl/go or "
                 "impl/rust. Generated by tools/mcp_oracle.py; do not hand-edit."),
        "mcp_annotation_contract": MCP_ANNOTATION_CONTRACT,
        "annotation_key": ANNOTATION_KEY,
        "effects": [{"value": v, "name": n} for v, n in EFFECT_NAME.items()],
        "mapping_table": build_mapping_table(),
        "annotations": build_annotation_vectors(),
        "malformed_annotations": build_malformed_annotations(),
        "tool_calls": build_tool_calls(),
        "resolution": build_resolution(),
        "approval_binding": build_approval_binding(),
        "edge_cases": build_edge_cases(),
    }


def main():
    data = build()
    out = os.path.normpath(os.path.join(HERE, "..", "vectors", "mcp", "cases.json"))
    os.makedirs(os.path.dirname(out), exist_ok=True)
    # newline="\n" forces LF on every platform (Python text mode emits CRLF on Windows, which would
    # diverge the worktree vector from the LF-normalized git blob and break the pinned gate).
    with io.open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print("wrote", os.path.relpath(out, os.path.join(HERE, "..")))
    for a in data["annotations"]:
        print("  annotation %-32s %-14s -> %s" % (a["name"], a["label"], a["mapped_effect_name"]))
    for r in data["resolution"]:
        print("  resolution %-42s mapped=%s declared=%s -> %s%s"
              % (r["name"], r["annotation_mapped_name"], r["declared_name"], r["verdict"],
                 (" enforced=" + r["enforced_name"]) if r["enforced_name"] else ""))
    for t in data["tool_calls"]:
        print("  tool_call  %-24s body %3dB annmap=%s" % (t["name"], len(t["body_hex"]) // 2,
                                                          t["annotation_mapped_effect_name"]))


if __name__ == "__main__":
    main()
