# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""NAALP-MCP binding-profile conformance for the Python SDK (design.md §19; Companion-Spec
Requirement 6.1), graded against the shared independent corpus vectors/mcp/cases.json (NOT produced
by this code): the annotation-set wire bytes, the published annotation->effect mapping table, every
malformed-annotation rejection, the tool-call body/content-id/tool-id/args-id/call-binding bytes,
the more-severe effect resolution (accept + EffectUnderDeclared verdicts), the approval-binding
content ids (a changed argument or changed tool description yields a new call content id), and the
edge cases (non-canonical rejection, empty-vs-absent annotations, minimal, look-alike).

The end-to-end governance path -- a real ML-DSA-65 signed McpToolCall verified through the frozen
envelope, its enforced effect resolved to the more severe, and the per-call approval consumed
single-use through the §7 ledger -- is real behaviour demonstrated in isolation (the corpus carries
no signed-object vector, stated honestly, so it is NOT corpus-graded).

Written test-first; the mcp module is absent until ported, so this fails RED on import until
impl/python/naalp/mcp.py lands, and a mutation dropping the fail-closed destructive default flips
test_mapped_effect_matches_oracle.

Run:  python -m unittest -v tests.test_mcp      (from impl/python/)
"""
import json
import os
import tempfile
import unittest

from naalp import approval, cbor, cose, identity, mcp, policy


def _vectors():
    d = os.path.dirname(os.path.abspath(__file__))
    for _ in range(6):
        p = os.path.join(d, "vectors", "mcp", "cases.json")
        if os.path.isfile(p):
            with open(p, encoding="utf-8") as f:
                return json.load(f)
        d = os.path.dirname(d)
    raise FileNotFoundError("vectors/mcp/cases.json not found")


ALG = cose.ALG_MLDSA65
PROFILE = cose.PROFILE_PUBLIC

# hint cbor-key -> Annotations attribute name
_HINT_ATTR = {1: "read_only", 2: "destructive", 3: "idempotent", 4: "open_world"}


def _ann(hints):
    """Build an Annotations from a corpus hints dict (string cbor-key -> 0/1)."""
    a = mcp.Annotations()
    for k, v in hints.items():
        setattr(a, _HINT_ATTR[int(k)], bool(v))
    return a


class _Key:
    __slots__ = ("seed", "pk", "id")

    def __init__(self, n):
        self.seed = bytes([n & 0xFF] * 32)
        self.pk = cose.mldsa_keygen("ML-DSA-65", self.seed)
        self.id = identity.signer_id(ALG, self.pk)


class McpConformance(unittest.TestCase):
    C = _vectors()

    # ---- annotation wire bytes (design §6.1) ---------------------------------------------

    def test_annotations_encode_match_oracle(self):
        self.assertTrue(self.C["annotations"])
        for av in self.C["annotations"]:
            a = _ann(av["hints"])
            self.assertEqual(a.encode().hex(), av["annotations_hex"], av["name"])

    # ---- the published annotation -> effect mapping table (THE mutation target) -----------

    def test_mapped_effect_matches_oracle(self):
        # Each annotation set maps to the closed four-effect lattice by the published table; an absent
        # readOnlyHint defaults false, an absent destructiveHint defaults TRUE (the fail-closed
        # collapse to destructive), openWorldHint never enters the mapping.
        for av in self.C["annotations"]:
            a = _ann(av["hints"])
            self.assertEqual(mcp.map_annotations_to_effect(a), av["mapped_effect"], av["name"])

    def test_malformed_annotations_rejected(self):
        for mv in self.C["malformed_annotations"]:
            v = cbor.decode(bytes.fromhex(mv["annotations_hex"]))
            with self.assertRaises(mcp.McpError, msg=mv["name"]) as cm:
                mcp.annotations_from_value(v)
            self.assertEqual(cm.exception.kind, "MalformedAnnotation", mv["name"])

    # ---- tool-call body / content-id / tool-id / args-id / call-binding bytes --------------

    def test_tool_call_bodies_match_oracle(self):
        self.assertTrue(self.C["tool_calls"])
        for tv in self.C["tool_calls"]:
            tc = mcp.ToolCall(bytes.fromhex(tv["tool_hex"]), bytes.fromhex(tv["args_hex"]),
                              _ann(tv["hints"]))
            self.assertEqual(tc.bytes().hex(), tv["body_hex"], tv["name"])
            self.assertEqual(tc.content_id().hex(), tv["content_id_hex"], tv["name"])
            cb = tc.call_binding()
            self.assertEqual(cb.tool_id.hex(), tv["tool_id_hex"], tv["name"])
            self.assertEqual(cb.args_id.hex(), tv["args_id_hex"], tv["name"])
            self.assertEqual(cb.bytes().hex(), tv["call_binding_hex"], tv["name"])
            self.assertEqual(cb.content_id().hex(), tv["call_content_id_hex"], tv["name"])
            self.assertEqual(mcp.map_annotations_to_effect(tc.annotations),
                             tv["annotation_mapped_effect"], tv["name"])
            # a tool call re-parses from its own body bytes
            got = mcp.tool_call_from_body(cbor.decode(tc.bytes()))
            self.assertEqual(got.tool, tc.tool, tv["name"])
            self.assertEqual(got.args, tc.args, tv["name"])

    # ---- more-severe effect resolution (the good-regulator attenuator) --------------------

    def test_resolution_matches_oracle(self):
        self.assertTrue(self.C["resolution"])
        for rv in self.C["resolution"]:
            mapped, declared = rv["annotation_mapped"], rv["declared"]
            if rv["verdict"] == "accept":
                enforced, mismatch = mcp.resolve_enforced_effect(mapped, declared)
                self.assertEqual(enforced, rv["enforced"], rv["name"])
                self.assertEqual(mismatch, rv["mismatch"], rv["name"])
            else:
                with self.assertRaises(mcp.McpError, msg=rv["name"]) as cm:
                    mcp.resolve_enforced_effect(mapped, declared)
                self.assertEqual(cm.exception.kind, rv["verdict"], rv["name"])

    def test_resolve_effect_outside_lattice(self):
        # NOT corpus-graded: a declared effect outside the closed lattice is rejected, never defaulted.
        with self.assertRaises(mcp.McpError) as cm:
            mcp.resolve_enforced_effect(policy.READ_ONLY, 4)
        self.assertEqual(cm.exception.kind, "EffectOutsideLattice")

    # ---- the approval binds the exact call (AC-6.1.2 / AC-6.1.3) ---------------------------

    def test_approval_binding_content_ids_match_oracle(self):
        binds = self.C["approval_binding"]
        self.assertTrue(binds)
        seen = set()
        for bv in binds:
            cb = mcp.new_call_binding(bytes.fromhex(bv["tool_hex"]), bytes.fromhex(bv["args_hex"]))
            self.assertEqual(cb.tool_id.hex(), bv["tool_id_hex"], bv["name"])
            self.assertEqual(cb.args_id.hex(), bv["args_id_hex"], bv["name"])
            self.assertEqual(cb.bytes().hex(), bv["call_binding_hex"], bv["name"])
            self.assertEqual(cb.content_id().hex(), bv["call_content_id_hex"], bv["name"])
            seen.add(bv["call_content_id_hex"])
        # a changed argument (T,B) and a changed tool description (T2,A) each yield a DISTINCT call
        # content id from the base (T,A) -- so a prior approval bound to (T,A) matches neither.
        self.assertEqual(len(seen), len(binds))

    # ---- edge cases (design §6.1 CDDL) ----------------------------------------------------

    def test_edge_cases(self):
        ec = self.C["edge_cases"]

        # canonical body parses; the descending-key body is rejected NonCanonical at decode.
        koo = ec["keys_out_of_order"]
        mcp.tool_call_from_body(cbor.decode(bytes.fromhex(koo["canonical_body_hex"])))
        with self.assertRaises(cbor.NonCanonical):
            cbor.decode(bytes.fromhex(koo["noncanonical_body_hex"]))

        # an empty annotations map is PRESENT and valid (all MCP defaults -> destructive); an
        # annotations-absent body is a distinct wire shape and is rejected ToolCallMalformed.
        eva = ec["empty_vs_absent"]
        empty = eva["empty_annotations"]
        tc = mcp.tool_call_from_body(cbor.decode(bytes.fromhex(empty["body_hex"])))
        self.assertEqual(tc.content_id().hex(), empty["content_id_hex"])
        self.assertEqual(mcp.map_annotations_to_effect(tc.annotations), empty["mapped_effect"])
        with self.assertRaises(mcp.McpError) as cm:
            mcp.tool_call_from_body(cbor.decode(bytes.fromhex(eva["absent_annotations"]["body_hex"])))
        self.assertEqual(cm.exception.kind, "ToolCallMalformed")

        # the smallest valid tool call: empty tool, empty args, empty annotations (-> destructive).
        mn = ec["minimal"]
        tc = mcp.ToolCall(bytes.fromhex(mn["tool_hex"]), bytes.fromhex(mn["args_hex"]), mcp.Annotations())
        self.assertEqual(tc.bytes().hex(), mn["body_hex"])
        self.assertEqual(tc.content_id().hex(), mn["content_id_hex"])
        self.assertEqual(mcp.map_annotations_to_effect(tc.annotations), mn["mapped_effect"])

        # a 2-field call-binding fed to the tool-call parser is rejected (a tool call is 3 fields).
        la = ec["look_alike"]
        with self.assertRaises(mcp.McpError) as cm:
            mcp.tool_call_from_body(cbor.decode(bytes.fromhex(la["call_binding_body_hex"])))
        self.assertEqual(cm.exception.kind, "ToolCallMalformed")

    # ---- end-to-end signed governance path, in isolation (NOT corpus-graded) ---------------

    def test_verify_tool_call_in_isolation(self):
        signer = _Key(11)
        tc = mcp.ToolCall(b'{"name":"delete_file"}', b'{"path":"a"}',
                          mcp.Annotations(read_only=False, destructive=True))  # maps -> destructive
        obj = tc.envelope_object(signer.id.encode(), 1, PROFILE, policy.DESTRUCTIVE, [])
        signed = mcp.sign_tool_call(obj, ALG, signer.seed)
        r = mcp.verify_tool_call(PROFILE, ALG, signer.pk, signed)
        self.assertEqual(r.enforced, policy.DESTRUCTIVE)
        self.assertEqual(r.annotation_mapped, policy.DESTRUCTIVE)
        self.assertFalse(r.mismatch)
        self.assertEqual(r.content_id, obj.content_id())

        # a benign annotation with a severe DECLARED effect: enforced is the more severe, mismatch true.
        tc2 = mcp.ToolCall(b"t", b"a", mcp.Annotations(read_only=True))       # maps -> read_only
        obj2 = tc2.envelope_object(signer.id.encode(), 1, PROFILE, policy.DESTRUCTIVE, [])
        r2 = mcp.verify_tool_call(PROFILE, ALG, signer.pk, mcp.sign_tool_call(obj2, ALG, signer.seed))
        self.assertEqual(r2.enforced, policy.DESTRUCTIVE)
        self.assertTrue(r2.mismatch)

        # a tampered signature is rejected BadSignature (envelope crypto).
        bad = bytearray(signed)
        bad[-1] ^= 1
        with self.assertRaises(Exception) as cm:
            mcp.verify_tool_call(PROFILE, ALG, signer.pk, bytes(bad))
        self.assertEqual(getattr(cm.exception, "kind", None), "BadSignature")

    def test_under_declared_rejected_in_isolation(self):
        # A wrapper whose DECLARED effect sits below its own carried annotations' mapping is rejected
        # EffectUnderDeclared at the enforcement point (a signed, attributable inconsistency).
        signer = _Key(12)
        tc = mcp.ToolCall(b"t", b"a", mcp.Annotations(read_only=False, destructive=True))  # -> destructive
        obj = tc.envelope_object(signer.id.encode(), 1, PROFILE, policy.READ_ONLY, [])      # declares below
        signed = mcp.sign_tool_call(obj, ALG, signer.seed)
        with self.assertRaises(mcp.McpError) as cm:
            mcp.verify_tool_call(PROFILE, ALG, signer.pk, signed)
        self.assertEqual(cm.exception.kind, "EffectUnderDeclared")

    def test_authorize_call_binds_exact_call_and_consumes_once(self):
        signer = _Key(13)
        approver = _Key(14)
        tc = mcp.ToolCall(b'{"name":"transfer"}', b'{"to":"acct-1"}',
                          mcp.Annotations(read_only=False, destructive=True))
        obj = tc.envelope_object(signer.id.encode(), 1, PROFILE, policy.DESTRUCTIVE, [])
        r = mcp.verify_tool_call(PROFILE, ALG, signer.pk, mcp.sign_tool_call(obj, ALG, signer.seed))
        call_cid = r.tool_call.call_binding().content_id()
        appr = approval.ApprovalRecord(call_cid, approver.id, policy.DESTRUCTIVE, b"\x01\x02", 1_000_000)
        sig = approval.sign_approval(appr, ALG, approver.seed)
        with tempfile.TemporaryDirectory() as tmp:
            ledger = approval.open_ledger(os.path.join(tmp, "consume.log"))
            try:
                self.assertIsNone(mcp.authorize_call(r, appr, ALG, approver.pk, sig, signer.id,
                                                     500, ledger))
                self.assertTrue(ledger.is_consumed(appr.id()))
                # single-use: a replay of the same approval is AlreadyConsumed, no second append.
                with self.assertRaises(approval.ApprovalError) as cm:
                    mcp.authorize_call(r, appr, ALG, approver.pk, sig, signer.id, 500, ledger)
                self.assertEqual(cm.exception.kind, "AlreadyConsumed")
                self.assertEqual(len(ledger), 1)
            finally:
                ledger.close()

    def test_authorize_call_wrong_binding_requires_approval(self):
        # An approval that binds a DIFFERENT call (different args) does not satisfy this call: the
        # mismatch is a held outcome surfaced as ApprovalRequired, with no ledger append (fail-closed).
        signer = _Key(15)
        approver = _Key(16)
        tc = mcp.ToolCall(b'{"name":"transfer"}', b'{"to":"acct-1"}',
                          mcp.Annotations(read_only=False, destructive=True))
        obj = tc.envelope_object(signer.id.encode(), 1, PROFILE, policy.DESTRUCTIVE, [])
        r = mcp.verify_tool_call(PROFILE, ALG, signer.pk, mcp.sign_tool_call(obj, ALG, signer.seed))
        other = mcp.new_call_binding(b'{"name":"transfer"}', b'{"to":"acct-2"}').content_id()
        appr = approval.ApprovalRecord(other, approver.id, policy.DESTRUCTIVE, b"\x01", 1_000_000)
        sig = approval.sign_approval(appr, ALG, approver.seed)
        with tempfile.TemporaryDirectory() as tmp:
            ledger = approval.open_ledger(os.path.join(tmp, "consume.log"))
            try:
                with self.assertRaises(mcp.McpError) as cm:
                    mcp.authorize_call(r, appr, ALG, approver.pk, sig, signer.id, 500, ledger)
                self.assertEqual(cm.exception.kind, "ApprovalRequired")
                self.assertEqual(len(ledger), 0)
            finally:
                ledger.close()


if __name__ == "__main__":
    unittest.main()
