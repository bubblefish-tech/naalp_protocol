# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""Conformance + mutation-surviving tests for the N-AALP MCP tool-integration bridge (E2.1,
ecosystem requirement R4.1/4.2/4.3; design.md Sec.19).

Non-circularity (F3): the annotation->effect mapping and every carried wire quantity (the
call-binding content id built from the tool/args bytes) is checked against the PRE-EXISTING,
independent top-level oracle vectors/mcp/cases.json (tools/mcp_oracle.py) -- generated from the
MCP ToolAnnotations contract read from the MCP specification plus the closed effect lattice,
sharing no code with naalp_mcp_bridge or with impl/python/naalp/mcp.py. The end-to-end
sign/verify/approve chain is exercised through the REAL Part-1 primitives (naalp.mcp.sign_tool_call
/ verify_tool_call / authorize_call, naalp.approval.open_ledger) -- nothing here is mocked.

Run (from ecosystem/naalp-mcp-bridge/, PYTHONDONTWRITEBYTECODE=1, using the real Python on this
machine -- not the Microsoft Store `python` stub):
    python -m unittest -v tests.test_mcp_bridge
"""
import json
import os
import sys
import tempfile
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)
import _paths  # noqa: E402

_PKG_ROOT = os.path.dirname(_THIS_DIR)  # ecosystem/naalp-mcp-bridge
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

from naalp_mcp_bridge import (  # noqa: E402
    BridgeError,
    annotations_from_mcp_dict,
    carry_tool_call, carry_tool_call_from_objects, receive_tool_call, bridged_call_request,
)
from naalp import approval, cose, envelope, mcp, policy  # noqa: E402

ALG = cose.ALG_MLDSA65
PROFILE = cose.PROFILE_PUBLIC

# CBOR-key (as the oracle names them) -> the MCP JSON hint name, the reverse of
# naalp_mcp_bridge.mcp_bridge._MCP_HINT_ATTR's JSON->attr direction.
_ORACLE_KEY_TO_MCP_JSON = {1: "readOnlyHint", 2: "destructiveHint", 3: "idempotentHint", 4: "openWorldHint"}


def _seed(b):
    return bytes([b]) * 32


def _oracle_hints_to_mcp_annotations(hints):
    """Convert an oracle `hints` dict ({"1": 1, "2": 0, ...}, cbor-key -> uint 0/1) into the MCP
    JSON annotations object naalp_mcp_bridge.annotations_from_mcp_dict actually consumes."""
    return {_ORACLE_KEY_TO_MCP_JSON[int(k)]: bool(v) for k, v in hints.items()}


class AnnotationTranscriptionMatchesOracle(unittest.TestCase):
    """F3: this bridge's own MCP-JSON->naalp.mcp.Annotations transcription, followed by Part-1's
    published mapping table, reproduces the independent oracle's `mapped_effect` for every one of
    its 14 annotation combinations -- never derived from naalp_mcp_bridge's own output."""

    def test_all_oracle_annotation_combinations(self):
        cases = _paths.load_mcp_cases()
        self.assertEqual(len(cases["annotations"]), 14)  # sanity: the full oracle breadth is exercised
        for case in cases["annotations"]:
            mcp_json = _oracle_hints_to_mcp_annotations(case["hints"])
            ann = annotations_from_mcp_dict(mcp_json)
            mapped = mcp.map_annotations_to_effect(ann)
            self.assertEqual(mapped, case["mapped_effect"],
                              "case %s: expected %s got %s" % (case["name"], case["mapped_effect_name"], mapped))

    def test_absent_hint_distinct_from_present_false(self):
        """§19.2: an absent hint takes the MCP default; a PRESENT `false` is a distinct wire value
        even when it resolves to the same effect. This bridge must preserve that distinction when
        transcribing MCP JSON (absent key -> None -> default applied; present `false` -> False)."""
        absent = annotations_from_mcp_dict({})
        present_false = annotations_from_mcp_dict({"readOnlyHint": False})
        self.assertIsNone(absent.read_only)
        self.assertIs(present_false.read_only, False)
        self.assertNotEqual(absent.to_value().pairs, present_false.to_value().pairs)

    def test_non_boolean_hint_value_rejected(self):
        """A bridge-only decode failure with no Part-1 analogue: naalp.mcp's own annotation map
        parser only ever sees uint 0/1 (this bridge's job is to reject a malformed JSON hint
        BEFORE it ever reaches that parser)."""
        with self.assertRaises(BridgeError) as cm:
            annotations_from_mcp_dict({"readOnlyHint": "yes"})
        self.assertEqual(cm.exception.kind, "ForeignToolNotJSON")


class OracleByteIdentity(unittest.TestCase):
    """F3: carrying the oracle's own raw foreign tool/args octets through this bridge reproduces
    the oracle's independently-computed annotation-mapped effect and call-binding content id, and
    receive_tool_call recovers the exact original octets."""

    def test_all_oracle_tool_calls_round_trip_and_match(self):
        cases = _paths.load_mcp_cases()
        self.assertEqual(len(cases["tool_calls"]), 5)
        for i, case in enumerate(cases["tool_calls"]):
            tool_bytes = bytes.fromhex(case["tool_hex"])
            args_bytes = bytes.fromhex(case["args_hex"])
            seed = _seed(0x50 + i)
            pk = cose.mldsa_keygen("ML-DSA-65", seed)

            carried = carry_tool_call(tool_bytes, args_bytes, signer_seed=seed,
                                       created=1_800_000_000_000)
            self.assertEqual(carried.annotation_mapped_effect, case["annotation_mapped_effect"],
                              "case %s" % case["name"])
            self.assertEqual(carried.call_binding_content_id, bytes.fromhex(case["call_content_id_hex"]),
                              "case %s" % case["name"])

            recv = receive_tool_call(carried.signed_object, PROFILE, ALG, pk)
            self.assertEqual(recv.tool_bytes, tool_bytes, "case %s tool recovery" % case["name"])
            self.assertEqual(recv.args_bytes, args_bytes, "case %s args recovery" % case["name"])
            self.assertEqual(recv.call_binding_content_id, bytes.fromhex(case["call_content_id_hex"]))
            self.assertEqual(recv.annotation_mapped_effect, case["annotation_mapped_effect"])

    def test_approval_binding_vectors_match_oracle(self):
        """AC-6.1.2 / AC-6.1.3: this bridge's call_binding_content_id agrees with the oracle for
        the base call AND for both single-variable perturbations (changed args, changed tool
        description) -- proving the binding genuinely covers both halves, not just one."""
        cases = _paths.load_mcp_cases()
        entries = {e["name"]: e for e in cases["approval_binding"]}
        base, changed_args, changed_tool = entries["base_T_A"], entries["changed_args_T_B"], entries["changed_tool_desc_T2_A"]
        seed = _seed(0x60)

        def cid_for(entry):
            c = carry_tool_call(bytes.fromhex(entry["tool_hex"]), bytes.fromhex(entry["args_hex"]),
                                 signer_seed=seed, created=1)
            return c.call_binding_content_id

        base_cid = cid_for(base)
        self.assertEqual(base_cid, bytes.fromhex(base["call_content_id_hex"]))
        self.assertEqual(cid_for(changed_args), bytes.fromhex(changed_args["call_content_id_hex"]))
        self.assertEqual(cid_for(changed_tool), bytes.fromhex(changed_tool["call_content_id_hex"]))
        self.assertNotEqual(cid_for(changed_args), base_cid)
        self.assertNotEqual(cid_for(changed_tool), base_cid)


class RoundTripOctetExact(unittest.TestCase):
    """(a) the core R4 property: a foreign tool call carried through this bridge -> signed N-AALP
    object -> verified -> RECOVERED foreign bytes is byte-identical to the original -- including
    when the original bytes are deliberately NOT in canonical form, proving nothing is
    re-serialized anywhere on the path (design.md Sec.19.1 / R-14.4)."""

    def test_raw_bytes_non_canonical_round_trip_byte_identical(self):
        # Deliberately non-canonical JSON (extra whitespace, keys out of alphabetical order) --
        # if anything on the path re-serialized this, the recovered bytes would differ.
        tool_bytes = b'{"name": "append_note",  "annotations": {"idempotentHint": false, "readOnlyHint": false, "destructiveHint": false}}'
        args_bytes = b'{"b": 2,   "a": 1, "text": "remember the milk"}'
        seed = _seed(0x71)
        pk = cose.mldsa_keygen("ML-DSA-65", seed)

        carried = carry_tool_call(tool_bytes, args_bytes, signer_seed=seed, created=1_800_000_000_001)
        self.assertEqual(carried.tool_bytes, tool_bytes)
        self.assertEqual(carried.args_bytes, args_bytes)

        recv = receive_tool_call(carried.signed_object, PROFILE, ALG, pk)
        self.assertEqual(recv.tool_bytes, tool_bytes, "recovered tool bytes must be byte-identical")
        self.assertEqual(recv.args_bytes, args_bytes, "recovered args bytes must be byte-identical")
        # and the developer-facing arguments/tool_definition still parse correctly despite the
        # non-canonical formatting
        self.assertEqual(recv.arguments, {"b": 2, "a": 1, "text": "remember the milk"})
        self.assertEqual(recv.tool_definition["name"], "append_note")

    def test_dict_convenience_round_trip_preserves_effect_and_audience_relevant_fields(self):
        """The dict-based ingestion path: effect class + the recovered foreign JSON-RPC shape
        both survive the boundary (auth/audit preservation)."""
        tool_def = {"name": "delete_file",
                    "annotations": {"readOnlyHint": False, "destructiveHint": True}}
        call = {"jsonrpc": "2.0", "id": 42, "method": "tools/call",
                "params": {"name": "delete_file", "arguments": {"path": "reports/q3.pdf"}}}
        seed = _seed(0x72)
        pk = cose.mldsa_keygen("ML-DSA-65", seed)

        carried = carry_tool_call_from_objects(tool_def, call, signer_seed=seed, created=1)
        self.assertEqual(carried.declared_effect, policy.DESTRUCTIVE)

        recv = receive_tool_call(carried.signed_object, PROFILE, ALG, pk)
        self.assertEqual(recv.enforced_effect, policy.DESTRUCTIVE)
        self.assertFalse(recv.mismatch)
        rebuilt = bridged_call_request(recv, rpc_id=42)
        self.assertEqual(rebuilt, call)  # the full foreign JSON-RPC shape recovers exactly


class EffectMappingIsApplied(unittest.TestCase):
    """(b) the annotation->effect mapping (design.md Sec.19.3) is genuinely applied -- not just
    threaded through as a constant -- across the full breadth of effect classes, and the
    more-severe resolution + fail-closed under-declaration rejection both hold."""

    def test_unannotated_tool_defaults_to_destructive(self):
        """The fail-closed crown jewel: a tool with NO annotations at all maps to destructive."""
        tool_def = {"name": "do_thing"}
        carried = carry_tool_call_from_objects(
            tool_def, {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "do_thing", "arguments": {}}},
            signer_seed=_seed(0x81), created=1)
        self.assertEqual(carried.annotation_mapped_effect, policy.DESTRUCTIVE)
        self.assertEqual(carried.declared_effect, policy.DESTRUCTIVE)

    def test_read_only_true_maps_to_read_only(self):
        tool_def = {"name": "get_weather", "annotations": {"readOnlyHint": True}}
        carried = carry_tool_call_from_objects(
            tool_def, {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "get_weather", "arguments": {}}},
            signer_seed=_seed(0x82), created=1)
        self.assertEqual(carried.annotation_mapped_effect, policy.READ_ONLY)

    def test_idempotent_write_maps_correctly(self):
        tool_def = {"name": "set_config",
                    "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True}}
        carried = carry_tool_call_from_objects(
            tool_def, {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "set_config", "arguments": {}}},
            signer_seed=_seed(0x83), created=1)
        self.assertEqual(carried.annotation_mapped_effect, policy.IDEMPOTENT_WRITE)

    def test_signer_may_escalate_declared_effect_above_the_mapping(self):
        """A wrapping signer MAY declare a MORE severe effect than its tool's own annotations map
        to (design.md Sec.19.4); the resolved enforced effect follows the more-severe declaration."""
        tool_def = {"name": "set_config",
                    "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True}}
        seed = _seed(0x84)
        pk = cose.mldsa_keygen("ML-DSA-65", seed)
        carried = carry_tool_call_from_objects(
            tool_def, {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "set_config", "arguments": {}}},
            signer_seed=seed, created=1, declared_effect=policy.DESTRUCTIVE)
        self.assertEqual(carried.annotation_mapped_effect, policy.IDEMPOTENT_WRITE)
        self.assertEqual(carried.declared_effect, policy.DESTRUCTIVE)
        recv = receive_tool_call(carried.signed_object, PROFILE, ALG, pk)
        self.assertEqual(recv.enforced_effect, policy.DESTRUCTIVE)
        self.assertTrue(recv.mismatch)

    def test_under_declared_signer_rejected_fail_closed(self):
        """§19.4: a wrapper's declared effect can never sit under the effect its own carried
        annotations map to. Signing succeeds (the design's own note: under-declaration is not
        rejected at construction); receive_tool_call is the enforcement point."""
        tool_def = {"name": "delete_file",
                    "annotations": {"readOnlyHint": False, "destructiveHint": True}}
        seed = _seed(0x85)
        pk = cose.mldsa_keygen("ML-DSA-65", seed)
        carried = carry_tool_call_from_objects(
            tool_def, {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "delete_file", "arguments": {}}},
            signer_seed=seed, created=1, declared_effect=policy.READ_ONLY)  # lies about its own annotations
        self.assertEqual(carried.declared_effect, policy.READ_ONLY)  # signing did not reject it
        with self.assertRaises(mcp.McpError) as cm:
            receive_tool_call(carried.signed_object, PROFILE, ALG, pk)
        self.assertEqual(cm.exception.kind, "EffectUnderDeclared")


class TamperDetectionFailsClosed(unittest.TestCase):
    """(c) a tampered/corrupted carried object fails verification, fail-closed, with a named
    error -- no partial or silent success."""

    def _carried(self, seed):
        tool_def = {"name": "get_weather", "annotations": {"readOnlyHint": True}}
        call = {"jsonrpc": "2.0", "method": "tools/call",
                "params": {"name": "get_weather", "arguments": {"location": "NYC"}}}
        return carry_tool_call_from_objects(tool_def, call, signer_seed=seed, created=1)

    def test_tampered_signature_rejected(self):
        seed = _seed(0x91)
        pk = cose.mldsa_keygen("ML-DSA-65", seed)
        carried = self._carried(seed)
        tampered = bytearray(carried.signed_object)
        tampered[-1] ^= 0xFF  # flip the final byte of the ML-DSA signature
        with self.assertRaises(envelope.EnvelopeError) as cm:
            receive_tool_call(bytes(tampered), PROFILE, ALG, pk)
        self.assertEqual(cm.exception.kind, "BadSignature")

    def test_verified_with_wrong_key_rejected(self):
        seed = _seed(0x92)
        wrong_pk = cose.mldsa_keygen("ML-DSA-65", _seed(0x93))
        carried = self._carried(seed)
        with self.assertRaises(envelope.EnvelopeError) as cm:
            receive_tool_call(carried.signed_object, PROFILE, ALG, wrong_pk)
        self.assertEqual(cm.exception.kind, "BadSignature")

    def test_non_json_tool_bytes_rejected_before_signing(self):
        with self.assertRaises(BridgeError) as cm:
            carry_tool_call(b"not json at all", b"{}", signer_seed=_seed(0x94), created=1)
        self.assertEqual(cm.exception.kind, "ForeignToolNotJSON")


class ToolNameMismatchAndMalformed(unittest.TestCase):
    """Bridge-only sanity checks with no Part-1 analogue (Part-1 has no notion of a tool name)."""

    def test_call_naming_a_different_tool_rejected(self):
        tool_def = {"name": "get_weather", "annotations": {"readOnlyHint": True}}
        call = {"jsonrpc": "2.0", "method": "tools/call",
                "params": {"name": "delete_file", "arguments": {}}}
        with self.assertRaises(BridgeError) as cm:
            carry_tool_call_from_objects(tool_def, call, signer_seed=_seed(0xA1), created=1)
        self.assertEqual(cm.exception.kind, "ToolNameMismatch")

    def test_call_request_missing_params_rejected(self):
        tool_def = {"name": "get_weather"}
        with self.assertRaises(BridgeError) as cm:
            carry_tool_call_from_objects(tool_def, {"jsonrpc": "2.0", "method": "tools/call"},
                                          signer_seed=_seed(0xA2), created=1)
        self.assertEqual(cm.exception.kind, "ForeignCallMalformed")


class ApprovalBindsExactCall(unittest.TestCase):
    """(d) an approval binds the EXACT call (tool_id + args_id); a changed argument invalidates a
    prior approval -- named ApprovalRequired, fail-closed, no ledger append."""

    def _signed_call(self, seed, tool_name, args, declared=None):
        tool_def = {"name": tool_name, "annotations": {"readOnlyHint": False, "destructiveHint": True}}
        call = {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": tool_name, "arguments": args}}
        return carry_tool_call_from_objects(tool_def, call, signer_seed=seed, created=1,
                                             declared_effect=declared)

    def test_approval_authorizes_the_exact_call_and_is_single_use(self):
        seed = _seed(0xB1)
        pk = cose.mldsa_keygen("ML-DSA-65", seed)
        carried = self._signed_call(seed, "transfer", {"to": "acct-1", "amount": 100})
        recv = receive_tool_call(carried.signed_object, PROFILE, ALG, pk)

        approver_seed = _seed(0xB2)
        rec = approval.ApprovalRecord(recv.call_binding_content_id, "approver-1", policy.DESTRUCTIVE,
                                       b"\x01" * 8, 9_999_999_999_999, "")
        sig = approval.sign_approval(rec, ALG, approver_seed)
        approver_pk = cose.mldsa_keygen("ML-DSA-65", approver_seed)

        with tempfile.TemporaryDirectory() as d:
            ledger = approval.open_ledger(os.path.join(d, "consume.wal"))
            try:
                recv.authorize(rec, ALG, approver_pk, sig, "requester-1", 1, ledger)  # succeeds, consumes
                with self.assertRaises(approval.ApprovalError) as cm:
                    recv.authorize(rec, ALG, approver_pk, sig, "requester-1", 1, ledger)  # replay
                self.assertEqual(cm.exception.kind, "AlreadyConsumed")
            finally:
                ledger.close()  # Windows: TemporaryDirectory cleanup fails on an open WAL handle

    def test_approval_bound_to_original_args_rejects_changed_args_call(self):
        """AC-6.1.2: an approval for args A does not satisfy a call with args B."""
        seed = _seed(0xB3)
        pk = cose.mldsa_keygen("ML-DSA-65", seed)
        carried_a = self._signed_call(seed, "transfer", {"to": "acct-1", "amount": 100})
        recv_a = receive_tool_call(carried_a.signed_object, PROFILE, ALG, pk)
        carried_b = self._signed_call(seed, "transfer", {"to": "acct-2", "amount": 100})
        recv_b = receive_tool_call(carried_b.signed_object, PROFILE, ALG, pk)
        self.assertNotEqual(recv_a.call_binding_content_id, recv_b.call_binding_content_id)

        approver_seed = _seed(0xB4)
        rec = approval.ApprovalRecord(recv_a.call_binding_content_id, "approver-1", policy.DESTRUCTIVE,
                                       b"\x02" * 8, 9_999_999_999_999, "")
        sig = approval.sign_approval(rec, ALG, approver_seed)
        approver_pk = cose.mldsa_keygen("ML-DSA-65", approver_seed)

        with tempfile.TemporaryDirectory() as d:
            ledger = approval.open_ledger(os.path.join(d, "consume.wal"))
            try:
                with self.assertRaises(mcp.McpError) as cm:
                    recv_b.authorize(rec, ALG, approver_pk, sig, "requester-1", 1, ledger)
                self.assertEqual(cm.exception.kind, "ApprovalRequired")
                # the rejected wrong-args attempt appended nothing -- the original call can still
                # be authorized by the same (still-valid, still-unconsumed) approval.
                recv_a.authorize(rec, ALG, approver_pk, sig, "requester-1", 1, ledger)
            finally:
                ledger.close()  # Windows: TemporaryDirectory cleanup fails on an open WAL handle

    def test_approval_bound_to_original_tool_description_rejects_changed_description_call(self):
        """AC-6.1.3: a changed tool description invalidates a prior approval."""
        seed = _seed(0xB5)
        pk = cose.mldsa_keygen("ML-DSA-65", seed)
        args = {"to": "acct-1", "amount": 100}

        def call_with_description(desc):
            tool_def = {"name": "transfer", "description": desc,
                        "annotations": {"readOnlyHint": False, "destructiveHint": True}}
            req = {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "transfer", "arguments": args}}
            return carry_tool_call_from_objects(tool_def, req, signer_seed=seed, created=1)

        carried_1 = call_with_description("Transfer funds")
        recv_1 = receive_tool_call(carried_1.signed_object, PROFILE, ALG, pk)
        carried_2 = call_with_description("Transfer funds (updated wording)")
        recv_2 = receive_tool_call(carried_2.signed_object, PROFILE, ALG, pk)
        self.assertNotEqual(recv_1.call_binding_content_id, recv_2.call_binding_content_id)

        approver_seed = _seed(0xB6)
        rec = approval.ApprovalRecord(recv_1.call_binding_content_id, "approver-1", policy.DESTRUCTIVE,
                                       b"\x03" * 8, 9_999_999_999_999, "")
        sig = approval.sign_approval(rec, ALG, approver_seed)
        approver_pk = cose.mldsa_keygen("ML-DSA-65", approver_seed)

        with tempfile.TemporaryDirectory() as d:
            ledger = approval.open_ledger(os.path.join(d, "consume.wal"))
            try:
                with self.assertRaises(mcp.McpError) as cm:
                    recv_2.authorize(rec, ALG, approver_pk, sig, "requester-1", 1, ledger)
                self.assertEqual(cm.exception.kind, "ApprovalRequired")
            finally:
                ledger.close()  # Windows: TemporaryDirectory cleanup fails on an open WAL handle


if __name__ == "__main__":
    unittest.main()
