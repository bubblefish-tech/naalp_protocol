# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""Conformance tests for naalp_mcp_guard.proxy.GuardProxy (Group 6, Task A.1). Exercises the
message-routing/caching logic against a REAL EffectGate (real crypto, real ledger, real HITL
interceptor), with a fake `forward` standing in for the transport layer -- proving the policy
logic is correct independent of any subprocess.

Run (from ecosystem/naalp-mcp-guard/, PYTHONDONTWRITEBYTECODE=1):
    python -m unittest -v tests.test_proxy
"""
import os
import sys
import tempfile
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PKG_ROOT = os.path.dirname(_THIS_DIR)
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

from naalp_mcp_guard.effect_gate import EffectGate  # noqa: E402
from naalp_mcp_guard.proxy import GuardProxy  # noqa: E402
from naalp_mcp_guard import receipt as receipt_mod  # noqa: E402

from naalp import approval, cose  # noqa: E402
from naalp_hitl.interceptor import HumanInterface  # noqa: E402
from naalp_hitl.refusal_log import JsonlRefusalLog  # noqa: E402

ALG = cose.ALG_MLDSA65
AUDIENCE = "svc:mcp-guard-proxy-test"


class _AlwaysDenyInterface(HumanInterface):
    def request_approval(self, request):
        return None


class GuardProxyTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        guard_seed = bytes([0x61]) * 32
        approver_seed = bytes([0x62]) * 32
        approver_pk = cose.mldsa_keygen("ML-DSA-65", approver_seed)
        self.ledger = approval.open_ledger(os.path.join(self._tmp.name, "ledger.wal"), authority=AUDIENCE)
        self.addCleanup(self.ledger.close)
        refusal_log = JsonlRefusalLog(os.path.join(self._tmp.name, "refusals.jsonl"))
        gate = EffectGate(
            guard_seed=guard_seed, guard_identity="guard-1", audience=AUDIENCE,
            approver_alg=ALG, approver_pubkey=approver_pk,
            human_interface=_AlwaysDenyInterface(), refusal_log=refusal_log, ledger=self.ledger,
        )
        self.receipts_dir = os.path.join(self._tmp.name, "receipts")
        self.proxy = GuardProxy(gate, receipts_dir=self.receipts_dir)

    def test_note_tools_list_response_populates_the_cache(self):
        response = {
            "jsonrpc": "2.0", "id": 1,
            "result": {"tools": [{"name": "list_files", "annotations": {"readOnlyHint": True}}]},
        }
        self.proxy.note_tools_list_response(response)
        self.assertIn("list_files", self.proxy.known_tools)

    def test_note_tools_list_response_ignores_malformed_input(self):
        self.proxy.note_tools_list_response({"jsonrpc": "2.0", "id": 1, "result": {}})
        self.proxy.note_tools_list_response("not even a dict")
        self.assertEqual(self.proxy.known_tools, {})

    def test_read_only_call_forwards_and_returns_the_real_result(self):
        self.proxy.note_tools_list_response({
            "jsonrpc": "2.0", "id": 0,
            "result": {"tools": [{"name": "list_files", "annotations": {"readOnlyHint": True}}]},
        })
        request = {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                   "params": {"name": "list_files", "arguments": {}}}
        real_response = {"jsonrpc": "2.0", "id": 5, "result": {"content": [], "isError": False}}
        response = self.proxy.handle_tools_call(request, forward=lambda: real_response)
        self.assertEqual(response, real_response)

    def test_denied_destructive_call_returns_a_fail_closed_is_error_result_never_forwarding(self):
        self.proxy.note_tools_list_response({
            "jsonrpc": "2.0", "id": 0,
            "result": {"tools": [{"name": "delete_repo", "annotations": {"readOnlyHint": False, "destructiveHint": True}}]},
        })
        request = {"jsonrpc": "2.0", "id": 9, "method": "tools/call",
                   "params": {"name": "delete_repo", "arguments": {}}}
        forwarded = {"called": False}

        def forward():
            forwarded["called"] = True
            return {"result": "SHOULD_NEVER_HAPPEN"}

        response = self.proxy.handle_tools_call(request, forward=forward)
        self.assertFalse(forwarded["called"])
        self.assertEqual(response["id"], 9)
        self.assertTrue(response["result"]["isError"])
        self.assertIn("naalp_guard_denied", response["result"]["content"][0]["text"])

    def test_denied_call_still_persists_a_verifiable_receipt_file(self):
        request = {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                   "params": {"name": "unseen_tool", "arguments": {}}}
        self.proxy.handle_tools_call(request, forward=lambda: {"result": "no"})
        files = os.listdir(self.receipts_dir)
        self.assertEqual(len(files), 1)
        with open(os.path.join(self.receipts_dir, files[0]), "rb") as f:
            data = f.read()
        self.assertTrue(receipt_mod.verify_receipt_bytes(data))

    def test_malformed_request_is_refused_not_raised(self):
        request = {"jsonrpc": "2.0", "id": 7, "method": "tools/call"}  # missing params entirely
        response = self.proxy.handle_tools_call(request, forward=lambda: {"result": "no"})
        self.assertTrue(response["result"]["isError"])


if __name__ == "__main__":
    unittest.main()
