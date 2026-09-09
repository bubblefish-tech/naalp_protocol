# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""Transport-layer tests for naalp_mcp_guard.cli (Group 6, Task A.1). `_DownstreamServer` is
exercised against a REAL subprocess (tests/fixtures/echo_mcp_server.py) speaking the real
newline-delimited JSON-RPC stdio framing -- this is not a mock of the transport, it is the real
transport code driving a real child process. `_route_client_message`/`cmd_verify` are exercised
with fakes standing in for the wrapped server and the filesystem respectively, matching how
tests/test_proxy.py isolates policy from transport.

Run (from ecosystem/naalp-mcp-guard/, PYTHONDONTWRITEBYTECODE=1, with `sys.executable` -- the
SAME interpreter running this test -- used to launch the fixture subprocess, never a bare
`python`/`python3` command that may resolve to a platform stub):
    python -m unittest -v tests.test_cli
"""
import io
import json
import os
import sys
import tempfile
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PKG_ROOT = os.path.dirname(_THIS_DIR)
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

from naalp_mcp_guard import cli  # noqa: E402
from naalp_mcp_guard import receipt as receipt_mod  # noqa: E402
from naalp import cose  # noqa: E402

_FIXTURE = os.path.join(_THIS_DIR, "fixtures", "echo_mcp_server.py")


class DownstreamServerRealSubprocessTests(unittest.TestCase):
    """A real subprocess round-trip: no fake, no in-process stand-in for the child process."""

    def setUp(self):
        self.downstream = cli._DownstreamServer([sys.executable, _FIXTURE])
        self.addCleanup(self.downstream.close)

    def test_tools_list_round_trips_through_a_real_subprocess(self):
        response = self.downstream.call({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        names = {t["name"] for t in response["result"]["tools"]}
        self.assertIn("list_files", names)
        self.assertIn("delete_repo", names)

    def test_tools_call_round_trips_through_a_real_subprocess(self):
        response = self.downstream.call({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "echo", "arguments": {"x": 1}},
        })
        self.assertFalse(response["result"]["isError"])
        self.assertIn("echoed:", response["result"]["content"][0]["text"])

    def test_unsolicited_server_notification_is_queued_not_lost(self):
        response = self.downstream.call({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "notify_then_reply", "arguments": {}},
        })
        self.assertFalse(response["result"]["isError"])
        unsolicited = self.downstream.drain_unsolicited()
        self.assertEqual(len(unsolicited), 1)
        self.assertEqual(unsolicited[0]["method"], "notifications/message")

    def test_two_ids_do_not_cross_talk(self):
        r1 = self.downstream.call({"jsonrpc": "2.0", "id": "a", "method": "tools/call",
                                    "params": {"name": "echo", "arguments": {"v": "a"}}})
        r2 = self.downstream.call({"jsonrpc": "2.0", "id": "b", "method": "tools/call",
                                    "params": {"name": "echo", "arguments": {"v": "b"}}})
        self.assertEqual(r1["id"], "a")
        self.assertEqual(r2["id"], "b")
        self.assertIn('"v": "a"', r1["result"]["content"][0]["text"])
        self.assertIn('"v": "b"', r2["result"]["content"][0]["text"])


class RouteClientMessageTests(unittest.TestCase):
    """Pure routing-shape tests with a fake downstream/proxy -- mirrors tests/test_proxy.py's
    isolation-from-transport discipline, one layer up."""

    class _FakeDownstream:
        def __init__(self):
            self.sent = []
            self.calls = []

        def call(self, msg):
            self.calls.append(msg)
            return {"jsonrpc": "2.0", "id": msg.get("id"), "result": {"ok": True}}

        def send(self, msg):
            self.sent.append(msg)

        def drain_unsolicited(self):
            return []

    class _FakeProxy:
        def __init__(self):
            self.gated = []
            self.noted = []

        def handle_tools_call(self, request, forward):
            self.gated.append(request)
            return forward()

        def note_tools_list_response(self, response):
            self.noted.append(response)

    def test_tools_call_is_routed_through_the_proxy_not_forwarded_directly(self):
        downstream = self._FakeDownstream()
        proxy = self._FakeProxy()
        out = io.StringIO()
        msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "x"}}
        cli._route_client_message(msg, downstream, proxy, out)
        self.assertEqual(len(proxy.gated), 1)
        written = json.loads(out.getvalue())
        self.assertEqual(written["result"], {"ok": True})

    def test_tools_list_is_forwarded_and_cached(self):
        downstream = self._FakeDownstream()
        proxy = self._FakeProxy()
        out = io.StringIO()
        msg = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
        cli._route_client_message(msg, downstream, proxy, out)
        self.assertEqual(len(proxy.noted), 1)
        self.assertEqual(len(downstream.calls), 1)

    def test_other_request_is_passed_through_unmodified(self):
        downstream = self._FakeDownstream()
        proxy = self._FakeProxy()
        out = io.StringIO()
        msg = {"jsonrpc": "2.0", "id": 3, "method": "initialize"}
        cli._route_client_message(msg, downstream, proxy, out)
        self.assertEqual(len(downstream.calls), 1)
        self.assertEqual(len(proxy.gated), 0)

    def test_notification_is_sent_not_called(self):
        downstream = self._FakeDownstream()
        proxy = self._FakeProxy()
        out = io.StringIO()
        msg = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        cli._route_client_message(msg, downstream, proxy, out)
        self.assertEqual(len(downstream.sent), 1)
        self.assertEqual(len(downstream.calls), 0)

    def test_client_reply_to_server_request_is_sent_not_called(self):
        """A message with an id but no method is a RESPONSE (here, the client answering
        something the server asked) -- it must be relayed downstream uncorrelated, never routed
        through `.call()` (which would wait forever for a reply to a reply)."""
        downstream = self._FakeDownstream()
        proxy = self._FakeProxy()
        out = io.StringIO()
        msg = {"jsonrpc": "2.0", "id": 42, "result": {"answer": 1}}
        cli._route_client_message(msg, downstream, proxy, out)
        self.assertEqual(len(downstream.sent), 1)
        self.assertEqual(len(downstream.calls), 0)


class CmdVerifyTests(unittest.TestCase):
    def test_valid_receipt_file_prints_pass_and_exits_zero(self):
        with tempfile.TemporaryDirectory() as d:
            seed = bytes([0x71]) * 32
            pk = cose.mldsa_keygen("ML-DSA-65", seed)
            rec = receipt_mod.EffectReceipt(
                tool_id=b"\x01" * 50, args_id=b"\x02" * 50, call_id=b"\x03" * 50, effect=1,
                decision=receipt_mod.DECISION_EXECUTED, reason="", result_hash=b"\x04" * 50,
                principal="", tool_name="x", guard_identity="g", created_ms=1,
            )
            sig = receipt_mod.sign_effect_receipt(rec, cose.ALG_MLDSA65, seed)
            path = os.path.join(d, "r.json")
            receipt_mod.write_receipt_file(path, rec, cose.ALG_MLDSA65, pk, sig)
            args = cli.build_parser().parse_args(["verify", path])
            self.assertEqual(cli.cmd_verify(args), 0)

    def test_tampered_receipt_file_exits_nonzero(self):
        with tempfile.TemporaryDirectory() as d:
            seed = bytes([0x72]) * 32
            pk = cose.mldsa_keygen("ML-DSA-65", seed)
            rec = receipt_mod.EffectReceipt(
                tool_id=b"\x01" * 50, args_id=b"\x02" * 50, call_id=b"\x03" * 50, effect=1,
                decision=receipt_mod.DECISION_EXECUTED, reason="", result_hash=b"\x04" * 50,
                principal="", tool_name="x", guard_identity="g", created_ms=1,
            )
            sig = receipt_mod.sign_effect_receipt(rec, cose.ALG_MLDSA65, seed)
            path = os.path.join(d, "r.json")
            receipt_mod.write_receipt_file(path, rec, cose.ALG_MLDSA65, pk, sig)
            with open(path, "r", encoding="utf-8") as f:
                obj = json.load(f)
            obj["body"] = "00" + obj["body"][2:]
            with open(path, "w", encoding="utf-8") as f:
                json.dump(obj, f)
            args = cli.build_parser().parse_args(["verify", path])
            self.assertEqual(cli.cmd_verify(args), 1)


if __name__ == "__main__":
    unittest.main()
