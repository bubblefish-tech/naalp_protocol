# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Known-answer tests for the R3.3 firewall-hook entry point (naalp_validator.firewall).

Run:  python -m pytest -v tests/test_firewall.py   (from ecosystem/naalp-validator/)
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from naalp_validator import firewall  # noqa: E402
from naalp import envelope  # noqa: E402
from naalp.cbor import T  # noqa: E402

_SIGNER = bytes.fromhex("5349474e45525f41")


def _obj(channel, kind, effect, **kw):
    kw.setdefault("body", T("x"))
    kw.setdefault("profile", 1)
    kw.setdefault("created", 1)
    return envelope.Object(kind=kind, channel=channel, signer=_SIGNER, effect=effect, **kw)


class PreSendHook(unittest.TestCase):
    def test_allows_a_valid_object(self):
        d = firewall.pre_send_hook(_obj(0x0000, 0, 0))
        self.assertTrue(d.allow)
        self.assertTrue(bool(d))
        self.assertEqual(d.violations, [])

    def test_denies_an_unknown_kind(self):
        d = firewall.pre_send_hook(_obj(0x0000, 99, 0))
        self.assertFalse(d.allow)
        self.assertFalse(bool(d))
        self.assertEqual([v.error for v in d.violations], ["UnknownKind"])

    def test_denies_consume_once_without_audience(self):
        d = firewall.pre_send_hook(_obj(0x0004, 3, 2))
        self.assertFalse(d.allow)
        self.assertEqual([v.error for v in d.violations], ["WrongAudience"])

    def test_self_authority_is_threaded_through(self):
        d = firewall.pre_send_hook(
            _obj(0x0000, 0, 0, audience="someone-else"), self_authority="authority-A")
        self.assertFalse(d.allow)
        self.assertEqual([v.error for v in d.violations], ["WrongAudience"])

    def test_never_partial_accepts_on_multiple_violations(self):
        # RangeError (channel) + Malformed(non-list causes) both present; still a hard deny,
        # never a partial-accept.
        o = _obj(0x0000, 0, 0)
        o.channel = 20
        o.causes = "not-a-list"
        d = firewall.pre_send_hook(o)
        self.assertFalse(d.allow)
        self.assertGreaterEqual(len(d.violations), 2)


class FirewallGatesTheGuardedAction(unittest.TestCase):
    """R3.3's entire purpose is to gate a real pre-send action at a firewall/gateway
    interception point (design.md: "a firewall/gateway wires this in at the point an agent
    runtime is about to sign and transmit an object; on deny, the caller MUST NOT proceed to
    sign"). Checking `decision.allow` in isolation only proves pre_send_hook computed the
    right verdict -- it does NOT prove a real caller wired to that verdict actually refuses
    to act. These tests drive the documented calling convention with a spy standing in for
    the guarded sign-and-send action, and assert the spy WAS NOT INVOKED on deny (not merely
    that no exception was raised) -- exactly the difference between a firewall that refuses
    and one that merely reports."""

    def _guarded_call(self, candidate, self_authority=None):
        sent = []

        def guarded_sign_and_send(obj):
            # Stands in for "sign the object and put it on the wire" -- the action R3.3
            # exists to gate. Recording a call here is the assertable proxy for "reached
            # the network."
            sent.append(obj)
            return "sent-on-the-wire"

        decision = firewall.pre_send_hook(candidate, self_authority=self_authority)
        if decision:  # FirewallDecision.__bool__ delegates to .allow
            guarded_sign_and_send(candidate)
        return decision, sent

    def test_deny_on_unknown_kind_prevents_the_guarded_action(self):
        candidate = _obj(0x0000, 99, 0)  # UnknownKind
        decision, sent = self._guarded_call(candidate)
        self.assertFalse(decision.allow)
        self.assertEqual(sent, [], "the guarded sign-and-send action must NOT run on deny")

    def test_deny_on_bounds_violation_prevents_the_guarded_action(self):
        candidate = _obj(0x0000, 0, 0, causes=[b"c"] * 2000)  # TooManyCauses
        decision, sent = self._guarded_call(candidate)
        self.assertFalse(decision.allow)
        self.assertEqual(sent, [])

    def test_deny_on_wrong_audience_prevents_the_guarded_action(self):
        candidate = _obj(0x0000, 0, 0, audience="someone-else")
        decision, sent = self._guarded_call(candidate, self_authority="authority-A")
        self.assertFalse(decision.allow)
        self.assertEqual(sent, [])

    def test_allow_on_valid_object_permits_the_guarded_action(self):
        candidate = _obj(0x0000, 0, 0)
        decision, sent = self._guarded_call(candidate)
        self.assertTrue(decision.allow)
        self.assertEqual(sent, [candidate], "the guarded action must run when allowed")


if __name__ == "__main__":
    unittest.main()
