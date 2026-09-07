# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
C10 channel state-machine + Workflow input-gate conformance for the Python SDK, graded against
the shared independent oracle vectors/channels/<name>/cases.json (NOT produced by this code):
per-channel id/name/kinds/states/transitions/errors (== Go == Rust == oracle), the twenty-channel
completeness sweep, representative AllowedTransition verdicts, Spatial's TransformCycle structural
check, and the Workflow durable input/approval gate whose crash test proves InputGateBypass cannot
occur (design-channels.md §18, mirrors impl/go/channels/channels_test.go).

TestWorkflowInputGateBypass is the MUTATION ANCHOR (design-channels.md §18): a task cannot Run
before its input/approval gate is passed, and the gate is DURABLE -- after a simulated crash
(close + reopen) it is STILL gated until SupplyInput. Neutering the gate check in WorkflowGate.run
(letting Run succeed from "awaiting-input"/"awaiting-approval") flips this test RED.

Written test-first; several surfaces (ChannelSpec/KindSpec, channel(), allowed_transition(),
check_frame_tree(), WorkflowGate/open_workflow_gate()) are absent until this task lands, so this
fails RED on import/AttributeError until impl/python/naalp/channels.py is extended.

Run:  python -m pytest tests/test_channels.py -q      (from impl/python/, using the port's
designated Python interpreter)
"""
import json
import os
import unittest

from naalp import channels
from naalp import policy


def _load_channel(name):
    """Walk up from this test file looking for vectors/channels/<name>/cases.json (the repo root
    is several levels above impl/python/tests/), mirroring the existing _vectors_file idiom used
    by test_approval.py / test_producing_boundary.py."""
    d = os.path.dirname(os.path.abspath(__file__))
    for _ in range(6):
        p = os.path.join(d, "vectors", "channels", name, "cases.json")
        if os.path.isfile(p):
            with open(p, encoding="utf-8") as f:
                return json.load(f)
        d = os.path.dirname(d)
    raise FileNotFoundError("vectors/channels/%s/cases.json not found" % name)


class ChannelsMatchesOracle(unittest.TestCase):
    """Mirrors Go TestTableMatchesOracle: the frozen impl registry equals the independent
    per-channel oracle, in both directions (=> Python == Go == Rust, which grades the same
    vectors). Exercises the ChannelSpec/KindSpec surface via channels.channel(id)."""

    def test_all_twenty_channels_match_oracle(self):
        ids = [c.id for c in channels.all_channels()]
        self.assertEqual(len(ids), 20, "table has %d channels, want 20" % len(ids))
        for ch in channels.all_channels():
            c = _load_channel(ch.name.lower())
            self.assertEqual(c["channel_id"], ch.id, "%s: id" % ch.name)
            self.assertEqual(c["name"], ch.name, "%s: name" % ch.name)
            self.assertEqual(len(c["kinds"]), len(ch.kinds), "%s: kind count" % ch.name)
            for i, k in enumerate(ch.kinds):
                o = c["kinds"][i]
                self.assertEqual(k.code, o["code"], "%s kind %d code" % (ch.name, i))
                self.assertEqual(k.name, o["name"], "%s kind %d name" % (ch.name, i))
                self.assertEqual(k.effect, o["effect"], "%s kind %d effect" % (ch.name, i))
                self.assertEqual(k.variable, o["variable"], "%s kind %d variable" % (ch.name, i))
            self.assertEqual(len(c["transitions"]), len(ch.transitions), "%s: transition count" % ch.name)
            for i, tr in enumerate(ch.transitions):
                self.assertEqual(tr[0], c["transitions"][i]["from"], "%s transition %d from" % (ch.name, i))
                self.assertEqual(tr[1], c["transitions"][i]["to"], "%s transition %d to" % (ch.name, i))
            self.assertEqual(list(ch.states), c["states"], "%s: states" % ch.name)
            self.assertEqual(list(ch.errors), c["errors"], "%s: errors" % ch.name)

    def test_channel_accessor_by_id(self):
        """channels.channel(id) returns the registered spec for a known id and None for an
        unregistered one (mirrors Go channels.Channel(id) / Rust channels::channel(id))."""
        c = channels.channel(0x0011)
        self.assertIsNotNone(c, "Workflow channel must be registered")
        self.assertEqual(c.id, 0x0011)
        self.assertEqual(c.name, "Workflow")
        self.assertIsNone(channels.channel(0x00FF), "unregistered channel id must be None")


class ChannelsCompleteness(unittest.TestCase):
    """Mirrors Go TestCompleteness: all twenty channels are present with ids 0..19, none thinned --
    every channel has at least one kind, and every kind a valid declared effect (R-11.1/R-11.2)."""

    def test_completeness(self):
        seen = set()
        for ch in channels.all_channels():
            self.assertTrue(len(ch.kinds) > 0, "%s has no kinds (thinned surface)" % ch.name)
            for k in ch.kinds:
                self.assertLessEqual(k.effect, policy.DESTRUCTIVE, "%s.%s has invalid effect %d" % (ch.name, k.name, k.effect))
            seen.add(ch.id)
        for cid in range(0, 0x0014):
            self.assertIn(cid, seen, "channel %#x missing" % cid)


class ChannelsStateMachine(unittest.TestCase):
    """Mirrors Go TestStateMachine: representative channels permit their declared transitions and
    reject others."""

    CASES = [
        (0x0001, "offered", "accepted", True),        # Memory
        (0x0001, "live", "revoked", True),             # Memory
        (0x0001, "revoked", "live", False),            # Memory regression
        (0x000E, "order", "fulfil", True),             # Commerce
        (0x000E, "offer", "fulfil", False),            # Commerce skip
        (0x0011, "awaiting-input", "running", True),   # Workflow
        (0x0011, "created", "running", False),         # Workflow gate skip
    ]

    def test_allowed_transition(self):
        for ch, frm, to, ok in self.CASES:
            with self.subTest(ch=hex(ch), frm=frm, to=to):
                self.assertEqual(channels.allowed_transition(ch, frm, to), ok,
                                  "channel %#x %s->%s" % (ch, frm, to))

    def test_unregistered_channel_never_allows(self):
        self.assertFalse(channels.allowed_transition(0x00FF, "a", "b"))


class ChannelsTransformCycle(unittest.TestCase):
    """Mirrors Go TestTransformCycle: Spatial's named error fires on a cyclic coordinate-frame
    tree, and a valid tree is accepted."""

    def test_valid_tree_accepted(self):
        tree = {"base": "", "arm": "base", "hand": "arm"}
        channels.check_frame_tree(tree)  # must not raise

    def test_cyclic_tree_rejected(self):
        cyclic = {"a": "b", "b": "c", "c": "a"}
        with self.assertRaises(channels.TransformCycle) as cm:
            channels.check_frame_tree(cyclic)
        self.assertEqual(cm.exception.kind, "TransformCycle")


class ChannelsWorkflowInputGateBypass(unittest.TestCase):
    """MUTATION ANCHOR (design-channels.md §18): the gated crash test -- a task cannot reach
    "running" without passing the input/approval gate, and a crash (close -> reopen) recovers to
    the pre-gate status rather than bypassing it. Neutering the gate check in WorkflowGate.run
    flips this test RED (Run-before-input would succeed instead of raising InputGateBypass)."""

    def test_gate_survives_a_simulated_crash(self):
        import tempfile
        d = tempfile.mkdtemp()
        path = os.path.join(d, "wf")
        g = channels.open_workflow_gate(path)
        g.create("t1", False)

        # Running before input is InputGateBypass.
        with self.assertRaises(channels.InputGateBypass) as cm:
            g.run("t1")
        self.assertEqual(cm.exception.kind, "InputGateBypass")

        # Simulate a crash right after Create: close, then reopen -- the durable status is still
        # the pre-gate status (the gate is DURABLE, a crash cannot bypass it).
        g.close()
        g2 = channels.open_workflow_gate(path)
        self.assertEqual(g2.status("t1"), "awaiting-input", "crash bypassed the gate")
        with self.assertRaises(channels.InputGateBypass) as cm:
            g2.run("t1")
        self.assertEqual(cm.exception.kind, "InputGateBypass")

        # Supplying input opens the gate; only then may it run.
        g2.supply_input("t1")
        g2.run("t1")
        self.assertEqual(g2.status("t1"), "running")
        g2.close()

    def test_create_rejects_duplicate_task(self):
        import tempfile
        d = tempfile.mkdtemp()
        path = os.path.join(d, "wf2")
        g = channels.open_workflow_gate(path)
        g.create("t1", False)
        with self.assertRaises(channels.TaskStateError):
            g.create("t1", False)
        g.close()

    def test_approval_gate_path(self):
        import tempfile
        d = tempfile.mkdtemp()
        path = os.path.join(d, "wf3")
        g = channels.open_workflow_gate(path)
        g.create("t2", True)
        self.assertEqual(g.status("t2"), "awaiting-approval")
        with self.assertRaises(channels.InputGateBypass):
            g.run("t2")
        g.supply_input("t2")
        self.assertEqual(g.status("t2"), "approved")
        g.run("t2")
        self.assertEqual(g.status("t2"), "running")
        g.close()

    def test_run_unknown_task_is_task_state_error(self):
        import tempfile
        d = tempfile.mkdtemp()
        path = os.path.join(d, "wf4")
        g = channels.open_workflow_gate(path)
        with self.assertRaises(channels.TaskStateError):
            g.run("ghost")
        g.close()


if __name__ == "__main__":
    unittest.main()
