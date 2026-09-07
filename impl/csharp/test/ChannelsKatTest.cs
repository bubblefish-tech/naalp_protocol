// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

using Naalp;
using Xunit;

namespace Sh.Bubblefish.Naalp.Tests
{
    /// <summary>
    /// The C10 channels wave (task #174) for the C# SDK: the <see cref="Channels.AllowedTransition"/>
    /// state-machine guard, the public <see cref="Channels.ChannelSpec"/>/<see cref="Channels.GetChannel"/>
    /// parity accessor, <see cref="Channels.CheckFrameTree"/> (Spatial TransformCycle, §20), and the
    /// durable WAL-backed <see cref="Channels.WorkflowGate"/> whose crash test proves InputGateBypass
    /// cannot occur (design-channels.md §18).
    ///
    /// <para>Graded against the independent, non-circular <c>vectors/channels/&lt;name&gt;/cases.json</c>
    /// corpus (NOT produced by this code) — the same corpus impl/go/channels/channels_test.go
    /// (TestTableMatchesOracle, TestStateMachine, TestTransformCycle, TestWorkflowInputGateBypass) and
    /// impl/rust/src/channels.rs's <c>#[cfg(test)]</c> module grade against. There is no CBOR/wire
    /// encoding in this surface (the twenty-channel registry and the WAL gate are internal state, not
    /// signed objects) — matching Go/Rust, which likewise define no encoder here — so this KAT grades
    /// verdicts (allowed/denied, accept/reject, gate status) rather than byte parity.</para>
    ///
    /// <para>Run: <c>dotnet test test/Bubblefish.Naalp.Tests.csproj --filter FullyQualifiedName~ChannelsKatTest</c></para>
    /// </summary>
    public sealed class ChannelsKatTest
    {
        // The twenty channel names in Table order (design-channels.md §1..§20), lower-cased to match
        // the vectors/channels/<name>/ directory naming.
        private static readonly string[] AllChannelNames =
        {
            "control", "memory", "capability", "identity", "governance", "immune", "federation",
            "settlement", "compliance", "sensory", "telemetry", "audit", "stream", "bridge",
            "commerce", "interaction", "discovery", "workflow", "knowledge", "spatial",
        };

        private static JsonElement LoadChannel(string dir)
        {
            var d = new DirectoryInfo(AppContext.BaseDirectory);
            string rel = Path.Combine("vectors", "channels", dir, "cases.json");
            for (int i = 0; i < 12 && d != null; i++)
            {
                string p = Path.Combine(d.FullName, rel);
                if (File.Exists(p))
                {
                    return JsonDocument.Parse(File.ReadAllText(p)).RootElement.Clone();
                }
                d = d.Parent;
            }
            throw new Xunit.Sdk.XunitException(rel + " not found from " + AppContext.BaseDirectory);
        }

        // ==== full descriptor parity: id/name/kinds/states/transitions/errors == the independent
        //      oracle, for all twenty channels (mirrors Go TestTableMatchesOracle / Rust table_matches_oracle) =

        [Fact]
        public void ChannelSpecMatchesOracleForAllTwentyChannels()
        {
            int n = 0;
            foreach (string dir in AllChannelNames)
            {
                JsonElement c = LoadChannel(dir);
                long id = c.GetProperty("channel_id").GetInt64();
                Channels.ChannelSpec? spec = Channels.GetChannel(id);
                Assert.NotNull(spec);
                Channels.ChannelSpec s = spec!;
                Assert.Equal(id, s.Id);
                Assert.Equal(c.GetProperty("name").GetString(), s.Name);

                JsonElement kinds = c.GetProperty("kinds");
                Assert.Equal(kinds.GetArrayLength(), s.Kinds.Length);
                int ki = 0;
                foreach (JsonElement k in kinds.EnumerateArray())
                {
                    Channels.KindSpec got = s.Kinds[ki];
                    Assert.True(k.GetProperty("code").GetInt64() == got.Code, dir + " kind " + ki + " code");
                    Assert.True(k.GetProperty("name").GetString() == got.Name, dir + " kind " + ki + " name");
                    Assert.True(k.GetProperty("effect").GetInt64() == got.Effect, dir + " kind " + ki + " effect");
                    Assert.True(k.GetProperty("variable").GetBoolean() == got.Variable, dir + " kind " + ki + " variable");
                    ki++;
                }

                JsonElement states = c.GetProperty("states");
                Assert.Equal(states.GetArrayLength(), s.States.Length);
                int si = 0;
                foreach (JsonElement st in states.EnumerateArray())
                {
                    Assert.True(st.GetString() == s.States[si], dir + " state " + si);
                    si++;
                }

                JsonElement transitions = c.GetProperty("transitions");
                Assert.Equal(transitions.GetArrayLength(), s.Transitions.Length);
                int ti = 0;
                foreach (JsonElement t in transitions.EnumerateArray())
                {
                    Assert.True(t.GetProperty("from").GetString() == s.Transitions[ti].From, dir + " transition " + ti + " from");
                    Assert.True(t.GetProperty("to").GetString() == s.Transitions[ti].To, dir + " transition " + ti + " to");
                    ti++;
                }

                JsonElement errors = c.GetProperty("errors");
                Assert.Equal(errors.GetArrayLength(), s.Errors.Length);
                int ei = 0;
                foreach (JsonElement e in errors.EnumerateArray())
                {
                    Assert.True(e.GetString() == s.Errors[ei], dir + " error " + ei);
                    ei++;
                }
                n++;
            }
            Assert.Equal(20, n);
        }

        [Fact]
        public void GetChannelReturnsNullForUnregisteredId()
        {
            Assert.Null(Channels.GetChannel(0x00FF));
            Channels.ChannelSpec? wf = Channels.GetChannel(0x0011);
            Assert.NotNull(wf);
            Assert.Equal("Workflow", wf!.Name);
        }

        // ==== AllowedTransition: every declared transition (per channel, read from the independent
        //      oracle) is allowed; representative reversed/skip/unregistered pairs are denied ==========

        [Fact]
        public void AllowedTransitionAcceptsEveryDeclaredTransitionAcrossAllChannels()
        {
            int checkedCount = 0;
            foreach (string dir in AllChannelNames)
            {
                JsonElement c = LoadChannel(dir);
                long id = c.GetProperty("channel_id").GetInt64();
                foreach (JsonElement t in c.GetProperty("transitions").EnumerateArray())
                {
                    string from = t.GetProperty("from").GetString()!;
                    string to = t.GetProperty("to").GetString()!;
                    Assert.True(Channels.AllowedTransition(id, from, to), dir + ": " + from + "->" + to + " must be allowed");
                    checkedCount++;
                }
            }
            Assert.True(checkedCount > 0, "no transitions loaded from the oracle");
        }

        [Fact]
        public void AllowedTransitionRejectsReversedSkipAndUnregistered()
        {
            // Mirrors impl/go/channels/channels_test.go TestStateMachine and
            // impl/rust/src/channels.rs state_machine byte-for-byte on the verdict.
            Assert.True(Channels.AllowedTransition(0x0001, "offered", "accepted"));   // Memory
            Assert.True(Channels.AllowedTransition(0x0001, "live", "revoked"));       // Memory
            Assert.False(Channels.AllowedTransition(0x0001, "revoked", "live"));      // Memory regression
            Assert.True(Channels.AllowedTransition(0x000E, "order", "fulfil"));       // Commerce
            Assert.False(Channels.AllowedTransition(0x000E, "offer", "fulfil"));      // Commerce skip
            Assert.True(Channels.AllowedTransition(0x0011, "awaiting-input", "running"));   // Workflow
            Assert.False(Channels.AllowedTransition(0x0011, "created", "running"));         // Workflow gate skip
            Assert.False(Channels.AllowedTransition(0x0001, "accepted", "offered"));  // reversed, never declared
            Assert.False(Channels.AllowedTransition(0x00FF, "a", "b"));               // unregistered channel
        }

        // ==== CheckFrameTree: Spatial's TransformCycle (design-channels.md §20) ======================

        [Fact]
        public void CheckFrameTreeAcceptsValidRejectsCyclic()
        {
            var tree = new Dictionary<string, string> { ["base"] = "", ["arm"] = "base", ["hand"] = "arm" };
            Channels.CheckFrameTree(tree); // must not throw

            var cyclic = new Dictionary<string, string> { ["a"] = "b", ["b"] = "c", ["c"] = "a" };
            NaalpException ex = Assert.Throws<NaalpException>(() => Channels.CheckFrameTree(cyclic));
            Assert.Equal("TransformCycle", ex.Kind);
        }

        [Fact]
        public void CheckFrameTreeAcceptsForestOfIndependentRoots()
        {
            // Two disjoint single-node roots form a valid (degenerate) forest -- not a cycle.
            var singles = new Dictionary<string, string> { ["x"] = "", ["y"] = "" };
            Channels.CheckFrameTree(singles); // must not throw
        }

        // ==== WorkflowGate: the durable input-gate crash test (design-channels.md §18) ===============
        //
        // MUTATION ANCHOR: Channels.WorkflowGate.Run's awaiting-input/awaiting-approval branch (which
        // throws InputGateBypass) is what WorkflowInputGateBypassMirrorsGoCrash exercises. Neutering
        // Run to persist "running" unconditionally -- skipping that branch -- flips this test from
        // pass to fail (recorded red evidence).

        private static string TempGatePath(string tag) =>
            Path.Combine(Path.GetTempPath(), "naalp-wf-gate-" + tag + "-" + Guid.NewGuid().ToString("N") + ".wal");

        [Fact]
        public void WorkflowInputGateBypassMirrorsGoCrash()
        {
            string path = TempGatePath("bypass");
            try
            {
                Channels.WorkflowGate g = Channels.OpenWorkflowGate(path);
                try
                {
                    g.Create("t1", false);

                    // Running before input is InputGateBypass.
                    NaalpException ex1 = Assert.Throws<NaalpException>(() => g.Run("t1"));
                    Assert.Equal("InputGateBypass", ex1.Kind);
                }
                finally
                {
                    // Simulate a crash right after Create: close the WAL (mirrors Go's explicit
                    // g.Close() in the same test).
                    g.Close();
                }

                Channels.WorkflowGate g2 = Channels.OpenWorkflowGate(path);
                try
                {
                    Assert.Equal("awaiting-input", g2.Status("t1")); // crash did not bypass the gate

                    NaalpException ex2 = Assert.Throws<NaalpException>(() => g2.Run("t1"));
                    Assert.Equal("InputGateBypass", ex2.Kind);

                    // Supplying input opens the gate; only then may it run.
                    g2.SupplyInput("t1");
                    g2.Run("t1"); // must not throw
                    Assert.Equal("running", g2.Status("t1"));
                }
                finally
                {
                    g2.Close();
                }
            }
            finally
            {
                if (File.Exists(path)) File.Delete(path);
            }
        }

        [Fact]
        public void WorkflowGateApprovalPathAndTaskStateErrors()
        {
            string path = TempGatePath("approval");
            try
            {
                Channels.WorkflowGate g = Channels.OpenWorkflowGate(path);
                try
                {
                    // needsApproval path: created -> awaiting-approval -> approved -> running.
                    g.Create("t-appr", true);
                    Assert.Equal("awaiting-approval", g.Status("t-appr"));
                    NaalpException gateEx = Assert.Throws<NaalpException>(() => g.Run("t-appr"));
                    Assert.Equal("InputGateBypass", gateEx.Kind);
                    g.SupplyInput("t-appr");
                    Assert.Equal("approved", g.Status("t-appr"));
                    g.Run("t-appr");
                    Assert.Equal("running", g.Status("t-appr"));

                    // Duplicate Create on an existing task id is TaskStateError, not silently accepted.
                    NaalpException dupEx = Assert.Throws<NaalpException>(() => g.Create("t-appr", false));
                    Assert.Equal("TaskStateError", dupEx.Kind);

                    // SupplyInput/Run on an unknown task id is TaskStateError, never InputGateBypass --
                    // there is no gate to bypass when the task does not exist.
                    NaalpException unkSupply = Assert.Throws<NaalpException>(() => g.SupplyInput("ghost"));
                    Assert.Equal("TaskStateError", unkSupply.Kind);
                    NaalpException unkRun = Assert.Throws<NaalpException>(() => g.Run("ghost"));
                    Assert.Equal("TaskStateError", unkRun.Kind);

                    // Supplying input twice (already past the gate) is TaskStateError.
                    NaalpException dupSupply = Assert.Throws<NaalpException>(() => g.SupplyInput("t-appr"));
                    Assert.Equal("TaskStateError", dupSupply.Kind);

                    Assert.Null(g.Status("never-created"));
                }
                finally
                {
                    g.Close();
                }
            }
            finally
            {
                if (File.Exists(path)) File.Delete(path);
            }
        }
    }
}
