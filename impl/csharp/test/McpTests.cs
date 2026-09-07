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
    /// NAALP-MCP binding-profile conformance for the C# SDK (design.md §19; Companion-Spec Requirement
    /// 6.1), graded against the shared independent corpus <c>vectors/mcp/cases.json</c> (NOT produced by
    /// this code): the annotation encoding, the published annotation->effect mapping table, the malformed
    /// annotation rejections, the tool-call bodies/content-ids, the (tool_id,args_id) call binding, the
    /// more-severe effect resolution (accept / EffectUnderDeclared), the approval-binding call content
    /// ids, and the edge cases (non-canonical rejection, empty-vs-absent annotations, minimal, look-alike).
    ///
    /// <para>The signed governance path (VerifyToolCall + the per-call approval gate, reusing the
    /// just-landed C# <see cref="Approval"/> single-use consume ledger UNCHANGED) is exercised with REAL
    /// deterministic ML-DSA-65 (BouncyCastle, rnd=0) and demonstrated in isolation — the corpus carries no
    /// signed vector, stated honestly (F2/F4). Ported from impl/go/mcp; mirrors impl/python/naalp/mcp.py.</para>
    /// </summary>
    public sealed class McpTests
    {
        private static JsonElement Vector()
        {
            var d = new DirectoryInfo(AppContext.BaseDirectory);
            for (int i = 0; i < 12 && d != null; i++)
            {
                string p = Path.Combine(d.FullName, "vectors", "mcp", "cases.json");
                if (File.Exists(p))
                {
                    return JsonDocument.Parse(File.ReadAllText(p)).RootElement.Clone();
                }
                d = d.Parent;
            }
            throw new Xunit.Sdk.XunitException("vectors/mcp/cases.json not found from " + AppContext.BaseDirectory);
        }

        private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();
        private static byte[] Hb(string s) => Convert.FromHexString(s);

        // Build an Annotations from a corpus `hints` object {"1":1,"2":0,...} (uint keys 1..4 -> 0/1).
        private static Mcp.Annotations AnnFromHints(JsonElement hints)
        {
            bool? ro = null, de = null, idem = null, ow = null;
            foreach (JsonProperty p in hints.EnumerateObject())
            {
                bool val = p.Value.GetInt32() == 1;
                switch (int.Parse(p.Name))
                {
                    case 1: ro = val; break;
                    case 2: de = val; break;
                    case 3: idem = val; break;
                    case 4: ow = val; break;
                }
            }
            return new Mcp.Annotations(ro, de, idem, ow);
        }

        // ---- the annotation encoding + the published annotation->effect mapping table --------------
        // MUTATION ANCHOR: flipping Mcp.DefaultDestructive (true) makes the all-absent / destructive-
        // default cases map to non_idempotent_write(2) instead of destructive(3), failing Assert.Equal.

        [Fact]
        public void AnnotationMappingMatchesOracle()
        {
            JsonElement v = Vector();
            int count = 0;
            foreach (JsonElement a in v.GetProperty("annotations").EnumerateArray())
            {
                Mcp.Annotations ann = AnnFromHints(a.GetProperty("hints"));
                Assert.Equal(a.GetProperty("annotations_hex").GetString(), Hex(ann.Encode()));
                Assert.Equal(a.GetProperty("mapped_effect").GetInt64(), Mcp.MapAnnotationsToEffect(ann));
                count++;
            }
            Assert.True(count > 0, "corpus carried no annotation cases");
        }

        // ---- every annotation set the oracle marks malformed is rejected, never defaulted to benign --

        [Fact]
        public void MalformedAnnotationsRejected()
        {
            JsonElement v = Vector();
            int count = 0;
            foreach (JsonElement mv in v.GetProperty("malformed_annotations").EnumerateArray())
            {
                // The malformed set must be structurally valid CBOR — the rejection is a profile rule,
                // not a codec rule (so a decoder that accepted it would still be caught here).
                Cbor.Value decoded = Cbor.Decode(Hb(mv.GetProperty("annotations_hex").GetString()!));
                var ex = Assert.Throws<NaalpException>(() => Mcp.AnnotationsFromValue(decoded));
                Assert.Equal(mv.GetProperty("expect").GetString(), ex.Kind);
                count++;
            }
            Assert.True(count > 0, "corpus carried no malformed-annotation cases");
        }

        // ---- tool-call bodies, content ids, the annotation mapping, and the call binding -----------

        [Fact]
        public void ToolCallBodiesMatchOracle()
        {
            JsonElement v = Vector();
            int count = 0;
            foreach (JsonElement tv in v.GetProperty("tool_calls").EnumerateArray())
            {
                byte[] tool = Hb(tv.GetProperty("tool_hex").GetString()!);
                byte[] args = Hb(tv.GetProperty("args_hex").GetString()!);
                Mcp.Annotations ann = AnnFromHints(tv.GetProperty("hints"));
                var tc = new Mcp.ToolCall(tool, args, ann);

                Assert.Equal(tv.GetProperty("annotations_hex").GetString(), Hex(ann.Encode()));
                Assert.Equal(tv.GetProperty("body_hex").GetString(), Hex(tc.Bytes()));
                Assert.Equal(tv.GetProperty("content_id_hex").GetString(), Hex(tc.ContentId()));
                Assert.Equal(tv.GetProperty("annotation_mapped_effect").GetInt64(), Mcp.MapAnnotationsToEffect(ann));

                Mcp.CallBinding cb = tc.CallBinding();
                Assert.Equal(tv.GetProperty("tool_id_hex").GetString(), Hex(cb.ToolId));
                Assert.Equal(tv.GetProperty("args_id_hex").GetString(), Hex(cb.ArgsId));
                Assert.Equal(tv.GetProperty("call_binding_hex").GetString(), Hex(cb.Bytes()));
                Assert.Equal(tv.GetProperty("call_content_id_hex").GetString(), Hex(cb.ContentId()));
                count++;
            }
            Assert.True(count > 0, "corpus carried no tool-call cases");
        }

        // ---- the more-severe effect resolution (the good-regulator attenuator) ---------------------

        [Fact]
        public void ResolutionMatchesOracle()
        {
            JsonElement v = Vector();
            int count = 0;
            foreach (JsonElement rv in v.GetProperty("resolution").EnumerateArray())
            {
                long mapped = rv.GetProperty("annotation_mapped").GetInt64();
                long declared = rv.GetProperty("declared").GetInt64();
                string verdict = rv.GetProperty("verdict").GetString()!;
                if (verdict == "accept")
                {
                    (long enforced, bool mismatch) = Mcp.ResolveEnforcedEffect(mapped, declared);
                    Assert.Equal(rv.GetProperty("enforced").GetInt64(), enforced);
                    Assert.Equal(rv.GetProperty("mismatch").GetBoolean(), mismatch);
                }
                else
                {
                    var ex = Assert.Throws<NaalpException>(() => Mcp.ResolveEnforcedEffect(mapped, declared));
                    Assert.Equal(verdict, ex.Kind); // "EffectUnderDeclared"
                }
                count++;
            }
            Assert.True(count > 0, "corpus carried no resolution cases");
        }

        // ---- the call binding content ids an approval binds (changed args / changed tool desc) -----

        [Fact]
        public void ApprovalBindingContentIdsMatchOracle()
        {
            JsonElement v = Vector();
            int count = 0;
            foreach (JsonElement av in v.GetProperty("approval_binding").EnumerateArray())
            {
                byte[] tool = Hb(av.GetProperty("tool_hex").GetString()!);
                byte[] args = Hb(av.GetProperty("args_hex").GetString()!);
                Mcp.CallBinding cb = Mcp.NewCallBinding(tool, args);
                Assert.Equal(av.GetProperty("tool_id_hex").GetString(), Hex(cb.ToolId));
                Assert.Equal(av.GetProperty("args_id_hex").GetString(), Hex(cb.ArgsId));
                Assert.Equal(av.GetProperty("call_binding_hex").GetString(), Hex(cb.Bytes()));
                Assert.Equal(av.GetProperty("call_content_id_hex").GetString(), Hex(cb.ContentId()));
                count++;
            }
            Assert.True(count >= 3, "want >= 3 approval-binding cases");
            // A changed args OR a changed tool description yields a DIFFERENT call content id.
            var ids = new HashSet<string>();
            foreach (JsonElement av in v.GetProperty("approval_binding").EnumerateArray())
            {
                ids.Add(av.GetProperty("call_content_id_hex").GetString()!);
            }
            Assert.Equal(count, ids.Count); // all three call content ids are distinct
        }

        // ---- edge cases: non-canonical rejection, empty-vs-absent, minimal, look-alike -------------

        [Fact]
        public void EdgeCasesMatchOracle()
        {
            JsonElement v = Vector();
            JsonElement ec = v.GetProperty("edge_cases");

            // keys emitted descending -> the strict decoder rejects NonCanonical.
            JsonElement koo = ec.GetProperty("keys_out_of_order");
            var nc = Assert.Throws<NaalpException>(() => Cbor.Decode(Hb(koo.GetProperty("noncanonical_body_hex").GetString()!)));
            Assert.Equal("NonCanonical", nc.Kind);
            Cbor.Decode(Hb(koo.GetProperty("canonical_body_hex").GetString()!)); // the canonical form decodes

            // an empty annotations map is PRESENT and valid (all MCP defaults -> destructive).
            JsonElement empty = ec.GetProperty("empty_vs_absent").GetProperty("empty_annotations");
            Mcp.ToolCall etc = Mcp.ToolCallFromBody(Cbor.Decode(Hb(empty.GetProperty("body_hex").GetString()!)));
            Assert.Equal(empty.GetProperty("body_hex").GetString(), Hex(etc.Bytes())); // round-trips byte-exact
            Assert.Equal(empty.GetProperty("content_id_hex").GetString(), Hex(etc.ContentId()));
            Assert.Equal(empty.GetProperty("mapped_effect").GetInt64(), Mcp.MapAnnotationsToEffect(etc.Annotations));

            // a tool-call whose annotations field is ABSENT is rejected (distinct from empty).
            JsonElement absent = ec.GetProperty("empty_vs_absent").GetProperty("absent_annotations");
            var abEx = Assert.Throws<NaalpException>(() => Mcp.ToolCallFromBody(Cbor.Decode(Hb(absent.GetProperty("body_hex").GetString()!))));
            Assert.Equal(absent.GetProperty("reject").GetString(), abEx.Kind); // ToolCallMalformed

            // the smallest valid tool-call: empty tool, empty args, empty annotations (-> destructive).
            JsonElement min = ec.GetProperty("minimal");
            var mtc = new Mcp.ToolCall(Hb(min.GetProperty("tool_hex").GetString()!), Hb(min.GetProperty("args_hex").GetString()!), new Mcp.Annotations());
            Assert.Equal(min.GetProperty("body_hex").GetString(), Hex(mtc.Bytes()));
            Assert.Equal(min.GetProperty("content_id_hex").GetString(), Hex(mtc.ContentId()));
            Assert.Equal(min.GetProperty("mapped_effect").GetInt64(), Mcp.MapAnnotationsToEffect(mtc.Annotations));

            // a 2-field call-binding fed to the tool-call parser is rejected (a tool-call is 3 fields).
            JsonElement la = ec.GetProperty("look_alike");
            var laEx = Assert.Throws<NaalpException>(() => Mcp.ToolCallFromBody(Cbor.Decode(Hb(la.GetProperty("call_binding_body_hex").GetString()!))));
            Assert.Equal(la.GetProperty("reject").GetString(), laEx.Kind); // ToolCallMalformed
        }

        // ---- the signed governance path + the per-call approval gate (REAL ML-DSA, isolation) ------
        // Reuses the just-landed C# Approval single-use consume ledger UNCHANGED for the §7 gate:
        // authorize once -> replay AlreadyConsumed -> a call with different arguments -> ApprovalRequired.
        // The corpus carries no signed vector, so this is demonstrated in isolation on corpus-anchored
        // tool/args bytes (approval_binding base_T_A vs changed_args_T_B). Stated honestly (F2/F4).

        [Fact]
        public void SignedGovernanceAndApprovalGateInIsolation()
        {
            const int alg = Cose.ALG_MLDSA65;
            JsonElement v = Vector();

            byte[] signerSeed = new byte[32];
            for (int i = 0; i < 32; i++) signerSeed[i] = 7;
            byte[] signerPk = Cose.MldsaKeygen("ML-DSA-65", signerSeed);

            // base call T/A (a destructive transfer) from the corpus approval_binding.
            JsonElement baseAB = FindBinding(v, "base_T_A");
            JsonElement changedAB = FindBinding(v, "changed_args_T_B");
            byte[] toolA = Hb(baseAB.GetProperty("tool_hex").GetString()!);
            byte[] argsA = Hb(baseAB.GetProperty("args_hex").GetString()!);
            byte[] argsB = Hb(changedAB.GetProperty("args_hex").GetString()!);

            // the tool's annotations declare destructive (readOnly=false, destructive=true) -> destructive.
            var ann = new Mcp.Annotations(readOnly: false, destructive: true);
            var tcA = new Mcp.ToolCall(toolA, argsA, ann);
            var tcB = new Mcp.ToolCall(toolA, argsB, ann);

            Envelope.Object objA = tcA.EnvelopeObject(signerPk, 100, Cose.PROFILE_PUBLIC, Policy.DESTRUCTIVE, new List<byte[]>());
            Envelope.Object objB = tcB.EnvelopeObject(signerPk, 100, Cose.PROFILE_PUBLIC, Policy.DESTRUCTIVE, new List<byte[]>());
            byte[] signedA = Envelope.Sign(objA, alg, signerSeed);
            byte[] signedB = Envelope.Sign(objB, alg, signerSeed);

            Mcp.Resolved rA = Mcp.VerifyToolCall(Cose.PROFILE_PUBLIC, alg, signerPk, signedA);
            Mcp.Resolved rB = Mcp.VerifyToolCall(Cose.PROFILE_PUBLIC, alg, signerPk, signedB);
            Assert.Equal(Policy.DESTRUCTIVE, rA.Enforced); // more-severe resolution: enforced == declared == destructive
            Assert.False(rA.Mismatch);                     // annotation-mapped (destructive) == declared

            // the human approval binds THE EXACT call A (its call-binding content id), grants destructive.
            byte[] approverSeed = new byte[32];
            for (int i = 0; i < 32; i++) approverSeed[i] = 9;
            byte[] approverPk = Cose.MldsaKeygen("ML-DSA-65", approverSeed);
            byte[] callCidA = rA.ToolCall.CallBinding().ContentId();
            var appr = new Approval.ApprovalRecord(callCidA, "human", Policy.DESTRUCTIVE, new byte[] { 1, 2, 3 }, 1000);
            byte[] apprSig = Approval.SignApproval(appr, alg, approverSeed);

            string wal = Path.Combine(Path.GetTempPath(), "naalp-mcp-" + Guid.NewGuid().ToString("N") + ".wal");
            try
            {
                Approval.Ledger ledger = Approval.OpenLedger(wal);

                // first authorization of call A succeeds and consumes the approval single-use.
                Mcp.AuthorizeCall(rA, appr, alg, approverPk, apprSig, "agent", 500, ledger);

                // replaying the SAME call+approval is rejected AlreadyConsumed (no double-spend).
                var replay = Assert.Throws<NaalpException>(() => Mcp.AuthorizeCall(rA, appr, alg, approverPk, apprSig, "agent", 500, ledger));
                Assert.Equal("AlreadyConsumed", replay.Kind);

                // the SAME approval offered for call B (different arguments -> different call content id)
                // does not bind -> ApprovalRequired, with no ledger append.
                var wrongCall = Assert.Throws<NaalpException>(() => Mcp.AuthorizeCall(rB, appr, alg, approverPk, apprSig, "agent", 500, ledger));
                Assert.Equal("ApprovalRequired", wrongCall.Kind);
                Assert.Equal(1, ledger.Len()); // exactly one consume happened
                ledger.Close();
            }
            finally
            {
                if (File.Exists(wal)) File.Delete(wal);
            }
        }

        private static JsonElement FindBinding(JsonElement v, string name)
        {
            foreach (JsonElement av in v.GetProperty("approval_binding").EnumerateArray())
            {
                if (av.GetProperty("name").GetString() == name)
                {
                    return av;
                }
            }
            throw new Xunit.Sdk.XunitException("no approval_binding named " + name);
        }

        // ---- a baseline-only endpoint rejects the tier-1 McpToolCall as UnknownKind (fail-closed) --

        [Fact]
        public void BaselineEndpointRejectsMcpKind()
        {
            // ComposedKindValidator accepts the tier-1 McpToolCall; the frozen baseline validator alone
            // does not (Bridge kind 1 is not a baseline kind — baseline Carriage is kind 0).
            Assert.True(Mcp.ComposedKindValidator(Mcp.ChannelBridge, Mcp.KindMcpToolCall));
            Assert.True(Mcp.ComposedKindValidator(Mcp.ChannelBridge, 0)); // baseline Carriage still accepted
            Assert.False(Mcp.KindValidator(Mcp.ChannelBridge, 0));        // the tier-1-only validator rejects baseline
            Assert.True(Mcp.KindValidator(Mcp.ChannelBridge, Mcp.KindMcpToolCall));
        }
    }
}
