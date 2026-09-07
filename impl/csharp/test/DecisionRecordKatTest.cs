// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;

using Naalp;
using Xunit;

namespace Sh.Bubblefish.Naalp.Tests
{
    /// <summary>
    /// S1 naalp-decision-record known-answer test for the C# SDK (design.md §26.4), graded against the
    /// independent, non-circular corpus <c>vectors/decision_record/cases.json</c> — mirroring
    /// impl/go/gateway/decision_record_test.go and impl/python/tests/test_decision_record.py.
    ///
    /// <para>A DecisionRecord is the SIGNED record a governed decision point emits that it decided
    /// about an action under a CLOSED, uniquely-selected condition set. It carries the T/T+n
    /// accountability triple (§26.1): UNIQUE SELECTION (field 2, the governing set); GOVERNED-AT-T
    /// (field 3, the spent consume-receipt); BINDING-FIXED-BY-T (established off-record via S3
    /// checkpoints). The record is deliberately CLOCK-FREE.</para>
    /// </summary>
    public sealed class DecisionRecordKatTest
    {
        private const int Alg = Cose.ALG_MLDSA65;

        private static JsonElement Vector()
        {
            var d = new DirectoryInfo(AppContext.BaseDirectory);
            for (int i = 0; i < 12 && d != null; i++)
            {
                string p = Path.Combine(d.FullName, "vectors", "decision_record", "cases.json");
                if (File.Exists(p))
                {
                    var doc = JsonDocument.Parse(File.ReadAllText(p));
                    return doc.RootElement.Clone();
                }
                d = d.Parent;
            }
            throw new Xunit.Sdk.XunitException("vectors/decision_record/cases.json not found from " + AppContext.BaseDirectory);
        }

        private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();
        private static byte[] Hb(string s) => Convert.FromHexString(s);

        private static byte[] Seed(int b)
        {
            var s = new byte[32];
            for (int i = 0; i < s.Length; i++) s[i] = (byte)b;
            return s;
        }

        private static string ErrKind(Action a)
        {
            try
            {
                a();
                return "no-error";
            }
            catch (NaalpException e)
            {
                return e.Kind;
            }
        }

        private static List<byte[]> HexArray(JsonElement arr)
        {
            var outp = new List<byte[]>();
            foreach (JsonElement e in arr.EnumerateArray())
            {
                outp.Add(Hb(e.GetString()!));
            }
            return outp;
        }

        /// <summary>consume_hex may be a JSON string, null, or absent; all three fall through to the
        /// empty (absent) byte string — the DecisionRecord.Consume "absent" convention.</summary>
        private static byte[] ConsumeHex(JsonElement rv)
        {
            if (rv.TryGetProperty("consume_hex", out JsonElement c) && c.ValueKind == JsonValueKind.String)
            {
                return Hb(c.GetString()!);
            }
            return Array.Empty<byte>();
        }

        /// <summary>Reconstructs a records{}/ordering_examples{} case with its exact
        /// ordering/terms/enforcement fixture, mirroring decision_record_test.go's build() switch /
        /// test_decision_record.py's _build() exactly.</summary>
        private static Gateway.DecisionRecord BuildRecord(string name, JsonElement rv)
        {
            byte[] action = Hb(rv.GetProperty("action_hex").GetString()!);
            List<byte[]> governing = HexArray(rv.GetProperty("governing_hex"));
            long outcome = rv.GetProperty("outcome").GetInt64();
            byte[] consume = ConsumeHex(rv);
            Gateway.OrderingDisclosure ordering;
            var terms = new Dictionary<long, Gateway.TermDisposition>();
            long enforcement = 0;
            switch (name)
            {
                case "allow_consuming":
                case "allow_no_consume":
                case "minimal":
                case "correspondence_only":
                    ordering = Gateway.CorrespondenceOnly();
                    break;
                case "deny_two_governing":
                    ordering = new Gateway.OrderingDisclosure(
                        Gateway.OrderingSingleBoundary, Encoding.UTF8.GetBytes("boundary-signer-X"),
                        Array.Empty<byte>(), Array.Empty<byte>());
                    break;
                case "hold_empty_governing":
                case "external_mechanism":
                    ordering = new Gateway.OrderingDisclosure(
                        Gateway.OrderingExternalMechanism, Array.Empty<byte>(),
                        Encoding.UTF8.GetBytes("external-log:acme-transparency-v1"),
                        Hb("2030c83b03ab5d26de33f037927bb2258fcfc3e8050793b68959bc5be954bcda9ca13875be35627f50f282c4eff9d807ea56"));
                    break;
                case "single_boundary":
                    ordering = new Gateway.OrderingDisclosure(
                        Gateway.OrderingSingleBoundary, Encoding.UTF8.GetBytes("SIGNER_B-boundary"),
                        Array.Empty<byte>(), Array.Empty<byte>());
                    break;
                case "external_mechanism_no_relation":
                    ordering = new Gateway.OrderingDisclosure(
                        Gateway.OrderingExternalMechanism, Array.Empty<byte>(),
                        Encoding.UTF8.GetBytes("external-log:acme-transparency-v1"), Array.Empty<byte>());
                    break;
                case "terms_valid":
                    ordering = Gateway.CorrespondenceOnly();
                    terms[1] = new Gateway.TermDisposition(Gateway.TermObserved);
                    terms[4] = new Gateway.TermDisposition(Gateway.TermReported, Encoding.UTF8.GetBytes("boundary:relay-partner-3"));
                    break;
                case "enforcement_enforced":
                    ordering = Gateway.CorrespondenceOnly();
                    enforcement = Gateway.EnforcementEnforced;
                    break;
                case "enforcement_advised":
                    ordering = Gateway.CorrespondenceOnly();
                    enforcement = Gateway.EnforcementAdvised;
                    break;
                default:
                    throw new Xunit.Sdk.XunitException("unhandled record name " + name + " -- add its ordering/terms/enforcement fixture");
            }
            return new Gateway.DecisionRecord(action, governing, outcome, ordering, consume, terms, enforcement);
        }

        private static string DrRejectKind(byte[] body)
        {
            try
            {
                Gateway.DecisionRecord d = Gateway.ParseDecisionRecord(body);
                try
                {
                    Gateway.ValidateDecisionRecord(d);
                }
                catch (NaalpException e)
                {
                    return e.Kind;
                }
                return "";
            }
            catch (NaalpException e)
            {
                return e.Kind;
            }
        }

        [Fact]
        public void Vocabulary()
        {
            JsonElement json = Vector();
            foreach (JsonElement vb in json.GetProperty("outcome_vocabulary").EnumerateArray())
            {
                string name = vb.GetProperty("name").GetString()!;
                long code = vb.GetProperty("code").GetInt64();
                Assert.True(Gateway.IsKnownDecision(code), "outcome " + name + " must be known");
                Assert.Equal(name, Gateway.DecisionName(code));
            }
            foreach (JsonElement vb in json.GetProperty("ordering_basis_vocabulary").EnumerateArray())
            {
                string name = vb.GetProperty("name").GetString()!;
                long code = vb.GetProperty("code").GetInt64();
                Assert.True(Gateway.IsKnownOrderingBasis(code), "ordering basis " + name + " must be known");
                Assert.Equal(name, Gateway.OrderingBasisName(code));
            }
            Assert.False(Gateway.IsKnownOrderingBasis(99));
        }

        [Fact]
        public void RecordsAndOrderingExamplesByteParity()
        {
            JsonElement json = Vector();
            JsonElement records = json.GetProperty("records");
            JsonElement orderingExamples = json.GetProperty("ordering_examples");

            var all = new List<(string Name, JsonElement Value)>();
            foreach (JsonProperty p in records.EnumerateObject())
            {
                all.Add((p.Name, p.Value));
            }
            foreach (JsonProperty p in orderingExamples.EnumerateObject())
            {
                all.Add((p.Name, p.Value));
            }

            foreach ((string name, JsonElement rv) in all)
            {
                Gateway.DecisionRecord d = BuildRecord(name, rv);
                Assert.Equal(rv.GetProperty("body_hex").GetString(), Hex(d.Bytes()));
                Assert.Equal(rv.GetProperty("head_hex").GetString(), Hex(d.Head()));
                Assert.Equal(rv.GetProperty("id_hex").GetString(), Hex(d.Id()));
                Gateway.DecisionRecord parsed = Gateway.ParseDecisionRecord(d.Bytes());
                Assert.Equal(rv.GetProperty("body_hex").GetString(), Hex(parsed.Bytes()));
                Gateway.ValidateDecisionRecord(parsed); // every records/ordering_examples case is POSITIVE
            }
        }

        [Fact]
        public void MinimalDirect()
        {
            JsonElement json = Vector();
            JsonElement minB = json.GetProperty("records").GetProperty("minimal");
            var minimal = new Gateway.DecisionRecord(
                Hb(minB.GetProperty("action_hex").GetString()!), HexArray(minB.GetProperty("governing_hex")),
                minB.GetProperty("outcome").GetInt64(), Gateway.CorrespondenceOnly());
            Assert.Equal(minB.GetProperty("body_hex").GetString(), Hex(minimal.Bytes()));
            Assert.Equal(minB.GetProperty("id_hex").GetString(), Hex(minimal.Id()));
            Gateway.ValidateDecisionRecord(Gateway.ParseDecisionRecord(minimal.Bytes()));
        }

        [Fact]
        public void NegativeRejections()
        {
            JsonElement json = Vector();
            JsonElement neg = json.GetProperty("negative");
            foreach (string name in new[]
                     {
                         "deny_with_consume_rejected", "hold_with_consume_rejected",
                         "terms_key_outside_field_set_rejected", "unknown_outcome_rejected", "look_alike",
                     })
            {
                JsonElement c = neg.GetProperty(name);
                Assert.Equal(c.GetProperty("reject").GetString(), DrRejectKind(Hb(c.GetProperty("body_hex").GetString()!)));
            }
            foreach (JsonProperty p in neg.GetProperty("ordering_malformed").EnumerateObject())
            {
                Assert.Equal(p.Value.GetProperty("reject").GetString(), DrRejectKind(Hb(p.Value.GetProperty("body_hex").GetString()!)));
            }

            // keys_out_of_order: canonical decodes+validates cleanly; the descending-key body is
            // rejected at the CBOR layer (NonCanonical) before ParseDecisionRecord's own checks run.
            JsonElement koo = neg.GetProperty("keys_out_of_order");
            Gateway.ValidateDecisionRecord(Gateway.ParseDecisionRecord(Hb(koo.GetProperty("canonical_body_hex").GetString()!)));
            var ce = Assert.Throws<NaalpException>(() => Cbor.Decode(Hb(koo.GetProperty("noncanonical_body_hex").GetString()!)));
            Assert.Equal("NonCanonical", ce.Kind);
            Assert.Equal("DecisionMalformed", DrRejectKind(Hb(koo.GetProperty("noncanonical_body_hex").GetString()!)));
        }

        [Fact]
        public void ThirdPartyReServe()
        {
            JsonElement json = Vector();
            JsonElement allowConsuming = json.GetProperty("records").GetProperty("allow_consuming");
            Gateway.DecisionRecord acRecord = BuildRecord("allow_consuming", allowConsuming);
            Assert.Equal(allowConsuming.GetProperty("body_hex").GetString(), Hex(acRecord.Bytes()));

            byte[] seedProducer = Seed(0x71);
            byte[] seedForeign = Seed(0x72);
            byte[] producerPk = Cose.MldsaKeygen("ML-DSA-65", seedProducer);
            byte[] foreignPk = Cose.MldsaKeygen("ML-DSA-65", seedForeign);
            byte[] drObj = Gateway.SignDecisionRecord(acRecord, Alg, seedProducer);
            Gateway.ResolvedDecisionRecord byProducer = Gateway.VerifyDecisionRecord(drObj, Cose.PROFILE_PUBLIC, Alg, producerPk);
            Gateway.ResolvedDecisionRecord byThirdParty = Gateway.VerifyDecisionRecord((byte[])drObj.Clone(), Cose.PROFILE_PUBLIC, Alg, producerPk);
            Assert.Equal(Hex(byProducer.Action), Hex(byThirdParty.Action));
            Assert.Equal(Gateway.DecisionAllow, byThirdParty.Outcome);
            Assert.Equal(allowConsuming.GetProperty("consume_hex").GetString(), Hex(byThirdParty.Consume));

            var badSig = Assert.Throws<NaalpException>(() => Gateway.VerifyDecisionRecord(drObj, Cose.PROFILE_PUBLIC, Alg, foreignPk));
            Assert.Equal("BadSignature", badSig.Kind);
        }

        [Fact]
        public void TermsValidSignVerify()
        {
            JsonElement json = Vector();
            JsonElement termsValid = json.GetProperty("records").GetProperty("terms_valid");
            Gateway.DecisionRecord tvRecord = BuildRecord("terms_valid", termsValid);
            byte[] tvSeed = Seed(0x11);
            byte[] tvPk = Cose.MldsaKeygen("ML-DSA-65", tvSeed);
            byte[] tvObj = Gateway.SignDecisionRecord(tvRecord, Alg, tvSeed);
            Gateway.ResolvedDecisionRecord tvResolved = Gateway.VerifyDecisionRecord(tvObj, Cose.PROFILE_PUBLIC, Alg, tvPk);
            Assert.Equal(Gateway.TermObserved, tvResolved.Terms[1].Kind);
            Assert.Equal(Gateway.TermReported, tvResolved.Terms[4].Kind);
            Assert.Equal("boundary:relay-partner-3", Encoding.UTF8.GetString(tvResolved.Terms[4].Source));
        }
    }
}
