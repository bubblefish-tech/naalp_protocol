// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.IO;
using System.Text.Json;

using Naalp;
using Xunit;

namespace Sh.Bubblefish.Naalp.Tests
{
    /// <summary>
    /// C21 portable gateway-decision object graded against the non-circular oracle
    /// <c>vectors/gateway/cases.json</c>: <c>{1:decision,2:action,3:policy,4:effect}</c> is a signed
    /// decision an enforcement gateway of any vendor emits as portable evidence; its authority is the
    /// signature over the bytes, never the connection, so it verifies offline and re-verifies
    /// IDENTICALLY when a party other than the gateway serves it (third-party re-serve). decision is
    /// the closed set allow/deny/hold; head = SHA-384(body); content-id = multihash(0x20,0x30,...).
    /// The signed-deny SHA-384 pin is cross-validated against the Go/Rust pin. Expected values come
    /// from the committed corpus, not from the module under test.
    /// </summary>
    public sealed class GatewayTests
    {
        private const int Alg = Cose.ALG_MLDSA65;

        // The pinned SHA-384 of the deterministic COSE_Sign1 object obtained by signing the deny
        // gateway-decision body with the shared all-0x11 32-byte ML-DSA-65 seed. Go and Rust both pin
        // it (impl/go/gateway/gateway_test.go const crossLangPinnedSignedDecisionSHA384) — an
        // independent authority, not this C# code. C# must reproduce it byte-for-byte.
        private const string CrossLangPinnedSignedDecisionSha384 =
            "774047d87f11f688c57d985e9cab632ea66d0abc8b9ec3d48d1c3063c54ef5df0f761ce8239cbf68302d547097f01047";

        private static JsonElement Vector()
        {
            var d = new DirectoryInfo(AppContext.BaseDirectory);
            for (int i = 0; i < 12 && d != null; i++)
            {
                string p = Path.Combine(d.FullName, "vectors", "gateway", "cases.json");
                if (File.Exists(p))
                {
                    var doc = JsonDocument.Parse(File.ReadAllText(p));
                    return doc.RootElement.Clone();
                }
                d = d.Parent;
            }
            throw new Xunit.Sdk.XunitException("vectors/gateway/cases.json not found from " + AppContext.BaseDirectory);
        }

        private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();
        private static byte[] Hb(string s) => Convert.FromHexString(s);

        private static byte[] Sha384(byte[] b)
        {
            using var sha = SHA384.Create();
            return sha.ComputeHash(b);
        }

        private static Gateway.GatewayDecision DecFrom(JsonElement dv)
        {
            return new Gateway.GatewayDecision(
                dv.GetProperty("decision").GetInt64(),
                Hb(dv.GetProperty("action_hex").GetString()!),
                Hb(dv.GetProperty("policy_hex").GetString()!),
                dv.GetProperty("effect").GetInt64());
        }

        [Fact]
        public void ByteParityAgainstOracle()
        {
            JsonElement v = Vector();
            JsonElement decisions = v.GetProperty("decisions");
            foreach (string name in new[] { "allow", "deny", "hold" })
            {
                JsonElement dv = decisions.GetProperty(name);
                Gateway.GatewayDecision d = DecFrom(dv);
                Assert.Equal(dv.GetProperty("body_hex").GetString(), Hex(d.Bytes()));
                Assert.Equal(dv.GetProperty("head_hex").GetString(), Hex(d.Head()));
                Assert.Equal(dv.GetProperty("id_hex").GetString(), Hex(d.Id()));
            }
            foreach (JsonElement e in v.GetProperty("decision_vocabulary").EnumerateArray())
            {
                long code = e.GetProperty("code").GetInt64();
                string dname = e.GetProperty("name").GetString()!;
                Assert.True(Gateway.IsKnownDecision(code), "decision " + dname + " must be known");
                Assert.Equal(dname, Gateway.DecisionName(code));
            }
            Assert.False(Gateway.IsKnownDecision(v.GetProperty("unknown_decision").GetInt64()));
        }

        [Fact]
        public void KeysOutOfOrderRejected()
        {
            JsonElement v = Vector();
            JsonElement e = v.GetProperty("edge_cases").GetProperty("keys_out_of_order");
            var d = new Gateway.GatewayDecision(
                e.GetProperty("decision").GetInt64(),
                Hb(e.GetProperty("action_hex").GetString()!),
                Hb(e.GetProperty("policy_hex").GetString()!),
                e.GetProperty("effect").GetInt64());
            Assert.Equal(e.GetProperty("canonical_body_hex").GetString(), Hex(d.Bytes()));

            byte[] canon = Hb(e.GetProperty("canonical_body_hex").GetString()!);
            byte[] noncanon = Hb(e.GetProperty("noncanonical_body_hex").GetString()!);
            // canonical body decodes and parses
            Cbor.Decode(canon);
            Gateway.ParseDecision(canon);
            // descending-key body is NonCanonical to the strict codec, GwMalformed to ParseDecision
            var ce = Assert.Throws<NaalpException>(() => Cbor.Decode(noncanon));
            Assert.Equal("NonCanonical", ce.Kind);
            var pe = Assert.Throws<NaalpException>(() => Gateway.ParseDecision(noncanon));
            Assert.Equal("GwMalformed", pe.Kind);
        }

        [Fact]
        public void EmptyVsAbsentPolicy()
        {
            JsonElement v = Vector();
            JsonElement ea = v.GetProperty("edge_cases").GetProperty("empty_vs_absent");
            byte[] actionCid = Hb(v.GetProperty("action_cid_hex").GetString()!);

            var empty = new Gateway.GatewayDecision(Gateway.DecisionAllow, actionCid, Array.Empty<byte>(), 1);
            var populated = new Gateway.GatewayDecision(
                Gateway.DecisionAllow, actionCid,
                Hb(ea.GetProperty("populated_policy").GetProperty("policy_hex").GetString()!), 1);

            Assert.Equal(ea.GetProperty("empty_policy").GetProperty("body_hex").GetString(), Hex(empty.Bytes()));
            Assert.Equal(ea.GetProperty("populated_policy").GetProperty("body_hex").GetString(), Hex(populated.Bytes()));
            Assert.NotEqual(Hex(empty.Id()), Hex(populated.Id()));
            Assert.Equal(ea.GetProperty("empty_policy").GetProperty("id_hex").GetString(), Hex(empty.Id()));

            Gateway.ParseDecision(empty.Bytes());
            Gateway.ParseDecision(populated.Bytes());
            byte[] absent = Hb(ea.GetProperty("absent_field").GetProperty("body_hex").GetString()!);
            var pe = Assert.Throws<NaalpException>(() => Gateway.ParseDecision(absent));
            Assert.Equal("GwMalformed", pe.Kind);
        }

        [Fact]
        public void MinimalDecisionRoundtrips()
        {
            JsonElement v = Vector();
            JsonElement m = v.GetProperty("edge_cases").GetProperty("minimal");
            var d = new Gateway.GatewayDecision(
                m.GetProperty("decision").GetInt64(),
                Hb(m.GetProperty("action_hex").GetString()!),
                Hb(m.GetProperty("policy_hex").GetString()!),
                m.GetProperty("effect").GetInt64());
            Assert.Equal(m.GetProperty("body_hex").GetString(), Hex(d.Bytes()));
            Assert.Equal(m.GetProperty("id_hex").GetString(), Hex(d.Id()));
            Gateway.ParseDecision(d.Bytes());

            // verifies end-to-end (allow is a known decision code)
            byte[] seed = new byte[32];
            for (int i = 0; i < seed.Length; i++) seed[i] = 0x53;
            byte[] pk = Cose.MldsaKeygen("ML-DSA-65", seed);
            byte[] obj = Gateway.SignDecision(d, Alg, seed);
            Gateway.VerifyDecision(obj, Cose.PROFILE_PUBLIC, Alg, pk);
        }

        [Fact]
        public void LookAlikeRejected()
        {
            JsonElement v = Vector();
            byte[] body = Hb(v.GetProperty("edge_cases").GetProperty("look_alike").GetProperty("body_hex").GetString()!);
            var pe = Assert.Throws<NaalpException>(() => Gateway.ParseDecision(body));
            Assert.Equal("GwMalformed", pe.Kind);
        }

        [Fact]
        public void ThirdPartyReServe()
        {
            JsonElement v = Vector();
            Gateway.GatewayDecision deny = DecFrom(v.GetProperty("decisions").GetProperty("deny"));

            byte[] gwSeed = new byte[32];
            for (int i = 0; i < gwSeed.Length; i++) gwSeed[i] = 0x51;
            byte[] gwPk = Cose.MldsaKeygen("ML-DSA-65", gwSeed);
            byte[] foreignSeed = new byte[32];
            for (int i = 0; i < foreignSeed.Length; i++) foreignSeed[i] = 0x52;
            byte[] foreignPk = Cose.MldsaKeygen("ML-DSA-65", foreignSeed);

            byte[] obj = Gateway.SignDecision(deny, Alg, gwSeed);

            // Served by the gateway, then re-served by an unrelated third party: the SAME bytes with
            // the SAME (no) serving-party input resolve IDENTICALLY.
            Gateway.ResolvedDecision byGateway = Gateway.VerifyDecision(obj, Cose.PROFILE_PUBLIC, Alg, gwPk);
            Gateway.ResolvedDecision byThirdParty = Gateway.VerifyDecision(obj, Cose.PROFILE_PUBLIC, Alg, gwPk);
            Assert.Equal(byGateway.Decision, byThirdParty.Decision);
            Assert.Equal(Hex(byGateway.Action), Hex(byThirdParty.Action));
            Assert.Equal(Hex(byGateway.Policy), Hex(byThirdParty.Policy));
            Assert.Equal(byGateway.Effect, byThirdParty.Effect);
            Assert.Equal(Gateway.DecisionDeny, byThirdParty.Decision);
            Assert.Equal(v.GetProperty("action_cid_hex").GetString(), Hex(byThirdParty.Action));

            // A foreign key never verifies the gateway's decision.
            var badSig = Assert.Throws<NaalpException>(
                () => Gateway.VerifyDecision(obj, Cose.PROFILE_PUBLIC, Alg, foreignPk));
            Assert.Equal("BadSignature", badSig.Kind);

            // An unknown decision code is rejected fail-closed.
            var bad = new Gateway.GatewayDecision(
                v.GetProperty("unknown_decision").GetInt64(),
                Hb(v.GetProperty("action_cid_hex").GetString()!),
                Hb(v.GetProperty("policy_hex").GetString()!), 0);
            byte[] badObj = Gateway.SignDecision(bad, Alg, gwSeed);
            var unk = Assert.Throws<NaalpException>(
                () => Gateway.VerifyDecision(badObj, Cose.PROFILE_PUBLIC, Alg, gwPk));
            Assert.Equal("UnknownGatewayDecision", unk.Kind);
        }

        [Fact]
        public void CrossLangSignedDecisionPin()
        {
            JsonElement v = Vector();
            Gateway.GatewayDecision deny = DecFrom(v.GetProperty("decisions").GetProperty("deny"));
            byte[] seed = new byte[32];
            for (int i = 0; i < seed.Length; i++) seed[i] = 0x11;
            byte[] obj = Gateway.SignDecision(deny, Alg, seed);
            Assert.Equal(CrossLangPinnedSignedDecisionSha384, Hex(Sha384(obj)));
        }

        // ---- R1 ordering (field 5) + R8 foreign-profile (field 6), graded against this SAME corpus's
        //      optional_fields{} block (mirrors gateway_test.go's optional-fields section). ------------

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

        // The bare {1: alg} COSE_Sign1 protected header (§4) Gateway's private BareProtected produces —
        // reconstructed here since the test assembly cannot reach that private helper directly.
        private static byte[] BareProtected(int alg)
        {
            return Cbor.Encode(new Cbor.M(new List<Cbor.Pair>
            {
                new Cbor.Pair(new Cbor.U(1), new Cbor.N(alg)),
            }));
        }

        [Fact]
        public void OptionalFieldsOrderingAndForeignProfile()
        {
            JsonElement v = Vector();
            JsonElement of = v.GetProperty("optional_fields");

            // with_ordering: field 5 present (single-boundary), field 6 absent.
            JsonElement wo = of.GetProperty("with_ordering");
            JsonElement woOrd = wo.GetProperty("ordering");
            var ordWo = new Gateway.OrderingDisclosure(
                woOrd.GetProperty("basis").GetInt64(), Hb(woOrd.GetProperty("boundary_hex").GetString()!),
                Array.Empty<byte>(), Array.Empty<byte>());
            var dWo = new Gateway.GatewayDecision(
                wo.GetProperty("decision").GetInt64(), Hb(wo.GetProperty("action_hex").GetString()!),
                Hb(wo.GetProperty("policy_hex").GetString()!), wo.GetProperty("effect").GetInt64(), ordWo, null);
            Assert.Equal(wo.GetProperty("body_hex").GetString(), Hex(dWo.Bytes()));
            Assert.Equal(wo.GetProperty("id_hex").GetString(), Hex(dWo.Id()));
            Gateway.GatewayDecision parsedWo = Gateway.ParseDecision(Hb(wo.GetProperty("body_hex").GetString()!));
            Assert.NotNull(parsedWo.Ordering);
            Assert.Null(parsedWo.ForeignProfile);
            Assert.Equal(woOrd.GetProperty("basis").GetInt64(), parsedWo.Ordering!.Basis);
            Assert.Equal(woOrd.GetProperty("boundary_hex").GetString(), Hex(parsedWo.Ordering.Boundary));
            parsedWo.Ordering.Validate(); // no throw

            // with_foreign_profile: field 6 present, field 5 absent.
            JsonElement wf = of.GetProperty("with_foreign_profile");
            JsonElement wfFp = wf.GetProperty("foreign_profile");
            var fpWf = new Gateway.ForeignProfilePin(wfFp.GetProperty("id").GetString()!, wfFp.GetProperty("revision").GetString()!);
            var dWf = new Gateway.GatewayDecision(
                wf.GetProperty("decision").GetInt64(), Hb(wf.GetProperty("action_hex").GetString()!),
                Hb(wf.GetProperty("policy_hex").GetString()!), wf.GetProperty("effect").GetInt64(), null, fpWf);
            Assert.Equal(wf.GetProperty("body_hex").GetString(), Hex(dWf.Bytes()));
            Assert.Equal(wf.GetProperty("id_hex").GetString(), Hex(dWf.Id()));
            Gateway.GatewayDecision parsedWf = Gateway.ParseDecision(Hb(wf.GetProperty("body_hex").GetString()!));
            Assert.Null(parsedWf.Ordering);
            Assert.NotNull(parsedWf.ForeignProfile);
            Assert.Equal(wfFp.GetProperty("id").GetString(), parsedWf.ForeignProfile!.Id);
            Assert.Equal(wfFp.GetProperty("revision").GetString(), parsedWf.ForeignProfile.Revision);
            parsedWf.ForeignProfile.Validate(); // no throw

            // with_both: field 5 (external-mechanism, with relation) AND field 6 both present.
            JsonElement wb = of.GetProperty("with_both");
            JsonElement wbOrd = wb.GetProperty("ordering");
            JsonElement wbFp = wb.GetProperty("foreign_profile");
            var ordWb = new Gateway.OrderingDisclosure(
                wbOrd.GetProperty("basis").GetInt64(), Array.Empty<byte>(),
                Hb(wbOrd.GetProperty("mechanism_hex").GetString()!), Hb(wbOrd.GetProperty("relation_hex").GetString()!));
            var fpWb = new Gateway.ForeignProfilePin(wbFp.GetProperty("id").GetString()!, wbFp.GetProperty("revision").GetString()!);
            var dWb = new Gateway.GatewayDecision(
                wb.GetProperty("decision").GetInt64(), Hb(wb.GetProperty("action_hex").GetString()!),
                Hb(wb.GetProperty("policy_hex").GetString()!), wb.GetProperty("effect").GetInt64(), ordWb, fpWb);
            Assert.Equal(wb.GetProperty("body_hex").GetString(), Hex(dWb.Bytes()));
            Assert.Equal(wb.GetProperty("id_hex").GetString(), Hex(dWb.Id()));
            Gateway.GatewayDecision parsedWb = Gateway.ParseDecision(Hb(wb.GetProperty("body_hex").GetString()!));
            Assert.NotNull(parsedWb.Ordering);
            Assert.NotNull(parsedWb.ForeignProfile);
            parsedWb.Ordering!.Validate();
            parsedWb.ForeignProfile!.Validate();
            byte[] seedWb = Seed(0x71);
            byte[] pkWb = Cose.MldsaKeygen("ML-DSA-65", seedWb);
            byte[] objWb = Gateway.SignDecision(dWb, Alg, seedWb);
            Assert.Equal("no-error", ErrKind(() => Gateway.VerifyDecision(objWb, Cose.PROFILE_PUBLIC, Alg, pkWb)));

            // foreign_profile_malformed: field 6 present but omits key 2 (revision). ParseDecision
            // decodes it structurally fine; ForeignProfilePin.Validate()/VerifyDecision reject it.
            JsonElement fpm = of.GetProperty("foreign_profile_malformed");
            byte[] fpmBody = Hb(fpm.GetProperty("body_hex").GetString()!);
            Gateway.GatewayDecision parsedFpm = Gateway.ParseDecision(fpmBody);
            Assert.NotNull(parsedFpm.ForeignProfile);
            Assert.Equal("ForeignProfileMalformed", ErrKind(() => parsedFpm.ForeignProfile!.Validate()));
            byte[] seedFpm = Seed(0x72);
            byte[] pkFpm = Cose.MldsaKeygen("ML-DSA-65", seedFpm);
            byte[] objFpm = Cose.CoseSign1(Alg, seedFpm, BareProtected(Alg), fpmBody);
            Assert.Equal("ForeignProfileMalformed", ErrKind(() => Gateway.VerifyDecision(objFpm, Cose.PROFILE_PUBLIC, Alg, pkFpm)));

            // ordering_malformed: field 5 basis=external-mechanism but key 2 (boundary) is ALSO present.
            JsonElement om = of.GetProperty("ordering_malformed");
            byte[] omBody = Hb(om.GetProperty("body_hex").GetString()!);
            Gateway.GatewayDecision parsedOm = Gateway.ParseDecision(omBody);
            Assert.NotNull(parsedOm.Ordering);
            Assert.Equal("OrderingDisclosureMalformed", ErrKind(() => parsedOm.Ordering!.Validate()));
            byte[] seedOm = Seed(0x73);
            byte[] pkOm = Cose.MldsaKeygen("ML-DSA-65", seedOm);
            byte[] objOm = Cose.CoseSign1(Alg, seedOm, BareProtected(Alg), omBody);
            Assert.Equal("OrderingDisclosureMalformed", ErrKind(() => Gateway.VerifyDecision(objOm, Cose.PROFILE_PUBLIC, Alg, pkOm)));

            // ForeignProfilePin.Validate() direct unit tests (no oracle vector needed).
            Assert.Equal("no-error", ErrKind(() => new Gateway.ForeignProfilePin("https://example.test/p", "1").Validate()));
            Assert.Equal("ForeignProfileMalformed", ErrKind(() => new Gateway.ForeignProfilePin("", "1").Validate()));
            Assert.Equal("ForeignProfileMalformed", ErrKind(() => new Gateway.ForeignProfilePin("https://example.test/p", "").Validate()));
            Assert.Equal("ForeignProfileMalformed", ErrKind(() => new Gateway.ForeignProfilePin("", "").Validate()));

            // foreign profile extra key rejected: a field-6 map carrying a THIRD key (3) beyond {1,2}
            // decodes structurally (the extra key does not fail decode) but fails Validate().
            var fpExtra = new Cbor.M(new List<Cbor.Pair>
            {
                new Cbor.Pair(new Cbor.U(1), new Cbor.T("https://example-registry.test/profiles/acme")),
                new Cbor.Pair(new Cbor.U(2), new Cbor.T("2026-01")),
                new Cbor.Pair(new Cbor.U(3), new Cbor.T("unexpected")),
            });
            var mExtra = new Cbor.M(new List<Cbor.Pair>
            {
                new Cbor.Pair(new Cbor.U(1), new Cbor.U(Gateway.DecisionAllow)),
                new Cbor.Pair(new Cbor.U(2), new Cbor.B(Hb(v.GetProperty("action_cid_hex").GetString()!))),
                new Cbor.Pair(new Cbor.U(3), new Cbor.B(Hb(v.GetProperty("policy_hex").GetString()!))),
                new Cbor.Pair(new Cbor.U(4), new Cbor.U(1)),
                new Cbor.Pair(new Cbor.U(6), fpExtra),
            });
            byte[] extraBody = Cbor.Encode(mExtra);
            Gateway.GatewayDecision parsedExtra = Gateway.ParseDecision(extraBody);
            Assert.NotNull(parsedExtra.ForeignProfile);
            Assert.Equal("https://example-registry.test/profiles/acme", parsedExtra.ForeignProfile!.Id);
            Assert.Equal("2026-01", parsedExtra.ForeignProfile.Revision);
            Assert.Equal("ForeignProfileMalformed", ErrKind(() => parsedExtra.ForeignProfile!.Validate()));
        }
    }
}
