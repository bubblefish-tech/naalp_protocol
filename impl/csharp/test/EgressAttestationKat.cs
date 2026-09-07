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
    /// E6.3 naalp-egress-attestation known-answer test for the C# SDK, graded against the independent,
    /// non-circular corpus <c>vectors/egress_attestation/cases.json</c> — mirroring
    /// impl/go/gateway/egress_attestation_test.go and impl/python/tests/test_egress_attestation.py.
    ///
    /// <para>A naalp-egress-attestation is a SIGNED attestation a gateway/sidecar emits that an object
    /// of a given effect class, bound to a given audience, crossed an egress boundary at a given time —
    /// third-party verifiable WITHOUT the payload. A near-clone of GatewayDecision: authority lives in
    /// the signature, never the serving party.</para>
    /// </summary>
    public sealed class EgressAttestationKat
    {
        private const int Alg = Cose.ALG_MLDSA65;

        private static JsonElement Vector()
        {
            var d = new DirectoryInfo(AppContext.BaseDirectory);
            for (int i = 0; i < 12 && d != null; i++)
            {
                string p = Path.Combine(d.FullName, "vectors", "egress_attestation", "cases.json");
                if (File.Exists(p))
                {
                    var doc = JsonDocument.Parse(File.ReadAllText(p));
                    return doc.RootElement.Clone();
                }
                d = d.Parent;
            }
            throw new Xunit.Sdk.XunitException("vectors/egress_attestation/cases.json not found from " + AppContext.BaseDirectory);
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

        private static long LongField(JsonElement scope, string key)
        {
            string s = scope.GetProperty(key).GetString()!;
            return unchecked((long)ulong.Parse(s));
        }

        private static Gateway.EgressAttestation AttFrom(JsonElement av)
        {
            return new Gateway.EgressAttestation(
                av.GetProperty("binding").GetInt64(), Hb(av.GetProperty("digest_hex").GetString()!),
                av.GetProperty("effect").GetInt64(), Hb(av.GetProperty("audience_hex").GetString()!), LongField(av, "at_str"));
        }

        private static string EgRejectKind(byte[] body)
        {
            try
            {
                Gateway.EgressAttestation a = Gateway.ParseEgressAttestation(body);
                try
                {
                    Gateway.ValidateEgressAttestation(a);
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

        /// <summary>Mirrors TestEgressVendorOnlyMutation: the honest VerifyEgressAttestation takes NO
        /// serving-party identity, so a mutant "vendor-only" verifier that additionally requires
        /// servingParty == gatewayId wrongly rejects a third party re-serving the identical
        /// bytes.</summary>
        private static void MutantVerify(byte[] obj, byte[] gwPk, byte[] gatewayId, byte[] servingParty)
        {
            Gateway.VerifyEgressAttestation(obj, Cose.PROFILE_PUBLIC, Alg, gwPk);
            if (!((ReadOnlySpan<byte>)servingParty).SequenceEqual(gatewayId))
            {
                throw new NaalpException("EgMalformed", "stands in for a not-served-by-vendor rejection");
            }
        }

        [Fact]
        public void AttestationsByteParity()
        {
            JsonElement json = Vector();
            foreach (JsonProperty p in json.GetProperty("attestations").EnumerateObject())
            {
                JsonElement av = p.Value;
                Gateway.EgressAttestation a = AttFrom(av);
                Assert.Equal(av.GetProperty("body_hex").GetString(), Hex(a.Bytes()));
                Assert.Equal(av.GetProperty("head_hex").GetString(), Hex(a.Head()));
                Assert.Equal(av.GetProperty("id_hex").GetString(), Hex(a.Id()));
            }
            foreach (JsonElement vb in json.GetProperty("binding_vocabulary").EnumerateArray())
            {
                string name = vb.GetProperty("name").GetString()!;
                long code = vb.GetProperty("code").GetInt64();
                Assert.True(Gateway.IsKnownBinding(code), "binding " + name + " must be known");
                Assert.Equal(name, Gateway.BindingName(code));
            }
            Assert.False(Gateway.IsKnownBinding(json.GetProperty("unknown_binding").GetInt64()));
        }

        [Fact]
        public void OversizedCounter()
        {
            JsonElement json = Vector();
            JsonElement ov = json.GetProperty("edge_cases").GetProperty("oversized_counter");
            Assert.Equal("18446744073709551615", ov.GetProperty("at_str").GetString());
            Gateway.EgressAttestation oversized = AttFrom(ov);
            Assert.Equal("18446744073709551615", unchecked((ulong)oversized.At).ToString());
            Assert.Equal(ov.GetProperty("body_hex").GetString(), Hex(oversized.Bytes()));
            Assert.Equal(
                unchecked((ulong)oversized.At).ToString(),
                unchecked((ulong)Gateway.ParseEgressAttestation(oversized.Bytes()).At).ToString());
        }

        [Fact]
        public void ThirdPartyReServe()
        {
            JsonElement json = Vector();
            byte[] seedGw = Seed(0x61);
            byte[] seedForeign = Seed(0x62);
            byte[] gwPk = Cose.MldsaKeygen("ML-DSA-65", seedGw);
            byte[] foreignPk = Cose.MldsaKeygen("ML-DSA-65", seedForeign);
            Gateway.EgressAttestation cb = AttFrom(json.GetProperty("attestations").GetProperty("content_bound"));
            byte[] egObj = Gateway.SignEgressAttestation(cb, Alg, seedGw);
            Gateway.ResolvedEgressAttestation byGateway = Gateway.VerifyEgressAttestation(egObj, Cose.PROFILE_PUBLIC, Alg, gwPk);
            Gateway.ResolvedEgressAttestation byThirdParty = Gateway.VerifyEgressAttestation((byte[])egObj.Clone(), Cose.PROFILE_PUBLIC, Alg, gwPk);
            Assert.Equal(byGateway.Binding, byThirdParty.Binding);
            Assert.Equal(Hex(byGateway.Digest), Hex(byThirdParty.Digest));
            Assert.Equal(byGateway.Effect, byThirdParty.Effect);
            Assert.Equal(Hex(byGateway.Audience), Hex(byThirdParty.Audience));
            Assert.Equal(unchecked((ulong)byGateway.At), unchecked((ulong)byThirdParty.At));
            Assert.Equal(Gateway.BindingContentBound, byThirdParty.Binding);
            Assert.Equal(json.GetProperty("object_cid_hex").GetString(), Hex(byThirdParty.Digest));

            var badSig = Assert.Throws<NaalpException>(() => Gateway.VerifyEgressAttestation(egObj, Cose.PROFILE_PUBLIC, Alg, foreignPk));
            Assert.Equal("BadSignature", badSig.Kind);

            long unknownBinding = json.GetProperty("unknown_binding").GetInt64();
            var bad = new Gateway.EgressAttestation(
                unknownBinding, Hb(json.GetProperty("object_cid_hex").GetString()!), 0,
                Hb(json.GetProperty("audience_hex").GetString()!), 0);
            byte[] badObj = Gateway.SignEgressAttestation(bad, Alg, seedGw);
            var unk = Assert.Throws<NaalpException>(() => Gateway.VerifyEgressAttestation(badObj, Cose.PROFILE_PUBLIC, Alg, gwPk));
            Assert.Equal("UnknownEgressBinding", unk.Kind);
        }

        [Fact]
        public void VendorOnlyMutation()
        {
            JsonElement json = Vector();
            byte[] seedGw = Seed(0x61);
            byte[] gwPk = Cose.MldsaKeygen("ML-DSA-65", seedGw);
            byte[] gatewayId = Encoding.UTF8.GetBytes("gateway-id-0x61");
            byte[] thirdPartyId = Encoding.UTF8.GetBytes("did:example:mirror-cache");
            Gateway.EgressAttestation cf = AttFrom(json.GetProperty("attestations").GetProperty("content_free"));
            byte[] cfObj = Gateway.SignEgressAttestation(cf, Alg, seedGw);
            Gateway.VerifyEgressAttestation(cfObj, Cose.PROFILE_PUBLIC, Alg, gwPk); // honest: no throw
            Assert.Equal("no-error", ErrKind(() => MutantVerify(cfObj, gwPk, gatewayId, gatewayId)));
            Assert.Equal("EgMalformed", ErrKind(() => MutantVerify(cfObj, gwPk, gatewayId, thirdPartyId)));
        }

        [Fact]
        public void CommitmentOpenVerify()
        {
            JsonElement json = Vector();
            JsonElement co = json.GetProperty("commitment_open");
            Gateway.EgressAttestation cfForCommit = AttFrom(json.GetProperty("attestations").GetProperty("content_free"));
            Assert.Equal(co.GetProperty("commitment_hex").GetString(), Hex(cfForCommit.Digest));
            byte[] objectCid = Hb(co.GetProperty("object_cid_hex").GetString()!);
            byte[] wrongObjectCid = Hb(co.GetProperty("wrong_object_cid_hex").GetString()!);
            byte[] salt = Hb(co.GetProperty("salt_hex").GetString()!);
            byte[] wrongSalt = Hb(co.GetProperty("wrong_salt_hex").GetString()!);
            Assert.Equal(co.GetProperty("commitment_hex").GetString(), Hex(Gateway.EgressCommit(objectCid, salt)));
            Assert.True(Gateway.OpenEgressCommitment(cfForCommit, objectCid, salt));
            Assert.False(Gateway.OpenEgressCommitment(cfForCommit, objectCid, wrongSalt));
            Assert.False(Gateway.OpenEgressCommitment(cfForCommit, wrongObjectCid, salt));
            Assert.False(Gateway.OpenEgressCommitment(cfForCommit, wrongObjectCid, wrongSalt));

            Gateway.EgressAttestation cbForCommit = AttFrom(json.GetProperty("attestations").GetProperty("content_bound"));
            Assert.False(Gateway.OpenEgressCommitment(cbForCommit, objectCid, salt));
        }

        [Fact]
        public void KeysOutOfOrderRejected()
        {
            JsonElement json = Vector();
            JsonElement koo = json.GetProperty("edge_cases").GetProperty("keys_out_of_order");
            Gateway.EgressAttestation kooAtt = AttFrom(koo);
            Assert.Equal(koo.GetProperty("canonical_body_hex").GetString(), Hex(kooAtt.Bytes()));
            byte[] canon = Hb(koo.GetProperty("canonical_body_hex").GetString()!);
            byte[] noncanon = Hb(koo.GetProperty("noncanonical_body_hex").GetString()!);
            Cbor.Decode(canon); // should decode
            Gateway.ParseEgressAttestation(canon); // should parse
            var ce = Assert.Throws<NaalpException>(() => Cbor.Decode(noncanon));
            Assert.Equal("NonCanonical", ce.Kind);
            Assert.Equal("EgMalformed", EgRejectKind(noncanon));
        }

        [Fact]
        public void EmptyVsAbsentAudience()
        {
            JsonElement json = Vector();
            JsonElement eva = json.GetProperty("edge_cases").GetProperty("empty_vs_absent");
            byte[] objectCidBytes = Hb(json.GetProperty("object_cid_hex").GetString()!);
            JsonElement emptyAudBlock = eva.GetProperty("empty_audience");
            JsonElement populatedAudBlock = eva.GetProperty("populated_audience");
            var emptyAud = new Gateway.EgressAttestation(Gateway.BindingContentBound, objectCidBytes, 1, Array.Empty<byte>(), 1735689600000L);
            var populatedAud = new Gateway.EgressAttestation(
                Gateway.BindingContentBound, objectCidBytes, 1, Hb(populatedAudBlock.GetProperty("audience_hex").GetString()!), 1735689600000L);
            Assert.Equal(emptyAudBlock.GetProperty("body_hex").GetString(), Hex(emptyAud.Bytes()));
            Assert.Equal(populatedAudBlock.GetProperty("body_hex").GetString(), Hex(populatedAud.Bytes()));
            Assert.NotEqual(Hex(emptyAud.Id()), Hex(populatedAud.Id()));
            Assert.Equal(emptyAudBlock.GetProperty("id_hex").GetString(), Hex(emptyAud.Id()));
            Gateway.ParseEgressAttestation(emptyAud.Bytes());
            Gateway.ParseEgressAttestation(populatedAud.Bytes());
            JsonElement absentFieldBlock = eva.GetProperty("absent_field");
            Assert.Equal("EgMalformed", EgRejectKind(Hb(absentFieldBlock.GetProperty("body_hex").GetString()!)));
        }

        [Fact]
        public void Minimal()
        {
            JsonElement json = Vector();
            JsonElement minB = json.GetProperty("edge_cases").GetProperty("minimal");
            Gateway.EgressAttestation minimal = AttFrom(minB);
            Assert.Equal(minB.GetProperty("body_hex").GetString(), Hex(minimal.Bytes()));
            Assert.Equal(minB.GetProperty("id_hex").GetString(), Hex(minimal.Id()));
            Gateway.ParseEgressAttestation(minimal.Bytes());
            byte[] minSeed = Seed(0x63);
            byte[] minPk = Cose.MldsaKeygen("ML-DSA-65", minSeed);
            byte[] minObj = Gateway.SignEgressAttestation(minimal, Alg, minSeed);
            Assert.Equal("no-error", ErrKind(() => Gateway.VerifyEgressAttestation(minObj, Cose.PROFILE_PUBLIC, Alg, minPk)));
        }

        [Fact]
        public void LookAlikeRejected()
        {
            JsonElement json = Vector();
            JsonElement la = json.GetProperty("edge_cases").GetProperty("look_alike");
            Assert.Equal(la.GetProperty("reject").GetString(), EgRejectKind(Hb(la.GetProperty("body_hex").GetString()!)));
        }

        [Fact]
        public void OrderingByteParity()
        {
            JsonElement json = Vector();
            foreach (JsonElement vb in json.GetProperty("ordering_basis_vocabulary").EnumerateArray())
            {
                string name = vb.GetProperty("name").GetString()!;
                long code = vb.GetProperty("code").GetInt64();
                Assert.True(Gateway.IsKnownOrderingBasis(code), "ordering basis " + name + " must be known");
                Assert.Equal(name, Gateway.OrderingBasisName(code));
            }

            foreach (JsonProperty p in json.GetProperty("attestations_with_ordering").EnumerateObject())
            {
                string name = p.Name;
                JsonElement av = p.Value;
                Gateway.EgressAttestation baseAtt = AttFrom(av);
                Gateway.OrderingDisclosure ord = name switch
                {
                    "correspondence_only" => Gateway.CorrespondenceOnly(),
                    "single_boundary" => new Gateway.OrderingDisclosure(
                        Gateway.OrderingSingleBoundary, Encoding.UTF8.GetBytes("boundary-signer-X"),
                        Array.Empty<byte>(), Array.Empty<byte>()),
                    "external_mechanism" => new Gateway.OrderingDisclosure(
                        Gateway.OrderingExternalMechanism, Array.Empty<byte>(),
                        Encoding.UTF8.GetBytes("external-log:acme-transparency-v1"),
                        Hb("2030c83b03ab5d26de33f037927bb2258fcfc3e8050793b68959bc5be954bcda9ca13875be35627f50f282c4eff9d807ea56")),
                    _ => throw new Xunit.Sdk.XunitException("unhandled attestations_with_ordering name " + name),
                };
                var withOrd = new Gateway.EgressAttestation(baseAtt.Binding, baseAtt.Digest, baseAtt.Effect, baseAtt.Audience, baseAtt.At, ord);
                Assert.Equal(av.GetProperty("body_hex").GetString(), Hex(withOrd.Bytes()));
                Assert.Equal(av.GetProperty("head_hex").GetString(), Hex(withOrd.Head()));
                Assert.Equal(av.GetProperty("id_hex").GetString(), Hex(withOrd.Id()));
                Gateway.EgressAttestation parsed = Gateway.ParseEgressAttestation(withOrd.Bytes());
                Assert.NotNull(parsed.Ordering);
                Assert.Equal(av.GetProperty("body_hex").GetString(), Hex(parsed.Bytes()));
                Gateway.ValidateEgressAttestation(parsed); // no throw
            }
            Gateway.EgressAttestation plain = Gateway.ParseEgressAttestation(
                AttFrom(json.GetProperty("attestations").GetProperty("content_bound")).Bytes());
            Assert.Null(plain.Ordering);
        }

        [Fact]
        public void OrderingNegative()
        {
            JsonElement json = Vector();
            JsonElement negOrd = json.GetProperty("negative_ordering");
            JsonElement sbwm = negOrd.GetProperty("ordering_malformed_single_boundary_with_mechanism");
            Assert.Equal(sbwm.GetProperty("reject").GetString(), EgRejectKind(Hb(sbwm.GetProperty("body_hex").GetString()!)));
            JsonElement uob = negOrd.GetProperty("unknown_ordering_basis");
            Assert.Equal(uob.GetProperty("reject").GetString(), EgRejectKind(Hb(uob.GetProperty("body_hex").GetString()!)));
        }

        [Fact]
        public void MissingAtFieldRejected()
        {
            var missingAt = new Cbor.M(new List<Cbor.Pair>
            {
                new Cbor.Pair(new Cbor.U(1), new Cbor.U(Gateway.BindingContentBound)),
                new Cbor.Pair(new Cbor.U(2), new Cbor.B(new byte[] { 0x20, 0x30 })),
                new Cbor.Pair(new Cbor.U(3), new Cbor.U(1)),
                new Cbor.Pair(new Cbor.U(4), new Cbor.B(Array.Empty<byte>())),
            });
            Assert.Equal("EgMalformed", EgRejectKind(Cbor.Encode(missingAt)));
        }
    }
}
