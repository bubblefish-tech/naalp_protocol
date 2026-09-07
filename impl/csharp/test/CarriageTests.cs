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
    /// C12 — foreign carriage by class for the C# SDK (design.md §13; R-14.1..14.8, R-18.6), ported
    /// from impl/go/carriage and cross-checked against impl/python/naalp/carriage.py. Each carriage
    /// class is graded against its OWN per-class oracle
    /// <c>vectors/carriage/&lt;class&gt;/cases.json</c> for class in {jsonrpc, http, msg, stream, doc,
    /// opaque}, NOT produced by this code.
    ///
    /// <para>BYTE surface (⟹ csharp == Go == Rust == Python == oracle): every per-class carriage body
    /// hex and the octet-exact recovery of the foreign message (R-14.7, R-14.4). Behaviour: the §13.4
    /// protocol-id range classification 0x00..0xFF, a typed MappingError on an unknown class (R-14.8),
    /// NotDelivered on a below-foreign failure (R-14.8), the OPAQUE undefined-protocol path (R-18.6),
    /// and — over a REAL signed N-AALP envelope — R-14.6 identity containment: a foreign principal named
    /// inside the foreign bytes confers NO authority; the authorizing principal is the N-AALP signer.
    /// Carriage bodies are UNSIGNED (the six per-class body hexes ARE the byte parity).</para>
    /// </summary>
    public sealed class CarriageTests
    {
        private const int Alg = Cose.ALG_MLDSA65;

        private static readonly (string Dir, long Class)[] ClassDirs =
        {
            ("jsonrpc", Carriage.ClassJSONRPC),
            ("http", Carriage.ClassHTTP),
            ("msg", Carriage.ClassMSG),
            ("stream", Carriage.ClassSTREAM),
            ("doc", Carriage.ClassDOC),
            ("opaque", Carriage.ClassOPAQUE),
        };

        private static JsonElement ClassVector(string dir)
        {
            var d = new DirectoryInfo(AppContext.BaseDirectory);
            for (int i = 0; i < 12 && d != null; i++)
            {
                string p = Path.Combine(d.FullName, "vectors", "carriage", dir, "cases.json");
                if (File.Exists(p))
                {
                    return JsonDocument.Parse(File.ReadAllText(p)).RootElement.Clone();
                }
                d = d.Parent;
            }
            throw new Xunit.Sdk.XunitException("vectors/carriage/" + dir + "/cases.json not found from " + AppContext.BaseDirectory);
        }

        private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();
        private static byte[] Hb(string s) => Convert.FromHexString(s);

        // ---- per-class byte parity + octet-exact foreign round-trip (all six oracles) ---------------

        [Fact]
        public void PerClassOctetExactRoundTrip()
        {
            foreach ((string dir, long klass) in ClassDirs)
            {
                JsonElement c = ClassVector(dir);
                Assert.Equal(klass, c.GetProperty("class").GetInt64());

                byte[] foreign = Hb(c.GetProperty("foreign_hex").GetString()!);
                Carriage.CarriageBody cb = Carriage.Carry(
                    c.GetProperty("protocol_id").GetInt64(), c.GetProperty("class").GetInt64(),
                    c.GetProperty("content_type").GetInt64(), Hb(c.GetProperty("correlation_hex").GetString()!),
                    c.GetProperty("method").GetString()!, foreign);
                Assert.Equal(c.GetProperty("body_hex").GetString(), Hex(cb.Bytes()));

                // Round-trip: decode the carriage body and recover the foreign octets exactly.
                Cbor.Value v = Cbor.Decode(cb.Bytes());
                Carriage.CarriageBody rec = Carriage.CarriageFromValue(v);
                Assert.Equal(Hex(foreign), Hex(rec.Foreign)); // octet-exact — the foreign bytes are never re-serialized
                Assert.Equal(c.GetProperty("protocol_id").GetInt64(), rec.ProtocolID);
                Assert.Equal(c.GetProperty("class").GetInt64(), rec.Class);
                Assert.Equal(c.GetProperty("method").GetString(), rec.Method);
            }
        }

        // ---- §13.4 protocol-id range classification 0x00..0xFF -------------------------------------

        [Fact]
        public void ProtocolRangeClassification()
        {
            // The declared boundary map (design §13.4).
            var boundaries = new Dictionary<long, string>
            {
                { 0x00, "reserved" }, { 0x01, "standards" }, { 0x0F, "standards" },
                { 0x10, "experimental" }, { 0x7F, "experimental" }, { 0x80, "private" }, { 0xFF, "private" },
            };
            foreach (KeyValuePair<long, string> kv in boundaries)
            {
                Assert.Equal(kv.Value, Carriage.ProtocolRange(kv.Key));
            }
            // A full sweep 0x00..0xFF: every one-octet id classifies into exactly one of the four ranges.
            for (long id = 0x00; id <= 0xFF; id++)
            {
                string r = Carriage.ProtocolRange(id);
                Assert.Contains(r, new[] { "reserved", "standards", "experimental", "private" });
            }
            // An id wider than one octet is invalid.
            Assert.Equal("invalid", Carriage.ProtocolRange(0x100));
        }

        // ---- R-14.8: an unrepresentable class is a typed mapping error, never a silent drop ---------

        [Fact]
        public void MappingErrorOnUnknownClass()
        {
            var ex = Assert.Throws<NaalpException>(() => Carriage.Carry(0x10, 99, 0, Array.Empty<byte>(), "x", new byte[] { 0x79 }));
            Assert.Equal("MappingError", ex.Kind);
            var ex2 = Assert.Throws<NaalpException>(() => Carriage.ValidateClass(99));
            Assert.Equal("MappingError", ex2.Kind);
        }

        // ---- R-14.8: a below-foreign failure reports NotDelivered, never a false "delivered" --------

        [Fact]
        public void NotDeliveredIsHonest()
        {
            var ex = Assert.Throws<NaalpException>(() => Carriage.Report(false));
            Assert.Equal("NotDelivered", ex.Kind);
            Carriage.DeliveryReport rep = Carriage.Report(true);
            Assert.True(rep.Delivered);
        }

        // ---- R-18.6: an undefined protocol carries under OPAQUE on an experimental id, byte-exact ----

        [Fact]
        public void OpaqueUndefinedProtocol()
        {
            JsonElement c = ClassVector("opaque");
            long pid = c.GetProperty("protocol_id").GetInt64();
            Assert.Equal("experimental", Carriage.ProtocolRange(pid));
            byte[] blob = { 0x00, 0x01, 0x02, 0xFF, 0xFE, 0x7F, 0x80 };
            Carriage.CarriageBody cb = Carriage.Carry(pid, Carriage.ClassOPAQUE, 1, Array.Empty<byte>(), "", blob);
            Carriage.CarriageBody rec = Carriage.CarriageFromValue(Cbor.Decode(cb.Bytes()));
            Assert.Equal(Hex(blob), Hex(rec.Foreign));
        }

        // ---- a malformed carriage body is rejected fail-closed (Malformed) --------------------------

        [Fact]
        public void MalformedRejected()
        {
            // A body missing the mandatory foreign field (key 6): {1:1,2:0,3:0,4:'',5:'x'}.
            var noForeign = new Cbor.M(new List<Cbor.Pair>
            {
                new Cbor.Pair(new Cbor.U(1), new Cbor.U(1)),
                new Cbor.Pair(new Cbor.U(2), new Cbor.U(0)),
                new Cbor.Pair(new Cbor.U(3), new Cbor.U(0)),
                new Cbor.Pair(new Cbor.U(4), new Cbor.B(Array.Empty<byte>())),
                new Cbor.Pair(new Cbor.U(5), new Cbor.T("x")),
            });
            var ex = Assert.Throws<NaalpException>(() => Carriage.CarriageFromValue(noForeign));
            Assert.Equal("Malformed", ex.Kind);

            // A non-map value is Malformed.
            var ex2 = Assert.Throws<NaalpException>(() => Carriage.CarriageFromValue(new Cbor.U(0)));
            Assert.Equal("Malformed", ex2.Kind);
        }

        // ---- R-14.6 identity containment over a REAL signed N-AALP envelope (MUTATION ANCHOR) -------
        // MUTATION ANCHOR: making CarriageAuthority read the foreign principal instead of the signed
        // envelope's signer flips the Assert.Equal(signer, auth) and the DoesNotContain below.

        [Fact]
        public void IdentityContainmentOverSignedEnvelope()
        {
            byte[] seed = new byte[32];
            for (int i = 0; i < 32; i++) seed[i] = 80;
            byte[] pk = Cose.MldsaKeygen("ML-DSA-65", seed);

            byte[] foreign = Encoding.UTF8.GetBytes("{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"from\":\"attacker-principal\"}}");
            Carriage.CarriageBody cb = Carriage.Carry(0x01, Carriage.ClassJSONRPC, 0, new byte[] { 1, 2, 3, 4 }, "tools/call", foreign);

            // The carriage object is a normal signed N-AALP envelope object (Bridge channel 13, R-14.2).
            var obj = new Envelope.Object(kind: 0, channel: 13, signer: pk, created: 100, effect: 0,
                body: cb.ToValue(), tier: 0, profile: Cose.PROFILE_PUBLIC);
            byte[] signed = Envelope.Sign(obj, Alg, seed);
            Envelope.Object o = Envelope.Verify(Cose.PROFILE_PUBLIC, Alg, pk, (ch, k) => true, signed);

            // The authority is the N-AALP signer, NOT the foreign principal.
            byte[] auth = Carriage.CarriageAuthority(o);
            Assert.Equal(Hex(pk), Hex(auth));
            Assert.DoesNotContain("attacker-principal", Encoding.UTF8.GetString(auth));

            // The foreign message still carries the (non-authoritative) principal, recovered octet-exact.
            Carriage.CarriageBody rec = Carriage.CarriageFromValue(o.Body);
            Assert.Equal(Hex(foreign), Hex(rec.Foreign));
            Assert.Contains("attacker-principal", Encoding.UTF8.GetString(rec.Foreign));
        }
    }
}
