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
    /// The object-audience (field 13, §2.5.3) known-answer + gate tests for the C# SDK.
    ///
    /// <para>Byte match: an audience-bearing object's content id (computed over the body WITH the
    /// audience) reproduces the independent oracle's <c>object_with_audience.content_id_hex</c>
    /// (vectors/envelope/cases.json), and a NO-audience object reproduces the base
    /// <c>object.content_id_hex</c> — proving omit-when-empty additivity byte-for-byte
    /// (C# == Go == Rust == Python == TS == Ruby == PHP == the oracle). ContentId() runs the impl's
    /// own BodyMap-with-audience, so a wrong field number/type/placement would flip it.</para>
    ///
    /// <para>CheckAudience is the three-branch point-of-use gate; ConsumeObject enforces it at the
    /// consume choke point BEFORE the compare-and-set (wrong/absent -> WrongAudience with no append;
    /// unnamed ledger -> LedgerUnsigned; correct -> consumes once).</para>
    /// </summary>
    public sealed class AudienceKatTest
    {
        private const int Alg = Cose.ALG_MLDSA65;
        private static readonly byte[] Signer = Convert.FromHexString("5349474e45525f41"); // "SIGNER_A"
        private const string Audience = "consuming-authority-xyz";

        private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();

        private static Envelope.Object AudienceObject() => new Envelope.Object(
            kind: 2, channel: 4, signer: Signer, created: 1785000000000L, effect: 2,
            body: new Cbor.T("hello"), tier: 0, profile: 1, audience: Audience);

        private static Envelope.Object PlainObject() => new Envelope.Object(
            kind: 2, channel: 4, signer: Signer, created: 1785000000000L, effect: 2,
            body: new Cbor.T("hello"), tier: 0, profile: 1);

        private static Envelope.Object GateObject(string aud) => new Envelope.Object(
            kind: 2, channel: 4, signer: Signer, created: 0, effect: 0,
            body: new Cbor.T("x"), profile: 1, audience: aud);

        private static string? FindVector()
        {
            var d = new DirectoryInfo(AppContext.BaseDirectory);
            for (int i = 0; i < 10 && d != null; i++)
            {
                string p = Path.Combine(d.FullName, "vectors", "envelope", "cases.json");
                if (File.Exists(p))
                {
                    return p;
                }
                d = d.Parent;
            }
            return null;
        }

        [Fact]
        public void AudienceContentIdMatchesOracle()
        {
            string? p = FindVector();
            Assert.True(p != null, "committed oracle vector vectors/envelope/cases.json not found from " + AppContext.BaseDirectory);
            using JsonDocument doc = JsonDocument.Parse(File.ReadAllText(p!, Encoding.UTF8));
            JsonElement root = doc.RootElement;
            string wantAudience = root.GetProperty("object_with_audience").GetProperty("content_id_hex").GetString()!;
            string wantPlain = root.GetProperty("object").GetProperty("content_id_hex").GetString()!;

            // the audience-bearing content id (body WITH field 13) reproduces the oracle
            Assert.Equal(wantAudience, Hex(AudienceObject().ContentId()));
            // omit-when-empty is additive: a no-audience object reproduces the BASE draft-00 content id
            Assert.Equal(wantPlain, Hex(PlainObject().ContentId()));
            // and the two must actually differ (the audience field changes the identity)
            Assert.NotEqual(Hex(AudienceObject().ContentId()), Hex(PlainObject().ContentId()));
        }

        [Fact]
        public void SignVerifyRoundtripPreservesAudience()
        {
            byte[] seed = new byte[32];
            for (int i = 0; i < seed.Length; i++) { seed[i] = 0x2a; }
            byte[] pk = Cose.MldsaKeygen("ML-DSA-65", seed);
            string signerId = Identity.SignerId(Alg, pk);
            var obj = new Envelope.Object(
                kind: 1, channel: 4, signer: Encoding.UTF8.GetBytes(signerId), created: 1785000000000L,
                effect: 2, body: new Cbor.M(new List<Cbor.Pair> { new Cbor.Pair(new Cbor.U(1), new Cbor.T("hi")) }),
                profile: Cose.PROFILE_PUBLIC, audience: "authority-A");
            byte[] signed = Envelope.Sign(obj, Alg, seed);
            Envelope.Object got = Envelope.Verify(Cose.PROFILE_PUBLIC, Alg, pk, (c, k) => c == 4 && k == 1, signed);
            Assert.Equal("authority-A", got.Audience);
        }

        [Theory]
        [InlineData("authority-A", true)]   // consume-once, correct
        [InlineData("", false)]             // unrestricted, absent
        [InlineData("authority-A", false)]  // unrestricted, correct
        public void CheckAudiencePasses(string aud, bool consumeOnce)
        {
            Envelope.CheckAudience(GateObject(aud), "authority-A", consumeOnce); // no throw
        }

        [Theory]
        [InlineData("authority-B", true)]   // consume-once, foreign
        [InlineData("", true)]              // consume-once, absent
        [InlineData("authority-B", false)]  // foreign even when not consume-once
        public void CheckAudienceRejects(string aud, bool consumeOnce)
        {
            var ex = Assert.Throws<NaalpException>(() => Envelope.CheckAudience(GateObject(aud), "authority-A", consumeOnce));
            Assert.Equal("WrongAudience", ex.Kind);
        }

        private static byte[] Aid()
        {
            byte[] a = new byte[50];
            for (int i = 0; i < 50; i++) { a[i] = (byte)i; }
            return a;
        }

        private static void WithLedger(string authority, Action<Approval.Ledger> body)
        {
            string path = Path.GetTempFileName();
            try
            {
                using Approval.Ledger led = Approval.OpenLedger(path, authority);
                body(led);
            }
            finally
            {
                try { File.Delete(path); } catch { /* best-effort */ }
            }
        }

        [Fact]
        public void ConsumeObjectWrongAudienceRejectedNoAppend()
        {
            WithLedger("authority-A", led =>
            {
                var ex = Assert.Throws<NaalpException>(() => led.ConsumeObject(GateObject("authority-B"), Aid(), "consumer"));
                Assert.Equal("WrongAudience", ex.Kind);
                Assert.Equal(0, led.Len());
            });
        }

        [Fact]
        public void ConsumeObjectAbsentAudienceRejectedNoAppend()
        {
            WithLedger("authority-A", led =>
            {
                var ex = Assert.Throws<NaalpException>(() => led.ConsumeObject(GateObject(""), Aid(), "consumer"));
                Assert.Equal("WrongAudience", ex.Kind);
                Assert.Equal(0, led.Len());
            });
        }

        [Fact]
        public void ConsumeObjectCorrectAudienceConsumesOnce()
        {
            WithLedger("authority-A", led =>
            {
                led.ConsumeObject(GateObject("authority-A"), Aid(), "consumer");
                Assert.Equal(1, led.Len());
                var ex = Assert.Throws<NaalpException>(() => led.ConsumeObject(GateObject("authority-A"), Aid(), "consumer"));
                Assert.Equal("AlreadyConsumed", ex.Kind);
            });
        }

        [Fact]
        public void ConsumeObjectUnnamedLedgerRefuses()
        {
            WithLedger("", led =>
            {
                var ex = Assert.Throws<NaalpException>(() => led.ConsumeObject(GateObject("authority-A"), Aid(), "consumer"));
                Assert.Equal("LedgerUnsigned", ex.Kind);
            });
        }
    }
}
