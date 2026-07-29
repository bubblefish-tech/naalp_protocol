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
    /// The full-object known-answer test: the reference worked object (fixed seed 0x2a*32, ML-DSA-65,
    /// a Governance Approval object) MUST be reproduced byte-for-byte, and the resulting object MUST
    /// verify and reject tampering. The self-contained anchors below (signer id, content id) are
    /// checked always; when the committed vector (vectors/worked/example.json) is found, the exact
    /// <c>signed_object_hex</c> is compared byte-for-byte — this is the CI byte-KAT for the C# SDK.
    ///
    /// <para>Run (from the repo root): <c>dotnet test -c Release impl/csharp/test/Bubblefish.Naalp.Tests.csproj</c></para>
    /// </summary>
    public sealed class WorkedExampleKat
    {
        private const int Alg = Cose.ALG_MLDSA65;
        private const string SignerIdExpected = "bciqmqbeciwpwrbuv4j2ldnf2araohpsnsy6rfidj3kcrroy6tl222ua";
        private const string ContentIdHex =
            "2030192922f9be80623bea1c689ddfe91dc15303abc851c8811b86cf9e53b837b5cc99d9c17e3acf95279f55e48203f79134";
        private const string ArgsIdHex =
            "20304e8abef02897dcc39231d926feb79b34534c6d474cd49a5b4dec2cc2cce90d251eef7418782006d829bd7f30ae8626ff";

        private static byte[] Seed()
        {
            byte[] s = new byte[32];
            for (int i = 0; i < s.Length; i++)
            {
                s[i] = 0x2a;
            }
            return s;
        }

        private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();

        private static Envelope.Object WorkedObject()
        {
            byte[] pk = Cose.MldsaKeygen("ML-DSA-65", Seed());
            string signerId = Identity.SignerId(Alg, pk);
            var body = new Cbor.M(new List<Cbor.Pair>
            {
                new Cbor.Pair(new Cbor.U(1), new Cbor.B(Convert.FromHexString(ArgsIdHex))),
                new Cbor.Pair(new Cbor.U(2), new Cbor.T(signerId)),
                new Cbor.Pair(new Cbor.U(3), new Cbor.U(2)),
                new Cbor.Pair(new Cbor.U(4), new Cbor.B(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 })),
                new Cbor.Pair(new Cbor.U(5), new Cbor.U(1785000000000L)),
            });
            return new Envelope.Object(
                kind: 1, channel: 4, signer: Encoding.UTF8.GetBytes(signerId), created: 1785000000000L,
                effect: 2, body: body, tier: 0, profile: Cose.PROFILE_PUBLIC);
        }

        private static string? FindVector()
        {
            var d = new DirectoryInfo(AppContext.BaseDirectory);
            for (int i = 0; i < 10 && d != null; i++)
            {
                string p = Path.Combine(d.FullName, "vectors", "worked", "example.json");
                if (File.Exists(p))
                {
                    return p;
                }
                d = d.Parent;
            }
            return null;
        }

        [Fact]
        public void SignerAndContentId()
        {
            byte[] pk = Cose.MldsaKeygen("ML-DSA-65", Seed());
            Assert.Equal(SignerIdExpected, Identity.SignerId(Alg, pk));
            Assert.Equal(ContentIdHex, Hex(WorkedObject().ContentId()));
        }

        [Fact]
        public void SignVerifyRoundtrip()
        {
            byte[] pk = Cose.MldsaKeygen("ML-DSA-65", Seed());
            byte[] signed = Envelope.Sign(WorkedObject(), Alg, Seed());
            Envelope.Object got = Envelope.Verify(
                Cose.PROFILE_PUBLIC, Alg, pk, (c, k) => c == 4 && k == 1, signed);
            Assert.Equal(1, got.Kind);
            Assert.Equal(4, got.Channel);
            Assert.Equal(2, got.Effect);
        }

        [Fact]
        public void TamperRejected()
        {
            byte[] pk = Cose.MldsaKeygen("ML-DSA-65", Seed());
            byte[] signed = (byte[])Envelope.Sign(WorkedObject(), Alg, Seed()).Clone();
            signed[signed.Length - 1] ^= 1;
            var ex = Assert.Throws<NaalpException>(() =>
                Envelope.Verify(Cose.PROFILE_PUBLIC, Alg, pk, (c, k) => true, signed));
            Assert.Equal("BadSignature", ex.Kind);
        }

        [Fact]
        public void ByteExactVsCommittedVector()
        {
            string? p = FindVector();
            Assert.True(p != null, "committed vector vectors/worked/example.json not found from " + AppContext.BaseDirectory);
            using JsonDocument doc = JsonDocument.Parse(File.ReadAllText(p!, Encoding.UTF8));
            JsonElement root = doc.RootElement;
            string wantSigned = root.GetProperty("signed_object_hex").GetString()!;
            string wantContentId = root.GetProperty("content_id_hex").GetString()!;

            byte[] signed = Envelope.Sign(WorkedObject(), Alg, Seed());
            Assert.Equal(wantContentId, Hex(WorkedObject().ContentId()));
            Assert.Equal(wantSigned, Hex(signed));
        }
    }
}
