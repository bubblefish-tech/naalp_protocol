// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

using Naalp;
using Xunit;

namespace Sh.Bubblefish.Naalp.Tests
{
    /// <summary>
    /// Self-contained conformance smoke tests over the SDK primitives, anchored to independent
    /// standards vectors (FIPS 180-4 SHA-384, RFC 8949 canonical CBOR, the multiformats signer id,
    /// the §6.1 effect lattice, the twenty-channel registry, the §2.2 alg-level/profile floor). The
    /// authoritative cross-language grading is the naalp-conform harness against the shared corpus
    /// (== Go == Rust); these keep the published package independently checkable without the harness.
    /// </summary>
    public sealed class PrimitivesSmoke
    {
        private static byte[] Sha384(byte[] b)
        {
            using var sha = SHA384.Create();
            return sha.ComputeHash(b);
        }

        private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();

        [Fact]
        public void Sha384Kat()
        {
            Assert.Equal(
                "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
                + "8086072ba1e7cc2358baeca134c825a7",
                Hex(Sha384(Encoding.UTF8.GetBytes("abc"))));
        }

        [Fact]
        public void CborCanonicalEncodeAndContentId()
        {
            // canonical map: keys emitted in bytewise-ascending order regardless of input order
            var m = new Cbor.M(new List<Cbor.Pair>
            {
                new Cbor.Pair(new Cbor.U(3), new Cbor.U(4)),
                new Cbor.Pair(new Cbor.U(2), new Cbor.U(0)),
            });
            Assert.Equal("a2020003 04".Replace(" ", ""), Hex(Cbor.Encode(m)));
            byte[] cid = Cbor.ContentId(Cbor.Encode(m));
            Assert.Equal(0x20, cid[0]);
            Assert.Equal(0x30, cid[1]);
            Assert.Equal(2 + 48, cid.Length);
        }

        [Fact]
        public void CborRejectsNonCanonical()
        {
            // out-of-order / non-shortest / indefinite / duplicate-key
            foreach (string bad in new[] { "a202000100", "1800", "9f00ff", "a201000101" })
            {
                var ex = Assert.Throws<NaalpException>(() => Cbor.Decode(Convert.FromHexString(bad)));
                Assert.Equal("NonCanonical", ex.Kind);
            }
        }

        [Fact]
        public void CoseToBeSignedRfc9052()
        {
            byte[] tbs = Cose.ToBeSignedRaw(Convert.FromHexString("a1013830"), Convert.FromHexString("a10700"));
            // ["Signature1", ...]  ->  84 6a 5369676e6174757265 31
            Assert.StartsWith("846a5369676e617475726531", Hex(tbs));
        }

        [Fact]
        public void SignerIdForm()
        {
            byte[] pk = Cose.MldsaKeygen("ML-DSA-65", new byte[32]);
            Assert.StartsWith("b", Identity.SignerId(Cose.ALG_MLDSA65, pk));
        }

        [Fact]
        public void EffectLattice()
        {
            Assert.Equal(Policy.DESTRUCTIVE, Policy.NormalizeEffect(99)); // unknown -> destructive
            Assert.True(Policy.Authorizes(Policy.NON_IDEMPOTENT_WRITE, Policy.IDEMPOTENT_WRITE));
            Assert.False(Policy.Authorizes(Policy.READ_ONLY, Policy.DESTRUCTIVE));
        }

        [Fact]
        public void ChannelsRegistry()
        {
            Channels.KindSpec ks = Channels.Lookup(0x0004, 1); // Governance.Approval
            Assert.Equal("Approval", ks.Name);
            Assert.Equal((int)Policy.NON_IDEMPOTENT_WRITE, ks.Effect);
            Assert.False(ks.Variable);
            var ex = Assert.Throws<NaalpException>(() => Channels.Lookup(0x0000, 9999));
            Assert.Equal("UnknownKind", ex.Kind);
        }

        [Fact]
        public void RecordsDeterministic()
        {
            // a receipt body round-trips to stable bytes and the head is SHA-384 of it
            byte[] body = Records.ReceiptBody(new byte[48], Convert.FromHexString("2030" + new string('0', 96)), 0, 100);
            Assert.Equal(Hex(Sha384(body)), Hex(Records.ReceiptHead(body)));
        }

        [Fact]
        public void AlgLevelAndProfileFloor()
        {
            Assert.Equal(5, Cose.AlgLevel(Cose.ALG_MLDSA87).Level);
            Assert.Equal(3, Cose.AlgLevel(Cose.ALG_MLDSA65).Level);
            Assert.False(Cose.AlgLevel(999).Known);
            Assert.Equal(5, Cose.ProfileMinLevel(Cose.PROFILE_SOVEREIGN));
            Assert.Equal(3, Cose.ProfileMinLevel(Cose.PROFILE_PUBLIC));
        }
    }
}
