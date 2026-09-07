// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System;
using System.Collections.Generic;
using System.Text;

using Naalp;
using Xunit;

namespace Sh.Bubblefish.Naalp.Tests
{
    /// <summary>
    /// Decoder bounds (design.md §3.4, R7), ported from impl/go/envelope/bounds_test.go. Each bound
    /// is proven by a BOUNDARY PAIR: an otherwise-valid object AT the limit verifies, and an
    /// otherwise-valid object one past the limit is rejected with the named error. "Otherwise valid"
    /// is load-bearing for mutation survival: because the only defect is the bound, deleting the
    /// bound check makes the over-limit object verify, so a constant-return mutation is caught.
    /// </summary>
    public sealed class EnvelopeBoundsTests
    {
        private const int Alg = Cose.ALG_MLDSA65;

        private static bool AcceptKind(long channel, long kind) => true;

        private static byte[] Seed()
        {
            var s = new byte[32];
            for (int i = 0; i < s.Length; i++)
            {
                s[i] = 0x37;
            }
            return s;
        }

        // buildObject returns a fresh, otherwise-valid object with the given body, signed by the
        // fixed test seed.
        private static Envelope.Object BuildObject(Cbor.Value body)
        {
            byte[] pk = Cose.MldsaKeygen("ML-DSA-65", Seed());
            string signerId = Identity.SignerId(Alg, pk);
            return new Envelope.Object(
                kind: 1, channel: 4, signer: Encoding.UTF8.GetBytes(signerId), created: 1785000000000L,
                effect: 2, body: body, tier: 0, profile: Cose.PROFILE_PUBLIC);
        }

        // makeCauses builds n content-id-shaped bstrs (multihash sha2-384 = 0x20 0x30 + 48 bytes).
        private static List<byte[]> MakeCauses(int n)
        {
            var outp = new List<byte[]>(n);
            for (int i = 0; i < n; i++)
            {
                var b = new byte[50];
                b[0] = 0x20;
                b[1] = 0x30;
                outp.Add(b);
            }
            return outp;
        }

        // makeExtMap builds n distinct non-critical extension entries (unknown keys, which the
        // may-ignore rule accepts), so the object is otherwise valid at any cardinality.
        private static Cbor.M MakeExtMap(int n)
        {
            var pairs = new List<Cbor.Pair>(n);
            for (int i = 0; i < n; i++)
            {
                pairs.Add(new Cbor.Pair(new Cbor.U(100 + i), new Cbor.U(0)));
            }
            return new Cbor.M(pairs);
        }

        // nestArrays returns k single-element arrays wrapping a zero scalar. As a body value it sits
        // at depth 2 (the object body map is depth 1), so the scalar is at depth 2+k.
        private static Cbor.Value NestArrays(int k)
        {
            Cbor.Value v = new Cbor.U(0);
            for (int i = 0; i < k; i++)
            {
                v = new Cbor.A(new List<Cbor.Value> { v });
            }
            return v;
        }

        [Fact]
        public void BoundsAcceptAtLimit()
        {
            byte[] pk = Cose.MldsaKeygen("ML-DSA-65", Seed());

            void Accept(string name, Envelope.Object o)
            {
                byte[] obj = Envelope.Sign(o, Alg, Seed());
                Envelope.Verify(Cose.PROFILE_PUBLIC, Alg, pk, AcceptKind, obj);
            }

            Envelope.Object oc = BuildObject(new Cbor.U(0));
            oc.Causes = MakeCauses((int)Envelope.MaxCauses);
            Accept("causes==MaxCauses", oc);

            Envelope.Object oe = BuildObject(new Cbor.U(0));
            oe.Ext = MakeExtMap((int)Envelope.MaxExt);
            Accept("ext==MaxExt", oe);

            // body nested so the deepest scalar sits at exactly MaxNestingDepth (2 + (MaxNestingDepth-2)).
            Envelope.Object od = BuildObject(NestArrays((int)Envelope.MaxNestingDepth - 2));
            Accept("depth==MaxNestingDepth", od);
        }

        [Fact]
        public void BoundsRejectOverLimit()
        {
            byte[] pk = Cose.MldsaKeygen("ML-DSA-65", Seed());

            void Expect(string name, Envelope.Object o, string kind)
            {
                byte[] obj = Envelope.Sign(o, Alg, Seed());
                var ex = Assert.Throws<NaalpException>(() => Envelope.Verify(Cose.PROFILE_PUBLIC, Alg, pk, AcceptKind, obj));
                Assert.Equal(kind, ex.Kind);
            }

            Envelope.Object oc = BuildObject(new Cbor.U(0));
            oc.Causes = MakeCauses((int)Envelope.MaxCauses + 1);
            Expect("TooManyCauses", oc, "TooManyCauses");

            Envelope.Object oe = BuildObject(new Cbor.U(0));
            oe.Ext = MakeExtMap((int)Envelope.MaxExt + 1);
            Expect("TooManyExtensions(ext)", oe, "TooManyExtensions");

            // cext over the limit also yields TooManyExtensions: the cardinality check in
            // ObjectFromMap fires before the critical-extension recognition check.
            Envelope.Object ox = BuildObject(new Cbor.U(0));
            ox.Cext = MakeExtMap((int)Envelope.MaxCext + 1);
            Expect("TooManyExtensions(cext)", ox, "TooManyExtensions");

            // body nested so the deepest scalar sits at MaxNestingDepth+1.
            Envelope.Object od = BuildObject(NestArrays((int)Envelope.MaxNestingDepth - 1));
            Expect("DepthExceeded", od, "DepthExceeded");
        }

        [Fact]
        public void BoundTooLarge()
        {
            byte[] pk = Cose.MldsaKeygen("ML-DSA-65", Seed());

            Envelope.Object under = BuildObject(new Cbor.B(new byte[Envelope.MaxObjectSize - 16384]));
            byte[] uobj = Envelope.Sign(under, Alg, Seed());
            Assert.True(uobj.Length <= Envelope.MaxObjectSize, $"under-limit object is {uobj.Length} bytes, expected <= {Envelope.MaxObjectSize}");
            Envelope.Verify(Cose.PROFILE_PUBLIC, Alg, pk, AcceptKind, uobj); // must not throw

            Envelope.Object over = BuildObject(new Cbor.B(new byte[Envelope.MaxObjectSize]));
            byte[] bobj = Envelope.Sign(over, Alg, Seed());
            Assert.True(bobj.Length > Envelope.MaxObjectSize, $"over-limit object is only {bobj.Length} bytes, expected > {Envelope.MaxObjectSize}");
            var ex = Assert.Throws<NaalpException>(() => Envelope.Verify(Cose.PROFILE_PUBLIC, Alg, pk, AcceptKind, bobj));
            Assert.Equal("TooLarge", ex.Kind);
        }
    }
}
