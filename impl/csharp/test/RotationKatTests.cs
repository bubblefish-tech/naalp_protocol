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
    /// §5.2 Rotation object (tag-98 COSE_Sign, old+new co-signature) known-answer + fail-closed
    /// tests for the C# SDK.
    ///
    /// <para>Mutation-surviving properties: (1) BYTE PARITY -- <see cref="Envelope.SignRotationObject"/>
    /// over the fixed worked fixture reproduces the Go/Rust/oracle bytes: the SHA-256 of the
    /// 6798-byte tag-98 object is pinned and equals the Go rotation.sign reference (C# == Go == Rust
    /// == Python == oracle on the whole two-leg object). (2) Round-trip --
    /// <see cref="Envelope.VerifyRotationObject"/> accepts a co-signed rotation (both legs, old then
    /// new). (3) Fail-closed reject family -- a tag-18 single-signature rotation, a dropped old leg,
    /// a wrong-key old leg, a tag-98 object on a non-rotation (channel,kind), and a Sovereign
    /// verifier over a rotation whose OLD key is below the profile floor are ALL rejected with the
    /// named kind.</para>
    ///
    /// <para>Run: <c>dotnet test test/Bubblefish.Naalp.Tests.csproj -c Release --filter FullyQualifiedName~RotationKatTests</c></para>
    /// </summary>
    public sealed class RotationKatTests
    {
        private static readonly byte[] OldSeed = Repeat(0x0B);        // old ML-DSA-65 key
        private static readonly byte[] NewSeed = Repeat(0x16);        // new ML-DSA-65 key (go-forward)
        private static readonly byte[] FloorOldSeed = Repeat(0x21);   // below-floor old ML-DSA-65 key (33)
        private static readonly byte[] FloorNewSeed = Repeat(0x2C);   // go-forward ML-DSA-87 key (44)
        // SHA-256 of the 6798-byte tag-98 rotation object for the fixed worked fixture; byte-identical
        // to the Go rotation.sign reference and tools/rotation_oracle.py (a cross-language,
        // non-circular anchor, not a C#-only self-check).
        private const string ObjectSha256 = "298d5d5bac8a0bf556541784f3090ac7300897858e883dc3ab6e7625bc418194";

        private static readonly byte[] Signer = Encoding.ASCII.GetBytes("SIGNER_NEW");
        private const long NotBefore = 1785000000000L;

        private static byte[] Repeat(byte b)
        {
            byte[] s = new byte[32];
            for (int i = 0; i < s.Length; i++)
            {
                s[i] = b;
            }
            return s;
        }

        private static string HexLower(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();

        private static Cbor.M RotationRecord()
        {
            // field-10 naalp-rotation body {1: old_id, 2: new_id, 3: not_before}
            return new Cbor.M(new List<Cbor.Pair>
            {
                new Cbor.Pair(new Cbor.U(1), new Cbor.T("signer-old")),
                new Cbor.Pair(new Cbor.U(2), new Cbor.T("signer-new")),
                new Cbor.Pair(new Cbor.U(3), new Cbor.U(NotBefore)),
            });
        }

        private static Envelope.Object WorkedObject(long profile = Cose.PROFILE_PUBLIC)
        {
            return new Envelope.Object(
                kind: 0, channel: 3, signer: Signer, created: NotBefore, effect: 2,
                body: RotationRecord(), tier: 0, profile: profile);
        }

        private static bool KindOk(long ch, long k) => ch == 3 && k == 0;

        [Fact]
        public void ObjectBytesParityWithReference()
        {
            byte[] obj = Envelope.SignRotationObject(WorkedObject(), Cose.ALG_MLDSA65, OldSeed, Cose.ALG_MLDSA65, NewSeed);
            Assert.Equal(6798, obj.Length);
            Assert.Equal(ObjectSha256, HexLower(SHA256.HashData(obj)));
        }

        [Fact]
        public void RoundtripAccept()
        {
            byte[] oldPk = Cose.MldsaKeygen("ML-DSA-65", OldSeed);
            byte[] newPk = Cose.MldsaKeygen("ML-DSA-65", NewSeed);
            byte[] obj = Envelope.SignRotationObject(WorkedObject(), Cose.ALG_MLDSA65, OldSeed, Cose.ALG_MLDSA65, NewSeed);
            Envelope.Object o = Envelope.VerifyRotationObject(
                Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, oldPk, Cose.ALG_MLDSA65, newPk, KindOk, obj);
            Assert.Equal(3, o.Channel);
            Assert.Equal(0, o.Kind);
        }

        [Fact]
        public void Tag18SingleSigRejected()
        {
            // a channel-3/kind-0 object signed as a normal single-signature COSE_Sign1 (tag 18) is a
            // rotation missing the old-key co-signature -> the general verify rejects RotationUnauthorized.
            byte[] newPk = Cose.MldsaKeygen("ML-DSA-65", NewSeed);
            byte[] obj = Envelope.Sign(WorkedObject(), Cose.ALG_MLDSA65, NewSeed); // tag-18
            NaalpException ex = Assert.Throws<NaalpException>(() =>
                Envelope.Verify(Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, newPk, KindOk, obj));
            Assert.Equal("RotationUnauthorized", ex.Kind);
        }

        [Fact]
        public void OldLegDropped()
        {
            // the mutation anchor: dropping the old leg (one leg) MUST be rejected RotationUnauthorized.
            // Disabling the exactly-two-legs check in VerifyRotationObject flips this test.
            byte[] oldPk = Cose.MldsaKeygen("ML-DSA-65", OldSeed);
            byte[] newPk = Cose.MldsaKeygen("ML-DSA-65", NewSeed);
            byte[] obj = Envelope.SignRotationObject(WorkedObject(), Cose.ALG_MLDSA65, OldSeed, Cose.ALG_MLDSA65, NewSeed);
            (byte[] bodyProt, byte[] payload, List<byte[][]> legs) = Cose.ParseSignRaw(obj);
            byte[] oneLeg = Cose.AssembleSignRaw(bodyProt, payload, new List<byte[][]> { legs[1] }); // keep only the new leg
            NaalpException ex = Assert.Throws<NaalpException>(() =>
                Envelope.VerifyRotationObject(Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, oldPk, Cose.ALG_MLDSA65, newPk, KindOk, oneLeg));
            Assert.Equal("RotationUnauthorized", ex.Kind);
        }

        [Fact]
        public void OldLegWrongKey()
        {
            // both legs signed by the NEW key -> the trusted old key cannot verify slot 0.
            byte[] oldPk = Cose.MldsaKeygen("ML-DSA-65", OldSeed);
            byte[] newPk = Cose.MldsaKeygen("ML-DSA-65", NewSeed);
            byte[] obj = Envelope.SignRotationObject(WorkedObject(), Cose.ALG_MLDSA65, NewSeed, Cose.ALG_MLDSA65, NewSeed);
            NaalpException ex = Assert.Throws<NaalpException>(() =>
                Envelope.VerifyRotationObject(Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, oldPk, Cose.ALG_MLDSA65, newPk, KindOk, obj));
            Assert.Equal("RotationUnauthorized", ex.Kind);
        }

        [Fact]
        public void NonRotationKindRejected()
        {
            // a tag-98 object built over a non-rotation (channel 4, kind 2) is UnknownKind.
            byte[] oldPk = Cose.MldsaKeygen("ML-DSA-65", OldSeed);
            byte[] newPk = Cose.MldsaKeygen("ML-DSA-65", NewSeed);
            var o = new Envelope.Object(
                kind: 2, channel: 4, signer: Signer, created: NotBefore, effect: 2,
                body: new Cbor.T("hello"), tier: 0, profile: Cose.PROFILE_PUBLIC);
            // Sign() is only used here to obtain a valid (protected-header, payload) pair for this
            // object's fields -- ProtectedHeader() is private, so a real tag-18 object over the same
            // fields is parsed back with ParseSign1Raw to recover the identical bytes
            // SignatureLeg()/AssembleSignRaw() need. The tag-18 signature itself is discarded.
            byte[] signed = Envelope.Sign(o, Cose.ALG_MLDSA65, NewSeed);
            byte[][] parts = Cose.ParseSign1Raw(signed);
            byte[] bodyProt = parts[0];
            byte[] payload = parts[1];
            byte[][] oldLeg = Cose.SignatureLeg(bodyProt, Cose.ALG_MLDSA65, OldSeed, payload);
            byte[][] newLeg = Cose.SignatureLeg(bodyProt, Cose.ALG_MLDSA65, NewSeed, payload);
            byte[] obj = Cose.AssembleSignRaw(bodyProt, payload, new List<byte[][]> { oldLeg, newLeg });
            NaalpException ex = Assert.Throws<NaalpException>(() =>
                Envelope.VerifyRotationObject(Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, oldPk, Cose.ALG_MLDSA65, newPk,
                    (c, k) => true, obj));
            Assert.Equal("UnknownKind", ex.Kind);
        }

        [Fact]
        public void SovereignOldLegFloorRejected()
        {
            // old=ML-DSA-65 (level 3), new=ML-DSA-87 (level 5), Sovereign floor 5 -> the sub-floor OLD
            // leg yields ProfileDowngrade under the ratified fail-closed default.
            byte[] oldPk = Cose.MldsaKeygen("ML-DSA-65", FloorOldSeed);
            byte[] newPk = Cose.MldsaKeygen("ML-DSA-87", FloorNewSeed);
            byte[] obj = Envelope.SignRotationObject(WorkedObject(Cose.PROFILE_SOVEREIGN), Cose.ALG_MLDSA65,
                FloorOldSeed, Cose.ALG_MLDSA87, FloorNewSeed);
            NaalpException ex = Assert.Throws<NaalpException>(() =>
                Envelope.VerifyRotationObject(Cose.PROFILE_SOVEREIGN, Cose.ALG_MLDSA65, oldPk, Cose.ALG_MLDSA87, newPk,
                    KindOk, obj));
            Assert.Equal("ProfileDowngrade", ex.Kind);
        }
    }
}
