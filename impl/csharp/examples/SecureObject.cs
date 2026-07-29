// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// examples/SecureObject.cs — build, sign, verify, and tamper-check a full N-AALP object.
//
// Run (from the repo root):
//   dotnet run -c Release --project impl/csharp/examples
// Expected output:
//   signer   bciq...
//   signed   <N> bytes, verifies=True
//   tampered rejected: BadSignature
using System;
using System.Collections.Generic;
using System.Text;

using Naalp;

internal static class SecureObject
{
    private static void Main()
    {
        // a deterministic 32-byte key seed (use a real random seed in production)
        byte[] seed = new byte[32];
        for (int i = 0; i < seed.Length; i++)
        {
            seed[i] = 0x2a;
        }
        int alg = Cose.ALG_MLDSA65;
        byte[] pk = Cose.MldsaKeygen("ML-DSA-65", seed);
        string signerId = Identity.SignerId(alg, pk);
        Console.WriteLine("signer   " + signerId);

        // a Governance Approval object (channel 0x0004, kind 1) on the Public profile. args_id is the
        // content id of the object the approval authorizes.
        byte[] argsId = new Envelope.Object(
            kind: 0, channel: 0, signer: Array.Empty<byte>(), created: 0, effect: 0,
            body: new Cbor.M(new List<Cbor.Pair> { new Cbor.Pair(new Cbor.U(1), new Cbor.T("the-args")) })
        ).ContentId();

        var approval = new Cbor.M(new List<Cbor.Pair>
        {
            new Cbor.Pair(new Cbor.U(1), new Cbor.B(argsId)),
            new Cbor.Pair(new Cbor.U(2), new Cbor.T(signerId)),
            new Cbor.Pair(new Cbor.U(3), new Cbor.U(2)),                                       // granted effect
            new Cbor.Pair(new Cbor.U(4), new Cbor.B(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 })),   // nonce
            new Cbor.Pair(new Cbor.U(5), new Cbor.U(1785000000000L)),                          // not_after (ms)
        });

        var obj = new Envelope.Object(
            kind: 1, channel: 4, signer: Encoding.UTF8.GetBytes(signerId), created: 1785000000000L,
            effect: 2, body: approval, tier: 0, profile: Cose.PROFILE_PUBLIC);

        byte[] signed = Envelope.Sign(obj, alg, seed);
        Envelope.Object got = Envelope.Verify(
            Cose.PROFILE_PUBLIC, alg, pk, (c, k) => c == 4 && k == 1, signed);
        bool verifies = got.Kind == 1 && got.Channel == 4;
        Console.WriteLine("signed   " + signed.Length + " bytes, verifies=" + verifies);

        byte[] tampered = (byte[])signed.Clone();
        tampered[tampered.Length - 1] ^= 1;
        try
        {
            Envelope.Verify(Cose.PROFILE_PUBLIC, alg, pk, (c, k) => true, tampered);
            Console.WriteLine("tampered NOT rejected (bug)");
        }
        catch (NaalpException e)
        {
            Console.WriteLine("tampered rejected: " + e.Kind);
        }
    }
}
