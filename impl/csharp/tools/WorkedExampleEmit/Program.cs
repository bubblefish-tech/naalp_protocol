// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// Emit the worked-example N-AALP object as one line of lowercase hex: the whole
// COSE_Sign1 the reference produces from the fixed 0x2a seed for the Governance
// Approval object (channel 0x0004, kind 1) -- the same construction the Go
// cmd/naalp-worked-example emitter and WorkedExampleKat build.
// scripts/record_cross_port_objects.py runs this and records the bytes; the
// cross-port object gate compares them to vectors/worked/example.json. Prints ONLY
// the hex so the recorder reads it unambiguously.
//
//   dotnet run -c Release --project tools/WorkedExampleEmit   (from impl/csharp/)

using System.Text;
using Naalp;

const int alg = Cose.ALG_MLDSA65;
const string argsIdHex =
    "20304e8abef02897dcc39231d926feb79b34534c6d474cd49a5b4dec2cc2cce90d251eef7418782006d829bd7f30ae8626ff";

byte[] seed = new byte[32];
Array.Fill(seed, (byte)0x2a);

byte[] pk = Cose.MldsaKeygen("ML-DSA-65", seed);
string signerId = Identity.SignerId(alg, pk);
var body = new Cbor.M(new List<Cbor.Pair>
{
    new Cbor.Pair(new Cbor.U(1), new Cbor.B(Convert.FromHexString(argsIdHex))),
    new Cbor.Pair(new Cbor.U(2), new Cbor.T(signerId)),
    new Cbor.Pair(new Cbor.U(3), new Cbor.U(2)),
    new Cbor.Pair(new Cbor.U(4), new Cbor.B(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 })),
    new Cbor.Pair(new Cbor.U(5), new Cbor.U(1785000000000L)),
});
var obj = new Envelope.Object(
    kind: 1, channel: 4, signer: Encoding.UTF8.GetBytes(signerId), created: 1785000000000L,
    effect: 2, body: body, tier: 0, profile: Cose.PROFILE_PUBLIC);
byte[] signed = Envelope.Sign(obj, alg, seed);
Console.WriteLine(Convert.ToHexString(signed).ToLowerInvariant());
