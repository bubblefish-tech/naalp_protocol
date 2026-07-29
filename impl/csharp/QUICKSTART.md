<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# N-AALP C# / .NET SDK

The C# reference implementation of **N-AALP** (draft-bubblefish-naalp-00) — an
application-layer object protocol for autonomous agents. NuGet package `Bubblefish.Naalp`,
namespace `Naalp`, target `net8.0`. Every N-AALP object is a deterministically-encoded CBOR
structure signed with COSE that carries, under one signature, its content identity, its signer, a
closed effect label, optional approval/audit bindings, and its causal derivation — **verifiable
offline, over any transport.**

## What this SDK provides

- **The full object envelope** — `Envelope.Object` + `Envelope.Sign` / `Envelope.Verify`: build,
  content-id-bind, deterministically sign, and offline-verify a complete N-AALP object.
- **Post-quantum signatures** — deterministic ML-DSA-65/-87 (FIPS 204, rnd=0) and Ed25519
  (RFC 8032), in COSE_Sign1 (`Cose`), via Bouncy Castle.
- **The byte-level primitives** — deterministic CBOR + content id (`Cbor`), self-certifying
  signer id (`Identity`), the effect lattice + authorization (`Policy`), the spine record bodies
  — approval, receipt, delivery, stream, carriage, transport boundary (`Records`), causal verify
  + federation reconcile (`Graph`), and the twenty-channel registry (`Channels`).

Every construction is **graded byte-for-byte** against the shared conformance corpus
(== Go == Rust == Python); the reference worked object is reproduced exactly by the CI byte-KAT
(`test/WorkedExampleKat.cs`).

## What this SDK does NOT provide

- A transport. N-AALP objects are transport-independent; carry them over N-PAMP, QUIC, WebSocket,
  or HTTP with your own client. The confidentiality boundary is `Records.TransportEmit`.
- Production key management. Bouncy Castle's `MLDsaSigner` is a correct FIPS 204 implementation
  used here in its deterministic (rnd=0) mode for reference/interop; apply your own key-storage
  and side-channel controls for production while keeping the same object bytes.

## Layout

- `Bubblefish.Naalp.csproj` — the NuGet library (`PackageId` `Bubblefish.Naalp`, `Version` 0.1.0,
  `RootNamespace` `Sh.Bubblefish.Naalp`, `PackageLicenseExpression` Apache-2.0,
  `GenerateDocumentationFile`, dependency `BouncyCastle.Cryptography` 2.6.2). `test/**` and
  `examples/**` are `Compile Remove`d from the library and built as their own projects.
- The SDK sources (namespace `Naalp`):
  - `Envelope.cs` — `Envelope.Object` + `Sign` / `Verify` (the full C3 object).
  - `Cbor.cs` — deterministic CBOR encode + strict canonical decode + `ContentId`.
  - `Cose.cs` — `ToBeSignedRaw`, `AssembleSign1Raw`, `ParseSign1Raw`, deterministic ML-DSA,
    Ed25519, `CoseSign1`/`CoseVerify1`/`CoseVerify1Raw`, `AlgLevel`/`ProfileMinLevel`.
  - `Identity.cs` — the self-certifying `SignerId` (multiformats) + `RequireNfc`.
  - `Policy.cs` — effect `NormalizeEffect` / `Authorizes` + `SafetyLabelBytes`.
  - `Records.cs` — approval / ledger / receipt / delivery / stream / carriage bodies + transport.
  - `Graph.cs` — causal verify + deterministic federation reconcile.
  - `Channels.cs` — the 20-channel / 65-kind table (`Lookup`, `CheckEffect`).
  - `Hex.cs`, `NaalpException.cs` — helpers.
- `test/Bubblefish.Naalp.Tests.csproj` — `WorkedExampleKat` (byte-exact worked object),
  `PrimitivesSmoke` (standards-anchored primitives), xUnit.
- `examples/SecureObject.cs` — a runnable build → sign → verify → tamper demo.

## Install / build

```sh
dotnet add package Bubblefish.Naalp        # from NuGet
```

Or build from this directory:

```sh
dotnet build -c Release impl/csharp/Bubblefish.Naalp.csproj
```

## Sign and verify an object

```csharp
using Naalp;
using System.Collections.Generic;
using System.Text;

byte[] seed = new byte[32];                                 // a real 32-byte key seed in production
int    alg  = Cose.ALG_MLDSA65;
byte[] pk   = Cose.MldsaKeygen("ML-DSA-65", seed);
string sid  = Identity.SignerId(alg, pk);

var body = new Cbor.M(new List<Cbor.Pair> {
    new Cbor.Pair(new Cbor.U(1), new Cbor.T("hello")) });
var obj  = new Envelope.Object(
    kind: 1, channel: 4, signer: Encoding.UTF8.GetBytes(sid), created: 1785000000000L,
    effect: 2, body: body, profile: Cose.PROFILE_PUBLIC);

byte[] signed = Envelope.Sign(obj, alg, seed);              // a self-describing signed object (bytes)
Envelope.Object got = Envelope.Verify(
    Cose.PROFILE_PUBLIC, alg, pk, (c, k) => c == 4 && k == 1, signed);
```

## Run the example

```sh
dotnet run -c Release --project impl/csharp/examples
# signer   bciqmqbeciwpwrbuv4j2ldnf2araohpsnsy6rfidj3kcrroy6tl222ua
# signed   3665 bytes, verifies=True
# tampered rejected: BadSignature
```

## Run the tests

The byte-KAT (`WorkedExampleKat`) reproduces the committed worked object
(`vectors/worked/example.json`) byte-for-byte, including the full `signed_object_hex`;
`PrimitivesSmoke` anchors the primitives to their standards vectors:

```sh
dotnet test -c Release impl/csharp/test/Bubblefish.Naalp.Tests.csproj
```

Cross-language conformance (the authoritative grade) builds the adapter — which project-references
this library — and drives the shared corpus through it:

```sh
dotnet build -c Release harness/adapters/csharp/Adapter.csproj
./harness/runner/naalp-conform.exe run --testee \
  "dotnet harness/adapters/csharp/bin/Release/net8.0/naalp-adapter-csharp.dll"
# RESULT: PASS (239 graded, 0 unimplemented/skipped)
```

Every op is implemented, including the crypto leg (`mldsa.keygen`, `ed25519.sign`, `cose.sign1`);
nothing is skipped. In CI the C# adapter is built and graded via `actions/setup-dotnet` (the
`dotnet` SDK is not available on the authoring dev box, so the C# leg is CI-graded).

## License

Apache-2.0 — see the repository `LICENSE.md` and `NOTICE`. The Internet-Draft is additionally
under the IETF Trust's BCP 78.
