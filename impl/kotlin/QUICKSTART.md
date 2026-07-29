<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# N-AALP Kotlin SDK

The Kotlin reference implementation of **N-AALP** (draft-bubblefish-naalp-00) — an
application-layer object protocol for autonomous agents. Every N-AALP object is a
deterministically-encoded CBOR structure signed with COSE that carries, under one signature, its
content identity, its signer, a closed effect label, optional approval/audit bindings, and its
causal derivation — **verifiable offline, over any transport.** Package `sh.bubblefish.naalp`;
Maven artifact `sh.bubblefish:naalp-kotlin` (the `-kotlin` suffix disambiguates it from the sibling
`naalp-java` artifact).

## What this SDK provides

- **The full object envelope** — `Envelope.Object` + `Envelope.sign` / `Envelope.verify` (re-exported
  as `Naalp.sign` / `Naalp.verify` and the `NaalpObject` typealias): build, content-id-bind,
  deterministically sign, and offline-verify a complete N-AALP object.
- **Post-quantum signatures** — deterministic ML-DSA-65/-87 (FIPS 204, rnd=0) and Ed25519
  (RFC 8032), in COSE_Sign1 (`Cose`), via Bouncy Castle.
- **The byte-level primitives** — deterministic CBOR + content id (`Cbor`), self-certifying
  signer id (`Identity`), the effect lattice + authorization (`Policy`), the spine record bodies
  — approval, receipt, delivery, stream, carriage, transport boundary (`Records`), causal verify
  + federation reconcile (`Graph`), and the twenty-channel registry (`Channels`).

Every construction is **graded byte-for-byte** against the shared conformance corpus
(== Go == Rust == Python); the reference worked object is reproduced exactly
(`src/test/kotlin/WorkedExampleKat.kt`).

## What this SDK does NOT provide

- A transport. N-AALP objects are transport-independent; carry them over N-PAMP, QUIC, WebSocket,
  or HTTP with your own client. The confidentiality boundary is `Records.transportEmit`.
- Production key management. Point the crypto leg at a constant-time FIPS 204 provider for
  production key handling while keeping the same object bytes; the same-alg object bytes are
  independent of the provider.

## Install

The published artifact is `sh.bubblefish:naalp-kotlin:0.1.0` (depends on
`org.bouncycastle:bcprov-jdk18on:1.85`). With Gradle:

```kotlin
dependencies {
    implementation("sh.bubblefish:naalp-kotlin:0.1.0")
}
```

Build and publish locally from this directory:

```sh
./gradlew build                 # compile + run the KAT and smoke tests
./gradlew publishToMavenLocal
```

## Sign and verify an object

```kotlin
import sh.bubblefish.naalp.*

val seed = ByteArray(32)                                   // a real 32-byte key seed in production
val alg  = Naalp.ALG_MLDSA65
val pk   = Cose.mldsaKeygen("ML-DSA-65", seed)
val sid  = Identity.signerId(alg, pk)

val body = Cbor.M(listOf(Cbor.Pair(Cbor.U(1), Cbor.T("hello"))))
val obj  = NaalpObject(
    kind = 1, channel = 4, signer = sid.toByteArray(),
    created = 1785000000000L, effect = 2, profile = Naalp.PROFILE_PUBLIC, body = body,
)
val signed = Naalp.sign(obj, alg, seed)                    // a self-describing signed object (bytes)
val got    = Naalp.verify(Naalp.PROFILE_PUBLIC, alg, pk, { c, k -> c == 4L && k == 1L }, signed)
```

## Run the example

```sh
KOTLINC=kotlinc
BC=harness/adapters/kotlin/lib/bcprov-jdk18on-1.85.jar
"$KOTLINC" -cp "$BC" impl/kotlin/src/main/kotlin/sh/bubblefish/naalp/*.kt impl/kotlin/examples/SecureObject.kt -include-runtime -d secure-object.jar
java -cp "secure-object.jar;$BC" sh.bubblefish.naalp.SecureObjectKt
# signer   bciq...
# signed   <N> bytes, verifies=true
# tampered rejected: BadSignature
```

## Run the tests

```sh
./gradlew check                 # runs workedExampleKat + primitivesSmoke
```

or standalone, without Gradle:

```sh
"$KOTLINC" -cp "$BC" impl/kotlin/src/main/kotlin/sh/bubblefish/naalp/*.kt impl/kotlin/src/test/kotlin/*.kt -include-runtime -d naalp-tests.jar
java -cp "naalp-tests.jar;$BC" sh.bubblefish.naalp.WorkedExampleKatKt
java -cp "naalp-tests.jar;$BC" sh.bubblefish.naalp.PrimitivesSmokeKt
```

Cross-language conformance (the authoritative grade) runs the adapter through the shared harness:

```sh
./harness/runner/naalp-conform run --testee "<the java launch of the Kotlin adapter>"
# RESULT: PASS (239 graded, 0 unimplemented/skipped)
```

## License

Apache-2.0 — see the repository `LICENSE.md` and `NOTICE`. The Internet-Draft is additionally
under the IETF Trust's BCP 78.
