<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# N-AALP Java SDK

The Java reference implementation of **N-AALP** (draft-bubblefish-naalp-00) — an
application-layer object protocol for autonomous agents, package `sh.bubblefish.naalp`, Java 21.
Every N-AALP object is a deterministically-encoded CBOR structure signed with COSE that carries,
under one signature, its content identity, its signer, a closed effect label, optional
approval/audit bindings, and its causal derivation — **verifiable offline, over any transport.**

## What this SDK provides

- **The full object envelope** — `Envelope.Object` + `Envelope.sign` / `Envelope.verify`: build,
  content-id-bind, deterministically sign, and offline-verify a complete N-AALP object.
- **Post-quantum signatures** — deterministic ML-DSA-65/-87 (FIPS 204, rnd=0) and Ed25519
  (RFC 8032), in COSE_Sign1 (`Cose`), via Bouncy Castle.
- **The byte-level primitives** — deterministic CBOR + content id (`Cbor`), self-certifying
  signer id (`Identity`), the effect lattice + authorization (`Policy`), the spine record bodies
  — approval, receipt, delivery, stream, carriage, transport boundary (`Records`), causal verify
  + federation reconcile (`Graph`), and the twenty-channel registry (`Channels`).

Every construction is **graded byte-for-byte** against the shared conformance corpus
(== Go == Rust == Python); the reference worked object is reproduced exactly
(`src/test/java/sh/bubblefish/naalp/WorkedExampleKat.java`).

## What this SDK does NOT provide

- A transport. N-AALP objects are transport-independent; carry them over N-PAMP, QUIC, WebSocket,
  or HTTP with your own client. The confidentiality boundary is `Records.transportEmit`.
- Production key management. Bouncy Castle's `MLDSASigner` is a correct FIPS 204 implementation
  used here in its deterministic (rnd=0) mode for reference/interop; apply your own key-storage
  and side-channel controls for production while keeping the same object bytes.

## Layout (Maven)

- `pom.xml` — `sh.bubblefish:naalp:0.1.0`, `maven.compiler.release` 21, dependency
  `org.bouncycastle:bcprov-jdk18on:1.85`, `maven-source-plugin` (attaches a `-sources` jar).
- `src/main/java/sh/bubblefish/naalp/` — the SDK library:
  - `Envelope.java` — `Envelope.Object` + `sign` / `verify` (the full C3 object).
  - `Cbor.java` — deterministic CBOR encode + strict canonical decode + `contentId`.
  - `Cose.java` — `toBeSignedRaw`, `assembleSign1Raw`, `parseSign1Raw`, deterministic ML-DSA,
    Ed25519, `coseSign1`/`coseVerify1`, `algLevel`/`profileMinLevel`.
  - `Identity.java` — the self-certifying `signerId` (multiformats) + `requireNfc`.
  - `Policy.java` — effect `normalizeEffect` / `authorizes` + `safetyLabelBytes`.
  - `Records.java` — approval / ledger / receipt / delivery / stream / carriage bodies +
    `transportEmit`.
  - `Graph.java` — `verifyCausal`, deterministic `reconcile`, `reconcileRecord`.
  - `Channels.java` — the 20-channel / 65-kind table (`lookup`, `checkEffect`).
  - `Hex.java`, `NaalpException.java` — helpers.
- `src/test/java/sh/bubblefish/naalp/` — `WorkedExampleKat` (byte-exact worked object),
  `PrimitivesSmoke` (standards-anchored primitives).
- `examples/SecureObject.java` — a runnable build → sign → verify → tamper demo.

## Install / build

With Maven (compiles, tests, packages, and attaches the `-sources` jar):

```sh
cd impl/java && mvn -q package
```

Or with `javac` directly (the crypto leg needs `bcprov-jdk18on` 1.85; the harness downloads it to
`harness/adapters/java/lib/`). On Windows the classpath separator is `;` (use `:` on POSIX):

```sh
javac -cp "harness/adapters/java/lib/bcprov-jdk18on-1.85.jar" -d impl/java/out \
    impl/java/src/main/java/sh/bubblefish/naalp/*.java
```

## Sign and verify an object

```java
import sh.bubblefish.naalp.*;
import java.nio.charset.StandardCharsets;
import java.util.List;

byte[] seed = new byte[32];                              // a real 32-byte key seed in production
int    alg  = Cose.ALG_MLDSA65;
byte[] pk   = Cose.mldsaKeygen("ML-DSA-65", seed);
String sid  = Identity.signerId(alg, pk);

Cbor.M body = new Cbor.M(List.of(
        new Cbor.Pair(new Cbor.U(1), new Cbor.T("hello"))));
Envelope.Object obj = new Envelope.Object(
        1, 4, sid.getBytes(StandardCharsets.UTF_8), 1785000000000L, 2, body);
obj.profile = Cose.PROFILE_PUBLIC;

byte[] signed = Envelope.sign(obj, alg, seed);           // a self-describing signed object (bytes)
Envelope.Object got = Envelope.verify(
        Cose.PROFILE_PUBLIC, alg, pk, (c, k) -> c == 4 && k == 1, signed, null);
```

## Run the example

```sh
javac -cp "harness/adapters/java/lib/bcprov-jdk18on-1.85.jar" -d impl/java/out \
    impl/java/src/main/java/sh/bubblefish/naalp/*.java impl/java/examples/SecureObject.java
java -cp "impl/java/out;harness/adapters/java/lib/bcprov-jdk18on-1.85.jar" SecureObject
# signer   bciqmqbeciwpwrbuv4j2ldnf2araohpsnsy6rfidj3kcrroy6tl222ua
# signed   3665 bytes, verifies=true
# tampered rejected: BadSignature
```

## Run the tests

The tests are self-contained `main()` runners (no JUnit dependency); each prints `PASS` and exits
non-zero on failure:

```sh
javac -cp "harness/adapters/java/lib/bcprov-jdk18on-1.85.jar" -d impl/java/tout \
    impl/java/src/main/java/sh/bubblefish/naalp/*.java impl/java/src/test/java/sh/bubblefish/naalp/*.java
java -cp "impl/java/tout;harness/adapters/java/lib/bcprov-jdk18on-1.85.jar" sh.bubblefish.naalp.WorkedExampleKat
java -cp "impl/java/tout;harness/adapters/java/lib/bcprov-jdk18on-1.85.jar" sh.bubblefish.naalp.PrimitivesSmoke
```

Cross-language conformance (the authoritative grade) runs the adapter through the shared harness:

```sh
javac -cp "harness/adapters/java/lib/bcprov-jdk18on-1.85.jar" -d harness/adapters/java/out \
    impl/java/src/main/java/sh/bubblefish/naalp/*.java harness/adapters/java/Json.java harness/adapters/java/Adapter.java

./harness/runner/naalp-conform.exe run --testee \
  "java -cp harness/adapters/java/out;harness/adapters/java/lib/bcprov-jdk18on-1.85.jar sh.bubblefish.naalp.Adapter"
# RESULT: PASS (239 graded, 0 unimplemented/skipped)
```

Every op is implemented, including the crypto leg (`mldsa.keygen`, `ed25519.sign`, `cose.sign1`);
nothing is skipped.

## License

Apache-2.0 — see the repository `LICENSE.md` and `NOTICE`. The Internet-Draft is additionally
under the IETF Trust's BCP 78.
