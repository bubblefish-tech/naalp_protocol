<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Implementations

N-AALP ships **ten** reference SDKs. **Go and Rust are the primary references** — they produce
byte-identical output for every construction (CBOR, signed input, signatures, digests) and both
carry the full deterministic ML-DSA (FIPS 204, rnd=0) crypto leg. The other eight SDKs implement
the same object model and the shared conformance-adapter contract, and are graded against the same
non-circular corpus.

Every SDK exposes the same shape: the full object envelope (`Envelope` — build → content-id-bind →
sign → offline-verify), the post-quantum + Ed25519 COSE layer, and the byte-level primitives
(deterministic CBOR + content id, self-certifying identity, effect/authorization, the spine record
bodies, causal + federation ordering, the twenty-channel registry).

| Language | Path | Package / registry | Crypto leg | Quickstart |
|---|---|---|---|---|
| Go (primary) | `impl/go/` | `github.com/bubblefish-tech/naalp_protocol/impl/go` (VCS tag) | full ML-DSA-65/-87 + Ed25519 | [Go](../../impl/go/QUICKSTART.md) |
| Rust (primary) | `impl/rust/` | `naalp` (crates.io) | full ML-DSA-65/-87 + Ed25519 | [Rust](../../impl/rust/QUICKSTART.md) |
| Python | `impl/python/` | `naalp` (PyPI) | full ML-DSA + Ed25519 | [Python](../../impl/python/QUICKSTART.md) |
| TypeScript | `impl/typescript/` | `@bubblefish/naalp` (npm) | full ML-DSA + Ed25519 | [TypeScript](../../impl/typescript/QUICKSTART.md) |
| Java | `impl/java/` | `sh.bubblefish:naalp` (Maven Central) | full ML-DSA + Ed25519 | [Java](../../impl/java/QUICKSTART.md) |
| Kotlin | `impl/kotlin/` | `sh.bubblefish:naalp-kotlin` (Maven Central) | full ML-DSA + Ed25519 | [Kotlin](../../impl/kotlin/QUICKSTART.md) |
| C# | `impl/csharp/` | `Bubblefish.Naalp` (NuGet) | full ML-DSA + Ed25519 (CI-graded) | [C#](../../impl/csharp/QUICKSTART.md) |
| Ruby | `impl/ruby/` | `naalp` (RubyGems) | full ML-DSA + Ed25519 (OpenSSL ≥ 3.5) | [Ruby](../../impl/ruby/QUICKSTART.md) |
| PHP | `impl/php/` | `bubblefish/naalp` (Packagist) | pure + Ed25519 (ML-DSA skip-tracked) | [PHP](../../impl/php/QUICKSTART.md) |
| Swift | `impl/swift/` | `Naalp` (SwiftPM) | pure + Ed25519 (ML-DSA skip-tracked, CI-graded) | [Swift](../../impl/swift/QUICKSTART.md) |

## Crypto scope, stated honestly

- **Full ML-DSA** SDKs sign *and* verify deterministic ML-DSA and join the cross-language
  byte-parity consensus (every one produces the same COSE_Sign1 bytes for the same logical input).
- **Pure + Ed25519** SDKs (PHP, Swift) implement the entire pure object surface plus a real
  Ed25519 leg, but their available libraries have **no deterministic-from-seed FIPS 204 path**, so
  the ML-DSA signature step is **skip-tracked** — an honest `Unimplemented`, never a false green.
  They still perform every structural + policy check and assemble byte-identical ML-DSA objects
  around an externally-produced signature.

## Grading

The authoritative grade is the cross-language harness, run from the repo root:

```console
$ bash harness/cross_language.sh
...
CROSS-LANGUAGE CONFORMANCE: PASS (N adapters graded; M byte-identical on deterministic ML-DSA)
```

It regenerates the corpus from the per-family **non-circular** oracles (expected values come from
the standards / an independent constructor, never the code under test), grades every adapter whose
toolchain is present, and asserts deterministic ML-DSA byte-parity across the crypto-capable SDKs.
Adapters whose toolchain is CI-only (C#, Swift) are built and graded in CI via `setup-dotnet` /
`swift-actions`. The single end-to-end gate is `bash harness/run.sh`.
