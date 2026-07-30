<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Troubleshooting

Common first-contact issues, by area. If your problem is not here, see [`SUPPORT.md`](SUPPORT.md).

## Post-quantum (ML-DSA) availability

N-AALP signs with deterministic ML-DSA-65/-87 (FIPS 204, `rnd = 0`). Not every language ecosystem
has a deterministic seed→key ML-DSA path:

| SDK | ML-DSA | Notes |
|---|---|---|
| Go, Rust, Python, TypeScript, Java, Kotlin, C# | **full** | signs + verifies; joins the byte-parity consensus |
| Ruby | full, **but** needs **OpenSSL ≥ 3.5** | on older OpenSSL the ML-DSA ops are skipped, not failed |
| PHP, Swift | **pure-only** | no deterministic ML-DSA in the ecosystem; Ed25519 is real, the ML-DSA leg is honestly skip-tracked |

If you see ML-DSA operations reported as `skipped`/`unimplemented` for PHP, Swift, or Ruby-on-old-OpenSSL, that is **by design**, not a failure.

## PHP: "sodium/intl function not found"

The PHP SDK needs `ext-sodium` (Ed25519) and `ext-intl` (NFC). Enable them per-invocation:

```sh
php -d extension=sodium -d extension=intl your_script.php
```

## Go: `go get` cannot find the module

The module path is `github.com/bubblefish-tech/naalp_protocol/impl/go` (note `naalp_protocol`, and
the `impl/go` subdirectory). Ensure a version tag exists, or pin a commit:

```sh
go get github.com/bubblefish-tech/naalp_protocol/impl/go@latest
```

## TypeScript: no types on import

The package ships `naalp/*.d.mts` declarations. If your editor shows `any`, confirm your
`tsconfig.json` uses `"moduleResolution": "bundler"` (or `node16`/`nodenext`) so the `exports`
`types` condition resolves, and that you are on a version that includes the declarations
(`0.1.0`+).

## Node: syntax/module errors

The TypeScript/JS SDK is ESM and targets **Node.js ≥ 22**. On older Node you may see ESM or
top-level-`await` errors.

## A byte-parity mismatch between two SDKs

Every crypto-capable SDK must emit byte-identical COSE_Sign1 for identical input. To localize a
divergence, run the shared conformance runner and compare the op output against the corpus:

```sh
./harness/runner/naalp-conform run --testee "<your adapter launch command>"
```

Then cross-check with `bash harness/cross_language.sh`, which grades every available adapter and
asserts the deterministic-ML-DSA byte-parity consensus. Report the failing op/case id and the first
differing byte offset.

## Java / Kotlin: Maven Central publish rejected

Maven Central requires a `-sources.jar`, a `-javadoc.jar`, and a GPG signature per artifact. The
Java `pom.xml` produces these under the `release` profile (`mvn -P release deploy`); the Kotlin
build attaches `withSourcesJar()` + `withJavadocJar()` and signs via the `signing` plugin. Both
require the operator's Central Portal token + GPG key as CI secrets.

## Verifying an object fails with `ProfileDowngrade`

N-AALP floors every profile at ML-DSA strength (signature level ≥ 3). A pure-Ed25519 object
(level 0) is **intentionally rejected** at `ProfileDowngrade` — Ed25519 is valid only as a hybrid
leg. Sign a production object with ML-DSA (or assemble it around an external FIPS 204 signature on
the pure-only SDKs).
