<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Third-Party Notices

N-AALP's reference SDKs are Apache-2.0. This file lists their third-party runtime dependencies and
each dependency's license. **Every dependency is under a permissive license (MIT, Apache-2.0,
BSD-3-Clause, ISC, or the ICU/Unicode license) — there is no copyleft (no GPL / LGPL / AGPL / SSPL),
no non-commercial restriction, and nothing proprietary. All are commercial-use-safe.**

Cryptography is deliberately sourced from well-known, standards-aligned libraries: Cloudflare CIRCL
and RustCrypto/`fips204` for deterministic ML-DSA (FIPS 204), Bouncy Castle (FIPS-certified APIs
available) on the JVM/.NET, `@noble/post-quantum` in JS, `dilithium-py` in Python, and Apple
`swift-crypto` / platform OpenSSL / libsodium for Ed25519 and hashing.

## Runtime dependencies by SDK

| SDK | Dependency | Version | License | Commercial-safe |
|---|---|---|---|:--:|
| Go | github.com/cloudflare/circl | v1.6.4 | BSD-3-Clause | ✅ |
| Go | golang.org/x/text | v0.21.0 | BSD-3-Clause | ✅ |
| Go | golang.org/x/sys (indirect) | v0.38.0 | BSD-3-Clause | ✅ |
| Rust | sha2 | 0.10 | MIT OR Apache-2.0 | ✅ |
| Rust | fips204 | 0.4 | MIT OR Apache-2.0 | ✅ |
| Rust | ed25519-dalek | 2 | BSD-3-Clause | ✅ |
| Rust | unicode-normalization | 0.1 | MIT OR Apache-2.0 | ✅ |
| Rust | data-encoding | 2 | MIT | ✅ |
| Python | dilithium-py | ≥ 1.4.0 | MIT OR Apache-2.0 | ✅ |
| Python | cryptography | ≥ 42 | Apache-2.0 OR BSD-3-Clause | ✅ |
| TypeScript | @noble/curves | ^2.2.0 | MIT | ✅ |
| TypeScript | @noble/hashes | ^2.2.0 | MIT | ✅ |
| TypeScript | @noble/post-quantum | ^0.6.1 | MIT | ✅ |
| Java | org.bouncycastle:bcprov-jdk18on | 1.85 | MIT (Bouncy Castle License) | ✅ |
| Kotlin | org.bouncycastle:bcprov-jdk18on | 1.85 | MIT (Bouncy Castle License) | ✅ |
| Kotlin | Kotlin standard library | 2.4.0 | Apache-2.0 | ✅ |
| C# | BouncyCastle.Cryptography | 2.6.2 | MIT | ✅ |
| Ruby | OpenSSL (via Ruby's stdlib `openssl`) | ≥ 3.5 | Apache-2.0 (OpenSSL 3.x) | ✅ |
| PHP | ext-sodium (libsodium) | bundled with PHP | ISC | ✅ |
| PHP | ext-intl (ICU) | bundled with PHP | ICU / Unicode (permissive) | ✅ |
| Swift | apple/swift-crypto | ≥ 3.0.0 (pinned 3.15.1) | Apache-2.0 | ✅ |
| Swift | apple/swift-asn1 (indirect, via swift-crypto) | 1.7.1 | Apache-2.0 | ✅ |

Go and Swift are distributed from source via a VCS tag and pull the above at build time; the JVM,
.NET, Python, JS, Ruby, and PHP SDKs pull theirs from their registries.

## Build / CI-only tooling (not shipped in any package)

Dev + CI tooling is likewise permissive and is never a runtime dependency of a published package:
TypeScript + TypeDoc (Apache-2.0); the GitHub Actions used in CI — `actions/*`, `pypa/gh-action-
pypi-publish`, `anchore/sbom-action`, `sigstore/cosign-installer`, `dtolnay/rust-toolchain`,
`shivammathur/setup-php`, `ruby/setup-ruby`, `gradle/actions` (MIT / Apache-2.0). Java/Kotlin build
plugins (maven-source/javadoc/gpg, central-publishing, Gradle `signing`) are Apache-2.0.

## Methodology

Licenses were confirmed against each project's published license this session (manifests in
`impl/<lang>/`, plus the projects' own license pages). None require reciprocal source disclosure or
restrict commercial use. If a future dependency is added, add it here and re-confirm its license is
permissive before it ships.
