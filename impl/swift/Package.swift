// swift-tools-version:5.9
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// The N-AALP reference SDK for Swift: module `Naalp`. Implements the deterministic-CBOR spine
// (CBOR codec, content-id, COSE ToBeSigned/assembly, self-certifying signer-id, effect lattice,
// spine record bodies, causal graph + federation reconcile, the twenty-channel registry) plus
// Ed25519 (RFC 8032) via swift-crypto. SHA-256/384 are provided by swift-crypto.
//
// ML-DSA (FIPS 204): the deterministic-from-seed path this protocol requires is NOT available in
// SwiftDilithium 3.6.0 (it exposes no seed/xi key derivation — only random GenerateKeyPair, and a
// SecretKey init that needs the full expanded key), so the SDK does not depend on it and the
// adapter returns `skipped` for the ML-DSA crypto ops (Unimplemented, never a false green).
import PackageDescription

let package = Package(
    name: "Naalp",
    products: [
        .library(name: "Naalp", targets: ["Naalp"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
    ],
    targets: [
        .target(
            name: "Naalp",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),
    ]
)
