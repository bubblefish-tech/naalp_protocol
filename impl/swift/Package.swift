// swift-tools-version:5.9
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// The N-AALP reference SDK for Swift: module `Naalp`. Implements the deterministic-CBOR spine
// (CBOR codec, content-id, COSE ToBeSigned/assembly, self-certifying signer-id, effect lattice,
// spine record bodies, causal graph + federation reconcile, the twenty-channel registry) plus
// Ed25519 (RFC 8032) via swift-crypto. SHA-256/384 are provided by swift-crypto.
//
// ML-DSA (FIPS 204): the deterministic-from-seed path this protocol requires is provided by
// swift-crypto's vendored BoringSSL (MLDSA65/MLDSA87). Keygen-from-seed and verify use the public
// swift-crypto API; deterministic (rnd=0) signing uses the CNaalpMldsa C shim, because the public
// sign API is HEDGED and cannot reproduce a pinned FIPS-204 KAT (see Sources/CNaalpMldsa). The
// swift-crypto version is pinned .exact("4.5.1") because the deterministic signer reaches an
// internal BoringSSL symbol (BCM_mldsa*_sign_internal); the composite/KAT tests are the canary that
// fails loud on any silent change, so every future bump is a deliberate re-validation event.
import PackageDescription

let package = Package(
    name: "Naalp",
    // macOS 10.15.4 is the floor: swift-crypto's SHA-256/384/512 + Ed25519 are @available(macOS 10.15),
    // and the SDK's durable delivery/approval logs (Delivery.swift, Approval.swift) use the modern
    // throwing FileHandle APIs — write(contentsOf:), read(upToCount:), seekToEnd(), synchronize() —
    // which are @available(macOS 10.15.4). (10.15.4 is March 2020; final Catalina is 10.15.7, so this
    // excludes no deployed macOS.) ML-DSA is NOT a constraint: it routes through the CNaalpMldsa
    // BoringSSL shim (raw C, no OS gate), not the macOS-26-gated public MLDSA API.
    platforms: [
        .macOS("10.15.4"),
    ],
    products: [
        .library(name: "Naalp", targets: ["Naalp"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", exact: "4.5.1"),
    ],
    targets: [
        // C shim reaching swift-crypto's vendored BoringSSL deterministic ML-DSA signer (rnd=0).
        .target(name: "CNaalpMldsa"),
        .target(
            name: "Naalp",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                // Force-links libCCryptoBoringSSL.a on EVERY platform. On Apple, `Crypto` alone
                // resolves to CryptoKit and does NOT link BoringSSL (swift-crypto's manifest gates
                // the CCryptoBoringSSL edge to non-Darwin platforms), so the CNaalpMldsa shim's
                // BCM_mldsa{65,87}_* externs would be undefined at link on macOS. _CryptoExtras ->
                // CryptoExtras -> CCryptoBoringSSL is an UNCONDITIONAL edge in swift-crypto 4.5.1's
                // manifest, so this dependency puts the BoringSSL archive (which contains the mldsa
                // objects) on the macOS link line. That is what lets ML-DSA — hence the whole SDK —
                // build and verify on macOS, not just Linux (task #142).
                .product(name: "_CryptoExtras", package: "swift-crypto"),
                "CNaalpMldsa",
            ]
        ),
        // Not a product: a tools-only emitter for the cross-port object ledger, so it
        // does not alter what library consumers depend on.
        .executableTarget(
            name: "naalp-worked-example",
            dependencies: ["Naalp"],
            path: "tools/NaalpWorkedExample"
        ),
        // XCTest conformance target: the worked-example known-answer test plus the per-capability
        // corpus-graded tests (Tests/NaalpTests). Not a product; it does not alter what library
        // consumers depend on.
        .testTarget(
            name: "NaalpTests",
            dependencies: ["Naalp"]
        ),
    ]
)
