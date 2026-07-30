// swift-tools-version:6.0
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// The N-AALP conformance adapter for Swift: executable `naalp-adapter`. Wraps the `Naalp` SDK
// (impl/swift) behind the length-prefixed JSON op protocol the naalp-conform runner drives
// (harness/INSTRUCTIONS.md).
// Build:  swift build -c release --package-path harness/adapters/swift_adapter
// Launch: harness/adapters/swift_adapter/.build/release/naalp-adapter
//
// This adapter directory is deliberately named `swift_adapter`, NOT `swift`: SwiftPM 6 derives a
// path-dependency's package identity from its directory basename, so an adapter directory named
// `swift` would collide with the SDK directory `impl/swift` (also basename `swift`) and the build
// would fail with "product 'Naalp' ... not found in package 'Naalp'". A distinct basename gives the
// SDK the identity `swift` and this adapter the identity `swift_adapter`, so the two do not collide.
import PackageDescription

let package = Package(
    name: "naalp-adapter",
    dependencies: [
        // The SDK (impl/swift). Its package identity is its directory basename, `swift`.
        .package(path: "../../../impl/swift"),
    ],
    targets: [
        .executableTarget(
            name: "naalp-adapter",
            dependencies: [
                .product(name: "Naalp", package: "swift"),
            ]
        ),
    ]
)
