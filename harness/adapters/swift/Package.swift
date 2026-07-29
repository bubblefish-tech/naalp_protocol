// swift-tools-version:5.9
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// The N-AALP conformance adapter for Swift: executable `naalp-adapter`. Wraps the `Naalp` SDK
// (impl/swift) behind the length-prefixed JSON op protocol the naalp-conform runner drives
// (harness/INSTRUCTIONS.md). Build:  swift build -c release --package-path harness/adapters/swift
// Launch: harness/adapters/swift/.build/release/naalp-adapter
import PackageDescription

let package = Package(
    name: "naalp-adapter",
    dependencies: [
        .package(name: "Naalp", path: "../../../impl/swift"),
    ],
    targets: [
        .executableTarget(
            name: "naalp-adapter",
            dependencies: [
                .product(name: "Naalp", package: "Naalp"),
            ]
        ),
    ]
)
