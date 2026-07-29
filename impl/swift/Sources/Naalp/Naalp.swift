// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// Naalp — the Swift reference SDK for N-AALP (draft-bubblefish-naalp-00).
//
// N-AALP makes the *object*, not the connection, the unit of security: every message is a
// deterministically-encoded CBOR structure signed with COSE that carries, under one signature,
// its content identity, its signer, a closed effect label, optional approval/audit bindings, and
// its causal derivation — verifiable offline, over any transport.
//
// The independent, byte-level primitives live as public namespaces in this module: `Cbor`
// (deterministic CBOR + content id), `Cose` (COSE_Sign1 + Ed25519), `Identity` (self-certifying
// signer id), `Policy` (effect + authorization), `Records` (approval/receipt/delivery/stream/
// carriage bodies + the transport boundary), `Graph` (causal verify + federation reconcile),
// `Channels` (the twenty-channel registry), and `Envelope` (the full object). Every pure
// construction is graded byte-for-byte against the shared conformance corpus (== Go == Rust).
//
// CRYPTO SURFACE: this SDK implements the full pure spine plus Ed25519 (RFC 8032) via
// swift-crypto. The deterministic-from-seed ML-DSA (FIPS 204) path is NOT available in
// SwiftDilithium 3.6.0, so ML-DSA signing/verification is skip-tracked — the envelope exposes
// the ML-DSA-agnostic assembly surface (`Envelope.assembleSigned` / `Envelope.toBeSigned`) so a
// caller can pair it with any external FIPS 204 signer while keeping the exact object bytes.
//
// Quick start (Ed25519, a fully-supported pure sign/verify round-trip on the COSE layer):
//
//     import Naalp
//
//     let seed = [UInt8](repeating: 0x2a, count: 32)
//     let pk   = try Cose.ed25519PublicKey(seed)                 // see Cose (swift-crypto)
//     let sid  = try Identity.signerId(Cose.ALG_ED25519, pk)
//     var obj  = Envelope.Object(kind: 1, channel: 4, signer: Array(sid.utf8),
//                                created: 1785000000000, effect: 2, body: .m([(.u(1), .t("hi"))]))
//     let signed = try Envelope.signEd25519(&obj, seed)          // tagged COSE_Sign1 bytes
//     let ok     = try Cose.coseVerify1(Cose.ALG_ED25519, pk, signed)   // true

public enum NaalpSDK {
    /// The SDK version.
    public static let version = "0.1.0"
    /// The Internet-Draft this SDK implements.
    public static let draft = "draft-bubblefish-naalp-00"
}
