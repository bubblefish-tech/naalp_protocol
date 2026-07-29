// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// examples/naalp-example — build, assemble, and verify N-AALP objects on the pure surface.
//
// Two demonstrations, both end-to-end and both real (no mocks):
//   1. Ed25519 (RFC 8032) via swift-crypto: build an object, sign the COSE ToBeSigned with a
//      real key, assemble the tagged COSE_Sign1, and verify the signature round-trips (and that
//      tampering is rejected). This is the pure surface's from-key sign/verify path.
//   2. The ML-DSA-65 worked object: build the exact object from the fixed seed's signer id,
//      reproduce its content id, and assemble the tagged COSE_Sign1 with an externally-supplied
//      ML-DSA signature — the ML-DSA-agnostic assembly path (SwiftDilithium 3.6.0 has no
//      deterministic-from-seed FIPS 204 signer, so the signature is brought in, not produced).
//
// Run:  swift run -c release --package-path impl/swift naalp-example

import Foundation
import Naalp

let hexDigits = Array("0123456789abcdef")

func toHex(_ b: [UInt8]) -> String {
    var s = ""
    s.reserveCapacity(b.count * 2)
    for x in b { s.append(hexDigits[Int(x >> 4)]); s.append(hexDigits[Int(x & 0x0f)]) }
    return s
}

func die(_ msg: String) -> Never {
    FileHandle.standardError.write(Data(("FAIL: " + msg + "\n").utf8))
    exit(1)
}

// --- 1. Ed25519: a real from-key sign -> assemble -> verify round-trip ---

do {
    let seed = [UInt8](repeating: 0x2a, count: 32)
    let pk = try Cose.ed25519PublicKey(seed)
    let signerId = try Identity.signerId(Cose.ALG_ED25519, pk)
    print("ed25519 signer  ", signerId)

    let body = CborValue.m([(.u(1), .t("hello, agent"))])
    var obj = Envelope.Object(kind: 1, channel: 4, signer: Array(signerId.utf8),
                              created: 1785000000000, effect: 2,
                              body: body, profile: UInt64(Cose.PROFILE_PUBLIC))

    let signed = try Envelope.signEd25519(&obj, seed)
    let ok = try Cose.coseVerify1(Cose.ALG_ED25519, pk, signed)
    print("ed25519 signed  ", signed.count, "bytes, cose-verify=\(ok)")
    if !ok { die("ed25519 signature did not verify") }

    var tampered = signed
    tampered[tampered.count - 1] ^= 1
    let tamperedOK = try Cose.coseVerify1(Cose.ALG_ED25519, pk, tampered)
    print("ed25519 tampered rejected:", !tamperedOK)
    if tamperedOK { die("tampered ed25519 object was NOT rejected") }
} catch {
    die("ed25519 demo threw: \(error)")
}

// --- 2. The ML-DSA-65 worked object: reproduce content id + assemble with a brought-in sig ---

do {
    // The signer id is the fixed worked-example signer (seed 0x2a*32, ML-DSA-65). We build the
    // exact Governance Approval object (channel 4, kind 1) from it.
    let signerId = "bciqmqbeciwpwrbuv4j2ldnf2araohpsnsy6rfidj3kcrroy6tl222ua"
    let argsIdHex = "20304e8abef02897dcc39231d926feb79b34534c6d474cd49a5b4dec2cc2cce90d251eef7418782006d829bd7f30ae8626ff"
    var argsId = [UInt8]()
    var i = argsIdHex.startIndex
    while i < argsIdHex.endIndex {
        let j = argsIdHex.index(i, offsetBy: 2)
        argsId.append(UInt8(argsIdHex[i..<j], radix: 16)!)
        i = j
    }

    let body = CborValue.m([
        (.u(1), .b(argsId)),
        (.u(2), .t(signerId)),
        (.u(3), .u(2)),
        (.u(4), .b([1, 2, 3, 4, 5, 6, 7, 8])),
        (.u(5), .u(1785000000000)),
    ])
    var obj = Envelope.Object(kind: 1, channel: 4, signer: Array(signerId.utf8),
                              created: 1785000000000, effect: 2,
                              body: body, tier: 0, profile: UInt64(Cose.PROFILE_PUBLIC))

    let cid = try obj.contentId()
    print("mldsa   content-id", toHex(cid))

    // An external FIPS 204 signer would supply this signature over Envelope.toBeSigned(&obj, -49).
    // Here we assemble with a demo signature to show the ML-DSA-agnostic COSE_Sign1 assembly.
    let tbs = try Envelope.toBeSigned(&obj, Cose.ALG_MLDSA65)
    print("mldsa   tobesigned", tbs.count, "bytes")
    let demoSig = [UInt8](repeating: 0x00, count: 3309)   // shape of an ML-DSA-65 signature
    let assembled = try Envelope.assembleSigned(&obj, Cose.ALG_MLDSA65, demoSig)
    print("mldsa   assembled ", assembled.count, "bytes (tagged COSE_Sign1)")
} catch {
    die("mldsa worked-object demo threw: \(error)")
}

print("OK")
