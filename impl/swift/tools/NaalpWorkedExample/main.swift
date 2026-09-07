// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// Emit the worked-example N-AALP object's deterministic ToBeSigned bytes as one
// line of lowercase hex. Swift is PURE-ONLY here: SwiftDilithium 3.6.0 has no
// deterministic-from-seed FIPS 204 path, so this port cannot produce the full
// signed_object_hex. It CAN produce every pre-signature byte -- the COSE
// Sig_structure (protected header + payload) -- which is what the cross-port object
// gate compares for a pure-only port, against the authority's to_be_signed_hex.
// Same construction as Tests/NaalpTests/WorkedExampleTests.swift. Prints ONLY the
// hex so the recorder reads it unambiguously.
//
//   swift run naalp-worked-example        (from impl/swift/)
import Foundation
import Naalp

let SIGNER_ID = "bciqmqbeciwpwrbuv4j2ldnf2araohpsnsy6rfidj3kcrroy6tl222ua"
let ARGS_ID_HEX =
    "20304e8abef02897dcc39231d926feb79b34534c6d474cd49a5b4dec2cc2cce90d251eef7418782006d829bd7f30ae8626ff"

func hexToBytes(_ s: String) -> [UInt8] {
    var out = [UInt8]()
    var i = s.startIndex
    while i < s.endIndex {
        let j = s.index(i, offsetBy: 2)
        out.append(UInt8(s[i..<j], radix: 16)!)
        i = j
    }
    return out
}

func toHex(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }

let body = CborValue.m([
    (.u(1), .b(hexToBytes(ARGS_ID_HEX))),
    (.u(2), .t(SIGNER_ID)),
    (.u(3), .u(2)),
    (.u(4), .b([1, 2, 3, 4, 5, 6, 7, 8])),
    (.u(5), .u(1785000000000)),
])
var obj = Envelope.Object(kind: 1, channel: 4, signer: Array(SIGNER_ID.utf8),
                          created: 1785000000000, effect: 2, body: body, tier: 0,
                          profile: UInt64(Cose.PROFILE_PUBLIC))
do {
    let inputs = try Envelope.signingInputs(&obj, Cose.ALG_MLDSA65)
    print(toHex(inputs.toBeSigned))
} catch {
    FileHandle.standardError.write("worked-example emit failed: \(error)\n".data(using: .utf8)!)
    exit(1)
}
