// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// Emit the worked-example N-AALP object as one line of lowercase hex: the whole
// COSE_Sign1 the reference produces from the fixed 0x2a seed for the Governance
// Approval object (channel 0x0004, kind 1) -- the same construction the Go
// cmd/naalp-worked-example emitter and WorkedExampleKat build. Lives in tools/ (not
// src/main/kotlin) so it is not shipped in the published jar.
// scripts/record_cross_port_objects.py runs this and records the bytes; the
// cross-port object gate compares them to vectors/worked/example.json. Prints ONLY
// the hex so the recorder reads it unambiguously.
package sh.bubblefish.naalp

private const val ARGS_ID_HEX =
    "20304e8abef02897dcc39231d926feb79b34534c6d474cd49a5b4dec2cc2cce90d251eef7418782006d829bd7f30ae8626ff"

fun main() {
    val seed = ByteArray(32) { 0x2a }
    val alg = Cose.ALG_MLDSA65
    val pk = Cose.mldsaKeygen("ML-DSA-65", seed)
    val signerId = Identity.signerId(alg, pk)
    val body = Cbor.M(
        listOf(
            Cbor.Pair(Cbor.U(1), Cbor.B(Hex.decode(ARGS_ID_HEX))),
            Cbor.Pair(Cbor.U(2), Cbor.T(signerId)),
            Cbor.Pair(Cbor.U(3), Cbor.U(2)),
            Cbor.Pair(Cbor.U(4), Cbor.B(byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8))),
            Cbor.Pair(Cbor.U(5), Cbor.U(1785000000000L)),
        )
    )
    val obj = Envelope.Object(
        kind = 1, channel = 4, tier = 0,
        signer = signerId.toByteArray(Charsets.UTF_8),
        created = 1785000000000L, effect = 2, profile = Cose.PROFILE_PUBLIC, body = body,
    )
    println(Hex.encode(Envelope.sign(obj, alg, seed)))
}
