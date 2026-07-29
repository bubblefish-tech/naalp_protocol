// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

import java.security.MessageDigest

/**
 * Self-contained conformance smoke tests over the SDK primitives, anchored to independent
 * standards vectors (FIPS 180-4 SHA-384, RFC 8949 canonical CBOR, the multiformats signer id,
 * the §6.1 effect lattice, the twenty-channel registry). The authoritative cross-language grading
 * is the naalp-conform harness against the 239-case corpus; these keep the published package
 * independently checkable.
 *
 * Run (main()-driven, no test framework):
 *   java -cp "primitives-smoke.jar;<bcprov.jar>" sh.bubblefish.naalp.PrimitivesSmokeKt
 */

private class SmokeFailure(msg: String) : RuntimeException(msg)

private fun expect(what: String, cond: Boolean) {
    if (!cond) throw SmokeFailure(what)
    println("  ok  $what")
}

private fun sha384(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-384").digest(b)

fun main() {
    println("PrimitivesSmoke — standards-anchored primitives")

    // FIPS 180-4 SHA-384("abc")
    expect(
        "SHA-384(\"abc\")",
        Hex.encode(sha384("abc".toByteArray(Charsets.US_ASCII))) ==
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
    )

    // RFC 8949 canonical CBOR: keys emitted bytewise-ascending regardless of input order
    val m = Cbor.M(
        listOf(
            Cbor.Pair(Cbor.U(3), Cbor.U(4)),
            Cbor.Pair(Cbor.U(2), Cbor.U(0)),
        )
    )
    val enc = Cbor.encode(m)
    expect("canonical CBOR map order", Hex.encode(enc) == "a202000304")
    val cid = Cbor.contentId(enc)
    expect("content id multihash prefix", cid[0].toInt() == 0x20 && cid[1].toInt() == 0x30)
    expect("content id length", cid.size == 2 + 48)

    // strict decoder rejects non-canonical forms (out-of-order / non-shortest / indefinite / dup)
    for (bad in listOf("a202000100", "1800", "9f00ff", "a201000101")) {
        var kind = ""
        try {
            Cbor.decode(Hex.decode(bad))
        } catch (e: NaalpException) {
            kind = e.kind
        }
        expect("rejects non-canonical $bad", kind == "NonCanonical")
    }

    // RFC 9052 §4.4 Sig_structure begins with ["Signature1", ...]
    val tbs = Cose.toBeSignedRaw(Hex.decode("a1013830"), Hex.decode("a10700"))
    expect("ToBeSigned Sig_structure prefix", Hex.encode(tbs).startsWith("846a5369676e617475726531"))

    // multiformats self-certifying signer id: multibase base32 prefix 'b'
    val pk = Cose.mldsaKeygen("ML-DSA-65", ByteArray(32))
    val sid = Identity.signerId(Cose.ALG_MLDSA65, pk)
    expect("signer id multibase prefix", sid.startsWith("b"))

    // §6.1 effect lattice
    expect("effect: unknown -> destructive", Policy.normalizeEffect(99) == Policy.DESTRUCTIVE)
    expect("effect: niw authorizes iw", Policy.authorizes(Policy.NON_IDEMPOTENT_WRITE, Policy.IDEMPOTENT_WRITE))
    expect("effect: ro does not authorize destructive", !Policy.authorizes(Policy.READ_ONLY, Policy.DESTRUCTIVE))

    // twenty-channel registry: Governance.Approval (channel 4, kind 1)
    val ks = Channels.lookup(4, 1)
    expect("channel 4/1 = Approval", ks.name == "Approval")
    expect("channel 4/1 effect = non_idempotent_write", ks.effect.toLong() == Policy.NON_IDEMPOTENT_WRITE)
    expect("channel 4/1 not variable", !ks.variable)
    var unknownKind = ""
    try {
        Channels.lookup(0, 9999)
    } catch (e: NaalpException) {
        unknownKind = e.kind
    }
    expect("unknown channel/kind rejected", unknownKind.isNotEmpty())

    // record bodies are deterministic: receipt head == SHA-384(body)
    val body = Records.receiptBody(ByteArray(48), Hex.decode("2030" + "00".repeat(48)), 0, 100)
    expect("receipt head = SHA-384(body)", Records.receiptHead(body).contentEquals(sha384(body)))

    println("PrimitivesSmoke: PASS")
}
