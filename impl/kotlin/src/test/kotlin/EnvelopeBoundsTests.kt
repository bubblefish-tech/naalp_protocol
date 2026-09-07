// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

/**
 * Decoder resource bounds (design.md §3.4, R7) known-answer tests for the Kotlin SDK's envelope
 * verify path, mirroring impl/go/envelope/bounds_test.go: the object octet-size bound, the
 * causes[]/ext/cext cardinality bounds, and the CBOR nesting-depth bound as seen through
 * Envelope.verify(). Each bound is proven by a BOUNDARY PAIR: an otherwise-valid object AT the
 * limit verifies, and an otherwise-valid object one past the limit is rejected with the named
 * error. "Otherwise valid" is load-bearing for mutation survival: because the only defect is the
 * bound, deleting the bound check makes the over-limit object verify.
 *
 * Run (main()-driven, no test framework):
 *   kotlinc src/main/kotlin src/test/kotlin/EnvelopeBoundsTests.kt -cp <bcprov.jar> -include-runtime -d out/envelope-bounds.jar
 *   java -cp "out/envelope-bounds.jar;<bcprov.jar>" sh.bubblefish.naalp.EnvelopeBoundsTestsKt
 */

private class EnvelopeBoundsFailure(msg: String) : RuntimeException(msg)

private fun ebOk(what: String) = println("  ok  $what")

private val EB_SEED = ByteArray(32) { it.toByte() } // a LOCAL test signing seed -- these are
                                                     // boundary tests, not a reproduction of any
                                                     // corpus signature.
private const val EB_ALG = Cose.ALG_MLDSA65
private val ebKindOk = Envelope.KindValidator { c, k -> c == 4L && k == 2L }

/** An otherwise-valid base object (kind=2/channel=4 accepted by ebKindOk, tier=0, profile=public,
 *  no causes/ext/cext). Overriding exactly one of [bodyOverride]/[causes]/[ext]/[cext] per test
 *  isolates each bound so the only defect a deleted check could hide is the bound itself. */
private fun ebBuildObject(
    bodyOverride: Cbor.Value? = null,
    causes: List<ByteArray> = emptyList(),
    ext: Cbor.M? = null,
    cext: Cbor.M? = null,
): Envelope.Object = Envelope.Object(
    kind = 2L, channel = 4L, tier = 0L, signer = Hex.decode("5349474e45525f41"),
    created = 1785000000000L, effect = 2L, causes = causes, profile = Cose.PROFILE_PUBLIC,
    body = bodyOverride ?: Cbor.T("hello"), ext = ext, cext = cext,
)

/** n content-id-shaped bstrs (multihash sha2-384 = 0x20 0x30 + 48 zero bytes), mirroring Go's
 *  makeCauses. */
private fun ebMakeCauses(n: Int): List<ByteArray> = (0 until n).map {
    val b = ByteArray(50)
    b[0] = 0x20
    b[1] = 0x30
    b
}

/** n distinct non-critical extension entries (unknown keys 100+i, which the may-ignore rule
 *  accepts), so the object is otherwise valid at any cardinality. */
private fun ebMakeExtMap(n: Int): Cbor.M = Cbor.M((0 until n).map { i -> Cbor.Pair(Cbor.U((100 + i).toLong()), Cbor.U(0)) })

/** k single-element arrays wrapping a zero scalar. As a body value it sits at depth 2 (the object
 *  body map is depth 1), so the deepest scalar is at depth 2+k. */
private fun ebNestArrays(k: Int): Cbor.Value {
    var v: Cbor.Value = Cbor.U(0)
    repeat(k) { v = Cbor.A(listOf(v)) }
    return v
}

/** Run [block]; return "ok" if it returns, else the NaalpException kind. */
private fun ebVerifyKind(block: () -> Unit): String = try {
    block()
    "ok"
} catch (e: NaalpException) {
    e.kind
}

// TestBoundsAcceptAtLimit: an object exactly AT each cardinality/depth bound verifies, so the
// boundary is inclusive and the reject tests below prove the boundary itself.
private fun testBoundsAcceptAtLimit() {
    val pk = Cose.mldsaKeygen("ML-DSA-65", EB_SEED)

    fun accept(name: String, o: Envelope.Object) {
        val obj = Envelope.sign(o, EB_ALG, EB_SEED)
        val kind = ebVerifyKind { Envelope.verify(Cose.PROFILE_PUBLIC, EB_ALG, pk, ebKindOk, obj) }
        if (kind != "ok") throw EnvelopeBoundsFailure("$name verify at-limit: want ok, got $kind")
        ebOk(name)
    }

    accept("causes==MaxCauses", ebBuildObject(causes = ebMakeCauses(MAX_CAUSES.toInt())))
    accept("ext==MaxExt", ebBuildObject(ext = ebMakeExtMap(MAX_EXT.toInt())))
    // body nested so the deepest scalar sits at exactly MaxNestingDepth (2 + (MaxNestingDepth-2)).
    accept("depth==MaxNestingDepth", ebBuildObject(bodyOverride = ebNestArrays((MAX_NESTING_DEPTH - 2).toInt())))
}

// TestBoundsRejectOverLimit: an otherwise-valid object one past each bound is rejected with its
// named error (fail-closed).
private fun testBoundsRejectOverLimit() {
    val pk = Cose.mldsaKeygen("ML-DSA-65", EB_SEED)

    fun expect(name: String, o: Envelope.Object, wantKind: String) {
        val obj = Envelope.sign(o, EB_ALG, EB_SEED)
        val kind = ebVerifyKind { Envelope.verify(Cose.PROFILE_PUBLIC, EB_ALG, pk, ebKindOk, obj) }
        if (kind != wantKind) throw EnvelopeBoundsFailure("$name: want $wantKind, got $kind")
        ebOk(name)
    }

    expect("TooManyCauses", ebBuildObject(causes = ebMakeCauses((MAX_CAUSES + 1).toInt())), "TooManyCauses")
    expect("TooManyExtensions(ext)", ebBuildObject(ext = ebMakeExtMap((MAX_EXT + 1).toInt())), "TooManyExtensions")
    // cext over the limit also yields TooManyExtensions: the cardinality check in objectFromMap
    // fires before the critical-extension recognition check.
    expect("TooManyExtensions(cext)", ebBuildObject(cext = ebMakeExtMap((MAX_CEXT + 1).toInt())), "TooManyExtensions")
    // body nested so the deepest scalar sits at MaxNestingDepth+1.
    expect("DepthExceeded", ebBuildObject(bodyOverride = ebNestArrays((MAX_NESTING_DEPTH - 1).toInt())), "DepthExceeded")
}

// TestBoundTooLarge pins the object octet-size bound: a large-but-under-limit signed object
// verifies, and an otherwise-valid object over the limit is rejected TooLarge on the raw bytes
// before any parse (RFC 8949 §10 decoder-memory guard).
private fun testBoundTooLarge() {
    val pk = Cose.mldsaKeygen("ML-DSA-65", EB_SEED)

    val under = ebBuildObject(bodyOverride = Cbor.B(ByteArray((MAX_OBJECT_SIZE - 16384L).toInt())))
    val uobj = Envelope.sign(under, EB_ALG, EB_SEED)
    if (uobj.size > MAX_OBJECT_SIZE) {
        throw EnvelopeBoundsFailure("under-limit object is ${uobj.size} bytes, expected < $MAX_OBJECT_SIZE")
    }
    val underKind = ebVerifyKind { Envelope.verify(Cose.PROFILE_PUBLIC, EB_ALG, pk, ebKindOk, uobj) }
    if (underKind != "ok") throw EnvelopeBoundsFailure("verify under-limit: want ok, got $underKind")
    ebOk("verify under-limit ($MAX_OBJECT_SIZE-bound object)")

    val over = ebBuildObject(bodyOverride = Cbor.B(ByteArray(MAX_OBJECT_SIZE.toInt())))
    val bobj = Envelope.sign(over, EB_ALG, EB_SEED)
    if (bobj.size <= MAX_OBJECT_SIZE) {
        throw EnvelopeBoundsFailure("over-limit object is only ${bobj.size} bytes, expected > $MAX_OBJECT_SIZE")
    }
    val overKind = ebVerifyKind { Envelope.verify(Cose.PROFILE_PUBLIC, EB_ALG, pk, ebKindOk, bobj) }
    if (overKind != "TooLarge") throw EnvelopeBoundsFailure("TooLarge: want TooLarge, got $overKind")
    ebOk("TooLarge over-limit object rejected before parse")
}

fun main() {
    println("EnvelopeBoundsTests -- decoder resource bounds (design.md §3.4, R7)")
    testBoundsAcceptAtLimit()
    testBoundsRejectOverLimit()
    testBoundTooLarge()
    println("EnvelopeBoundsTests: PASS")
}
