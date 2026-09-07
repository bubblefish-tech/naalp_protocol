// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

import java.io.File
import kotlin.system.exitProcess

/**
 * C9 native-streaming known-answer test for the Kotlin SDK (design.md section 10; R-10.1..10.6),
 * graded against the shared independent corpus vectors/stream/cases.json (the oracle directory is
 * `stream`, NOT `streaming`; the module is named streaming). The corpus was NOT produced by this
 * code.
 *
 * CORPUS-GRADED (pure): the rolling SHA-384 commitment over chunks in absolute-offset order, the
 * mid-stream checkpoint digests, the StreamOpen/StreamCommit/StreamCheckpoint bodies, the tamper
 * digest, and the offset-order-independence property (reversed input yields the same commitment;
 * swapping which bytes sit at which offset changes it). CRYPTO-GRADED (real FIPS-204 ML-DSA-65 via
 * BouncyCastle -- Kotlin is a full-signature port): the single end-commitment signature covering the
 * whole stream verifies, and a tampered signature does not. Full-duplex concurrency (R-10.5, Go
 * -race) is not applicable to a single-thread KAT; the load-bearing offset-order-independence
 * property it protects is graded directly here instead.
 *
 * KAT convention (a standalone main() exiting non-zero on any failure); the filename carries the
 * "Tests" token the ten-language-parity gate indexes. Written test-first: [Streaming] is absent until
 * Streaming.kt lands, so this fails RED with a kotlinc "unresolved reference: Streaming"; a mutation
 * that drops the absolute-offset sort in CommitDigest flips "reversed-input same commitment".
 */

private var stFails = 0

private fun stCheck(name: String, got: String, want: String) {
    if (got == want) {
        println("  ok   $name")
    } else {
        stFails++
        println("  FAIL $name\n       got  $got\n       want $want")
    }
}

// ---- minimal regex JSON access (no JSON library on the Kotlin port) ----

private fun stFindVector(): File {
    var d: File? = File(".").absoluteFile
    repeat(6) {
        val cur = d ?: throw AssertionError("vectors/stream/cases.json not found")
        val p = File(File(cur, "vectors"), "stream/cases.json")
        if (p.isFile) return p
        d = cur.parentFile
    }
    throw AssertionError("vectors/stream/cases.json not found from ${File(".").absolutePath}")
}

/** The string value of a "key": "value" pair inside [scope]. */
private fun stField(scope: String, key: String): String {
    val m = Regex("\"$key\"\\s*:\\s*\"([^\"]*)\"").find(scope)
        ?: throw AssertionError("string key not found: $key")
    return m.groupValues[1]
}

/** The integer value of a "key": <number> pair inside [scope]. */
private fun stIntField(scope: String, key: String): Long {
    val m = Regex("\"$key\"\\s*:\\s*(\\d+)").find(scope)
        ?: throw AssertionError("int key not found: $key")
    return m.groupValues[1].toLong()
}

/** The flat inner { ... } block of the object-valued field named [key] (no nesting). */
private fun stSubObject(json: String, key: String): String {
    val m = Regex("\"$key\"\\s*:\\s*\\{([^{}]*)\\}", RegexOption.DOT_MATCHES_ALL).find(json)
        ?: throw AssertionError("object key not found: $key")
    return m.groupValues[1]
}

/** The flat object blocks of the array named [arrayKey]. */
private fun stObjectBlocks(json: String, arrayKey: String): List<String> {
    val a = Regex("\"$arrayKey\"\\s*:\\s*\\[(.*?)\\]", RegexOption.DOT_MATCHES_ALL).find(json)
        ?: throw AssertionError("array key not found: $arrayKey")
    return Regex("\\{([^{}]*)\\}", RegexOption.DOT_MATCHES_ALL).findAll(a.groupValues[1])
        .map { it.groupValues[1] }.toList()
}

private fun streamingRun() {
    val json = stFindVector().readText(Charsets.UTF_8)

    val streamId = Hex.decode(stField(json, "stream_id_hex"))
    val substream = stIntField(json, "substream")
    val effect = stIntField(json, "effect")
    val approval = Hex.decode(stField(json, "approval_hex"))
    val finalDigest = stField(json, "final_digest_hex")

    val chunks = stObjectBlocks(json, "chunks").map {
        Streaming.Chunk(stIntField(it, "offset"), Hex.decode(stField(it, "data_hex")))
    }
    val checkpoints = stObjectBlocks(json, "checkpoints").map {
        Pair(stIntField(it, "through_offset"), stField(it, "digest_so_far_hex"))
    }

    // 1. the rolling commitment over chunks in absolute-offset order equals the oracle.
    stCheck("commit digest == oracle", Hex.encode(Streaming.commitDigest(chunks)), finalDigest)

    // 2. rolling: DigestSoFar after each chunk equals the corresponding checkpoint; the last equals
    //    the final commitment (the digest is not finalized by a checkpoint, so streaming continues).
    val sd = Streaming.StreamDigest()
    for ((i, ch) in chunks.withIndex()) {
        sd.update(ch.data)
        if (i < checkpoints.size) {
            stCheck("checkpoint $i digest_so_far == oracle", Hex.encode(sd.digestSoFar()), checkpoints[i].second)
        }
    }
    stCheck("rolling final == final_digest", Hex.encode(sd.digestSoFar()), finalDigest)

    // 3. the StreamOpen / StreamCommit / StreamCheckpoint bodies equal the oracle bytes.
    val open = Streaming.StreamOpen(streamId, effect, approval, substream)
    stCheck("StreamOpen body == oracle", Hex.encode(open.bytes()), stField(json, "open_body_hex"))
    val commit = Streaming.StreamCommit(streamId, Hex.decode(finalDigest))
    stCheck("StreamCommit body == oracle", Hex.encode(commit.bytes()), stField(json, "commit_body_hex"))
    val cp0 = Streaming.StreamCheckpoint(streamId, checkpoints[0].first, Hex.decode(checkpoints[0].second))
    stCheck("StreamCheckpoint body == oracle", Hex.encode(cp0.bytes()), stField(json, "checkpoint_body_hex"))

    // 4. R-10.2 tamper: the valid stream verifies; delivering a tampered chunk in place of the
    //    corpus tamper index invalidates the commitment (StreamDigestMismatch). The tampered stream's
    //    recomputed commitment also equals the independent tamper oracle.
    val tamper = stSubObject(json, "tamper")
    val tamperIdx = stIntField(tamper, "chunk_index").toInt()
    stCheck("valid stream verifies", verifyKind { Streaming.verifyCommit(commit, chunks) }, "ok")
    val tampered = chunks.toMutableList()
    tampered[tamperIdx] = Streaming.Chunk(chunks[tamperIdx].offset, Hex.decode(stField(tamper, "flipped_data_hex")))
    stCheck("tampered stream rejected", verifyKind { Streaming.verifyCommit(commit, tampered) }, "StreamDigestMismatch")
    stCheck("tampered commit digest == oracle", Hex.encode(Streaming.commitDigest(tampered)), stField(tamper, "digest_hex"))

    // 5. checkpoints confirm a prefix WITHOUT the end; a prefix of the wrong length is rejected.
    for ((i, c) in checkpoints.withIndex()) {
        val cp = Streaming.StreamCheckpoint(streamId, c.first, Hex.decode(c.second))
        val prefix = chunks.subList(0, i + 1)
        stCheck("checkpoint $i verifies prefix", verifyKind { Streaming.verifyCheckpoint(cp, prefix) }, "ok")
    }
    val cpFull = Streaming.StreamCheckpoint(streamId, checkpoints[0].first, Hex.decode(checkpoints[0].second))
    stCheck("checkpoint rejects wrong-length prefix", verifyKind { Streaming.verifyCheckpoint(cpFull, chunks) }, "StreamDigestMismatch")

    // 6. R-10.3 effect refused before any chunk: a destructive stream under a read-only grant is
    //    refused; the corpus stream (idempotent_write) under an idempotent_write grant is authorized;
    //    an unrecognized effect fails closed to destructive and is refused below destructive.
    val destructive = Streaming.StreamOpen(streamId, Policy.DESTRUCTIVE, null, 1)
    stCheck("destructive under read-only refused", verifyKind { Streaming.openStream(destructive, Policy.READ_ONLY) }, "EffectNotAuthorized")
    val okOpen = Streaming.StreamOpen(streamId, effect, approval, substream)
    stCheck("idempotent stream authorized", verifyKind { Streaming.openStream(okOpen, Policy.IDEMPOTENT_WRITE) }, "ok")
    val unknownEff = Streaming.StreamOpen(streamId, 99, null, 1)
    stCheck("unknown effect refused below destructive", verifyKind { Streaming.openStream(unknownEff, Policy.NON_IDEMPOTENT_WRITE) }, "EffectNotAuthorized")

    // 7. CRYPTO-GRADED (real ML-DSA-65): the ONE end-commitment signature covers the whole stream and
    //    verifies; a tampered signature does not (the single signature makes the stream non-repudiable).
    val seed = ByteArray(32) { 0x3c }
    val pk = Cose.mldsaKeygen("ML-DSA-65", seed)
    val sig = Streaming.signCommit(commit, Cose.ALG_MLDSA65, seed)
    stCheck("commit signature verifies", Streaming.verifyCommitSig(commit, Cose.ALG_MLDSA65, pk, sig).toString(), "true")
    val badSig = sig.copyOf()
    badSig[0] = (badSig[0].toInt() xor 0x01).toByte()
    stCheck("tampered commit signature rejected", Streaming.verifyCommitSig(commit, Cose.ALG_MLDSA65, pk, badSig).toString(), "false")

    // 8. offset-order-independence (the property Go proves with -race + reversed/swapped input): the
    //    commitment folds chunks in ABSOLUTE-OFFSET order, so a reversed delivery of the same frames
    //    yields the SAME commitment, while swapping which bytes sit at which offset changes it.
    val reversed = chunks.reversed()
    stCheck("reversed-input same commitment", Hex.encode(Streaming.commitDigest(reversed)), finalDigest)
    val swapped = chunks.toMutableList()
    swapped[0] = Streaming.Chunk(chunks[0].offset, chunks[1].data)
    swapped[1] = Streaming.Chunk(chunks[1].offset, chunks[0].data)
    stCheck("swapped-offset content different commitment", (Hex.encode(Streaming.commitDigest(swapped)) != finalDigest).toString(), "true")
}

/** Run [block]; return "ok" if it returns, else the NaalpException kind. */
private fun verifyKind(block: () -> Unit): String = try {
    block()
    "ok"
} catch (e: NaalpException) {
    e.kind
}

fun main() {
    println("streaming conformance (Kotlin) -- graded vs vectors/stream/cases.json")
    streamingRun()
    println(if (stFails == 0) "StreamingTests: PASS" else "StreamingTests: FAIL ($stFails)")
    exitProcess(if (stFails == 0) 0 else 1)
}
