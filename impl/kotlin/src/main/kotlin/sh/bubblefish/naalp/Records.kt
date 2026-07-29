// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

import java.security.MessageDigest

/**
 * N-AALP body builders for the Kotlin SDK — the deterministic-CBOR bodies of the spine records:
 * approval + consume ledger (C6, §7), audit receipt (C7, §8), delivery update (C8, §9), stream
 * open/commit/checkpoint + rolling commitment (C9, §10), foreign carriage (C12, §13), and the
 * transport confidentiality boundary (C11, §12). Each body is exactly what the Go, Rust, Python and
 * Java reference implementations encode, so the bytes are byte-identical.
 */
object Records {

    private fun sha384(): MessageDigest = MessageDigest.getInstance("SHA-384")

    // --- C6 approval + consume ledger (§7) ---

    fun approvalBody(approves: ByteArray, approver: String, grant: Long, nonce: ByteArray, notAfter: Long): ByteArray =
        Cbor.encode(
            Cbor.M(
                listOf(
                    Cbor.Pair(Cbor.U(1), Cbor.B(approves)),
                    Cbor.Pair(Cbor.U(2), Cbor.T(approver)),
                    Cbor.Pair(Cbor.U(3), Cbor.U(grant)),
                    Cbor.Pair(Cbor.U(4), Cbor.B(nonce)),
                    Cbor.Pair(Cbor.U(5), Cbor.U(notAfter))
                )
            )
        )

    fun approvalId(approves: ByteArray, approver: String, grant: Long, nonce: ByteArray, notAfter: Long): ByteArray =
        Cbor.contentId(approvalBody(approves, approver, grant, nonce, notAfter))

    fun ledgerEntry(seq: Long, prev: ByteArray, approvalId: ByteArray, by: String): ByteArray =
        Cbor.encode(
            Cbor.M(
                listOf(
                    Cbor.Pair(Cbor.U(1), Cbor.U(seq)),
                    Cbor.Pair(Cbor.U(2), Cbor.B(prev)),
                    Cbor.Pair(Cbor.U(3), Cbor.B(approvalId)),
                    Cbor.Pair(Cbor.U(4), Cbor.T(by))
                )
            )
        )

    // --- C7 audit receipt (§8) ---

    fun receiptBody(prev: ByteArray, obj: ByteArray, seq: Long, at: Long): ByteArray =
        Cbor.encode(
            Cbor.M(
                listOf(
                    Cbor.Pair(Cbor.U(1), Cbor.B(prev)),
                    Cbor.Pair(Cbor.U(2), Cbor.B(obj)),
                    Cbor.Pair(Cbor.U(3), Cbor.U(seq)),
                    Cbor.Pair(Cbor.U(4), Cbor.U(at))
                )
            )
        )

    fun receiptHead(body: ByteArray): ByteArray = sha384().digest(body)

    // --- C8 delivery (§9) ---

    fun deliveryUpdate(obj: ByteArray, stage: Long, at: Long): ByteArray =
        Cbor.encode(
            Cbor.M(
                listOf(
                    Cbor.Pair(Cbor.U(1), Cbor.B(obj)),
                    Cbor.Pair(Cbor.U(2), Cbor.U(stage)),
                    Cbor.Pair(Cbor.U(3), Cbor.U(at))
                )
            )
        )

    // --- C9 streaming (§10) ---

    /** A stream chunk: an absolute offset and its data bytes. */
    class Chunk(val offset: Long, val data: ByteArray)

    /** Rolling SHA-384 over the chunk data in absolute-offset order (R-10.2). */
    fun streamDigest(chunks: List<Chunk>): ByteArray {
        val sorted = chunks.sortedBy { it.offset }
        val h = sha384()
        for (c in sorted) h.update(c.data)
        return h.digest()
    }

    fun streamOpenBody(streamId: ByteArray, effect: Long, approval: ByteArray?, substream: Long): ByteArray {
        val pairs = ArrayList<Cbor.Pair>()
        pairs.add(Cbor.Pair(Cbor.U(1), Cbor.B(streamId)))
        pairs.add(Cbor.Pair(Cbor.U(2), Cbor.U(effect)))
        pairs.add(Cbor.Pair(Cbor.U(4), Cbor.U(substream)))
        if (approval != null && approval.isNotEmpty()) { // field 3 present only with an approval binding
            pairs.add(Cbor.Pair(Cbor.U(3), Cbor.B(approval)))
        }
        return Cbor.encode(Cbor.M(pairs))
    }

    fun streamCommitBody(streamId: ByteArray, digest: ByteArray): ByteArray =
        Cbor.encode(
            Cbor.M(
                listOf(
                    Cbor.Pair(Cbor.U(1), Cbor.B(streamId)),
                    Cbor.Pair(Cbor.U(2), Cbor.B(digest))
                )
            )
        )

    fun streamCheckpointBody(streamId: ByteArray, throughOffset: Long, digestSoFar: ByteArray): ByteArray =
        Cbor.encode(
            Cbor.M(
                listOf(
                    Cbor.Pair(Cbor.U(1), Cbor.B(streamId)),
                    Cbor.Pair(Cbor.U(2), Cbor.U(throughOffset)),
                    Cbor.Pair(Cbor.U(3), Cbor.B(digestSoFar))
                )
            )
        )

    // --- C12 foreign carriage (§13) ---

    const val CLASS_OPAQUE = 5L

    fun carriageBody(
        protocolId: Long, cls: Long, contentType: Long,
        correlation: ByteArray, method: String, foreign: ByteArray
    ): ByteArray {
        if (cls > CLASS_OPAQUE) throw NaalpException("MappingError", "carriage class $cls is not defined")
        return Cbor.encode(
            Cbor.M(
                listOf(
                    Cbor.Pair(Cbor.U(1), Cbor.U(protocolId)),
                    Cbor.Pair(Cbor.U(2), Cbor.U(cls)),
                    Cbor.Pair(Cbor.U(3), Cbor.U(contentType)),
                    Cbor.Pair(Cbor.U(4), Cbor.B(correlation)),
                    Cbor.Pair(Cbor.U(5), Cbor.T(method)),
                    Cbor.Pair(Cbor.U(6), Cbor.B(foreign))
                )
            )
        )
    }

    // --- C11 transport confidentiality boundary (§12) ---

    private fun transport(name: String): BooleanArray? = when (name) {
        "npamp" -> booleanArrayOf(true, true)
        "quic" -> booleanArrayOf(true, true)
        "websocket+wss" -> booleanArrayOf(true, false)
        "websocket+ws" -> booleanArrayOf(false, false)
        "https" -> booleanArrayOf(true, false)
        "http" -> booleanArrayOf(false, false)
        else -> null
    }

    /** Apply the §12.3 confidentiality boundary + §12.4 peer-auth rule; returns the result label. */
    fun transportEmit(name: String, sensitive: Boolean, requirePeerAuth: Boolean): String {
        val t = transport(name) ?: throw NaalpException("UnknownTransport", "unknown transport $name")
        val confidential = t[0]
        val peerAuthenticated = t[1]
        if (sensitive && !confidential) return "ConfidentialTransportRequired"
        if (requirePeerAuth && !peerAuthenticated) return "PeerUnauthenticated"
        return "ok"
    }
}
