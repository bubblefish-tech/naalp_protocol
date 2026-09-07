// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

/**
 * N-AALP C12 foreign carriage by class for the Kotlin SDK (design.md section 13; R-14.1..14.8,
 * R-18.6).
 *
 * N-AALP carries a foreign agent protocol by wrapping its message, octet-for-octet, in a signed
 * N-AALP carriage object whose effect, safety, identity, and audit apply, and whose foreign body is
 * interpreted by a carriage CLASS -- not a bespoke per-protocol mapping (R-14.1). There are five
 * structured classes (JSONRPC, HTTP, MSG, STREAM, DOC) plus a universal OPAQUE class that makes any
 * protocol -- including one nobody has defined -- carriable immediately on an experimental protocol id
 * with no registration (R-14.1, R-18.6). The foreign field is carried VERBATIM and MUST NOT be
 * re-serialized, canonicalized, summarized, or rewritten (R-14.4); N-AALP metadata is carried around
 * it, never inside it. The carriage object's signer remains the authority -- a foreign identity never
 * becomes an N-AALP authorization identity (R-14.6).
 *
 * An independent transcription of impl/go/carriage (a second reference is
 * impl/python/naalp/carriage.py); each carriage class is graded against its own per-class oracle at
 * vectors/carriage/<class>/cases.json. Carriage bodies are UNSIGNED (the six per-class body_hex ARE
 * the byte parity); the R-14.6 identity-containment property is demonstrated over a real signed
 * Envelope object. Every check is fail-closed.
 */
object Carriage {
    // Carriage classes (design.md section 13.2).
    const val CLASS_JSONRPC = 0L
    const val CLASS_HTTP = 1L
    const val CLASS_MSG = 2L
    const val CLASS_STREAM = 3L
    const val CLASS_DOC = 4L
    const val CLASS_OPAQUE = 5L

    private val CLASS_NAMES = arrayOf("JSONRPC", "HTTP", "MSG", "STREAM", "DOC", "OPAQUE")

    /** The name of a class code (0..5), or "unknown". */
    fun className(c: Long): String = if (c in 0 until CLASS_NAMES.size.toLong()) CLASS_NAMES[c.toInt()] else "unknown"

    /**
     * The body of a carriage object (design.md section 13.2). [klass] is the carriage class (spelled
     * `klass` because `class` is a Kotlin keyword); [foreign] is the foreign message carried
     * octet-for-octet (R-14.4).
     */
    class CarriageBody(
        val protocolId: Long,
        val klass: Long,
        val contentType: Long,
        correlation: ByteArray,
        val method: String,
        foreign: ByteArray,
    ) {
        val correlation: ByteArray = correlation.copyOf()
        val foreign: ByteArray = foreign.copyOf()

        /** The carriage body as a CBOR map {1: protocol_id, 2: class, 3: content_type,
         *  4: correlation, 5: method, 6: foreign}. */
        fun toValue(): Cbor.Value = Cbor.M(
            listOf(
                Cbor.Pair(Cbor.U(1), Cbor.U(protocolId)),
                Cbor.Pair(Cbor.U(2), Cbor.U(klass)),
                Cbor.Pair(Cbor.U(3), Cbor.U(contentType)),
                Cbor.Pair(Cbor.U(4), Cbor.B(correlation)),
                Cbor.Pair(Cbor.U(5), Cbor.T(method)),
                Cbor.Pair(Cbor.U(6), Cbor.B(foreign))
            )
        )

        /** The deterministic-CBOR encoding of the carriage body. */
        fun bytes(): ByteArray = Cbor.encode(toValue())
    }

    /** Reject a class code outside the defined set with a typed mapping error, never a silent drop
     *  (R-14.8). Returns on a representable class. */
    fun validateClass(klass: Long) {
        if (klass > CLASS_OPAQUE || klass < 0) {
            throw NaalpException("MappingError", "an N-AALP semantic cannot be represented by this carriage class")
        }
    }

    /**
     * Wrap a foreign message octet-for-octet in a carriage body (R-14.1, R-14.4). It does not parse,
     * canonicalize, or rewrite the foreign bytes. An undefined protocol carries under OPAQUE with an
     * experimental protocol id and zero new specification (R-18.6).
     */
    fun carry(protocolId: Long, klass: Long, contentType: Long, correlation: ByteArray, method: String, foreign: ByteArray): CarriageBody {
        validateClass(klass)
        return CarriageBody(protocolId, klass, contentType, correlation, method, foreign)
    }

    /**
     * Parse a carriage body from a CBOR value, recovering the foreign field octet-for-octet. A
     * structurally invalid body is Malformed; an unknown class is a MappingError. Only the mandatory
     * foreign field (key 6) is required; fields 1-5 default to their zero values (matching Go/Python).
     * An unknown field key is rejected Malformed.
     */
    fun carriageFromValue(v: Cbor.Value): CarriageBody {
        if (v !is Cbor.M) throw NaalpException("Malformed", "carriage body is not a map")
        var protocolId = 0L
        var klass = 0L
        var contentType = 0L
        var correlation = ByteArray(0)
        var method = ""
        var foreign = ByteArray(0)
        var haveForeign = false
        for (p in v.pairs) {
            val k = p.k
            if (k !is Cbor.U) throw NaalpException("Malformed", "non-uint carriage key")
            when (k.v) {
                1L -> {
                    val u = p.v as? Cbor.U ?: throw NaalpException("Malformed", "protocol_id not a uint")
                    protocolId = u.v
                }
                2L -> {
                    val u = p.v as? Cbor.U ?: throw NaalpException("Malformed", "class not a uint")
                    klass = u.v
                }
                3L -> {
                    val u = p.v as? Cbor.U ?: throw NaalpException("Malformed", "content_type not a uint")
                    contentType = u.v
                }
                4L -> {
                    val b = p.v as? Cbor.B ?: throw NaalpException("Malformed", "correlation not a bstr")
                    correlation = b.v
                }
                5L -> {
                    val t = p.v as? Cbor.T ?: throw NaalpException("Malformed", "method not a tstr")
                    method = t.v
                }
                6L -> {
                    val b = p.v as? Cbor.B ?: throw NaalpException("Malformed", "foreign not a bstr")
                    foreign = b.v
                    haveForeign = true
                }
                else -> throw NaalpException("Malformed", "unknown carriage field ${k.v}")
            }
        }
        if (!haveForeign) throw NaalpException("Malformed", "carriage body missing the mandatory foreign field")
        validateClass(klass)
        return CarriageBody(protocolId, klass, contentType, correlation, method, foreign)
    }

    /**
     * The protocol-id range (design.md section 13.4): reserved 0x00, standards 0x01-0x0F,
     * experimental 0x10-0x7F (no registration), private 0x80-0xFF.
     * protocol_id is one octet; anything wider is invalid.
     */
    fun protocolRange(id: Long): String = when {
        id == 0x00L -> "reserved"
        id <= 0x0FL -> "standards"
        id <= 0x7FL -> "experimental"
        id <= 0xFFL -> "private"
        else -> "invalid"
    }

    /** Records whether a carried message was actually delivered. A report never claims delivery it did
     *  not achieve (R-14.8). */
    class DeliveryReport(val delivered: Boolean)

    /**
     * Produce a delivery report from the below-foreign outcome: a failed delivery throws NotDelivered
     * (never a false "delivered"); a success returns a delivered report (R-14.8).
     */
    fun report(deliveredBelow: Boolean): DeliveryReport {
        if (!deliveredBelow) throw NaalpException("NotDelivered", "a below-foreign failure; the message was not delivered")
        return DeliveryReport(true)
    }

    /**
     * The authorizing principal of a carriage object: the N-AALP signer of the object (envelope field
     * 5), never any foreign principal named inside the foreign bytes (R-14.6). It reads only the
     * signed envelope, never the carried foreign message.
     */
    fun carriageAuthority(obj: Envelope.Object): ByteArray = obj.signer
}
