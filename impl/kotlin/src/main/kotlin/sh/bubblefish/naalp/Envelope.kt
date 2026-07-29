// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

/**
 * N-AALP C3 object envelope for the Kotlin SDK — the full signed object and its offline verify.
 *
 * This is the ergonomic surface a developer uses: build an [Envelope.Object] (its channel/kind/
 * effect/body and the rest), sign it with a seed-derived ML-DSA key, and get a single self-
 * describing, offline-verifiable byte string; verify one from the object + key + spec alone. The
 * bytes are byte-identical to the Go, Rust and Python reference implementations — the worked
 * example in vectors/worked/example.json is the byte-level known-answer for this module.
 *
 * The object body is a deterministic-CBOR map (fields 1..12) carried as the COSE_Sign1 payload;
 * field 1 is the content id, multihash(0x20, 0x30, SHA-384(canonical-body-without-field-1)) (§2.3).
 * The COSE protected header carries the signature algorithm plus a routing copy of the signer,
 * profile and naalp-version (§2.1, §2.5); a verifier that finds the header copies disagreeing with
 * the body rejects the object (HeaderBodyMismatch), and every failure is fail-closed with a named
 * error and no partial application (§2.6).
 */
object Envelope {

    // Object body field numbers (design.md §2.1).
    const val FIELD_ID = 1L
    const val FIELD_KIND = 2L
    const val FIELD_CHANNEL = 3L
    const val FIELD_TIER = 4L
    const val FIELD_SIGNER = 5L
    const val FIELD_CREATED = 6L
    const val FIELD_EFFECT = 7L
    const val FIELD_CAUSES = 8L
    const val FIELD_PROFILE = 9L
    const val FIELD_BODY = 10L
    const val FIELD_EXT = 11L
    const val FIELD_CEXT = 12L

    /** The protected-header naalp-version (design.md §2.5). */
    const val NAALP_VERSION = 1L

    /**
     * The COSE protected-header parameter (a text-string label, which cannot collide with any
     * integer-labeled standard COSE parameter, RFC 9052 §3.1) under which N-AALP carries its
     * routing copies {1:signer, 2:profile, 3:version}.
     */
    const val HEADER_LABEL = "naalp"

    /** A validator reporting whether (channel, kind) is a recognized surface kind. A null validator
     *  rejects every kind. The envelope owns the fail-closed dispatch (UnknownKind); the per-channel
     *  kind tables are the surface layer's content. */
    fun interface KindValidator {
        fun accepts(channel: Long, kind: Long): Boolean
    }

    /**
     * A decoded N-AALP object body. [id] is set by [sign] (content id §2.3). [body] is any CBOR
     * value; [ext] (field 11, non-critical) and [cext] (field 12, critical) are optional maps.
     */
    class Object(
        var kind: Long,
        var channel: Long,
        var signer: ByteArray,
        var created: Long,
        var effect: Long,
        var body: Cbor.Value,
        var tier: Long = 0L,
        var profile: Long = Cose.PROFILE_PUBLIC,
        var causes: List<ByteArray> = emptyList(),
        var ext: Cbor.M? = null,
        var cext: Cbor.M? = null,
    ) {
        var id: ByteArray? = null

        /** The object body as a deterministic-CBOR map. Encode emits canonical key order, so the
         *  append order here is irrelevant to the bytes. */
        fun bodyMap(includeId: Boolean): Cbor.M {
            val pairs = ArrayList<Cbor.Pair>(12)
            if (includeId) {
                val cid = id ?: throw NaalpException("Malformed", "content id not set")
                pairs.add(Cbor.Pair(Cbor.U(FIELD_ID), Cbor.B(cid)))
            }
            pairs.add(Cbor.Pair(Cbor.U(FIELD_KIND), Cbor.U(kind)))
            pairs.add(Cbor.Pair(Cbor.U(FIELD_CHANNEL), Cbor.U(channel)))
            pairs.add(Cbor.Pair(Cbor.U(FIELD_TIER), Cbor.U(tier)))
            pairs.add(Cbor.Pair(Cbor.U(FIELD_SIGNER), Cbor.B(signer)))
            pairs.add(Cbor.Pair(Cbor.U(FIELD_CREATED), Cbor.U(created)))
            pairs.add(Cbor.Pair(Cbor.U(FIELD_EFFECT), Cbor.U(effect)))
            pairs.add(Cbor.Pair(Cbor.U(FIELD_CAUSES), Cbor.A(causes.map { Cbor.B(it) })))
            pairs.add(Cbor.Pair(Cbor.U(FIELD_PROFILE), Cbor.U(profile)))
            pairs.add(Cbor.Pair(Cbor.U(FIELD_BODY), body))
            ext?.let { pairs.add(Cbor.Pair(Cbor.U(FIELD_EXT), it)) }
            cext?.let { pairs.add(Cbor.Pair(Cbor.U(FIELD_CEXT), it)) }
            return Cbor.M(pairs)
        }

        /** The object content id over the body without field 1 (design.md §2.3). */
        fun contentId(): ByteArray = Cbor.contentId(Cbor.encode(bodyMap(false)))
    }

    /** Build the COSE protected header {1: nint(alg), "naalp": {1:signer, 2:profile, 3:version}}. */
    private fun protectedHeader(alg: Int, signer: ByteArray, profile: Long): ByteArray {
        val naalp = Cbor.M(
            listOf(
                Cbor.Pair(Cbor.U(1), Cbor.B(signer)),
                Cbor.Pair(Cbor.U(2), Cbor.U(profile)),
                Cbor.Pair(Cbor.U(3), Cbor.U(NAALP_VERSION)),
            )
        )
        val hdr = Cbor.M(
            listOf(
                Cbor.Pair(Cbor.U(1), Cbor.N(alg.toLong())),
                Cbor.Pair(Cbor.T(HEADER_LABEL), naalp),
            )
        )
        return Cbor.encode(hdr)
    }

    /**
     * Assemble, content-id-bind, and deterministically sign a full N-AALP object with an ML-DSA key
     * derived from [seed]. The alg and the object's signer/profile populate the protected-header
     * routing copies. Returns the tagged COSE_Sign1 object bytes.
     */
    fun sign(obj: Object, alg: Int, seed: ByteArray): ByteArray {
        obj.id = obj.contentId()
        val payload = Cbor.encode(obj.bodyMap(true))
        val prot = protectedHeader(alg, obj.signer, obj.profile)
        val tbs = Cose.toBeSignedRaw(prot, payload)
        val sig = Cose.mldsaSign(alg, seed, tbs)
        return Cose.assembleSign1Raw(prot, payload, sig)
    }

    private data class Header(val alg: Int, val signer: ByteArray, val profile: Long, val version: Long)

    private fun parseProtected(prot: ByteArray): Header {
        val v = Cbor.decode(prot)
        if (v !is Cbor.M) throw NaalpException("Malformed", "protected header not a map")
        var alg: Int? = null
        var signer: ByteArray? = null
        var profile: Long? = null
        var version: Long? = null
        for (p in v.pairs) {
            val k = p.k
            if (k is Cbor.U && k.v == 1L && p.v is Cbor.N) {
                alg = (p.v as Cbor.N).v.toInt()
            } else if (k is Cbor.T && k.v == HEADER_LABEL && p.v is Cbor.M) {
                for (np in (p.v as Cbor.M).pairs) {
                    val nk = np.k
                    if (nk !is Cbor.U) continue
                    when (nk.v) {
                        1L -> if (np.v is Cbor.B) signer = (np.v as Cbor.B).v
                        2L -> if (np.v is Cbor.U) profile = (np.v as Cbor.U).v
                        3L -> if (np.v is Cbor.U) version = (np.v as Cbor.U).v
                    }
                }
            }
        }
        if (alg == null || signer == null || profile == null || version == null) {
            throw NaalpException("Malformed", "protected header missing routing fields")
        }
        return Header(alg, signer, profile, version)
    }

    private fun objectFromMap(m: Cbor.M): Object {
        val fields = HashMap<Long, Cbor.Value>()
        for (p in m.pairs) {
            val k = p.k as? Cbor.U ?: throw NaalpException("Malformed", "non-uint body key")
            fields[k.v] = p.v
        }
        fun uintField(fnum: Long): Long {
            val v = fields[fnum]
            if (v !is Cbor.U) throw NaalpException("Malformed", "field $fnum wrong type/absent")
            return v.v
        }
        val signerV = fields[FIELD_SIGNER]
        if (signerV !is Cbor.B) throw NaalpException("Malformed", "field 5 wrong type/absent")
        val causesV = fields[FIELD_CAUSES]
        if (causesV !is Cbor.A) throw NaalpException("Malformed", "field 8 wrong type/absent")
        val causes = ArrayList<ByteArray>(causesV.items.size)
        for (c in causesV.items) {
            if (c !is Cbor.B) throw NaalpException("Malformed", "cause not a bstr")
            causes.add(c.v)
        }
        val bodyV = fields[FIELD_BODY] ?: throw NaalpException("Malformed", "field 10 absent")
        val extV = fields[FIELD_EXT]
        val cextV = fields[FIELD_CEXT]
        if (extV != null && extV !is Cbor.M) throw NaalpException("Malformed", "ext not a map")
        if (cextV != null && cextV !is Cbor.M) throw NaalpException("Malformed", "cext not a map")
        // required fields (kind/channel/tier/created/effect/profile) validated via uintField
        val o = Object(
            kind = uintField(FIELD_KIND),
            channel = uintField(FIELD_CHANNEL),
            signer = signerV.v,
            created = uintField(FIELD_CREATED),
            effect = uintField(FIELD_EFFECT),
            body = bodyV,
            tier = uintField(FIELD_TIER),
            profile = uintField(FIELD_PROFILE),
            causes = causes,
            ext = extV as Cbor.M?,
            cext = cextV as Cbor.M?,
        )
        val idV = fields[FIELD_ID]
        o.id = if (idV is Cbor.B) idV.v else null
        return o
    }

    /**
     * Verify a signed N-AALP object end-to-end, offline (R-2.4). Returns the [Object] on success;
     * throws a [NaalpException] with a stable kind on the first named failure. Check order
     * (fail-closed): decode -> content-id -> field ranges -> header/body copies + version ->
     * critical extensions -> kind dispatch -> profile floor -> signature.
     */
    fun verify(
        profile: Long,
        alg: Int,
        pubkey: ByteArray,
        kindValidator: KindValidator?,
        objBytes: ByteArray,
        knownCext: Set<Long> = emptySet(),
    ): Object {
        val parts = Cose.parseSign1Raw(objBytes)
        val prot = parts[0]
        val payload = parts[1]
        val sig = parts[2]

        val bv = Cbor.decode(payload) // throws NonCanonical on a non-canonical body
        if (bv !is Cbor.M) throw NaalpException("Malformed", "body not a map")

        // content-id: recompute over the body without field 1, compare to the claimed id.
        var claimed: ByteArray? = null
        val without = ArrayList<Cbor.Pair>(bv.pairs.size)
        for (p in bv.pairs) {
            val k = p.k
            if (k is Cbor.U && k.v == FIELD_ID) {
                val b = p.v as? Cbor.B ?: throw NaalpException("Malformed", "id not a bstr")
                claimed = b.v
                continue
            }
            without.add(p)
        }
        if (claimed == null) throw NaalpException("Malformed", "no content id")
        val recomputed = Cbor.contentId(Cbor.encode(Cbor.M(without)))
        if (!recomputed.contentEquals(claimed)) {
            throw NaalpException("ContentIdMismatch", "recomputed id differs")
        }

        val o = objectFromMap(bv)

        // field ranges (§3.3): channel 0..19, effect 0..3, profile 1..3.
        if (o.channel > 19 || o.effect > 3 || o.profile < 1 || o.profile > 3) {
            throw NaalpException("RangeError", "field out of range")
        }

        val h = parseProtected(prot)
        if (h.version != NAALP_VERSION) throw NaalpException("UnsupportedVersion", "bad naalp-version")
        if (!h.signer.contentEquals(o.signer) || h.profile != o.profile) {
            throw NaalpException("HeaderBodyMismatch", "protected header disagrees with body")
        }

        // critical extensions: any unrecognized key rejects (§2.5).
        o.cext?.let { cext ->
            for (p in cext.pairs) {
                val k = p.k
                if (k !is Cbor.U || k.v !in knownCext) {
                    throw NaalpException("UnknownCriticalExt", "unrecognized critical extension")
                }
            }
        }

        // kind/channel surface dispatch (UnknownKind, §2.6).
        if (kindValidator == null || !kindValidator.accepts(o.channel, o.kind)) {
            throw NaalpException("UnknownKind", "kind/channel not a registered surface")
        }

        // profile floor + COSE signature.
        val (level, known) = Cose.algLevel(h.alg)
        if (!known) throw NaalpException("UnknownAlg", "unregistered alg")
        if (level < Cose.profileMinLevel(profile)) {
            throw NaalpException("ProfileDowngrade", "signature level below the profile minimum")
        }
        val tbs = Cose.toBeSignedRaw(prot, payload)
        if (!Cose.coseVerify1Raw(h.alg, pubkey, tbs, sig)) {
            throw NaalpException("BadSignature", "signature does not verify")
        }
        return o
    }
}
