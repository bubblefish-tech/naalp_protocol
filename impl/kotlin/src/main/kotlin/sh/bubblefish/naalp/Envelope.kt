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

    // Field numbers (§2.1), the naalp-version (§2.5) and the COSE header label are generated from
    // spec/wire-constants.csv into the same-package WireConstants.kt (top-level consts), so they are
    // authored once and cannot be re-typed and drift (scripts/gen_wire_constants.py).

    /** The signed suite id carried in field 14 for the opt-in ML-DSA-65 + Ed25519 composite signature
     *  (§4.2); present iff a composite alg signs the object, so a pure object stays byte-identical to
     *  a draft-00 object. */
    const val SUITE_MLDSA65_ED25519 = 1L

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
        // field 13 (§2.5.3): the single-use consume binding. Omit-when-empty -- a no-audience object
        // encodes byte-identically to a draft-00 object (additivity). Anchors version 2.
        var audience: String = "",
        // field 14 (§4.2): the signed suite declaration, present (value 1) iff a composite alg signs
        // this object; 0 = absent, so a pure object stays byte-identical to draft-00.
        var suite: Long = 0L,
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
            if (audience.isNotEmpty()) pairs.add(Cbor.Pair(Cbor.U(FIELD_AUDIENCE), Cbor.T(audience)))
            if (suite != 0L) pairs.add(Cbor.Pair(Cbor.U(FIELD_SUITE), Cbor.U(suite)))
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

    /**
     * Assemble, content-id-bind, and sign a full N-AALP object with the opt-in LAMPS composite
     * signature (alg -65537, §4.2). Sets the signed suite field (14) present (value 1) BEFORE the
     * content id so the id covers it; the composite value is deterministic in both legs (ML-DSA-65
     * with ctx=Label, Ed25519 with no ctx). Returns the tagged COSE_Sign1 object bytes.
     */
    fun signComposite(obj: Object, mldsaSeed: ByteArray, edSeed: ByteArray): ByteArray {
        obj.suite = SUITE_MLDSA65_ED25519
        obj.id = obj.contentId()
        val payload = Cbor.encode(obj.bodyMap(true))
        val prot = protectedHeader(Cose.ALG_COMPOSITE_65_ED25519, obj.signer, obj.profile)
        val tbs = Cose.toBeSignedRaw(prot, payload)
        val sig = Cose.compositeSign(mldsaSeed, edSeed, tbs)
        return Cose.assembleSign1Raw(prot, payload, sig)
    }

    private data class Header(val alg: Int, val signer: ByteArray, val profile: Long, val version: Long)

    private fun parseProtected(prot: ByteArray): Header {
        // §3.1.1 (R5): the empty protected header is pinned to 0x40; a byte string wrapping an
        // empty CBOR map (the 0x41A0 form — its unwrapped content is the single byte 0xA0) MUST
        // be rejected as NonCanonical before the header is interpreted.
        if (prot.size == 1 && (prot[0].toInt() and 0xFF) == 0xA0) {
            throw NaalpException("NonCanonical", "empty protected header must be 0x40, not 0x41A0 (§3.1.1, R5)")
        }
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
        if (causesV.items.size > MAX_CAUSES) { // causal fan-in bound (§3.4, R7)
            throw NaalpException("TooManyCauses", "causes[] exceeds the maximum count (§3.4, R7)")
        }
        val causes = ArrayList<ByteArray>(causesV.items.size)
        for (c in causesV.items) {
            if (c !is Cbor.B) throw NaalpException("Malformed", "cause not a bstr")
            causes.add(c.v)
        }
        val bodyV = fields[FIELD_BODY] ?: throw NaalpException("Malformed", "field 10 absent")
        val extV = fields[FIELD_EXT]
        val cextV = fields[FIELD_CEXT]
        if (extV != null && extV !is Cbor.M) throw NaalpException("Malformed", "ext not a map")
        if (extV is Cbor.M && extV.pairs.size > MAX_EXT) { // ext cardinality bound (§3.4, R7)
            throw NaalpException("TooManyExtensions", "ext/cext exceeds the maximum cardinality (§3.4, R7)")
        }
        if (cextV != null && cextV !is Cbor.M) throw NaalpException("Malformed", "cext not a map")
        if (cextV is Cbor.M && cextV.pairs.size > MAX_CEXT) { // cext cardinality bound (§3.4, R7)
            throw NaalpException("TooManyExtensions", "ext/cext exceeds the maximum cardinality (§3.4, R7)")
        }
        val audV = fields[FIELD_AUDIENCE]
        if (audV != null && audV !is Cbor.T) throw NaalpException("Malformed", "audience not a tstr")
        val suiteV = fields[FIELD_SUITE]
        if (suiteV != null && suiteV !is Cbor.U) throw NaalpException("Malformed", "suite not a uint")
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
            audience = if (audV is Cbor.T) audV.v else "",
            suite = if (suiteV is Cbor.U) suiteV.v else 0L,
        )
        val idV = fields[FIELD_ID]
        o.id = if (idV is Cbor.B) idV.v else null
        return o
    }

    /**
     * The single-use consume binding gate (§2.5.3), checked at the point of use -- before the consume
     * logic (the CAS append) -- NEVER inside verify(). An in-transit relay, ordering authority, or
     * auditor legitimately verifies objects addressed to some OTHER authority; only the authority about
     * to CONSUME an object enforces that the object is addressed to it. Three branches: (a) absent
     * audience on a consume-once object -> WrongAudience; (b) an audience present but not this authority
     * -> WrongAudience; (c) a non-consume-once object with no audience -> pass. Throws
     * NaalpException("WrongAudience") on rejection.
     */
    fun checkAudience(o: Object, selfAuthority: String, consumeOnce: Boolean) {
        if (o.audience.isEmpty()) {
            if (consumeOnce) throw NaalpException("WrongAudience", "consume-once object has no audience")
            return
        }
        if (o.audience != selfAuthority) {
            throw NaalpException("WrongAudience", "object audience is not this consuming authority")
        }
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
        // Object octet-size bound (§3.4, R7): reject an oversized signed object on the raw bytes,
        // before any parse (RFC 8949 §10 decoder-memory guard).
        if (objBytes.size > MAX_OBJECT_SIZE) {
            throw NaalpException("TooLarge", "object exceeds the maximum octet size (§3.4, R7)")
        }
        val parts = Cose.parseSign1Raw(objBytes)
        val prot = parts[0]
        val payload = parts[1]
        val sig = parts[2]

        // non-canonical -> NonCanonical (§2.6); over-nested -> DepthExceeded (§3.4, R7).
        val bv = Cbor.decodeBounded(payload, MAX_NESTING_DEPTH.toInt())
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

        // A (channel 3, kind 0) Rotation object MUST be a tag-98 COSE_Sign co-signed by the old AND
        // new key (§5.2); a single-signature (tag-18) rotation is missing the old-key co-signature and
        // is rejected RotationUnauthorized (the single-Sign1 rotation-gap fix).
        if (isRotationObject(o.channel, o.kind)) {
            throw NaalpException("RotationUnauthorized", "single-signature rotation missing the old-key co-signature")
        }

        // field ranges (§3.3): channel 0..19, effect 0..3, profile 1..3.
        if (o.channel > 19 || o.effect > 3 || o.profile < 1 || o.profile > 3) {
            throw NaalpException("RangeError", "field out of range")
        }

        val h = parseProtected(prot)
        if (h.version != NAALP_VERSION) throw NaalpException("UnsupportedVersion", "bad naalp-version")
        if (!h.signer.contentEquals(o.signer) || h.profile != o.profile) {
            throw NaalpException("HeaderBodyMismatch", "protected header disagrees with body")
        }

        // critical extensions: any unrecognized key rejects (§2.5). RECHECK_KEY (13) is an
        // envelope-recognized critical key: a critical recheck naming an UNKNOWN procedure id is
        // rejected fail-closed (the critical-extension rule reaching the procedure it names, T1.3);
        // a known procedure id is recognized. A NON-critical recheck (ext, field 11) is never
        // rejected here -- an unknown non-critical procedure is ignored per the may-ignore rule.
        checkCriticalExtensions(o.cext, knownCext)

        // kind/channel surface dispatch (UnknownKind, §2.6).
        if (kindValidator == null || !kindValidator.accepts(o.channel, o.kind)) {
            throw NaalpException("UnknownKind", "kind/channel not a registered surface")
        }

        val tbs = Cose.toBeSignedRaw(prot, payload)
        if (h.alg == Cose.ALG_COMPOSITE_65_ED25519) {
            // Opt-in composite path (§4.2/§4.4/§4.5): CompositeRefused (Sovereign floors at level 5,
            // the composite ML-DSA-65 leg is level 3) -> SuiteMismatch (field 14 must declare the
            // matching suite) -> both-legs signature. Verifying key = mldsaPub || ed25519Pub.
            if (profile == Cose.PROFILE_SOVEREIGN) {
                throw NaalpException("CompositeRefused", "composite refused on the Sovereign profile")
            }
            if (o.suite != SUITE_MLDSA65_ED25519) {
                throw NaalpException("SuiteMismatch", "field 14 does not declare the composite suite")
            }
            val mldsaPub = pubkey.copyOfRange(0, Cose.MLDSA65_PUB_SIZE)
            val edPub = pubkey.copyOfRange(Cose.MLDSA65_PUB_SIZE, pubkey.size)
            if (edPub.size != 32 || !Cose.compositeVerify(mldsaPub, edPub, tbs, sig)) {
                throw NaalpException("BadSignature", "composite signature does not verify")
            }
            return o
        }
        // pure path: a non-composite alg MUST NOT carry the signed suite field (§4.2).
        if (o.suite != 0L) throw NaalpException("SuiteMismatch", "pure object carries a composite suite field")
        val (level, known) = Cose.algLevel(h.alg)
        if (!known) throw NaalpException("UnknownAlg", "unregistered alg")
        if (level < Cose.profileMinLevel(profile)) {
            throw NaalpException("ProfileDowngrade", "signature level below the profile minimum")
        }
        if (!Cose.coseVerify1Raw(h.alg, pubkey, tbs, sig)) {
            throw NaalpException("BadSignature", "signature does not verify")
        }
        return o
    }

    // --- §5.2 Rotation object (tag-98 COSE_Sign, old+new co-signature) ---

    // The OPEN-DECISION toggle (design.md §4.4 profile floor applied to a rotation): a Sovereign/High
    // verifier gates the OLD (authorizing) leg by the profile floor too (DEFAULT, fail-closed) rather
    // than only the NEW leg. Ratified default = true (matches impl/go rotationOldLegFloorApplies).
    const val ROTATION_OLD_LEG_FLOOR_APPLIES = true

    private fun isRotationObject(channel: Long, kind: Long): Boolean = channel == 3L && kind == 0L

    private fun isCompositeAlg(alg: Int): Boolean =
        alg == Cose.ALG_COMPOSITE_65_ED25519 || alg == Cose.ALG_COMPOSITE_44_ED25519

    /**
     * Build a §5.2 Rotation object as a tag-98 COSE_Sign co-signed by the OLD then the NEW key in
     * fixed order; the body protected header names the NEW (go-forward) key. Permitted ONLY for the
     * Identity Rotation object (channel 3, kind 0); a composite leg is rejected fail-closed. Bytes are
     * byte-identical to the Go/Rust/Python/TypeScript/Ruby/PHP/C#/Java reference implementations.
     */
    fun signRotationObject(o: Object, oldAlg: Int, oldSeed: ByteArray, newAlg: Int, newSeed: ByteArray): ByteArray {
        if (!isRotationObject(o.channel, o.kind)) {
            throw NaalpException("UnknownKind", "tag-98 permitted only for the Identity Rotation object")
        }
        if (isCompositeAlg(oldAlg) || isCompositeAlg(newAlg)) {
            throw NaalpException("Malformed", "composite-inside-rotation is undecided")
        }
        o.suite = 0L // a rotation object is never composite
        o.id = o.contentId()
        val payload = Cbor.encode(o.bodyMap(true))
        val bodyProt = protectedHeader(newAlg, o.signer, o.profile)
        val oldLeg = Cose.signatureLeg(bodyProt, oldAlg, oldSeed, payload)
        val newLeg = Cose.signatureLeg(bodyProt, newAlg, newSeed, payload)
        return Cose.assembleSignRaw(bodyProt, payload, listOf(oldLeg, newLeg))
    }

    /**
     * Verify a tag-98 Rotation object (§5.2): the same object-body checks as verify(), then EXACTLY
     * two legs in fixed order (old-key then new-key) BOTH verifying. Any missing/wrong/bad old leg is
     * RotationUnauthorized. Permitted ONLY for (channel 3, kind 0).
     */
    fun verifyRotationObject(
        profile: Long,
        oldAlg: Int,
        oldPk: ByteArray,
        newAlg: Int,
        newPk: ByteArray,
        kindValidator: KindValidator?,
        objBytes: ByteArray,
        knownCext: Set<Long> = emptySet(),
    ): Object {
        // Object octet-size bound (§3.4, R7): the tag-98 rotation object is a top-level signed
        // object too, so it is size-checked on raw bytes before any parse.
        if (objBytes.size > MAX_OBJECT_SIZE) {
            throw NaalpException("TooLarge", "object exceeds the maximum octet size (§3.4, R7)")
        }
        val rp = try {
            Cose.parseSignRaw(objBytes)
        } catch (e: NaalpException) {
            throw NaalpException("Malformed", "not a COSE_Sign object")
        }
        val bodyProt = rp.bodyProt
        val payload = rp.payload
        val legs = rp.legs

        val bv = Cbor.decodeBounded(payload, MAX_NESTING_DEPTH.toInt())
        if (bv !is Cbor.M) throw NaalpException("Malformed", "body not a map")

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
        if (!Cbor.contentId(Cbor.encode(Cbor.M(without))).contentEquals(claimed)) {
            throw NaalpException("ContentIdMismatch", "recomputed id differs")
        }

        val o = objectFromMap(bv)
        if (o.channel > 19 || o.effect > 3 || o.profile < 1 || o.profile > 3) {
            throw NaalpException("RangeError", "field out of range")
        }

        val h = parseProtected(bodyProt)
        if (h.version != NAALP_VERSION) throw NaalpException("UnsupportedVersion", "bad naalp-version")
        if (!h.signer.contentEquals(o.signer) || h.profile != o.profile) {
            throw NaalpException("HeaderBodyMismatch", "protected header disagrees with body")
        }
        checkCriticalExtensions(o.cext, knownCext)

        // tag-98 is permitted ONLY for the Identity-channel Rotation object (channel 3, kind 0).
        if (!isRotationObject(o.channel, o.kind)) {
            throw NaalpException("UnknownKind", "tag-98 permitted only for the Identity Rotation object")
        }
        if (kindValidator == null || !kindValidator.accepts(o.channel, o.kind)) {
            throw NaalpException("UnknownKind", "kind/channel not a registered surface")
        }
        if (isCompositeAlg(h.alg)) throw NaalpException("Malformed", "composite-inside-rotation is undecided")
        if (h.alg != newAlg) throw NaalpException("KeyAlgMismatch", "body header alg is not the new key alg")

        // EXACTLY two legs, fixed order (old, new). A missing/lone leg IS "old leg dropped".
        if (legs.size != 2) throw NaalpException("RotationUnauthorized", "rotation must carry exactly two legs")
        val oldLegAlg = Cose.algFromProtected(legs[0][0])
        val newLegAlg = Cose.algFromProtected(legs[1][0])
        if (isCompositeAlg(oldLegAlg) || isCompositeAlg(newLegAlg)) {
            throw NaalpException("Malformed", "composite leg in a rotation")
        }
        if (oldLegAlg != oldAlg || newLegAlg != newAlg) {
            throw NaalpException("RotationUnauthorized", "legs not in (old, new) order")
        }

        // profile floor: the NEW (go-forward) leg always; the OLD leg iff the fail-closed toggle applies.
        val (newLevel, nknown) = Cose.algLevel(newLegAlg)
        if (!nknown) throw NaalpException("UnknownAlg", "unregistered alg")
        if (newLevel < Cose.profileMinLevel(profile)) {
            throw NaalpException("ProfileDowngrade", "new-leg level below the profile minimum")
        }
        if (ROTATION_OLD_LEG_FLOOR_APPLIES) {
            val (oldLevel, oknown) = Cose.algLevel(oldLegAlg)
            if (!oknown) throw NaalpException("UnknownAlg", "unregistered alg")
            if (oldLevel < Cose.profileMinLevel(profile)) {
                throw NaalpException("ProfileDowngrade", "old-leg level below the profile minimum")
            }
        }

        // both legs MUST verify over their per-signer ToBeSigned.
        val oldTbs = Cose.signatureToBeSigned(bodyProt, oldLegAlg, payload)
        if (!Cose.coseVerify1Raw(oldLegAlg, oldPk, oldTbs, legs[0][1])) {
            throw NaalpException("RotationUnauthorized", "old leg does not verify")
        }
        val newTbs = Cose.signatureToBeSigned(bodyProt, newLegAlg, payload)
        if (!Cose.coseVerify1Raw(newLegAlg, newPk, newTbs, legs[1][1])) {
            throw NaalpException("RotationUnauthorized", "new leg does not verify")
        }
        return o
    }

    // --- NA-IETF-1 producing-boundary disclosure (OPTIONAL, self-asserted ext key 15, §2.5.4) ------

    // The ext extension key under which an object OPTIONALLY carries a per-object producing-boundary
    // disclosure (design.md §2.5.4, NA-IETF-1): the trust boundary that emitted the object and whether
    // that boundary OBSERVED the event it describes first-hand or is RELAYING a report of it. It rides
    // the NON-CRITICAL ext map (field 11): a verifier that does not understand it, or that reads a
    // malformed value, IGNORES the entry and the object still verifies (may-ignore). Because ext is
    // part of the signed body/payload, the disclosure is covered by the SIGNER's own COSE_Sign1
    // signature -- a SELF-ASSERTED claim. 15 collides with neither the safety-label ext key 1 (§6.4),
    // the recheck ext/cext key 13 (§2.5.1), nor the signer-counter ext key 14 (§2.5.2). Byte-identical
    // to impl/go, impl/rust and impl/python.
    const val PRODUCING_BOUNDARY_KEY = 15L

    // The producing-boundary kind (§2.5.4): a closed enum naming whether the emitting boundary
    // witnessed the event directly or is relaying a report of it.
    const val PRODUCING_BOUNDARY_OBSERVED = 1L // this boundary witnessed the event directly (first-hand)
    const val PRODUCING_BOUNDARY_REPORTED = 2L // this boundary is relaying a report it did not witness

    // The producing-boundary value sub-map keys (§2.5.4).
    private const val PB_FIELD_BOUNDARY = 1L   // bstr -- the emitting trust boundary (party id)
    private const val PB_FIELD_KIND = 2L       // 1 observed / 2 reported
    private const val PB_FIELD_REPORTING = 3L  // bstr -- report origin; present iff kind == reported

    /**
     * A decoded producing-boundary disclosure ([PRODUCING_BOUNDARY_KEY], §2.5.4). [boundary] is the
     * emitting trust boundary (the same bstr party-id form as [Object.signer]). [kind] is
     * [PRODUCING_BOUNDARY_OBSERVED] or [PRODUCING_BOUNDARY_REPORTED]. [reporting] names the report
     * origin and is non-null ONLY when [kind] is [PRODUCING_BOUNDARY_REPORTED] (an observer relays
     * from no one).
     */
    class ProducingBoundary(val boundary: ByteArray, val kind: Long, val reporting: ByteArray? = null)

    /**
     * Return (disclosure, true) iff [o] carries a WELL-FORMED producing-boundary disclosure in the
     * non-critical ext map (field 11, [PRODUCING_BOUNDARY_KEY]): a non-empty boundary (key 1), a kind
     * (key 2) in {observed, reported}, and a reporting-boundary (key 3) absent unless the kind is
     * reported. A malformed value is IGNORED -- returns (null, false), NEVER throwing (may-ignore). An
     * absent disclosure returns (null, false). An unrecognized sub-key is ignored and does not by
     * itself make an otherwise well-formed value malformed.
     */
    fun producingBoundary(o: Object): kotlin.Pair<ProducingBoundary?, Boolean> {
        val ext = o.ext ?: return kotlin.Pair(null, false)
        var value: Cbor.Value? = null
        for (p in ext.pairs) {
            val k = p.k
            if (k is Cbor.U && k.v == PRODUCING_BOUNDARY_KEY) {
                value = p.v
                break
            }
        }
        val sub = value as? Cbor.M ?: return kotlin.Pair(null, false)
        var boundary: ByteArray? = null
        var kind: Long? = null
        var reporting: ByteArray? = null
        var haveReporting = false
        for (p in sub.pairs) {
            val k = p.k as? Cbor.U ?: return kotlin.Pair(null, false)
            when (k.v) {
                PB_FIELD_BOUNDARY -> {
                    val b = p.v as? Cbor.B ?: return kotlin.Pair(null, false)
                    boundary = b.v
                }
                PB_FIELD_KIND -> {
                    val u = p.v as? Cbor.U ?: return kotlin.Pair(null, false)
                    kind = u.v
                }
                PB_FIELD_REPORTING -> {
                    val b = p.v as? Cbor.B ?: return kotlin.Pair(null, false)
                    reporting = b.v
                    haveReporting = true
                }
                // else: an unrecognized sub-key -- may-ignore. It does not surface a disclosure of its
                // own and does not invalidate a well-formed {boundary, kind, reporting?} core.
            }
        }
        // well-formedness (§2.5.4). Any failure returns (null, false) (may-ignore), never an error.
        if (boundary == null || boundary.isEmpty()) return kotlin.Pair(null, false) // no boundary named
        if (kind != PRODUCING_BOUNDARY_OBSERVED && kind != PRODUCING_BOUNDARY_REPORTED) {
            return kotlin.Pair(null, false) // absent or out-of-enum kind
        }
        if (haveReporting && kind != PRODUCING_BOUNDARY_REPORTED) {
            return kotlin.Pair(null, false) // a reporting-boundary under observed: an observer relays from no one
        }
        return kotlin.Pair(ProducingBoundary(boundary, kind, if (haveReporting) reporting else null), true)
    }

    /**
     * Name [pb] as [o]'s producing-boundary disclosure in the NON-CRITICAL ext map (field 11), covered
     * by the signer's COSE_Sign1 signature. Creates the ext carrier if absent and leaves any other
     * extension entries intact. The reporting-boundary is emitted ONLY when non-null AND the kind is
     * reported, so a caller cannot accidentally emit a malformed observed-with-reporting disclosure (an
     * observer relays from no one). Sub-map keys are appended in ascending order; encode emits
     * canonical CBOR regardless, so the object stays deterministic.
     */
    fun setProducingBoundary(o: Object, pb: ProducingBoundary) {
        val sub = ArrayList<Cbor.Pair>(3)
        sub.add(Cbor.Pair(Cbor.U(PB_FIELD_BOUNDARY), Cbor.B(pb.boundary)))
        sub.add(Cbor.Pair(Cbor.U(PB_FIELD_KIND), Cbor.U(pb.kind)))
        if (pb.reporting != null && pb.kind == PRODUCING_BOUNDARY_REPORTED) {
            sub.add(Cbor.Pair(Cbor.U(PB_FIELD_REPORTING), Cbor.B(pb.reporting)))
        }
        val entry = Cbor.Pair(Cbor.U(PRODUCING_BOUNDARY_KEY), Cbor.M(sub))
        val existing = o.ext
        if (existing == null) {
            o.ext = Cbor.M(listOf(entry))
            return
        }
        val newPairs = ArrayList<Cbor.Pair>(existing.pairs.size + 1)
        var replaced = false
        for (p in existing.pairs) {
            val k = p.k
            if (k is Cbor.U && k.v == PRODUCING_BOUNDARY_KEY) {
                newPairs.add(entry)
                replaced = true
            } else {
                newPairs.add(p)
            }
        }
        if (!replaced) newPairs.add(entry)
        o.ext = Cbor.M(newPairs)
    }

    // --- T1.3 recheck (the checkable-minimum field, NAALP-REQ-110/111, §2.5.1) -----------------------

    // The ext/cext extension key under which an object NAMES the re-check procedure for the claim in
    // its body (§2.5, NAALP-REQ-111(c) -- the "checkable minimum"). The value is a procedure id into
    // the CLOSED registry below. In the non-critical ext map (field 11) it is may-ignore; in the
    // critical cext map (field 12) it is must-understand and an unknown procedure id is rejected
    // fail-closed (UnknownCriticalExt), the same C3 critical-extension rule reaching the procedure it
    // names. 13 does not collide with the safety-label ext key 1 (§6.4). Byte-identical to impl/go,
    // impl/rust, impl/python.
    const val RECHECK_KEY = 13L

    // The closed re-check procedure registry (§2.5; T1.3); mirrors the spec recheck-procedure
    // production and vectors/registry/recheck.csv.
    const val RECHECK_RECOMPUTE_CONTENT_ID = 1L // recompute the content id from the body and compare (§2.3)
    const val RECHECK_VERIFY_COSE_SIGN1 = 2L    // verify the COSE_Sign1 signature under the signer key (§4)
    const val RECHECK_WALK_CAUSES = 3L          // walk the signed causal partial order offline (§8.2)
    const val RECHECK_REPLAY_CONSUME_CHECK = 4L // replay the single-use consume ledger for the approval (§7.2)

    /** True iff [id] is a recognized re-check procedure. The registry is CLOSED: an id outside it is
     *  unknown, and an unknown id under the critical map is rejected (§2.5). */
    fun isKnownRecheckProcedure(id: Long): Boolean =
        id in RECHECK_RECOMPUTE_CONTENT_ID..RECHECK_REPLAY_CONSUME_CHECK

    /**
     * The critical-extension gate (§2.5): every [cext] entry rejects UnknownCriticalExt unless it is
     * recognized. [RECHECK_KEY] is an envelope-recognized critical key: a critical recheck naming an
     * UNKNOWN procedure id is rejected fail-closed (the critical-extension rule reaching the
     * procedure it names, T1.3); a known procedure id is recognized. Any other key defers to the
     * caller's [knownCext] set. Shared by [verify] and [verifyRotationObject] so the two paths never
     * drift (mirrors impl/go's decodeAndCheck, which both the tag-18 verify and the tag-98 rotation
     * path call).
     */
    private fun checkCriticalExtensions(cext: Cbor.M?, knownCext: Set<Long>) {
        cext ?: return
        for (p in cext.pairs) {
            val k = p.k
            if (k !is Cbor.U) throw NaalpException("UnknownCriticalExt", "unrecognized critical extension")
            if (k.v == RECHECK_KEY) {
                val v = p.v
                if (v !is Cbor.U) throw NaalpException("Malformed", "recheck value not a uint")
                if (!isKnownRecheckProcedure(v.v)) {
                    throw NaalpException("UnknownCriticalExt", "unrecognized critical extension")
                }
                continue
            }
            if (k.v !in knownCext) throw NaalpException("UnknownCriticalExt", "unrecognized critical extension")
        }
    }

    /** The uint value under [key] in a CBOR ext/cext map, or null when the key is absent OR its value
     *  is not a uint (mirrors impl/go envelope.cextGetUint). A null [m] (no carrier) always misses. */
    private fun extUint(m: Cbor.M?, key: Long): Long? {
        if (m == null) return null
        for (p in m.pairs) {
            val k = p.k
            if (k is Cbor.U && k.v == key) {
                val v = p.v
                return if (v is Cbor.U) v.v else null
            }
        }
        return null
    }

    /** Insert-or-replace [entry] (keyed by [key]) into [existing], returning a NEW map (Cbor.M's
     *  pairs list is immutable); creates a fresh single-entry map when [existing] is null. Leaves
     *  every other entry intact -- the shared setter primitive behind [setRecheck] and
     *  [setSignerCounter]. */
    private fun upsertExt(existing: Cbor.M?, key: Long, entry: Cbor.Pair): Cbor.M {
        if (existing == null) return Cbor.M(listOf(entry))
        val newPairs = ArrayList<Cbor.Pair>(existing.pairs.size + 1)
        var replaced = false
        for (p in existing.pairs) {
            val k = p.k
            if (k is Cbor.U && k.v == key) {
                newPairs.add(entry)
                replaced = true
            } else {
                newPairs.add(p)
            }
        }
        if (!replaced) newPairs.add(entry)
        return Cbor.M(newPairs)
    }

    /**
     * Return (id, present, critical) for the re-check procedure [o] names ([RECHECK_KEY], §2.5):
     * present is true when a procedure is named, and critical is true iff it is named in the cext map
     * (field 12, must-understand) rather than the ext map (field 11, may-ignore). cext takes
     * precedence when both carry the key. When no procedure is named the claim is attributable-only
     * (NAALP-REQ-111).
     */
    fun recheck(o: Object): Triple<Long, Boolean, Boolean> {
        val cv = extUint(o.cext, RECHECK_KEY)
        if (cv != null) return Triple(cv, true, true)
        val ev = extUint(o.ext, RECHECK_KEY)
        if (ev != null) return Triple(ev, true, false)
        return Triple(0L, false, false)
    }

    /**
     * Name [procId] as [o]'s re-check procedure. [critical] places it in the cext map (field 12,
     * must-understand); otherwise the ext map (field 11, may-ignore). Creates the carrier if absent
     * and leaves any other extension entries intact.
     */
    fun setRecheck(o: Object, procId: Long, critical: Boolean) {
        val entry = Cbor.Pair(Cbor.U(RECHECK_KEY), Cbor.U(procId))
        if (critical) {
            o.cext = upsertExt(o.cext, RECHECK_KEY, entry)
        } else {
            o.ext = upsertExt(o.ext, RECHECK_KEY, entry)
        }
    }

    // --- T1.6 per-signer forward-only counter + duplication detection (NAALP-REQ-120, §2.5.2) -------

    // The ext extension key under which an object OPTIONALLY carries a forward-only per-signer counter
    // (§2.5.2, NAALP-REQ-120). The value is a forward-only position (a uint) the signer increments on
    // each object. It lives in the NON-CRITICAL ext map (field 11): a verifier that does not perform
    // duplication-detection ignores it and the object still verifies (may-ignore). Because ext (field
    // 11) is part of the signed body/payload, the counter is covered by the SIGNER's own COSE_Sign1
    // signature -- the deliberate contrast with the T1.5 consume-receipt position, which is signed by
    // the LEDGER key. 14 does not collide with the safety-label ext key 1 (§6.4) or the recheck
    // ext/cext key 13 (T1.3). Byte-identical to impl/go, impl/rust, impl/python.
    //
    // The counter is DETECTION, not prevention (NAALP-REQ-120; # Security Considerations): a single
    // self-authored sequence proves nothing. It is a NON-CRITICAL field only -- placing it in the
    // critical cext map (field 12) is an unrecognized critical extension and is rejected fail-closed
    // (UnknownCriticalExt), because a detection aid is never a must-understand verification gate.
    const val SIGNER_COUNTER_KEY = 14L

    /**
     * Return (seq, present) for the forward-only per-signer position [o] names ([SIGNER_COUNTER_KEY],
     * §2.5.2): present is true iff a counter is named in the non-critical ext map (field 11) as a
     * uint. The field is OPTIONAL -- absent (present == false) is valid. present is keyed on the KEY
     * being present, not on the value: a present counter of value 0 returns (0, true).
     */
    fun signerCounter(o: Object): kotlin.Pair<Long, Boolean> {
        val v = extUint(o.ext, SIGNER_COUNTER_KEY)
        return if (v != null) kotlin.Pair(v, true) else kotlin.Pair(0L, false)
    }

    /**
     * Name [seq] as [o]'s forward-only per-signer position in the NON-CRITICAL ext map (field 11),
     * covered by the signer's COSE_Sign1 signature. Creates the ext carrier if absent and leaves any
     * other extension entries intact. The counter is deliberately never placed in the critical cext
     * map (it is detection, not a verification gate).
     */
    fun setSignerCounter(o: Object, seq: Long) {
        val entry = Cbor.Pair(Cbor.U(SIGNER_COUNTER_KEY), Cbor.U(seq))
        o.ext = upsertExt(o.ext, SIGNER_COUNTER_KEY, entry)
    }

    /**
     * One detected per-signer counter conflict: two or more DISTINCT objects (distinct content ids)
     * from the SAME signer id that carry the SAME forward-only counter value. A forward-only counter
     * binds each value to at most one object, so a value bound to >= 2 distinct objects is the
     * observable fingerprint of the key incrementing in two places (key duplication). [ids] surfaces
     * BOTH sides of the contradiction (ascending by bytes) -- never a single flag with the evidence
     * hidden.
     */
    class DuplicationFinding(val signer: ByteArray, val counter: Long, val ids: List<ByteArray>)

    /**
     * Scan a SET of PRESENTED [objs] for per-signer counter reuse. This is the whole point of the
     * field, and it is DETECTION, not prevention (NAALP-REQ-120): it flags a signer id ONLY when two
     * conflicting sequences from that signer physically MEET in the presented set -- a counter value
     * bound to >= 2 distinct content ids by one signer. Given only ONE object per value (one sequence)
     * it returns no findings; the second conflicting object must be present, unsuppressed, for the
     * duplication to become provable. Objects with no counter do not participate. Output is
     * deterministic (findings ordered by signer id then counter; ids within a finding ascending).
     *
     * Operates over the SET, never per object: a per-object boolean could never express "these two
     * distinct objects reuse one position," and a single self-authored counter proves nothing on its
     * own.
     */
    fun detectSignerDuplication(objs: List<Object>): List<DuplicationFinding> {
        // signer-hex -> counter -> (content-id-hex -> content-id-bytes): a set that de-dups a
        // byte-identical re-presentation (one content id twice) so it is NOT a conflict. Hex keys give
        // ByteArray content-equality/order for free (Hex.encode is fixed 2-hex-chars-per-byte, so
        // lexicographic hex-string order == unsigned byte order).
        val groups = LinkedHashMap<String, LinkedHashMap<Long, LinkedHashMap<String, ByteArray>>>()
        val signerBytes = HashMap<String, ByteArray>()
        for (o in objs) {
            val (seq, present) = signerCounter(o)
            if (!present) continue // a counter-less object does not participate in detection
            val id = try {
                o.contentId()
            } catch (e: NaalpException) {
                continue // a body that cannot be canonically encoded cannot be a presented object
            }
            val sk = Hex.encode(o.signer)
            signerBytes[sk] = o.signer
            val byCounter = groups.getOrPut(sk) { LinkedHashMap() }
            val idset = byCounter.getOrPut(seq) { LinkedHashMap() }
            idset[Hex.encode(id)] = id
        }

        val findings = ArrayList<DuplicationFinding>()
        for (sk in groups.keys.sorted()) {
            val byCounter = groups.getValue(sk)
            val counters = byCounter.keys.sortedWith { a, b -> java.lang.Long.compareUnsigned(a, b) }
            for (c in counters) {
                val idset = byCounter.getValue(c)
                // A (signer, counter) that binds two-or-more DISTINCT content ids is a detected
                // duplication. The >= 2 requirement is the detection-requires-both invariant: relax
                // it to >= 1 and a single sequence would flag (prevention theatre) -- the mutation the
                // "one sequence alone -> not flagged" test is built to catch.
                if (idset.size < 2) continue
                val ids = idset.values.sortedWith { a, b -> Cbor.compareBytes(a, b) }
                findings.add(DuplicationFinding(signerBytes.getValue(sk), c, ids))
            }
        }
        return findings
    }
}
