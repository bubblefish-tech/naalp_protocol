// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

/**
 * Manufacturing Add-ons Component F, the physical-hazard authorization extension (design.md
 * addendum; requirements F1-F5; wire authority `spec/naalp-draft-01.cddl`), Kotlin port of
 * impl/rust/naalp-hazard/src/lib.rs
 * (mirroring impl/csharp/Hazard.cs).
 *
 * `effect` (Envelope field 7, [Policy]) describes DATA reversibility. `hazard` is a new,
 * ORTHOGONAL dimension describing PHYSICAL danger: a data-reversible action may still be a high
 * physical hazard. The two dimensions are never merged and neither derives the other.
 *
 * This module adds no new cryptography and no new CBOR codec of its own: every encode call
 * delegates to [Cbor.encode] / [Cbor.contentId], exactly as the Rust reference crate adds no
 * crypto/encoding of its own over the graded `naalp` core.
 *
 * The fail-closed rules (F2, F3):
 *  - [HazardClass.fromCode] is the ONE fail-closed decode entry point: any missing or
 *    out-of-range raw value normalizes to [HazardClass.MOTION_IN_SHARED_SPACE] -- the highest
 *    class -- never to "absent" or any weaker class.
 *  - [hazardAuthorized] requires an EXACT class match (not a `<=` ceiling the way the effect
 *    lattice's [Policy.authorizes] works) AND full containment of the claim's envelope inside
 *    the grant's on every axis, the speed bound, and the time window. Any single failing
 *    dimension denies the WHOLE claim -- there is no partial authorization.
 *  - [hazardAuthorizedOptional] additionally covers the case where an action carries NO hazard
 *    claim at all: there is no envelope to check containment against, so it denies immediately
 *    with a distinct error (HazardUnknown) rather than fabricating a sentinel envelope and
 *    running the ordinary coverage check.
 */
object Hazard {

    // ---- hazard-class (F2: closed, fail-closed to the highest class) ------------------------------

    /** The closed five-value hazard-class vocabulary (`spec/naalp-draft-01.cddl`).
     *  [MOTION_IN_SHARED_SPACE] is BOTH a named class (4) and the fail-closed default for an
     *  unrecognized or absent raw value (F2) -- the assumption that "the producer did not tell
     *  us" is at least as dangerous as the worst named class. */
    enum class HazardClass(val code: Long) {
        NONE(0), TOOL_ACTUATION(1), THERMAL(2), ENERGY_RELEASE(3), MOTION_IN_SHARED_SPACE(4);

        fun toValue(): Cbor.Value = Cbor.U(code)

        companion object {
            /** Fail-closed decode (F2). `null` (the raw value was absent) or any value outside
             *  0..=4 (unrecognized) normalizes to [MOTION_IN_SHARED_SPACE] -- never to a weaker
             *  class, and never a decode failure (there is no "invalid hazard" outcome; there is
             *  only "the worst case we must assume"). [code] carries an arbitrary-magnitude
             *  unsigned wire value as its bit pattern (the same convention Envelope's
             *  signer-counter uses for a u64-typed field), so a malformed wire value outside even
             *  a byte range still normalizes correctly rather than throwing. */
            fun fromCode(code: Long?): HazardClass {
                return when (code) {
                    0L -> NONE
                    1L -> TOOL_ACTUATION
                    2L -> THERMAL
                    3L -> ENERGY_RELEASE
                    4L -> MOTION_IN_SHARED_SPACE
                    else -> MOTION_IN_SHARED_SPACE // F2: unknown/absent -> highest class
                }
            }
        }
    }

    private fun intValue(v: Long): Cbor.Value = if (v >= 0) Cbor.U(v) else Cbor.N(v)

    private fun intFromValue(v: Cbor.Value): Long = when (v) {
        is Cbor.U -> v.v
        is Cbor.N -> v.v
        else -> throw malformedError()
    }

    // ---- spatial-bounds ---------------------------------------------------------------------------

    /** A named coordinate frame plus a signed axis-aligned bounding region in that frame, integer
     *  millimeters (`spec/naalp-draft-01.cddl` `spatial-bounds`). */
    class SpatialBounds(val frame: String, val axes: List<Pair<Long, Long>>) {

        /** Structural validity (`spec/naalp-draft-01.cddl`): non-empty axes, every min <= max,
         *  frame non-empty and Unicode NFC. */
        fun isWellFormed(): Boolean {
            if (axes.isEmpty()) return false
            if (axes.any { (min, max) -> min > max }) return false
            if (frame.isEmpty()) return false
            return try {
                Identity.requireNfc(frame)
                true
            } catch (e: NaalpException) {
                false
            }
        }

        fun toValue(): Cbor.Value {
            val axesVal = axes.map { (min, max) -> Cbor.A(listOf(Hazard.intValue(min), Hazard.intValue(max))) }
            return Cbor.M(listOf(
                Cbor.Pair(Cbor.U(1), Cbor.T(frame)),
                Cbor.Pair(Cbor.U(2), Cbor.A(axesVal)),
            ))
        }

        /** Deterministic-CBOR encoding of {1:frame,2:axes}. Malformed input still encodes
         *  (encoding is not the validity gate); callers MUST check [isWellFormed] before treating
         *  a [SpatialBounds] as authoritative, exactly as [fromValue] does on decode. */
        fun bytes(): ByteArray = Cbor.encode(toValue())

        companion object {
            /** Parse a `spatial-bounds` map. Rejects a non-map, an out-of-range/wrong-typed key
             *  or value, a missing key, empty axes, an axis with min > max, or a non-NFC/empty
             *  frame -- fail-closed (HazardMalformed), never a partially-valid result. */
            fun fromValue(v: Cbor.Value): SpatialBounds {
                if (v !is Cbor.M) throw Hazard.malformedError()
                var frame: String? = null
                var axes: List<Pair<Long, Long>>? = null
                for (p in v.pairs) {
                    val k = p.k as? Cbor.U ?: throw Hazard.malformedError()
                    when (k.v) {
                        1L -> {
                            val t = p.v as? Cbor.T ?: throw Hazard.malformedError()
                            frame = t.v
                        }
                        2L -> {
                            val a = p.v as? Cbor.A ?: throw Hazard.malformedError()
                            if (a.items.isEmpty()) throw Hazard.malformedError()
                            val out = ArrayList<Pair<Long, Long>>(a.items.size)
                            for (item in a.items) {
                                val pr = item as? Cbor.A ?: throw Hazard.malformedError()
                                if (pr.items.size != 2) throw Hazard.malformedError()
                                val min = Hazard.intFromValue(pr.items[0])
                                val max = Hazard.intFromValue(pr.items[1])
                                if (min > max) throw Hazard.malformedError()
                                out.add(min to max)
                            }
                            axes = out
                        }
                        else -> throw Hazard.malformedError()
                    }
                }
                if (frame == null || axes == null) throw Hazard.malformedError()
                val sb = SpatialBounds(frame, axes)
                if (!sb.isWellFormed()) throw Hazard.malformedError()
                return sb
            }
        }
    }

    /** Full containment (F3): same frame id (a bound in one frame says nothing about a bound in a
     *  different, unrelated frame), the SAME axis count in the SAME order, and every claim axis's
     *  [min,max] a subset of the matching grant axis's [min,max]. */
    fun spatialContained(claim: SpatialBounds, grant: SpatialBounds): Boolean {
        if (claim.frame != grant.frame) return false
        if (claim.axes.size != grant.axes.size) return false
        for (i in claim.axes.indices) {
            val (cmin, cmax) = claim.axes[i]
            val (gmin, gmax) = grant.axes[i]
            if (!(cmin >= gmin && cmax <= gmax)) return false
        }
        return true
    }

    // ---- hazard-window ------------------------------------------------------------------------------

    /** A validity window, epoch ms, the same convention as `naalp-object` field 6 (created) and
     *  `naalp-delegation-grant` fields 4/5. */
    class HazardWindow(val notBefore: Long, val notAfter: Long) {
        fun toValue(): Cbor.Value = Cbor.M(listOf(
            Cbor.Pair(Cbor.U(1), Cbor.U(notBefore)),
            Cbor.Pair(Cbor.U(2), Cbor.U(notAfter)),
        ))

        companion object {
            fun fromValue(v: Cbor.Value): HazardWindow {
                if (v !is Cbor.M) throw Hazard.malformedError()
                var notBefore: Long? = null
                var notAfter: Long? = null
                for (p in v.pairs) {
                    val k = p.k as? Cbor.U ?: throw Hazard.malformedError()
                    val vu = p.v as? Cbor.U ?: throw Hazard.malformedError()
                    when (k.v) {
                        1L -> notBefore = vu.v
                        2L -> notAfter = vu.v
                        else -> throw Hazard.malformedError()
                    }
                }
                if (notBefore == null || notAfter == null) throw Hazard.malformedError()
                return HazardWindow(notBefore, notAfter)
            }
        }
    }

    // ---- hazard-envelope -----------------------------------------------------------------------------

    /** The full physical envelope a claim or an authorization bounds itself by. All three fields
     *  are MANDATORY on the wire (`spec/naalp-draft-01.cddl`) -- a silently-absent axis would be
     *  fail-OPEN in a physical-safety context, so an issuer that means "unbounded" states so
     *  explicitly with wide numeric bounds; the wire never infers permissiveness from silence
     *  here (deliberate contrast with `naalp-delegation-grant`'s optional scope). */
    class HazardEnvelope(val spatial: SpatialBounds, val speedBoundMmS: Long, val window: HazardWindow) {
        fun toValue(): Cbor.Value = Cbor.M(listOf(
            Cbor.Pair(Cbor.U(1), spatial.toValue()),
            Cbor.Pair(Cbor.U(2), Cbor.U(speedBoundMmS)),
            Cbor.Pair(Cbor.U(3), window.toValue()),
        ))

        /** Deterministic-CBOR encoding of {1:spatial,2:speed_bound,3:window}. */
        fun bytes(): ByteArray = Cbor.encode(toValue())

        /** The envelope's content id (T1 framing): a pure function of the bytes above. */
        fun contentId(): ByteArray = Cbor.contentId(bytes())

        companion object {
            /** Parse a `hazard-envelope` map; fail-closed on any missing/malformed field. */
            fun fromValue(v: Cbor.Value): HazardEnvelope {
                if (v !is Cbor.M) throw Hazard.malformedError()
                var spatial: SpatialBounds? = null
                var speed: Long? = null
                var window: HazardWindow? = null
                for (p in v.pairs) {
                    val k = p.k as? Cbor.U ?: throw Hazard.malformedError()
                    when (k.v) {
                        1L -> spatial = SpatialBounds.fromValue(p.v)
                        2L -> {
                            val su = p.v as? Cbor.U ?: throw Hazard.malformedError()
                            speed = su.v
                        }
                        3L -> window = HazardWindow.fromValue(p.v)
                        else -> throw Hazard.malformedError()
                    }
                }
                if (spatial == null || speed == null || window == null) throw Hazard.malformedError()
                return HazardEnvelope(spatial, speed, window)
            }
        }
    }

    /** Full containment (F3): [spatialContained] AND `claim.speedBoundMmS <= grant.speedBoundMmS`
     *  AND the claim's window is a sub-interval of the grant's (`grant.notBefore <=
     *  claim.notBefore` and `claim.notAfter <= grant.notAfter`). */
    fun envelopeContained(claim: HazardEnvelope, grant: HazardEnvelope): Boolean {
        return spatialContained(claim.spatial, grant.spatial) &&
            claim.speedBoundMmS <= grant.speedBoundMmS &&
            grant.window.notBefore <= claim.window.notBefore &&
            claim.window.notAfter <= grant.window.notAfter
    }

    // ---- naalp-hazard-claim / naalp-hazard-authorization ---------------------------------------------

    /** A signed physical-hazard claim (`spec/naalp-draft-01.cddl` `naalp-hazard-claim`). Carriage
     *  (the object it accompanies and how) is a wire-impact decision, not this module's concern. */
    class HazardClaim(val hazardClass: HazardClass, val envelope: HazardEnvelope) {
        fun toValue(): Cbor.Value = Hazard.hazardBodyToValue(hazardClass, envelope)

        /** Deterministic-CBOR encoding of {1:class,2:envelope}. */
        fun bytes(): ByteArray = Cbor.encode(toValue())

        /** The claim's content id (T1 framing). */
        fun contentId(): ByteArray = Cbor.contentId(bytes())

        companion object {
            /** Parse a `naalp-hazard-claim` body. Both class and envelope are mandatory -- a
             *  claim declaring one and omitting the other is HazardMalformed, not partially
             *  valid. */
            fun fromValue(v: Cbor.Value): HazardClaim {
                val (cls, env) = Hazard.hazardBodyFromValue(v)
                return HazardClaim(cls, env)
            }
        }
    }

    /** A signed physical-hazard authorization ("a grant" in requirements F3's language;
     *  `spec/naalp-draft-01.cddl` `naalp-hazard-authorization`). Same shape as [HazardClaim]
     *  deliberately: one envelope shape for both sides keeps the containment check symmetric. */
    class HazardAuthorization(val hazardClass: HazardClass, val envelope: HazardEnvelope) {
        fun toValue(): Cbor.Value = Hazard.hazardBodyToValue(hazardClass, envelope)

        /** Deterministic-CBOR encoding of {1:class,2:envelope}. */
        fun bytes(): ByteArray = Cbor.encode(toValue())

        /** The authorization's content id (T1 framing). */
        fun contentId(): ByteArray = Cbor.contentId(bytes())

        companion object {
            /** Parse a `naalp-hazard-authorization` body. */
            fun fromValue(v: Cbor.Value): HazardAuthorization {
                val (cls, env) = Hazard.hazardBodyFromValue(v)
                return HazardAuthorization(cls, env)
            }
        }
    }

    private fun hazardBodyToValue(cls: HazardClass, envelope: HazardEnvelope): Cbor.Value = Cbor.M(listOf(
        Cbor.Pair(Cbor.U(1), cls.toValue()),
        Cbor.Pair(Cbor.U(2), envelope.toValue()),
    ))

    private fun hazardBodyFromValue(v: Cbor.Value): Pair<HazardClass, HazardEnvelope> {
        if (v !is Cbor.M) throw malformedError()
        var classCode: Long? = null
        var envelope: HazardEnvelope? = null
        for (p in v.pairs) {
            val k = p.k as? Cbor.U ?: throw malformedError()
            when (k.v) {
                1L -> {
                    // An out-of-range class ON THE WIRE (not merely "absent") is a malformed
                    // body, not a normalize-to-4 input: F2's fail-closed normalization is for the
                    // DECODE step that produces a class from a less-structured source (see
                    // HazardClass.fromCode), not for a CDDL-invalid hazard-class value already
                    // claiming to be well-formed.
                    val cu = p.v as? Cbor.U ?: throw malformedError()
                    if (cu.v < 0 || cu.v > 4) throw malformedError()
                    classCode = cu.v
                }
                2L -> envelope = HazardEnvelope.fromValue(p.v)
                else -> throw malformedError()
            }
        }
        if (classCode == null || envelope == null) throw malformedError()
        return HazardClass.fromCode(classCode) to envelope
    }

    // ---- F3: grant-coverage authorization -------------------------------------------------------------

    /** Authorize a well-formed, present claim against an authorization (F3): EXACT class match
     *  (not a `<=` ceiling -- see the module doc) AND [envelopeContained]. Any single failing
     *  dimension denies the WHOLE claim (HazardNotCovered) -- there is no partial authorization
     *  and no fail-open branch. */
    fun hazardAuthorized(claim: HazardClaim, grant: HazardAuthorization) {
        if (claim.hazardClass != grant.hazardClass) throw notCoveredError()
        if (!envelopeContained(claim.envelope, grant.envelope)) throw notCoveredError()
    }

    /** Authorize an OPTIONAL claim (F2's "absent" case at the object level, distinct from a
     *  present-but-unrecognized class byte inside a claim). `null` -- no hazard-claim object
     *  exists at all for an action that requires one -- denies immediately (HazardUnknown)
     *  rather than fabricating a sentinel envelope and running the ordinary coverage check: there
     *  is no envelope to check containment against, so the honest outcome is a distinct error,
     *  not a coverage denial that implies an envelope was compared. */
    fun hazardAuthorizedOptional(claim: HazardClaim?, grant: HazardAuthorization) {
        if (claim == null) throw unknownError()
        hazardAuthorized(claim, grant)
    }

    // ---- errors -----------------------------------------------------------------------------------------

    /** (HazardMalformed) a hazard-claim/hazard-authorization/envelope body is not the CDDL shape
     *  (`spec/naalp-draft-01.cddl`), a spatial-bounds axis has min > max, axes is empty, or frame
     *  is not Unicode NFC. */
    fun malformedError(): NaalpException =
        NaalpException("HazardMalformed", "hazard body is not the spec/naalp-draft-01.cddl shape, or an axis/frame is invalid")

    /** (HazardNotCovered) a well-formed claim's class or envelope is not fully covered by the
     *  presented authorization. */
    fun notCoveredError(): NaalpException =
        NaalpException("HazardNotCovered", "declared hazard class or envelope is not fully covered by the authorization")

    /** (HazardUnknown) the hazard value for an action requiring one is unrecognized or absent,
     *  and -- for the fully-absent case -- no envelope exists to check coverage against at all. */
    fun unknownError(): NaalpException =
        NaalpException("HazardUnknown", "hazard value unrecognized or absent; no claim to check coverage against")
}
