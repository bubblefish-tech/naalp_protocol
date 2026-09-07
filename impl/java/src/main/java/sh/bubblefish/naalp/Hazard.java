// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.util.ArrayList;
import java.util.List;

/**
 * Manufacturing Add-ons Component F, the physical-hazard authorization extension (design.md
 * addendum; requirements F1-F5; wire authority {@code spec/naalp-draft-01.cddl}), Java port of
 * {@code impl/rust/naalp-hazard/src/lib.rs} (mirroring {@code impl/csharp/Hazard.cs}).
 *
 * <p>{@code effect} (Envelope field 7, {@link Policy}) describes DATA reversibility. {@code hazard}
 * is a new, ORTHOGONAL dimension describing PHYSICAL danger: a data-reversible action may still be a
 * high physical hazard. The two dimensions are never merged and neither derives the other.
 *
 * <p>This module adds no new cryptography and no new CBOR codec of its own: every encode call
 * delegates to {@link Cbor#encode} / {@link Cbor#contentId(byte[])}, exactly as the Rust reference
 * crate adds no crypto/encoding of its own over the graded {@code naalp} core.
 *
 * <p>The fail-closed rules (F2, F3):
 * <ul>
 * <li>{@link #fromCode} is the ONE fail-closed decode entry point: any missing or out-of-range raw
 * value normalizes to {@link HazardClass#MOTION_IN_SHARED_SPACE} — the highest class — never to
 * "absent" or any weaker class.</li>
 * <li>{@link #hazardAuthorized} requires an EXACT class match (not a &lt;= ceiling the way the effect
 * lattice's {@link Policy#authorizes} works) AND full containment of the claim's envelope inside the
 * grant's on every axis, the speed bound, and the time window. Any single failing dimension denies
 * the WHOLE claim — there is no partial authorization.</li>
 * <li>{@link #hazardAuthorizedOptional} additionally covers the case where an action carries NO
 * hazard claim at all: there is no envelope to check containment against, so it denies immediately
 * with a distinct error ({@code HazardUnknown}) rather than fabricating a sentinel envelope and
 * running the ordinary coverage check.</li>
 * </ul>
 */
public final class Hazard {
    private Hazard() {}

    // ---- hazard-class (F2: closed, fail-closed to the highest class) --------------------------

    /** The closed five-value hazard-class vocabulary ({@code spec/naalp-draft-01.cddl}).
     * {@link #MOTION_IN_SHARED_SPACE} is BOTH a named class (4) and the fail-closed default for an
     * unrecognized or absent raw value (F2) — the assumption that "the producer did not tell us" is
     * at least as dangerous as the worst named class. */
    public enum HazardClass {
        NONE(0), TOOL_ACTUATION(1), THERMAL(2), ENERGY_RELEASE(3), MOTION_IN_SHARED_SPACE(4);

        /** The CDDL wire code (0..4). */
        public final long code;

        HazardClass(long code) { this.code = code; }
    }

    /** Fail-closed decode (F2). {@code null} (the raw value was absent) or any value outside 0..4
     * (unrecognized) normalizes to {@link HazardClass#MOTION_IN_SHARED_SPACE} — never to a weaker
     * class, and never a decode failure (there is no "invalid hazard" outcome; there is only "the
     * worst case we must assume"). {@code code} is a nullable boxed {@code long} carrying the raw
     * CBOR-argument bit pattern (unsigned 64-bit magnitude, exactly as {@link Cbor.U#v} does), so a
     * malformed wire value outside even a byte range still normalizes correctly rather than
     * throwing. */
    public static HazardClass fromCode(Long code) {
        if (code != null) {
            long v = code;
            if (v == 0) { return HazardClass.NONE; }
            if (v == 1) { return HazardClass.TOOL_ACTUATION; }
            if (v == 2) { return HazardClass.THERMAL; }
            if (v == 3) { return HazardClass.ENERGY_RELEASE; }
            if (v == 4) { return HazardClass.MOTION_IN_SHARED_SPACE; }
        }
        return HazardClass.MOTION_IN_SHARED_SPACE; // F2: unknown/absent -> highest class
    }

    private static Cbor.Value classToValue(HazardClass c) {
        return new Cbor.U(c.code);
    }

    // ---- spatial-bounds -------------------------------------------------------------------------

    /** One signed axis-aligned bound, {@code (min, max)}, integer millimeters. */
    public static final class Axis {
        public final long min;
        public final long max;
        public Axis(long min, long max) { this.min = min; this.max = max; }
    }

    /** A named coordinate frame plus a signed axis-aligned bounding region in that frame, integer
     * millimeters ({@code spec/naalp-draft-01.cddl} {@code spatial-bounds}). */
    public static final class SpatialBounds {
        public final String frame;
        /** Per-axis (min, max), millimeters, signed. MUST be non-empty; every entry MUST satisfy
         * min &lt;= max. */
        public final List<Axis> axes;

        public SpatialBounds(String frame, List<Axis> axes) {
            this.frame = frame;
            this.axes = axes;
        }

        /** Structural validity ({@code spec/naalp-draft-01.cddl}): non-empty axes, every
         * min &lt;= max, frame non-empty and Unicode NFC. */
        public boolean isWellFormed() {
            if (axes == null || axes.isEmpty()) { return false; }
            for (Axis a : axes) {
                if (a.min > a.max) { return false; }
            }
            if (frame == null || frame.isEmpty()) { return false; }
            try {
                Identity.requireNfc(frame);
            } catch (NaalpException e) {
                return false;
            }
            return true;
        }

        Cbor.Value toValue() {
            List<Cbor.Value> axesVals = new ArrayList<>(axes.size());
            for (Axis a : axes) {
                axesVals.add(new Cbor.A(List.of(intValue(a.min), intValue(a.max))));
            }
            return new Cbor.M(List.of(
                    new Cbor.Pair(new Cbor.U(1), new Cbor.T(frame)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.A(axesVals))));
        }

        /** Deterministic-CBOR encoding of {1:frame,2:axes}. Malformed input still encodes (encoding
         * is not the validity gate); callers MUST check {@link #isWellFormed} before treating a
         * {@link SpatialBounds} as authoritative, exactly as {@link #fromValue} does on decode. */
        public byte[] bytes() { return Cbor.encode(toValue()); }

        /** Parse a {@code spatial-bounds} map. Rejects a non-map, an out-of-range/wrong-typed key or
         * value, a missing key, empty axes, an axis with min &gt; max, or a non-NFC/empty frame —
         * fail-closed (HazardMalformed), never a partially-valid result. */
        public static SpatialBounds fromValue(Cbor.Value v) {
            if (!(v instanceof Cbor.M m)) { throw malformedError(); }
            String frame = null;
            List<Axis> axes = null;
            for (Cbor.Pair p : m.pairs) {
                if (!(p.k instanceof Cbor.U ku)) { throw malformedError(); }
                if (ku.v == 1) {
                    if (!(p.val instanceof Cbor.T t)) { throw malformedError(); }
                    frame = t.v;
                } else if (ku.v == 2) {
                    if (!(p.val instanceof Cbor.A a) || a.items.isEmpty()) { throw malformedError(); }
                    List<Axis> out = new ArrayList<>(a.items.size());
                    for (Cbor.Value it : a.items) {
                        if (!(it instanceof Cbor.A pair) || pair.items.size() != 2) { throw malformedError(); }
                        long min = intFromValue(pair.items.get(0));
                        long max = intFromValue(pair.items.get(1));
                        if (min > max) { throw malformedError(); }
                        out.add(new Axis(min, max));
                    }
                    axes = out;
                } else {
                    throw malformedError();
                }
            }
            if (frame == null || axes == null) { throw malformedError(); }
            SpatialBounds sb = new SpatialBounds(frame, axes);
            if (!sb.isWellFormed()) { throw malformedError(); }
            return sb;
        }
    }

    private static Cbor.Value intValue(long v) {
        return v >= 0 ? new Cbor.U(v) : new Cbor.N(v);
    }

    private static long intFromValue(Cbor.Value v) {
        if (v instanceof Cbor.U u) { return u.v; }
        if (v instanceof Cbor.N n) { return n.v; }
        throw malformedError();
    }

    /** Full containment (F3): same frame id (a bound in one frame says nothing about a bound in a
     * different, unrelated frame), the SAME axis count in the SAME order, and every claim axis's
     * [min,max] a subset of the matching grant axis's [min,max]. */
    public static boolean spatialContained(SpatialBounds claim, SpatialBounds grant) {
        if (!claim.frame.equals(grant.frame)) { return false; }
        if (claim.axes.size() != grant.axes.size()) { return false; }
        for (int i = 0; i < claim.axes.size(); i++) {
            Axis c = claim.axes.get(i);
            Axis g = grant.axes.get(i);
            if (!(c.min >= g.min && c.max <= g.max)) { return false; }
        }
        return true;
    }

    // ---- hazard-window --------------------------------------------------------------------------

    /** A validity window, epoch ms, the same convention as {@code naalp-object} field 6 (created)
     * and {@code naalp-delegation-grant} fields 4/5. */
    public static final class HazardWindow {
        public final long notBefore;
        public final long notAfter;

        public HazardWindow(long notBefore, long notAfter) {
            this.notBefore = notBefore;
            this.notAfter = notAfter;
        }

        Cbor.Value toValue() {
            return new Cbor.M(List.of(
                    new Cbor.Pair(new Cbor.U(1), new Cbor.U(notBefore)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.U(notAfter))));
        }

        static HazardWindow fromValue(Cbor.Value v) {
            if (!(v instanceof Cbor.M m)) { throw malformedError(); }
            Long notBefore = null;
            Long notAfter = null;
            for (Cbor.Pair p : m.pairs) {
                if (!(p.k instanceof Cbor.U ku) || !(p.val instanceof Cbor.U vu)) { throw malformedError(); }
                if (ku.v == 1) { notBefore = vu.v; }
                else if (ku.v == 2) { notAfter = vu.v; }
                else { throw malformedError(); }
            }
            if (notBefore == null || notAfter == null) { throw malformedError(); }
            return new HazardWindow(notBefore, notAfter);
        }
    }

    // ---- hazard-envelope ------------------------------------------------------------------------

    /** The full physical envelope a claim or an authorization bounds itself by. All three fields
     * are MANDATORY on the wire ({@code spec/naalp-draft-01.cddl}) — a silently-absent axis would
     * be fail-OPEN in a physical-safety context, so an issuer that means "unbounded" states so
     * explicitly with wide numeric bounds; the wire never infers permissiveness from silence here
     * (deliberate contrast with {@code naalp-delegation-grant}'s optional scope). */
    public static final class HazardEnvelope {
        public final SpatialBounds spatial;
        /** Max instantaneous speed, millimeters per second. */
        public final long speedBoundMmS;
        public final HazardWindow window;

        public HazardEnvelope(SpatialBounds spatial, long speedBoundMmS, HazardWindow window) {
            this.spatial = spatial;
            this.speedBoundMmS = speedBoundMmS;
            this.window = window;
        }

        Cbor.Value toValue() {
            return new Cbor.M(List.of(
                    new Cbor.Pair(new Cbor.U(1), spatial.toValue()),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.U(speedBoundMmS)),
                    new Cbor.Pair(new Cbor.U(3), window.toValue())));
        }

        /** Deterministic-CBOR encoding of {1:spatial,2:speed_bound,3:window}. */
        public byte[] bytes() { return Cbor.encode(toValue()); }

        /** The envelope's content id (T1 framing): a pure function of the bytes above. */
        public byte[] contentId() { return Cbor.contentId(bytes()); }

        /** Parse a {@code hazard-envelope} map; fail-closed on any missing/malformed field. */
        public static HazardEnvelope fromValue(Cbor.Value v) {
            if (!(v instanceof Cbor.M m)) { throw malformedError(); }
            SpatialBounds spatial = null;
            Long speed = null;
            HazardWindow window = null;
            for (Cbor.Pair p : m.pairs) {
                if (!(p.k instanceof Cbor.U ku)) { throw malformedError(); }
                if (ku.v == 1) {
                    spatial = SpatialBounds.fromValue(p.val);
                } else if (ku.v == 2) {
                    if (!(p.val instanceof Cbor.U su)) { throw malformedError(); }
                    speed = su.v;
                } else if (ku.v == 3) {
                    window = HazardWindow.fromValue(p.val);
                } else {
                    throw malformedError();
                }
            }
            if (spatial == null || speed == null || window == null) { throw malformedError(); }
            return new HazardEnvelope(spatial, speed, window);
        }
    }

    /** Full containment (F3): {@link #spatialContained} AND {@code claim.speedBoundMmS <=
     * grant.speedBoundMmS} AND the claim's window is a sub-interval of the grant's
     * ({@code grant.notBefore <= claim.notBefore} and {@code claim.notAfter <= grant.notAfter}). */
    public static boolean envelopeContained(HazardEnvelope claim, HazardEnvelope grant) {
        return spatialContained(claim.spatial, grant.spatial)
                && claim.speedBoundMmS <= grant.speedBoundMmS
                && grant.window.notBefore <= claim.window.notBefore
                && claim.window.notAfter <= grant.window.notAfter;
    }

    // ---- naalp-hazard-claim / naalp-hazard-authorization -----------------------------------------

    /** A signed physical-hazard claim ({@code spec/naalp-draft-01.cddl} {@code naalp-hazard-claim}).
     * Carriage (the object it accompanies and how) is a wire-impact decision, not this module's
     * concern. */
    public static final class HazardClaim {
        public final HazardClass hazardClass;
        public final HazardEnvelope envelope;

        public HazardClaim(HazardClass hazardClass, HazardEnvelope envelope) {
            this.hazardClass = hazardClass;
            this.envelope = envelope;
        }

        Cbor.Value toValue() { return hazardBodyToValue(hazardClass, envelope); }

        /** Deterministic-CBOR encoding of {1:class,2:envelope}. */
        public byte[] bytes() { return Cbor.encode(toValue()); }

        /** The claim's content id (T1 framing). */
        public byte[] contentId() { return Cbor.contentId(bytes()); }

        /** Parse a {@code naalp-hazard-claim} body. Both class and envelope are mandatory — a claim
         * declaring one and omitting the other is HazardMalformed, not partially valid. */
        public static HazardClaim fromValue(Cbor.Value v) {
            Object[] parts = hazardBodyFromValue(v);
            return new HazardClaim((HazardClass) parts[0], (HazardEnvelope) parts[1]);
        }
    }

    /** A signed physical-hazard authorization ("a grant" in requirements F3's language;
     * {@code spec/naalp-draft-01.cddl} {@code naalp-hazard-authorization}). Same shape as
     * {@link HazardClaim} deliberately: one envelope shape for both sides keeps the containment
     * check symmetric. */
    public static final class HazardAuthorization {
        public final HazardClass hazardClass;
        public final HazardEnvelope envelope;

        public HazardAuthorization(HazardClass hazardClass, HazardEnvelope envelope) {
            this.hazardClass = hazardClass;
            this.envelope = envelope;
        }

        Cbor.Value toValue() { return hazardBodyToValue(hazardClass, envelope); }

        /** Deterministic-CBOR encoding of {1:class,2:envelope}. */
        public byte[] bytes() { return Cbor.encode(toValue()); }

        /** The authorization's content id (T1 framing). */
        public byte[] contentId() { return Cbor.contentId(bytes()); }

        /** Parse a {@code naalp-hazard-authorization} body. */
        public static HazardAuthorization fromValue(Cbor.Value v) {
            Object[] parts = hazardBodyFromValue(v);
            return new HazardAuthorization((HazardClass) parts[0], (HazardEnvelope) parts[1]);
        }
    }

    private static Cbor.Value hazardBodyToValue(HazardClass cls, HazardEnvelope envelope) {
        return new Cbor.M(List.of(
                new Cbor.Pair(new Cbor.U(1), classToValue(cls)),
                new Cbor.Pair(new Cbor.U(2), envelope.toValue())));
    }

    private static Object[] hazardBodyFromValue(Cbor.Value v) {
        if (!(v instanceof Cbor.M m)) { throw malformedError(); }
        Long classCode = null;
        HazardEnvelope envelope = null;
        for (Cbor.Pair p : m.pairs) {
            if (!(p.k instanceof Cbor.U ku)) { throw malformedError(); }
            if (ku.v == 1) {
                // An out-of-range class ON THE WIRE (not merely "absent") is a malformed body, not a
                // normalize-to-4 input: F2's fail-closed normalization is for the DECODE step that
                // produces a class from a less-structured source (see fromCode), not for a
                // CDDL-invalid hazard-class value already claiming to be well-formed.
                if (!(p.val instanceof Cbor.U cu) || cu.v < 0 || cu.v > 4) { throw malformedError(); }
                classCode = cu.v;
            } else if (ku.v == 2) {
                envelope = HazardEnvelope.fromValue(p.val);
            } else {
                throw malformedError();
            }
        }
        if (classCode == null || envelope == null) { throw malformedError(); }
        return new Object[]{fromCode(classCode), envelope};
    }

    // ---- F3: grant-coverage authorization -----------------------------------------------------

    /** Authorize a well-formed, present claim against an authorization (F3): EXACT class match (not
     * a &lt;= ceiling — see the class doc) AND {@link #envelopeContained}. Any single failing
     * dimension denies the WHOLE claim (HazardNotCovered) — there is no partial authorization and no
     * fail-open branch. */
    public static void hazardAuthorized(HazardClaim claim, HazardAuthorization grant) {
        if (claim.hazardClass != grant.hazardClass) { throw notCoveredError(); }
        if (!envelopeContained(claim.envelope, grant.envelope)) { throw notCoveredError(); }
    }

    /** Authorize an OPTIONAL claim (F2's "absent" case at the object level, distinct from a
     * present-but-unrecognized class byte inside a claim). {@code null} — no hazard-claim object
     * exists at all for an action that requires one — denies immediately (HazardUnknown) rather than
     * fabricating a sentinel envelope and running the ordinary coverage check: there is no envelope
     * to check containment against, so the honest outcome is a distinct error, not a coverage denial
     * that implies an envelope was compared. */
    public static void hazardAuthorizedOptional(HazardClaim claim, HazardAuthorization grant) {
        if (claim == null) { throw unknownError(); }
        hazardAuthorized(claim, grant);
    }

    // ---- named, fail-closed errors ---------------------------------------------------------------

    /** (HazardMalformed) a hazard-claim/hazard-authorization/envelope body is not the CDDL shape
     * ({@code spec/naalp-draft-01.cddl}), a spatial-bounds axis has min &gt; max, axes is empty, or
     * frame is not Unicode NFC. */
    public static NaalpException malformedError() {
        return new NaalpException("HazardMalformed",
                "hazard body is not the spec/naalp-draft-01.cddl shape, or an axis/frame is invalid");
    }

    /** (HazardNotCovered) a well-formed claim's class or envelope is not fully covered by the
     * presented authorization. */
    public static NaalpException notCoveredError() {
        return new NaalpException("HazardNotCovered",
                "declared hazard class or envelope is not fully covered by the authorization");
    }

    /** (HazardUnknown) the hazard value for an action requiring one is unrecognized or absent, and
     * — for the fully-absent case — no envelope exists to check coverage against at all. */
    public static NaalpException unknownError() {
        return new NaalpException("HazardUnknown",
                "hazard value unrecognized or absent; no claim to check coverage against");
    }
}
