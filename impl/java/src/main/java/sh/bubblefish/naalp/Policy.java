// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.util.List;

/**
 * N-AALP C5 effect vocabulary and authorization for the Java SDK (§6).
 *
 * <p>The closed four-value effect set aligned 1:1 with the N-PAMP Bridge SafetyLabel; an
 * unrecognized value fails closed to destructive (R-6.2); authorization is the §6.1 lattice
 * (action &lt;= ceiling). The optional signed safety label is a CBOR map {1:risk, 2:scope}.
 */
public final class Policy {
    public static final long READ_ONLY = 0;
    public static final long IDEMPOTENT_WRITE = 1;
    public static final long NON_IDEMPOTENT_WRITE = 2;
    public static final long DESTRUCTIVE = 3;

    private Policy() {}

    /** Map a raw effect value to the closed set; anything outside 0..3 is destructive (R-6.2). */
    public static long normalizeEffect(long v) {
        return (v >= 0 && v <= 3) ? v : DESTRUCTIVE;
    }

    /** The §6.1 lattice: an action is permitted under ceiling iff action &lt;= ceiling. */
    public static boolean authorizes(long ceiling, long action) {
        return action <= ceiling;
    }

    /** The signed safety-label body {1: risk, 2: scope} (R-6.4). */
    public static byte[] safetyLabelBytes(String risk, String scope) {
        return Cbor.encode(new Cbor.M(List.of(
                new Cbor.Pair(new Cbor.U(1), new Cbor.T(risk)),
                new Cbor.Pair(new Cbor.U(2), new Cbor.T(scope)))));
    }

    /** Where a claimed identity came from; only a signature-derived identity is an authorization
     * principal (R-6.5). */
    public enum PrincipalSource {
        SIGNATURE,          // the verified COSE signature's signer id
        TRANSPORT_METADATA, // e.g. a TLS peer name / connection tag
        FOREIGN_HEADER,     // e.g. an X-Agent-ID or a carried foreign header
        CLIENT_NAME,        // e.g. a self-asserted clientInfo.name
    }

    /** Return the authorization principal id iff it is signature-derived and non-empty (R-6.5); a
     * transport-metadata, foreign-header, or client-supplied name is refused UnauthenticatedPrincipal —
     * it is never treated as an authorization identity. */
    public static String resolveAuthPrincipal(PrincipalSource src, String id) {
        if (src != PrincipalSource.SIGNATURE || id == null || id.isEmpty()) {
            throw new NaalpException("UnauthenticatedPrincipal",
                    "an authorization identity must be signature-derived, not transport/foreign/client-asserted");
        }
        return id;
    }

    /** The non-critical ext key under which the optional safety label is carried (design §6.4). */
    public static final long SAFETY_LABEL_EXT_KEY = 1;

    /** The OPTIONAL signed safety annotation (R-6.4): an accountable, attributable claim, not a
     * guarantee the content is safe. */
    public static final class SafetyLabel {
        public final String risk;
        public final String scope;
        public SafetyLabel(String risk, String scope) { this.risk = risk; this.scope = scope; }

        @Override public boolean equals(Object o) {
            if (!(o instanceof SafetyLabel)) { return false; }
            SafetyLabel s = (SafetyLabel) o;
            return risk.equals(s.risk) && scope.equals(s.scope);
        }
        @Override public int hashCode() { return risk.hashCode() * 31 + scope.hashCode(); }
    }

    /** The (label, present) pair {@link #safetyLabelFromExt} returns. */
    public static final class LabelResult {
        public final SafetyLabel label;
        public final boolean present;
        public LabelResult(SafetyLabel label, boolean present) { this.label = label; this.present = present; }
    }

    /** Extract the optional safety label from an object's ext map: (label, true) when a well-formed
     * label is present, (null, false) when absent, and throws MalformedSafetyLabel when the ext[1]
     * entry is present but not exactly {1:tstr, 2:tstr} — rejected, never silently accepted. */
    public static LabelResult safetyLabelFromExt(Cbor.M ext) {
        if (ext == null) { return new LabelResult(null, false); }
        for (Cbor.Pair p : ext.pairs) {
            if (!(p.k instanceof Cbor.U) || ((Cbor.U) p.k).v != SAFETY_LABEL_EXT_KEY) { continue; }
            if (!(p.val instanceof Cbor.M)) {
                throw new NaalpException("MalformedSafetyLabel", "safety label is not {1:tstr risk, 2:tstr scope}");
            }
            String risk = null, scope = null;
            for (Cbor.Pair q : ((Cbor.M) p.val).pairs) {
                if (!(q.k instanceof Cbor.U) || !(q.val instanceof Cbor.T)) {
                    throw new NaalpException("MalformedSafetyLabel", "safety label entry is not {uint: tstr}");
                }
                long kk = ((Cbor.U) q.k).v;
                if (kk == 1) { risk = ((Cbor.T) q.val).v; }
                else if (kk == 2) { scope = ((Cbor.T) q.val).v; }
            }
            if (risk == null || scope == null) {
                throw new NaalpException("MalformedSafetyLabel", "safety label missing risk or scope");
            }
            return new LabelResult(new SafetyLabel(risk, scope), true);
        }
        return new LabelResult(null, false);
    }

    /** A capability an endpoint issues to an authenticated signer id: the most dangerous effect that
     * principal is permitted to carry. The zero maxEffect (READ_ONLY) is the least-privilege default. */
    public static final class Grant {
        public final String principal;
        public final long maxEffect;
        public Grant(String principal, long maxEffect) { this.principal = principal; this.maxEffect = maxEffect; }

        /** The endpoint policy check making the effect an authorization input, not a hint (R-6.3):
         * resolve the presenter (refusing any non-signature source, R-6.5), require it to match this
         * grant's principal, and deny an object effect exceeding the ceiling (normalized fail-closed,
         * R-6.2). No side effect; throws on any failure. */
        public void authorizeObject(PrincipalSource src, String presented, long objectEffect) {
            String who = resolveAuthPrincipal(src, presented);
            if (!who.equals(principal)) {
                throw new NaalpException("EffectNotAuthorized", "object effect exceeds the granted capability");
            }
            if (!authorizes(maxEffect, normalizeEffect(objectEffect))) {
                throw new NaalpException("EffectNotAuthorized", "object effect exceeds the granted capability");
            }
        }
    }
}
