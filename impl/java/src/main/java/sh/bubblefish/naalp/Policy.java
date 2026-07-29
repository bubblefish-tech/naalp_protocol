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
}
