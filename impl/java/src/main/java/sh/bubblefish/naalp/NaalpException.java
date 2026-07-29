// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

/**
 * A rejection raised by an N-AALP construction when an input violates a normative rule
 * (non-canonical CBOR, non-NFC identity, unknown alg, causal violation, unknown channel/kind,
 * effect-declaration mismatch, unknown transport, undefined carriage class). The {@code kind}
 * field names the rule, mirroring the Python/Go reference error kinds. The conformance adapter
 * turns any NaalpException into a wire {@code {"error": ...}} response — which is exactly what a
 * MUST-reject ({@code result:"invalid"}) corpus case requires.
 */
public final class NaalpException extends RuntimeException {
    public final String kind;

    public NaalpException(String kind, String message) {
        super(kind + ": " + message);
        this.kind = kind;
    }
}
