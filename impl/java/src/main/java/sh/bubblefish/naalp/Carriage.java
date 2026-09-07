// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.util.List;

/**
 * C12 — foreign carriage by class for the Java SDK (design.md §13; R-14.1..14.8, R-18.6).
 *
 * <p>N-AALP carries a foreign agent protocol by wrapping its message, octet-for-octet, in a signed
 * N-AALP carriage object whose effect, safety, identity, and audit apply, and whose foreign body is
 * interpreted by a carriage CLASS — not a bespoke per-protocol mapping (R-14.1). There are five
 * structured classes (JSONRPC, HTTP, MSG, STREAM, DOC) plus a universal OPAQUE class that makes any
 * protocol — including one nobody has defined — carriable immediately on an experimental protocol id
 * with no registration (R-14.1, R-18.6). The foreign field is carried VERBATIM and MUST NOT be
 * re-serialized, canonicalized, summarized, or rewritten (R-14.4); N-AALP metadata is carried around
 * it, never inside it. The carriage object's signer remains the authority — a foreign identity never
 * becomes an N-AALP authorization identity (R-14.6).
 *
 * <p>An independent transcription of impl/go/carriage (cross-checked against
 * impl/python/naalp/carriage). Each class's carriage-body byte encoding and octet-exact foreign
 * recovery are graded PER CLASS against the independent per-class corpus
 * vectors/carriage/&lt;class&gt;/cases.json (the round-trip identity is the authority, R-14.7). Every
 * check is fail-closed (§15): a failing object is rejected whole, returns its named error, and causes
 * no state change.
 */
public final class Carriage {
    /** Carriage classes (design.md §13.2). */
    public static final long CLASS_JSONRPC = 0;
    public static final long CLASS_HTTP = 1;
    public static final long CLASS_MSG = 2;
    public static final long CLASS_STREAM = 3;
    public static final long CLASS_DOC = 4;
    public static final long CLASS_OPAQUE = 5;

    private static final String[] CLASS_NAMES = {"JSONRPC", "HTTP", "MSG", "STREAM", "DOC", "OPAQUE"};

    private Carriage() {}

    /** The name of a class code (0..5), or "unknown". */
    public static String className(long c) {
        if (c >= 0 && c < CLASS_NAMES.length) {
            return CLASS_NAMES[(int) c];
        }
        return "unknown";
    }

    /** The body of a carriage object (design.md §13.2): {1:protocol_id,2:class,3:content_type,
     * 4:correlation,5:method,6:foreign}, where {@code foreign} is carried octet-for-octet (R-14.4). */
    public static final class CarriageBody {
        public final long protocolId;
        public final long clazz;
        public final long contentType;
        public final byte[] correlation;
        public final String method;
        public final byte[] foreign; // the foreign message, carried octet-for-octet (R-14.4)

        public CarriageBody(long protocolId, long clazz, long contentType, byte[] correlation, String method, byte[] foreign) {
            this.protocolId = protocolId;
            this.clazz = clazz;
            this.contentType = contentType;
            this.correlation = correlation.clone();
            this.method = method;
            this.foreign = foreign.clone();
        }

        /** The carriage body as a CBOR map {1..6}. */
        public Cbor.Value toValue() {
            return new Cbor.M(List.of(
                    new Cbor.Pair(new Cbor.U(1), new Cbor.U(protocolId)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.U(clazz)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.U(contentType)),
                    new Cbor.Pair(new Cbor.U(4), new Cbor.B(correlation)),
                    new Cbor.Pair(new Cbor.U(5), new Cbor.T(method)),
                    new Cbor.Pair(new Cbor.U(6), new Cbor.B(foreign))));
        }

        /** The deterministic-CBOR encoding of the carriage body. */
        public byte[] bytes() {
            return Cbor.encode(toValue());
        }
    }

    /** Reject a class code outside the defined set with a typed mapping error, never a silent drop
     * (R-14.8). Returns normally for a defined class. */
    public static void validateClass(long clazz) {
        if (clazz > CLASS_OPAQUE) {
            throw new NaalpException("MappingError", "an N-AALP semantic cannot be represented by this carriage class");
        }
    }

    /** Wrap a foreign message octet-for-octet in a carriage body (R-14.1, R-14.4). It does NOT parse,
     * canonicalize, or rewrite the foreign bytes. An undefined protocol carries under OPAQUE with an
     * experimental protocol id and zero new specification (R-18.6). An unrepresentable class is a
     * typed MappingError. */
    public static CarriageBody carry(long protocolId, long clazz, long contentType, byte[] correlation, String method, byte[] foreign) {
        validateClass(clazz);
        return new CarriageBody(protocolId, clazz, contentType, correlation, method, foreign);
    }

    /** Parse a carriage body from a CBOR value, recovering the foreign field octet-for-octet. A
     * structurally invalid body is Malformed; an unknown class is a MappingError. Fail-closed. */
    public static CarriageBody carriageFromValue(Cbor.Value v) {
        if (!(v instanceof Cbor.M m)) {
            throw new NaalpException("Malformed", "malformed carriage body");
        }
        long protocolId = 0;
        long clazz = 0;
        long contentType = 0;
        byte[] correlation = new byte[0];
        String method = "";
        byte[] foreign = null;
        for (Cbor.Pair p : m.pairs) {
            if (!(p.k instanceof Cbor.U k)) {
                throw new NaalpException("Malformed", "non-uint carriage key");
            }
            switch ((int) k.v) {
                case 1:
                    protocolId = requireUint(p.val);
                    break;
                case 2:
                    clazz = requireUint(p.val);
                    break;
                case 3:
                    contentType = requireUint(p.val);
                    break;
                case 4:
                    correlation = requireBstr(p.val);
                    break;
                case 5:
                    if (!(p.val instanceof Cbor.T t)) {
                        throw new NaalpException("Malformed", "method is not a text string");
                    }
                    method = t.v;
                    break;
                case 6:
                    foreign = requireBstr(p.val);
                    break;
                default:
                    throw new NaalpException("Malformed", "unexpected carriage key " + k.v);
            }
        }
        if (foreign == null) {
            throw new NaalpException("Malformed", "carriage body has no foreign field");
        }
        validateClass(clazz);
        return new CarriageBody(protocolId, clazz, contentType, correlation, method, foreign);
    }

    private static long requireUint(Cbor.Value v) {
        if (!(v instanceof Cbor.U u)) {
            throw new NaalpException("Malformed", "expected a uint");
        }
        return u.v;
    }

    private static byte[] requireBstr(Cbor.Value v) {
        if (!(v instanceof Cbor.B b)) {
            throw new NaalpException("Malformed", "expected a byte string");
        }
        return b.v;
    }

    /** Protocol id ranges (design.md §13.4): reserved 0x00, standards 0x01-0x0F,
     * experimental 0x10-0x7F (no registration), private 0x80-0xFF; a value above one octet
     * is invalid. */
    public static String protocolRange(long id) {
        if (id == 0x00) {
            return "reserved";
        }
        if (id <= 0x0F) {
            return "standards";
        }
        if (id <= 0x7F) {
            return "experimental";
        }
        if (id <= 0xFF) {
            return "private";
        }
        return "invalid"; // protocol_id is one octet
    }

    /** Records whether a carried message was actually delivered. A report never claims delivery it did
     * not achieve (R-14.8). */
    public static final class DeliveryReport {
        public final boolean delivered;

        public DeliveryReport(boolean delivered) {
            this.delivered = delivered;
        }
    }

    /** Produce a delivery report from the below-foreign outcome: a failed delivery yields
     * delivered=false and NotDelivered — never a false "delivered" (R-14.8). */
    public static DeliveryReport report(boolean deliveredBelow) {
        if (!deliveredBelow) {
            throw new NaalpException("NotDelivered", "a below-foreign failure; the message was not delivered");
        }
        return new DeliveryReport(true);
    }

    /** The authorizing principal of a carriage object: the N-AALP signer of the object (envelope field
     * 5), never any foreign principal named inside the foreign bytes (R-14.6). It reads only the
     * signed envelope, never the carried foreign message. */
    public static byte[] carriageAuthority(Envelope.Object o) {
        return o.signer;
    }
}
