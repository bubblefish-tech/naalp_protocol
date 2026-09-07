// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * C12 foreign-carriage-by-class conformance for the Java SDK (design.md §13; R-14.1..14.8, R-18.6),
 * graded PER CLASS against the shared independent per-class corpus
 * vectors/carriage/{jsonrpc,http,msg,stream,doc,opaque}/cases.json (NOT produced by this code): each
 * class encodes to its oracle carriage-body bytes and recovers its foreign message octet-for-octet
 * (R-14.4/R-14.7), the protocol-id ranges classify per §13.4, an unrepresentable class is a typed
 * MappingError (never a silent drop, R-14.8), a below-foreign failure reports NotDelivered, and the
 * authorizing principal is the N-AALP signer, never any principal named inside the foreign bytes
 * (R-14.6).
 *
 * <p>CORPUS-GRADED (pure bytes / verdicts): the six per-class carriage-body byte encodings and the
 * octet-exact foreign recovery — the round-trip identity is the independent authority (R-14.7), so the
 * byte parity is non-circular (the oracle body_hex is not produced by this code). CARRIAGE OBJECTS ARE
 * UNSIGNED bodies, so there is no cross-language SIGNED pin for C12; byte-parity of the six oracle
 * bodies IS the cross-language parity (Java == Go == Rust == oracle). REAL BEHAVIOUR DEMONSTRATED IN
 * ISOLATION: R-14.6 identity containment — a foreign principal embedded in the foreign bytes is
 * recovered octet-exact but confers no authority; the authorizing principal is the real ML-DSA-65
 * envelope signer.
 *
 * <p>Written test-first: {@link Carriage} is absent until Carriage.java lands, so this fails RED with a
 * javac "cannot find symbol Carriage"; the recorded mutation forces {@link Carriage#carriageFromValue}
 * to truncate the recovered foreign field, which flips the named "opaque foreign recovered
 * octet-exact" check on its assertion.
 */
public final class CarriageKatTest {
    private static int fails = 0;

    private static void check(String name, String got, String want) {
        if (got.equals(want)) {
            System.out.println("  ok   " + name);
        } else {
            fails++;
            System.out.println("  FAIL " + name + "\n       got  " + got + "\n       want " + want);
        }
    }

    private static Path findCarriageRoot() {
        Path d = Path.of(System.getProperty("user.dir")).toAbsolutePath();
        for (int i = 0; i < 6 && d != null; i++) {
            Path p = d.resolve("vectors").resolve("carriage");
            if (Files.isDirectory(p)) {
                return p;
            }
            d = d.getParent();
        }
        throw new AssertionError("vectors/carriage not found from " + System.getProperty("user.dir"));
    }

    private static String field(String scope, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"").matcher(scope);
        if (!m.find()) {
            throw new AssertionError("string key not found: " + key);
        }
        return m.group(1);
    }

    private static long intField(String scope, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*(\\d+)").matcher(scope);
        if (!m.find()) {
            throw new AssertionError("int key not found: " + key);
        }
        return Long.parseLong(m.group(1));
    }

    private static byte[] hb(String s) {
        return Hex.decode(s);
    }

    private static String errKind(Runnable r) {
        try {
            r.run();
            return "no-error";
        } catch (NaalpException e) {
            return e.kind;
        }
    }

    private static final int ALG = Cose.ALG_MLDSA65;
    private static final int PROFILE = Cose.PROFILE_PUBLIC;

    private static final String[][] CLASSES = {
            {"jsonrpc", "0"}, {"http", "1"}, {"msg", "2"}, {"stream", "3"}, {"doc", "4"}, {"opaque", "5"}
    };

    private static void run() throws Exception {
        Path root = findCarriageRoot();

        // Per-class: each class grades against ITS OWN subdir (design §13.2, R-14.7).
        for (String[] cd : CLASSES) {
            String dir = cd[0];
            long wantClass = Long.parseLong(cd[1]);
            String c = Files.readString(root.resolve(dir).resolve("cases.json"), StandardCharsets.UTF_8);
            long protocolId = intField(c, "protocol_id");
            long clazz = intField(c, "class");
            long contentType = intField(c, "content_type");
            byte[] correlation = hb(field(c, "correlation_hex"));
            String method = field(c, "method");
            byte[] foreign = hb(field(c, "foreign_hex"));
            String bodyHex = field(c, "body_hex");

            check(dir + " class code == " + wantClass, Long.toString(clazz), Long.toString(wantClass));
            check(dir + " class name == oracle", Carriage.className(clazz), oracleClassName(dir));

            Carriage.CarriageBody cb = Carriage.carry(protocolId, clazz, contentType, correlation, method, foreign);
            check(dir + " body == oracle", Hex.encode(cb.bytes()), bodyHex);

            // Round-trip: decode the carriage body and recover the foreign octets EXACTLY (R-14.4).
            Carriage.CarriageBody rec = Carriage.carriageFromValue(Cbor.decode(cb.bytes()));
            check(dir + " foreign recovered octet-exact", Hex.encode(rec.foreign), field(c, "foreign_hex"));
            check(dir + " recovered protocol_id", Long.toString(rec.protocolId), Long.toString(protocolId));
            check(dir + " recovered class", Long.toString(rec.clazz), Long.toString(clazz));
            check(dir + " recovered method", rec.method, method);
            check(dir + " recovered correlation", Hex.encode(rec.correlation), field(c, "correlation_hex"));
        }

        // Opaque: an undefined protocol carries under OPAQUE on an EXPERIMENTAL protocol id (R-18.6).
        String opaque = Files.readString(root.resolve("opaque").resolve("cases.json"), StandardCharsets.UTF_8);
        long opaqueId = intField(opaque, "protocol_id");
        check("opaque protocol id is experimental (no registration)", Carriage.protocolRange(opaqueId), "experimental");

        // Protocol-id range boundaries (design §13.4).
        check("range 0x00 reserved", Carriage.protocolRange(0x00), "reserved");
        check("range 0x01 standards", Carriage.protocolRange(0x01), "standards");
        check("range 0x0F standards", Carriage.protocolRange(0x0F), "standards");
        check("range 0x10 experimental", Carriage.protocolRange(0x10), "experimental");
        check("range 0x7F experimental", Carriage.protocolRange(0x7F), "experimental");
        check("range 0x80 private", Carriage.protocolRange(0x80), "private");
        check("range 0xFF private", Carriage.protocolRange(0xFF), "private");
        check("range 0x100 invalid (one octet)", Carriage.protocolRange(0x100), "invalid");

        // An unrepresentable class is a typed MappingError, never a silent drop (R-14.8).
        check("unknown class rejected MappingError",
                errKind(() -> Carriage.carry(0x10, 99, 0, new byte[0], "x", "y".getBytes(StandardCharsets.UTF_8))), "MappingError");

        // A below-foreign failure reports NotDelivered and never a false "delivered" (R-14.8).
        check("failed delivery reports NotDelivered", errKind(() -> Carriage.report(false)), "NotDelivered");
        check("failed delivery report not delivered", Boolean.toString(reportDelivered(false)), "false");
        check("successful delivery reported", Boolean.toString(Carriage.report(true).delivered), "true");

        // R-14.6 identity containment (demonstrated in isolation with a real signed envelope): a foreign
        // principal named inside the foreign bytes confers no authority; the authority is the N-AALP signer.
        identityContainment();
    }

    private static boolean reportDelivered(boolean below) {
        try {
            return Carriage.report(below).delivered;
        } catch (NaalpException e) {
            return false;
        }
    }

    private static String oracleClassName(String dir) {
        switch (dir) {
            case "jsonrpc": return "JSONRPC";
            case "http": return "HTTP";
            case "msg": return "MSG";
            case "stream": return "STREAM";
            case "doc": return "DOC";
            case "opaque": return "OPAQUE";
            default: return "unknown";
        }
    }

    private static void identityContainment() {
        byte[] seed = new byte[32];
        java.util.Arrays.fill(seed, (byte) 80);
        byte[] pk = Cose.mldsaKeygen("ML-DSA-65", seed);

        byte[] foreign = "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"from\":\"attacker-principal\"}}"
                .getBytes(StandardCharsets.UTF_8);
        Carriage.CarriageBody cb = Carriage.carry(0x01, Carriage.CLASS_JSONRPC, 0,
                new byte[]{1, 2, 3, 4}, "tools/call", foreign);
        // The carriage object is a normal signed envelope object on the Bridge channel (13).
        Envelope.Object obj = new Envelope.Object(0, 13, pk, 100, 0, cb.toValue());
        byte[] signed = Envelope.sign(obj, ALG, seed);
        Envelope.Object o = Envelope.verify(PROFILE, ALG, pk, (ch, k) -> true, signed, null);

        byte[] auth = Carriage.carriageAuthority(o);
        check("authority is the N-AALP signer", Hex.encode(auth), Hex.encode(pk));
        check("authority did not leak the foreign principal",
                Boolean.toString(Hex.encode(auth).contains(Hex.encode("attacker-principal".getBytes(StandardCharsets.UTF_8)))), "false");

        Carriage.CarriageBody rec = Carriage.carriageFromValue(o.body);
        check("foreign recovered octet-exact from the signed object", Hex.encode(rec.foreign), Hex.encode(foreign));
        check("foreign still carries the (non-authoritative) principal",
                Boolean.toString(new String(rec.foreign, StandardCharsets.UTF_8).contains("attacker-principal")), "true");
    }

    public static void main(String[] args) throws Exception {
        System.out.println("carriage conformance (Java) — graded per class vs vectors/carriage/<class>/cases.json");
        run();
        System.out.println(fails == 0 ? "CarriageKatTest: PASS" : "CarriageKatTest: FAIL (" + fails + ")");
        System.exit(fails == 0 ? 0 : 1);
    }
}
