// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

/**
 * T3.3 naalp-error object + numeric error-code registry conformance for the Java SDK
 * (design.md §3.5, R3.3/R3.4), ported from impl/go/naalperror/naalperror_test.go (cross-read
 * against the byte-identical impl/rust/src/naalperror.rs {@code #[cfg(test)]} module, and the
 * already-ported impl/typescript/test/naalperror.test.mjs / impl/ruby/test/test_naalperror.rb /
 * impl/php/src/NaalpError.php). Pins the registry size/order, the hand-computed canonical-CBOR
 * KATs (independent of the oracle and of impl/go/impl/rust — these are the MANDATORY KATs), the
 * full grammar round-trip, and the two dual-carriage rules: a registered code with a disagreeing
 * name is rejected Malformed (the strengthening direction); a code outside the registry is
 * accepted opaque (open-registry contract).
 *
 * <p>KAT convention (a standalone {@code main} exiting non-zero on any failure); named
 * "…KatTest" so the filename carries the "test" token the ten-language-parity gate indexes.
 * Written test-first: {@link NaalpError} is absent until NaalpError.java lands, so this fails RED
 * with a javac "cannot find symbol NaalpError"; the recorded mutation drops the dual-carriage
 * name check in {@link NaalpError#decode}, which flips the
 * "dual-carriage mismatch rejected Malformed" assertion below.
 *
 * <p>Run: {@code java -cp impl/java/tout;<bcprov-jar> sh.bubblefish.naalp.NaalpErrorKatTest}
 */
public final class NaalpErrorKatTest {
    private static int fails = 0;

    private static void check(String name, String got, String want) {
        if (got.equals(want)) {
            System.out.println("  ok   " + name);
        } else {
            fails++;
            System.out.println("  FAIL " + name + "\n       got  " + got + "\n       want " + want);
        }
    }

    private static void check(String name, boolean got, boolean want) {
        check(name, Boolean.toString(got), Boolean.toString(want));
    }

    private static String errKind(Runnable r) {
        try {
            r.run();
            return "no-error";
        } catch (NaalpException e) {
            return e.kind;
        }
    }

    // TestRegistrySize: pins the registry to exactly 129 unique names with no gaps (the
    // fields-of-record invariant: code == index+1, sequential 1..129). A mutation that drops or
    // duplicates an entry flips this and the code/name relationship.
    private static void registrySizeAndIndex() {
        check("registry has 132 names", Integer.toString(NaalpError.NAMES.length), "132");
        java.util.Set<String> seen = new java.util.HashSet<>();
        for (int i = 0; i < NaalpError.NAMES.length; i++) {
            String n = NaalpError.NAMES[i];
            check("no duplicate name " + n, seen.add(n), true);
            Long code = NaalpError.codeForName(n);
            check("codeForName(" + n + ") registered", code != null, true);
            if (code != null) {
                check("codeForName(" + n + ") == index+1", Long.toString(code), Long.toString(i + 1));
            }
        }
        check("STANDARDS_MAX == 0x7FFF", Long.toString(NaalpError.STANDARDS_MAX), Long.toString(0x7FFFL));
    }

    // TestEncodeKAT: pins the deterministic naalp-error body bytes against hand-computed CBOR
    // (independent of the oracle and of impl/go/impl/rust): a2 (map-2) 01 <code> 02 <tstr name>.
    // A mutation of encode flips it. These are the MANDATORY KATs.
    private static void encodeKat() {
        check("encode(1, NonCanonical) == hand-computed CBOR",
                Hex.encode(NaalpError.encode(1, "NonCanonical", "", null)),
                "a20101026c4e6f6e43616e6f6e6963616c");
        check("encode(52, NotDelivered) == hand-computed CBOR",
                Hex.encode(NaalpError.encode(52, "NotDelivered", "", null)),
                "a2011834026c4e6f7444656c697665726564");
    }

    // TestEncodeDecodeFull: exercises the optional fields 3 and 4 (map grows to a4, keys stay
    // ascending). A mutation that drops a field or mis-orders keys flips this round-trip.
    private static void encodeDecodeFull() {
        Long code = NaalpError.codeForName("BadSignature");
        check("BadSignature is registered", code != null, true);
        byte[] subj = new byte[50];
        subj[0] = 0x20;
        subj[1] = 0x30;
        byte[] b = NaalpError.encode(code, "BadSignature", "reason", subj);
        NaalpError.Object o = NaalpError.decode(b);
        check("round-trip name == BadSignature", o.name, "BadSignature");
        check("round-trip detail == reason", o.detail, "reason");
        check("round-trip subject length == 50", Integer.toString(o.subject.length), "50");
    }

    // TestDualCarriageMismatch: a registered code carrying the wrong registered name is rejected
    // Malformed (the strengthening direction). A mutation that skips the name check flips this.
    // This is one of the MANDATORY KATs (code 22=BadSignature, wrong name "NotDelivered").
    private static void dualCarriageMismatchIsMalformed() {
        Long code = NaalpError.codeForName("BadSignature"); // code 22, name of code 52
        byte[] b = NaalpError.encode(code, "NotDelivered", "", null);
        check("dual-carriage mismatch rejected Malformed", errKind(() -> NaalpError.decode(b)), "Malformed");
    }

    // TestUnknownCodeOpaque: a code outside the registry is accepted opaque (open-registry
    // contract). A mutation that rejects unknown codes flips this. This is one of the MANDATORY
    // KATs.
    private static void unknownCodeIsOpaque() {
        byte[] b = NaalpError.encode(60000, "SomeFutureError", "", null);
        NaalpError.Object o = NaalpError.decode(b);
        check("unknown code round-trips code", Long.toString(o.code), "60000");
        check("unknown code round-trips name", o.name, "SomeFutureError");
    }

    // TestNameForCode: pins a few known code->name entries + the unregistered boundary.
    private static void nameForCodeBoundary() {
        NaalpError.Lookup l1 = NaalpError.nameForCode(1);
        check("nameForCode(1) registered", l1.registered, true);
        check("nameForCode(1) == NonCanonical", l1.name, "NonCanonical");
        NaalpError.Lookup l22 = NaalpError.nameForCode(22);
        check("nameForCode(22) registered", l22.registered, true);
        check("nameForCode(22) == BadSignature", l22.name, "BadSignature");
        NaalpError.Lookup l119 = NaalpError.nameForCode(119);
        check("nameForCode(119) registered", l119.registered, true);
        check("nameForCode(119) == RebindUnauthorized", l119.name, "RebindUnauthorized");
        for (long c : new long[]{0, 133, 60000}) {
            check("nameForCode(" + c + ") unregistered", NaalpError.nameForCode(c).registered, false);
        }
    }

    // Structural malformation: closed grammar. A non-map, a missing mandatory field, and an
    // unknown field key are all rejected Malformed -- never silently accepted or misclassified.
    private static void structurallyMalformedRejected() {
        // not a map at all (a CBOR array)
        byte[] notAMap = Cbor.encode(new Cbor.A(java.util.List.of()));
        check("a non-map body is Malformed", errKind(() -> NaalpError.decode(notAMap)), "Malformed");

        // missing the mandatory name field (key 2)
        byte[] missingName = Cbor.encode(new Cbor.M(java.util.List.of(
                new Cbor.Pair(new Cbor.U(1), new Cbor.U(1)))));
        check("missing name field is Malformed", errKind(() -> NaalpError.decode(missingName)), "Malformed");

        // an unknown field key (5) is a closed-grammar violation
        byte[] unknownField = Cbor.encode(new Cbor.M(java.util.List.of(
                new Cbor.Pair(new Cbor.U(1), new Cbor.U(1)),
                new Cbor.Pair(new Cbor.U(2), new Cbor.T("NonCanonical")),
                new Cbor.Pair(new Cbor.U(5), new Cbor.U(0)))));
        check("unknown field key is Malformed", errKind(() -> NaalpError.decode(unknownField)), "Malformed");

        // garbage bytes are not well-formed CBOR at all
        byte[] garbage = new byte[]{(byte) 0xff, (byte) 0xff};
        check("garbage bytes are Malformed", errKind(() -> NaalpError.decode(garbage)), "Malformed");
    }

    // The exact MANDATORY KATs named in the task, gathered in one place for visibility.
    private static void mandatoryKats() {
        check("KAT encode(1,NonCanonical)", Hex.encode(NaalpError.encode(1, "NonCanonical", "", null)),
                "a20101026c4e6f6e43616e6f6e6963616c");
        check("KAT encode(52,NotDelivered)", Hex.encode(NaalpError.encode(52, "NotDelivered", "", null)),
                "a2011834026c4e6f7444656c697665726564");
        byte[] mismatch = NaalpError.encode(22, "NotDelivered", "", null); // code 22 wrong name
        check("KAT decode(mismatch) rejected Malformed", errKind(() -> NaalpError.decode(mismatch)), "Malformed");
        byte[] unknown = NaalpError.encode(60000, "SomeFutureError", "", null);
        NaalpError.Object o = NaalpError.decode(unknown);
        check("KAT decode(unknown) accepted code 60000", Long.toString(o.code), "60000");
    }

    public static void main(String[] args) {
        System.out.println("naalp-error conformance (Java) — hand-computed KATs, independent of impl/go/impl/rust");
        registrySizeAndIndex();
        encodeKat();
        encodeDecodeFull();
        dualCarriageMismatchIsMalformed();
        unknownCodeIsOpaque();
        nameForCodeBoundary();
        structurallyMalformedRejected();
        mandatoryKats();
        System.out.println(fails == 0 ? "NaalpErrorKatTest: PASS" : "NaalpErrorKatTest: FAIL (" + fails + ")");
        System.exit(fails == 0 ? 0 : 1);
    }
}
