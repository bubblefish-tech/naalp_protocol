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
 * C21 (5B.1) NAALP-PAY payment-import known-answer test for the Java SDK (design.md §24; R-PAY-1..6),
 * graded against the shared independent corpus vectors/payment/cases.json (NOT produced by this code):
 * the closed payment-format registry, the byte-exact PaymentImport body/head/content-id (incl. the
 * oversized &gt;2^53 amount and the minimal import), the foreign-payload content id (carriage binding),
 * the byte-exact ChargeBinding body/head/content-id, the parse round-trip, the fail-closed edge cases
 * (non-canonical -&gt; NonCanonical / PayMalformed, absent mandatory field -&gt; PayMalformed, a
 * bstr-currency look-alike -&gt; PayMalformed, empty vs populated foreign distinct by content-id), and
 * the mismatch content-ids (a wrong amount, wrong payee, or substituted foreign payload yields a
 * DIFFERENT charge content-id, so a §7 approval bound to the original no longer matches).
 *
 * <p>The PaymentImport SIGNATURE is real deterministic ML-DSA-65 via a bare-{1:alg} COSE_Sign1 (as the
 * reference's cose.Sign1); the corpus carries no signed vector for this channel, so sign/verify is
 * demonstrated in isolation only — stated honestly, not corpus-graded.
 *
 * <p>ALSO exercised (STEP-2 ten-port parity wave, section 10 below): {@link Payment#authorizeCharge},
 * the per-charge approval gate reusing the §7 {@link Approval} object and single-use consume
 * {@link Approval.Ledger} UNCHANGED. The payment corpus carries no approval/consume vector, so this is
 * demonstrated in isolation over real deterministic ML-DSA-65 approvals and a real WAL-backed ledger —
 * all four deny paths (UnknownPaymentFormat, ApprovalMismatch/ApprovalExpired/BadSignature,
 * ApprovalRequired, AlreadyConsumed) plus the single success-consumes-exactly-once path.
 *
 * <p>Written test-first: {@link Payment} is absent until Payment.java lands, so this fails RED with a
 * javac "cannot find symbol Payment"; the recorded mutation forces the encoded ChargeBinding
 * {@code amount} field to a constant, which flips "ap2 charge-binding id == oracle".
 */
public final class PaymentKatTest {
    private static int fails = 0;

    private static void check(String name, String got, String want) {
        if (got.equals(want)) {
            System.out.println("  ok   " + name);
        } else {
            fails++;
            System.out.println("  FAIL " + name + "\n       got  " + got + "\n       want " + want);
        }
    }

    private static Path findVector() {
        Path d = Path.of(System.getProperty("user.dir")).toAbsolutePath();
        for (int i = 0; i < 6 && d != null; i++) {
            Path p = d.resolve("vectors").resolve("payment").resolve("cases.json");
            if (Files.isRegularFile(p)) {
                return p;
            }
            d = d.getParent();
        }
        throw new AssertionError("vectors/payment/cases.json not found from " + System.getProperty("user.dir"));
    }

    private static int matchClose(String s, int open) {
        char oc = s.charAt(open);
        char cc = oc == '{' ? '}' : ']';
        int depth = 0;
        boolean inStr = false;
        for (int i = open; i < s.length(); i++) {
            char ch = s.charAt(i);
            if (inStr) {
                if (ch == '\\') {
                    i++;
                } else if (ch == '"') {
                    inStr = false;
                }
                continue;
            }
            if (ch == '"') {
                inStr = true;
            } else if (ch == oc) {
                depth++;
            } else if (ch == cc && --depth == 0) {
                return i + 1;
            }
        }
        throw new AssertionError("unbalanced from " + open);
    }

    private static int afterKey(String s, String key) {
        Matcher m = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:").matcher(s);
        if (!m.find()) {
            throw new AssertionError("key not found: " + key);
        }
        return m.end();
    }

    private static String objBlock(String s, String key) {
        int open = s.indexOf('{', afterKey(s, key));
        int close = matchClose(s, open);
        return s.substring(open + 1, close - 1);
    }

    private static String arrayBlock(String s, String key) {
        int open = s.indexOf('[', afterKey(s, key));
        int close = matchClose(s, open);
        return s.substring(open + 1, close - 1);
    }

    private static List<String> splitObjects(String arrayInner) {
        List<String> out = new ArrayList<>();
        int i = 0;
        while (true) {
            int open = arrayInner.indexOf('{', i);
            if (open < 0) {
                return out;
            }
            int close = matchClose(arrayInner, open);
            out.add(arrayInner.substring(open + 1, close - 1));
            i = close;
        }
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

    private static String parseKind(byte[] body) {
        try {
            Payment.parsePaymentImport(body);
            return "no-error";
        } catch (NaalpException e) {
            return e.kind;
        }
    }

    private static Payment.PaymentImport importFrom(String iv) {
        return new Payment.PaymentImport(intField(iv, "format"), intField(iv, "amount"),
                field(iv, "currency"), Hex.decode(field(iv, "payee_hex")),
                intField(iv, "not_after"), Hex.decode(field(iv, "foreign_hex")));
    }

    private static final int ALG = Cose.ALG_MLDSA65;

    private static void run() throws Exception {
        String json = Files.readString(findVector(), StandardCharsets.UTF_8);
        byte[] zeroSeed = new byte[32];
        byte[] pk = Cose.mldsaKeygen("ML-DSA-65", zeroSeed);

        // 1. the closed payment-format registry; an out-of-set code is not registered.
        for (String fv : splitObjects(arrayBlock(json, "format_vocabulary"))) {
            long code = intField(fv, "code");
            String name = field(fv, "name");
            check("format " + name + " registered", Boolean.toString(Payment.isRegisteredFormat(code)), "true");
            check("format " + name + " name", Payment.formatName(code), name);
        }
        long unknown = intField(json, "unknown_format");
        check("unknown format not registered", Boolean.toString(Payment.isRegisteredFormat(unknown)), "false");
        check("unknown format name", Payment.formatName(unknown), "unknown");

        // 2. a payment spend is a non_idempotent_write (the value-bearing rule).
        check("charge effect == oracle", Long.toString(Payment.CHARGE_EFFECT), Long.toString(intField(json, "charge_effect")));
        check("charge effect == non_idempotent_write", Long.toString(Payment.CHARGE_EFFECT), Long.toString(Policy.NON_IDEMPOTENT_WRITE));

        // 3. PaymentImport body/head/id/foreign_id, and the ChargeBinding body/head/id (mutation target),
        //    byte-for-byte against the oracle for each imported format.
        String imports = objBlock(json, "imports");
        for (String name : new String[]{"ap2", "acp", "x402"}) {
            String iv = objBlock(imports, name);
            Payment.PaymentImport p = importFrom(iv);
            check(name + " import body == oracle", Hex.encode(p.bytes()), field(iv, "body_hex"));
            check(name + " import head == oracle", Hex.encode(p.head()), field(iv, "head_hex"));
            check(name + " import id == oracle", Hex.encode(p.id()), field(iv, "id_hex"));
            check(name + " foreign_id == oracle", Hex.encode(p.foreignId()), field(iv, "foreign_id_hex"));
            String cb = objBlock(iv, "charge_binding");
            Payment.ChargeBinding b = p.chargeBinding();
            check(name + " charge-binding body == oracle", Hex.encode(b.bytes()), field(cb, "body_hex"));
            check(name + " charge-binding head == oracle", Hex.encode(b.head()), field(cb, "head_hex"));
            check(name + " charge-binding id == oracle", Hex.encode(b.contentId()), field(cb, "id_hex"));
        }

        // 4. an oversized amount (0x0102030405060708 > 2^53) round-trips byte-exact (Java long is 64-bit).
        String big = objBlock(json, "big_amount");
        long bigAmount = Long.parseLong(field(big, "amount_str"));
        check("big amount > 2^53", Boolean.toString(bigAmount > (1L << 53)), "true");
        Payment.PaymentImport bp = new Payment.PaymentImport(intField(big, "format"), bigAmount,
                field(big, "currency"), Hex.decode(field(big, "payee_hex")),
                intField(big, "not_after"), Hex.decode(field(big, "foreign_hex")));
        check("big-amount body == oracle", Hex.encode(bp.bytes()), field(big, "body_hex"));
        check("big-amount head == oracle", Hex.encode(bp.head()), field(big, "head_hex"));
        check("big-amount id == oracle", Hex.encode(bp.id()), field(big, "id_hex"));
        check("big-amount charge-binding id == oracle", Hex.encode(bp.chargeBinding().contentId()), field(objBlock(big, "charge_binding"), "id_hex"));
        Payment.PaymentImport bpRoundtrip = Payment.parsePaymentImport(Hex.decode(field(big, "body_hex")));
        check("big-amount parse round-trips exact", Long.toString(bpRoundtrip.amount), Long.toString(bigAmount));

        // 5. the minimal import (all fields zero/empty) encodes to the oracle bytes.
        String minB = objBlock(json, "minimal");
        Payment.PaymentImport minimal = new Payment.PaymentImport(intField(minB, "format"), intField(minB, "amount"),
                field(minB, "currency"), Hex.decode(field(minB, "payee_hex")),
                intField(minB, "not_after"), Hex.decode(field(minB, "foreign_hex")));
        check("minimal body == oracle", Hex.encode(minimal.bytes()), field(minB, "body_hex"));
        check("minimal head == oracle", Hex.encode(minimal.head()), field(minB, "head_hex"));
        check("minimal id == oracle", Hex.encode(minimal.id()), field(minB, "id_hex"));

        // 6. parse round-trips the imported fields for each format.
        for (String name : new String[]{"ap2", "acp", "x402"}) {
            String iv = objBlock(imports, name);
            Payment.PaymentImport p = Payment.parsePaymentImport(Hex.decode(field(iv, "body_hex")));
            check(name + " parse format", Long.toString(p.format), Long.toString(intField(iv, "format")));
            check(name + " parse amount", Long.toString(p.amount), Long.toString(intField(iv, "amount")));
            check(name + " parse currency", p.currency, field(iv, "currency"));
            check(name + " parse payee", Hex.encode(p.payee), field(iv, "payee_hex"));
            check(name + " parse not_after", Long.toString(p.notAfter), Long.toString(intField(iv, "not_after")));
            check(name + " parse foreign", Hex.encode(p.foreign), field(iv, "foreign_hex"));
        }

        // 7. fail-closed edges: a descending-key body is NonCanonical (cbor) / PayMalformed (parse); the
        //    canonical form of the same content parses; an absent mandatory field and a bstr-currency
        //    look-alike are PayMalformed; empty vs populated foreign are distinct by content-id.
        String ec = objBlock(json, "edge_cases");
        String koo = objBlock(ec, "keys_out_of_order");
        byte[] noncanon = Hex.decode(field(koo, "noncanonical_body_hex"));
        String cborKind;
        try {
            Cbor.decode(noncanon);
            cborKind = "decoded";
        } catch (NaalpException e) {
            cborKind = e.kind;
        }
        check("descending-key body cbor-rejected", cborKind, "NonCanonical");
        check("descending-key body parse-rejected", parseKind(noncanon), "PayMalformed");
        check("canonical body parses", parseKind(Hex.decode(field(koo, "canonical_body_hex"))), "no-error");

        String eva = objBlock(ec, "empty_vs_absent");
        String emptyB = objBlock(eva, "empty_foreign");
        String popB = objBlock(eva, "populated_foreign");
        Payment.PaymentImport empty = Payment.parsePaymentImport(Hex.decode(field(emptyB, "body_hex")));
        check("empty-foreign is empty", Integer.toString(empty.foreign.length), "0");
        check("empty-foreign id == oracle", Hex.encode(empty.id()), field(emptyB, "id_hex"));
        check("empty-foreign foreign_id == oracle", Hex.encode(empty.foreignId()), field(emptyB, "foreign_id_hex"));
        Payment.PaymentImport populated = Payment.parsePaymentImport(Hex.decode(field(popB, "body_hex")));
        check("populated-foreign id == oracle", Hex.encode(populated.id()), field(popB, "id_hex"));
        check("populated-foreign foreign_id == oracle", Hex.encode(populated.foreignId()), field(popB, "foreign_id_hex"));
        check("empty vs populated ids distinct", Boolean.toString(!Hex.encode(empty.id()).equals(Hex.encode(populated.id()))), "true");
        check("empty vs populated foreign_ids distinct",
                Boolean.toString(!Hex.encode(empty.foreignId()).equals(Hex.encode(populated.foreignId()))), "true");
        String absB = objBlock(eva, "absent_field");
        check("absent mandatory field rejected", parseKind(Hex.decode(field(absB, "body_hex"))), field(absB, "reject"));

        String la = objBlock(ec, "look_alike");
        check("bstr-currency look-alike rejected", parseKind(Hex.decode(field(la, "body_hex"))), field(la, "reject"));

        // 8. the binding property: an approval binds the base ap2 charge-binding content-id; a wrong
        //    amount, wrong payee, or substituted foreign payload yields a DIFFERENT charge content-id.
        String ap2 = objBlock(imports, "ap2");
        Payment.PaymentImport base = importFrom(ap2);
        String baseId = Hex.encode(base.chargeBinding().contentId());
        check("base ap2 charge-binding id == oracle", baseId, field(objBlock(ap2, "charge_binding"), "id_hex"));
        String mm = objBlock(json, "mismatch");

        Payment.PaymentImport wrongAmount = new Payment.PaymentImport(base.format, base.amount + 8000,
                base.currency, base.payee, base.notAfter, base.foreign);
        check("wrong-amount charge id == oracle", Hex.encode(wrongAmount.chargeBinding().contentId()), field(mm, "wrong_amount_charge_id_hex"));

        Payment.PaymentImport wrongPayee = new Payment.PaymentImport(base.format, base.amount, base.currency,
                "merchant:evil-store".getBytes(StandardCharsets.UTF_8), base.notAfter, base.foreign);
        check("wrong-payee charge id == oracle", Hex.encode(wrongPayee.chargeBinding().contentId()), field(mm, "wrong_payee_charge_id_hex"));

        Payment.PaymentImport substituted = new Payment.PaymentImport(base.format, base.amount, base.currency,
                base.payee, base.notAfter, Hex.decode(field(mm, "substituted_foreign_hex")));
        check("substituted foreign_id == oracle", Hex.encode(substituted.foreignId()), field(mm, "substituted_foreign_id_hex"));
        check("substituted charge id == oracle", Hex.encode(substituted.chargeBinding().contentId()), field(mm, "substituted_charge_id_hex"));

        check("wrong-amount differs from base", Boolean.toString(!baseId.equals(field(mm, "wrong_amount_charge_id_hex"))), "true");
        check("wrong-payee differs from base", Boolean.toString(!baseId.equals(field(mm, "wrong_payee_charge_id_hex"))), "true");
        check("substituted differs from base", Boolean.toString(!baseId.equals(field(mm, "substituted_charge_id_hex"))), "true");

        // 9. signed import round-trip in isolation (real deterministic ML-DSA-65 via a bare COSE_Sign1;
        //    NOT corpus-graded — no signed vector): sign -> verify recovers the fields; a tampered
        //    signature is BadSignature; an unknown imported format is UnknownPaymentFormat.
        byte[] obj = Payment.signPaymentImport(base, ALG, zeroSeed);
        Payment.PaymentImport got = Payment.verifyPaymentImport(obj, Cose.PROFILE_PUBLIC, ALG, pk);
        boolean same = got.format == base.format && got.amount == base.amount
                && got.currency.equals(base.currency)
                && java.util.Arrays.equals(got.payee, base.payee)
                && got.notAfter == base.notAfter
                && java.util.Arrays.equals(got.foreign, base.foreign);
        check("sign/verify recovers import", Boolean.toString(same), "true");
        byte[] badObj = obj.clone();
        badObj[badObj.length - 1] ^= 1;
        String badKind = "no-error";
        try {
            Payment.verifyPaymentImport(badObj, Cose.PROFILE_PUBLIC, ALG, pk);
        } catch (NaalpException e) {
            badKind = e.kind;
        }
        check("tampered signature rejected", badKind, "BadSignature");
        Payment.PaymentImport badFmt = new Payment.PaymentImport(unknown, 1, "USD",
                "x".getBytes(StandardCharsets.UTF_8), 1, new byte[0]);
        byte[] badFmtObj = Payment.signPaymentImport(badFmt, ALG, zeroSeed);
        String fmtKind = "no-error";
        try {
            Payment.verifyPaymentImport(badFmtObj, Cose.PROFILE_PUBLIC, ALG, pk);
        } catch (NaalpException e) {
            fmtKind = e.kind;
        }
        check("unknown imported format rejected", fmtKind, "UnknownPaymentFormat");

        // 10. authorizeCharge: the per-charge approval gate reusing §7 approval + single-use consume
        //     ledger. Demonstrated in isolation (real ML-DSA-65 + a real WAL ledger; the payment corpus
        //     carries no approval/consume vector). All four deny paths + success-consumes-exactly-once.
        byte[] approverSeed = new byte[32];
        java.util.Arrays.fill(approverSeed, (byte) 0x11);
        byte[] approverPk = Cose.mldsaKeygen("ML-DSA-65", approverSeed);
        byte[] foreignSeed = new byte[32];
        java.util.Arrays.fill(foreignSeed, (byte) 0x22);
        byte[] foreignPk = Cose.mldsaKeygen("ML-DSA-65", foreignSeed);

        Payment.PaymentImport chargeBase = importFrom(ap2);
        byte[] chargeCid = chargeBase.chargeBinding().contentId();
        byte[] chargeNonce = new byte[16];
        java.util.Arrays.fill(chargeNonce, (byte) 0x01);
        Approval.ApprovalRecord chargeAppr = new Approval.ApprovalRecord(chargeCid, "approver-A",
                Payment.CHARGE_EFFECT, chargeNonce, chargeBase.notAfter);
        byte[] chargeApprSig = Approval.signApproval(chargeAppr, ALG, approverSeed);

        // success: authorized and consumed exactly once (seq 0).
        Path chargeWal = Files.createTempFile("naalp-pay-charge-", ".wal");
        chargeWal.toFile().deleteOnExit();
        Files.deleteIfExists(chargeWal);
        Approval.Ledger chargeLedger = Approval.Ledger.open(chargeWal);
        Approval.LedgerEntry firstEntry = Payment.authorizeCharge(chargeBase, chargeAppr, ALG, approverPk,
                chargeApprSig, "payer-1", chargeBase.notAfter, chargeLedger);
        check("authorizeCharge (honest) consumes at seq 0", Long.toString(firstEntry.seq), "0");
        // replay: the same approval is rejected by the ledger, no second spend, no state change.
        String replayKind = "no-error";
        try {
            Payment.authorizeCharge(chargeBase, chargeAppr, ALG, approverPk, chargeApprSig, "payer-1",
                    chargeBase.notAfter, chargeLedger);
        } catch (NaalpException e) {
            replayKind = e.kind;
        }
        check("authorizeCharge replay denied AlreadyConsumed", replayKind, "AlreadyConsumed");
        check("ledger has 1 entry after replay (no double-spend)", Integer.toString(chargeLedger.len()), "1");
        chargeLedger.close();

        // deny path 1: an unknown imported format is not chargeable (no ledger append).
        Payment.PaymentImport unkCharge = new Payment.PaymentImport(unknown, chargeBase.amount, chargeBase.currency,
                chargeBase.payee, chargeBase.notAfter, chargeBase.foreign);
        check("authorizeCharge unknown format denied UnknownPaymentFormat",
                authKind(unkCharge, chargeAppr, ALG, approverPk, chargeApprSig, "payer-1", chargeBase.notAfter),
                "UnknownPaymentFormat");

        // deny path 2a: a wrong-amount charge yields a different charge content-id (ApprovalMismatch).
        Payment.PaymentImport wrongAmountCharge = new Payment.PaymentImport(chargeBase.format, chargeBase.amount + 8000,
                chargeBase.currency, chargeBase.payee, chargeBase.notAfter, chargeBase.foreign);
        check("authorizeCharge wrong-amount denied ApprovalMismatch",
                authKind(wrongAmountCharge, chargeAppr, ALG, approverPk, chargeApprSig, "payer-1", chargeBase.notAfter),
                "ApprovalMismatch");

        // deny path 2b: a wrong-payee charge likewise fails the binding.
        Payment.PaymentImport wrongPayeeCharge = new Payment.PaymentImport(chargeBase.format, chargeBase.amount,
                chargeBase.currency, "merchant:evil-store".getBytes(StandardCharsets.UTF_8), chargeBase.notAfter,
                chargeBase.foreign);
        check("authorizeCharge wrong-payee denied ApprovalMismatch",
                authKind(wrongPayeeCharge, chargeAppr, ALG, approverPk, chargeApprSig, "payer-1", chargeBase.notAfter),
                "ApprovalMismatch");

        // deny path 2c: a substituted foreign payload changes the foreign content-id, hence the binding.
        Payment.PaymentImport substitutedCharge = new Payment.PaymentImport(chargeBase.format, chargeBase.amount,
                chargeBase.currency, chargeBase.payee, chargeBase.notAfter, Hex.decode(field(mm, "substituted_foreign_hex")));
        check("authorizeCharge substituted-foreign denied ApprovalMismatch",
                authKind(substitutedCharge, chargeAppr, ALG, approverPk, chargeApprSig, "payer-1", chargeBase.notAfter),
                "ApprovalMismatch");

        // deny path 2d: a foreign key never authenticates the approval (BadSignature).
        check("authorizeCharge foreign-key denied BadSignature",
                authKind(chargeBase, chargeAppr, ALG, foreignPk, chargeApprSig, "payer-1", chargeBase.notAfter),
                "BadSignature");

        // deny path 2e: an expired charge is rejected (ApprovalExpired).
        check("authorizeCharge expired denied ApprovalExpired",
                authKind(chargeBase, chargeAppr, ALG, approverPk, chargeApprSig, "payer-1", chargeBase.notAfter + 1),
                "ApprovalExpired");

        // deny path 3: an under-granting approval (read_only cannot authorize a non_idempotent_write
        // charge) is denied ApprovalRequired.
        byte[] underNonce = new byte[16];
        java.util.Arrays.fill(underNonce, (byte) 0x03);
        Approval.ApprovalRecord underAppr = new Approval.ApprovalRecord(chargeCid, "approver-A",
                Policy.READ_ONLY, underNonce, chargeBase.notAfter);
        byte[] underSig = Approval.signApproval(underAppr, ALG, approverSeed);
        check("authorizeCharge under-granting denied ApprovalRequired",
                authKind(chargeBase, underAppr, ALG, approverPk, underSig, "payer-1", chargeBase.notAfter),
                "ApprovalRequired");
    }

    /** Runs {@link Payment#authorizeCharge} against a fresh, empty ledger and returns the error kind, or
     * "no-error" on success (used for the deny-path grading above, where each call must not be able to
     * see another call's ledger state). */
    private static String authKind(Payment.PaymentImport p, Approval.ApprovalRecord appr, int approverAlg,
            byte[] approverPk, byte[] apprSig, String by, long now) throws Exception {
        Path wal = Files.createTempFile("naalp-pay-charge-deny-", ".wal");
        wal.toFile().deleteOnExit();
        Files.deleteIfExists(wal);
        Approval.Ledger ledger = Approval.Ledger.open(wal);
        try {
            Payment.authorizeCharge(p, appr, approverAlg, approverPk, apprSig, by, now, ledger);
            return "no-error";
        } catch (NaalpException e) {
            return e.kind;
        } finally {
            ledger.close();
        }
    }

    public static void main(String[] args) throws Exception {
        System.out.println("payment conformance (Java) — graded vs vectors/payment/cases.json");
        run();
        System.out.println(fails == 0 ? "PaymentKatTest: PASS" : "PaymentKatTest: FAIL (" + fails + ")");
        System.exit(fails == 0 ? 0 : 1);
    }
}
