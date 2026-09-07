// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * C6 approval known-answer test for the Java SDK (design.md §7; R-7.1..7.4), graded against the
 * shared independent corpus vectors/approval/cases.json (NOT produced by this code): the approval
 * body + content id, the durable hash-chained single-use consume ledger (entry bytes, per-entry
 * head_after, final head, and the fail-closed AlreadyConsumed on a second consume), and the expiry /
 * mismatch / bad-signature rejections.
 *
 * <p>CORPUS-GRADED (pure bytes / verdicts): every approval body and id, every ledger entry body and
 * head_after, the final chain head, and the AlreadyConsumed rejection — reproduced byte-for-byte or
 * verdict-for-verdict from the corpus. SECURITY-CRITICAL, DEMONSTRATED IN ISOLATION: the single-use
 * consume is proven ATOMIC (not merely sequential) by racing 16 concurrent consumers of one id and
 * observing exactly one winner and a ledger length of 1 — the single-writer lock serialises the
 * compare-and-set so there is no read-then-write TOCTOU window; and the approval signature is real
 * FIPS-204 ML-DSA-65 (via BouncyCastle) whose expiry/mismatch/bad-signature paths reject fail-closed.
 *
 * <p>WAVE-C ADDITIONS (T1.5 NAALP-REQ-121 + R-TDCS-3/4/5, design.md §7.5/§25): the ledger-signed
 * {@code ConsumeReceipt} (graded against the SEPARATE independent corpus vectors/consume_receipt/
 * cases.json), {@code Ledger.openLedgerSigned}/{@code consumeWithReceipt} (including the
 * first-append-wins compare-and-set mutation anchor and an exactly-once-under-race grader),
 * {@code ConsumeForkEvidence}/{@code ReceiptSet} (same-ledger and cross-ledger double-spend proofs),
 * the R-TDCS-5 approval audience binding and the R-TDCS-3 party-visible coarse {@code Refusal} object
 * (both graded against vectors/trust_decision/cases.json), and R-TDCS-4 freshness independence.
 *
 * <p>KAT convention (a standalone {@code main} exiting non-zero on any failure); named "…KatTest" so
 * the filename carries the "test" token the ten-language-parity gate indexes. Written test-first:
 * {@link Approval} is absent until Approval.java lands, so this fails RED with a javac "cannot find
 * symbol Approval"; the recorded mutation makes {@code Ledger.consume} always append (drops the
 * AlreadyConsumed guard), which flips the named "second consume of approval A rejected
 * AlreadyConsumed" check and the atomic-single-use race.
 */
public final class ApprovalKatTest {
    private static int fails = 0;

    private static void check(String name, String got, String want) {
        if (got.equals(want)) {
            System.out.println("  ok   " + name);
        } else {
            fails++;
            System.out.println("  FAIL " + name + "\n       got  " + got + "\n       want " + want);
        }
    }

    // ---- nesting-aware JSON access (Java has no JSON library; the corpus has nested objects,
    //      nested arrays, and braces inside string values, so the matcher skips quoted strings) ----

    private static Path findVector() {
        Path d = Path.of(System.getProperty("user.dir")).toAbsolutePath();
        for (int i = 0; i < 6 && d != null; i++) {
            Path p = d.resolve("vectors").resolve("approval").resolve("cases.json");
            if (Files.isRegularFile(p)) {
                return p;
            }
            d = d.getParent();
        }
        throw new AssertionError("vectors/approval/cases.json not found from " + System.getProperty("user.dir"));
    }

    /** Index just past the '{'/'[' at {@code open}'s match, skipping over double-quoted strings. */
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

    /** The inner content (braces stripped) of the object value that follows "key":. */
    private static String objBlock(String s, String key) {
        int open = s.indexOf('{', afterKey(s, key));
        int close = matchClose(s, open);
        return s.substring(open + 1, close - 1);
    }

    /** The inner content (brackets stripped) of the array value that follows "key":. */
    private static String arrayBlock(String s, String key) {
        int open = s.indexOf('[', afterKey(s, key));
        int close = matchClose(s, open);
        return s.substring(open + 1, close - 1);
    }

    /** The top-level {@code { ... }} object blocks (inner content) inside an array body. */
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

    private static boolean hasKey(String scope, String key) {
        return Pattern.compile("\"" + key + "\"\\s*:").matcher(scope).find();
    }

    private static long intField(String scope, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*(\\d+)").matcher(scope);
        if (!m.find()) {
            throw new AssertionError("int key not found: " + key);
        }
        return Long.parseLong(m.group(1));
    }

    /** The named kind thrown by {@code r}, or "no-error". */
    private static String errKind(Runnable r) {
        try {
            r.run();
            return "no-error";
        } catch (NaalpException e) {
            return e.kind;
        }
    }

    /** Like {@link #errKind}, but also recognizes {@link Approval.ConsumeForkDetected} -- it cannot
     * extend NaalpException (NaalpException is {@code final}) -- so fork-set assertions share the same
     * PASS/FAIL idiom as every other check in this file. */
    private static String errKindAny(Runnable r) {
        try {
            r.run();
            return "no-error";
        } catch (NaalpException e) {
            return e.kind;
        } catch (Approval.ConsumeForkDetected e) {
            return e.kind;
        }
    }

    private static final int ALG = Cose.ALG_MLDSA65;

    private static Path tempLedger() throws Exception {
        Path p = Files.createTempFile("naalp-approval-waveB-", ".wal");
        p.toFile().deleteOnExit();
        Files.deleteIfExists(p); // start with a clean (absent) WAL so the first consume is seq 0
        return p;
    }

    /** Locates vectors/{@code subdir}/cases.json by walking up from the working directory (mirrors
     * {@link #findVector}, generalized to the WAVE-C corpora consume_receipt/ and trust_decision/). */
    private static Path findVectorNamed(String subdir) {
        Path d = Path.of(System.getProperty("user.dir")).toAbsolutePath();
        for (int i = 0; i < 6 && d != null; i++) {
            Path p = d.resolve("vectors").resolve(subdir).resolve("cases.json");
            if (Files.isRegularFile(p)) {
                return p;
            }
            d = d.getParent();
        }
        throw new AssertionError("vectors/" + subdir + "/cases.json not found from " + System.getProperty("user.dir"));
    }

    /** An unsigned-64-bit integer field, via {@link Long#parseUnsignedLong} -- {@code position} in the
     * consume-receipt corpus ranges up to 2^64-1, beyond {@code Long.parseLong}'s signed range. */
    private static long longField(String scope, String key) {
        // R12 (NAALP-01-03): a 64-bit position above 2^53 is carried as a decimal STRING so a float64
        // decoder cannot round it; the optional quotes accept both `"position": 5` and `"position": "N"`.
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*\"?(\\d+)\"?").matcher(scope);
        if (!m.find()) {
            throw new AssertionError("int key not found: " + key);
        }
        return Long.parseUnsignedLong(m.group(1));
    }

    /** A {@link Approval.ConsumeReceipt} built from a consume-receipt corpus object scope
     * ({@code {ledger_hex, approval_id_hex, position, ...}}). */
    private static Approval.ConsumeReceipt crFromScope(String scope) {
        return new Approval.ConsumeReceipt(
                Hex.decode(field(scope, "ledger_hex")),
                Hex.decode(field(scope, "approval_id_hex")),
                longField(scope, "position"));
    }

    /** A 32-byte all-{@code b} seed, matching the reference test fixtures' {@code seedByte} keys. */
    private static byte[] seedOf(byte b) {
        byte[] seed = new byte[32];
        Arrays.fill(seed, b);
        return seed;
    }

    /** Plain byte-substring search (no charset assumptions), used by the R-TDCS-3 no-leak checks. */
    private static boolean containsBytes(byte[] haystack, byte[] needle) {
        if (needle.length == 0) {
            return true;
        }
        outer:
        for (int i = 0; i + needle.length <= haystack.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }

    private static void run() throws Exception {
        String json = Files.readString(findVector(), StandardCharsets.UTF_8);

        // 1. the approval body + content id reproduce the oracle for every approval in the corpus.
        List<String> approvalBlocks = splitObjects(arrayBlock(json, "approvals"));
        for (String ab : approvalBlocks) {
            Approval.ApprovalRecord rec = new Approval.ApprovalRecord(
                    Hex.decode(field(ab, "approves_hex")), field(ab, "approver"),
                    intField(ab, "grant"), Hex.decode(field(ab, "nonce_hex")), intField(ab, "not_after"));
            String name = field(ab, "name");
            check("approval " + name + " body == oracle", Hex.encode(rec.bytes()), field(ab, "record_hex"));
            check("approval " + name + " id == oracle", Hex.encode(rec.id()), field(ab, "approval_id_hex"));
        }

        // 2. the durable hash-chained single-use consume ledger reproduces every entry body + head,
        //    and a second consume of an already-consumed id is rejected AlreadyConsumed (fail-closed).
        String ledgerScope = objBlock(json, "ledger");
        check("ledger genesis head width == HEAD_SIZE",
                Integer.toString(Hex.decode(field(ledgerScope, "genesis_head_hex")).length),
                Integer.toString(Approval.HEAD_SIZE));
        check("ledger genesis head is all-zero",
                field(ledgerScope, "genesis_head_hex"),
                Hex.encode(new byte[Approval.HEAD_SIZE]));

        Approval.Ledger ledger = Approval.Ledger.open(tempLedger());
        for (String cb : splitObjects(arrayBlock(ledgerScope, "consumes"))) {
            byte[] aid = Hex.decode(field(cb, "approval_id_hex"));
            String by = field(cb, "by");
            String expect = field(cb, "expect");
            if (expect.equals("ok")) {
                long seq = intField(cb, "seq");
                Approval.LedgerEntry e = ledger.consume(aid, by);
                check("consume seq=" + seq + " entry == oracle", Hex.encode(e.bytes()), field(cb, "entry_hex"));
                check("consume seq=" + seq + " head_after == oracle", Hex.encode(e.head()), field(cb, "head_after_hex"));
                check("consume seq=" + seq + " ledger head == oracle", Hex.encode(ledger.head()), field(cb, "head_after_hex"));
            } else {
                // the second consume of approval A's id (by a different consumer) MUST fail closed.
                check("second consume of an already-consumed id rejected " + expect,
                        errKind(() -> ledger.consume(aid, by)), expect);
            }
        }
        check("final ledger head == oracle", Hex.encode(ledger.head()), field(ledgerScope, "final_head_hex"));
        check("ledger consumed count == 2", Integer.toString(ledger.len()), "2");
        ledger.close();

        // 3. expiry / mismatch / bad-signature — real FIPS-204 ML-DSA-65 in isolation (the corpus
        //    carries no signature vector; the sign/verify is demonstrated, the verdicts are the point).
        String args = objBlock(json, "args");
        byte[] argsId = Hex.decode(field(args, "content_id_hex"));
        String a0 = approvalBlocks.get(0);
        Approval.ApprovalRecord recA = new Approval.ApprovalRecord(
                Hex.decode(field(a0, "approves_hex")), field(a0, "approver"),
                intField(a0, "grant"), Hex.decode(field(a0, "nonce_hex")), intField(a0, "not_after"));
        byte[] zeroSeed = new byte[32];
        byte[] pk = Cose.mldsaKeygen("ML-DSA-65", zeroSeed);
        byte[] sig = Approval.signApproval(recA, ALG, zeroSeed);
        String expiry = objBlock(json, "expiry");
        long validAt = intField(expiry, "valid_at");
        long expiredAt = intField(expiry, "expired_at");
        check("approve A binds the corpus args id", Hex.encode(recA.approves), Hex.encode(argsId));
        check("valid approval verifies at valid_at",
                errKind(() -> Approval.verifyApproval(recA, ALG, pk, sig, argsId, validAt)), "no-error");
        check("expired approval rejected at expired_at",
                errKind(() -> Approval.verifyApproval(recA, ALG, pk, sig, argsId, expiredAt)), "ApprovalExpired");
        byte[] wrongArgs = Hex.decode(field(objBlock(json, "mismatch"), "wrong_args_id_hex"));
        check("mismatched args rejected ApprovalMismatch",
                errKind(() -> Approval.verifyApproval(recA, ALG, pk, sig, wrongArgs, validAt)), "ApprovalMismatch");
        byte[] badSig = sig.clone();
        badSig[badSig.length - 1] ^= 1;
        check("tampered signature rejected BadSignature",
                errKind(() -> Approval.verifyApproval(recA, ALG, pk, badSig, argsId, validAt)), "BadSignature");
        check("empty signature rejected BadSignature",
                errKind(() -> Approval.verifyApproval(recA, ALG, pk, new byte[0], argsId, validAt)), "BadSignature");

        // 4. ATOMIC single-use: 16 threads race to consume ONE id; exactly one wins, the ledger holds
        //    exactly one entry. With the single-writer lock the compare-and-set is serialised (no
        //    read-then-write TOCTOU); a consume that always appends would let several win (the mutation).
        Approval.Ledger race = Approval.Ledger.open(tempLedger());
        byte[] raceId = recA.id();
        int n = 16;
        AtomicInteger wins = new AtomicInteger(0);
        AtomicInteger already = new AtomicInteger(0);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(n);
        List<Thread> threads = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            final int id = i;
            Thread t = new Thread(() -> {
                try {
                    start.await();
                    try {
                        race.consume(raceId, "racer-" + id);
                        wins.incrementAndGet();
                    } catch (NaalpException e) {
                        if (e.kind.equals("AlreadyConsumed")) {
                            already.incrementAndGet();
                        }
                    }
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            });
            threads.add(t);
            t.start();
        }
        start.countDown();
        done.await();
        check("atomic single-use: exactly one of " + n + " concurrent consumers wins",
                Integer.toString(wins.get()), "1");
        check("atomic single-use: the other " + (n - 1) + " get AlreadyConsumed",
                Integer.toString(already.get()), Integer.toString(n - 1));
        check("atomic single-use: ledger holds exactly one entry", Integer.toString(race.len()), "1");
        race.close();

        // 5. the §7.4 held (not-yet-granted) outcome is a distinct, deterministic, decodable object.
        Approval.HeldResult held = new Approval.HeldResult(argsId, "awaiting approver B");
        byte[] hb = held.bytes();
        check("held result round-trips through the strict decoder",
                Hex.encode(Cbor.encode(Cbor.decode(hb))), Hex.encode(hb));
        check("held result is a 2-field map",
                Integer.toString(((Cbor.M) Cbor.decode(hb)).pairs.size()), "2");

        // ==== WAVE-C: T1.5 (NAALP-REQ-121) ledger-signed consume receipt + R-TDCS-3/4/5 ============

        // 6. every consume-receipt body (base + sequence + every fork's a/b) reproduces the
        //    independent oracle (⟹ Go == Rust == Java bytes).
        String crJson = Files.readString(findVectorNamed("consume_receipt"), StandardCharsets.UTF_8);
        String baseScope = objBlock(crJson, "base");
        List<String> crForkBlocks = splitObjects(arrayBlock(crJson, "forks"));
        List<String> crAll = new ArrayList<>();
        crAll.add(baseScope);
        crAll.addAll(splitObjects(arrayBlock(crJson, "sequence")));
        for (String fb : crForkBlocks) {
            crAll.add(objBlock(fb, "a"));
            crAll.add(objBlock(fb, "b"));
        }
        for (String rb : crAll) {
            check("consume-receipt body == oracle", Hex.encode(crFromScope(rb).bytes()), field(rb, "body_hex"));
        }

        // 7. sign/verify: a ledger-signed receipt verifies under the ledger key (REQ-121); an unnamed
        //    ledger, a tampered signature, and the wrong ledger key are each rejected fail-closed.
        byte[] ledgerSeed0x51 = seedOf((byte) 0x51);
        byte[] ledgerPk0x51 = Cose.mldsaKeygen("ML-DSA-65", ledgerSeed0x51);
        Approval.ConsumeReceipt crBase = crFromScope(baseScope);
        byte[] crSig = Approval.signConsumeReceipt(crBase, ALG, ledgerSeed0x51);
        check("valid ledger-signed receipt verifies",
                errKind(() -> Approval.verifyConsumeReceipt(crBase, ALG, ledgerPk0x51, crSig)), "no-error");
        Approval.ConsumeReceipt crUnnamed = new Approval.ConsumeReceipt(new byte[0], crBase.approvalId, crBase.position);
        check("unnamed-ledger receipt rejected",
                errKind(() -> Approval.verifyConsumeReceipt(crUnnamed, ALG, ledgerPk0x51, crSig)), "ConsumeReceiptUnsigned");
        byte[] tamperedCrSig = crSig.clone();
        tamperedCrSig[tamperedCrSig.length - 1] ^= 1;
        check("tampered receipt signature rejected",
                errKind(() -> Approval.verifyConsumeReceipt(crBase, ALG, ledgerPk0x51, tamperedCrSig)), "ConsumeReceiptUnsigned");
        byte[] otherLedgerPk = Cose.mldsaKeygen("ML-DSA-65", seedOf((byte) 0x52));
        check("wrong ledger key rejected",
                errKind(() -> Approval.verifyConsumeReceipt(crBase, ALG, otherLedgerPk, crSig)), "ConsumeReceiptUnsigned");

        // 8. wire cases: keys out of order -> NonCanonical; the canonical variant decodes cleanly;
        //    position too large (2^53 and 2^64-1) round-trips as a 64-bit uint; empty-ledger body
        //    matches the oracle and is verify-rejected fail-closed; empty != absent.
        String wireScope = objBlock(crJson, "wire");
        String koo = objBlock(wireScope, "keys_out_of_order");
        byte[] noncanon = Hex.decode(field(koo, "payload_hex"));
        check("keys-out-of-order receipt body rejected NonCanonical",
                errKind(() -> Cbor.decode(noncanon)), "NonCanonical");
        byte[] canonPayload = Hex.decode(field(koo, "canonical_payload_hex"));
        check("canonical receipt body decodes cleanly",
                errKind(() -> Cbor.decode(canonPayload)), "no-error");
        for (String big : splitObjects(arrayBlock(wireScope, "position_too_large"))) {
            long pos = longField(big, "position");
            Approval.ConsumeReceipt r = new Approval.ConsumeReceipt(
                    Hex.decode(field(baseScope, "ledger_hex")), Hex.decode(field(baseScope, "approval_id_hex")), pos);
            String bigName = field(big, "name");
            check("position " + bigName + " encode == oracle", Hex.encode(r.bytes()), field(big, "body_hex"));
            Cbor.Value decoded = Cbor.decode(Hex.decode(field(big, "body_hex")));
            if (!(decoded instanceof Cbor.M dm)) {
                throw new AssertionError(bigName + ": decoded body is not a map");
            }
            Long gotPos = null;
            for (Cbor.Pair p : dm.pairs) {
                if (p.k instanceof Cbor.U ku && ku.v == 3 && p.val instanceof Cbor.U pu) {
                    gotPos = pu.v;
                }
            }
            check("position " + bigName + " round-trip",
                    gotPos == null ? "missing" : Long.toUnsignedString(gotPos), Long.toUnsignedString(pos));
        }
        String emptyLedgerScope = objBlock(wireScope, "empty_ledger");
        Approval.ConsumeReceipt emptyLedgerReceipt = new Approval.ConsumeReceipt(
                new byte[0], Hex.decode(field(emptyLedgerScope, "approval_id_hex")), longField(emptyLedgerScope, "position"));
        check("empty-ledger receipt body == oracle", Hex.encode(emptyLedgerReceipt.bytes()), field(emptyLedgerScope, "body_hex"));
        byte[] throwawaySig = new byte[3309]; // ML-DSA-65 signature size; rejected on the unnamed-ledger check first
        check("empty-ledger receipt verify-rejected fail-closed",
                errKind(() -> Approval.verifyConsumeReceipt(emptyLedgerReceipt, ALG, ledgerPk0x51, throwawaySig)), "ConsumeReceiptUnsigned");
        String absentLedgerScope = objBlock(wireScope, "absent_ledger");
        check("empty-ledger body != absent-ledger body (empty != absent)",
                Boolean.toString(!field(emptyLedgerScope, "body_hex").equals(field(absentLedgerScope, "body_hex"))), "true");

        // 9. T1.5 OpenLedgerSigned + ConsumeWithReceipt -- the compare-and-set MUTATION anchor. On one
        //    signed ledger, consuming approval X twice yields exactly ONE receipt (position 0); the
        //    second throws AlreadyConsumed and mints nothing (first-append-wins).
        byte[] ledgerAId = Hex.decode(field(objBlock(crJson, "ledgers"), "a_hex"));
        byte[] ledgerBId = Hex.decode(field(objBlock(crJson, "ledgers"), "b_hex"));
        byte[] approvalX = Hex.decode(field(objBlock(crJson, "approvals"), "x_hex"));
        byte[] ledgerSeed0x41 = seedOf((byte) 0x41);
        byte[] ledgerPk0x41 = Cose.mldsaKeygen("ML-DSA-65", ledgerSeed0x41);
        Approval.Ledger casLedger = Approval.Ledger.openLedgerSigned(tempLedger(), ledgerAId, ALG, ledgerSeed0x41);
        Approval.ConsumeWithReceiptResult firstCr = casLedger.consumeWithReceipt(approvalX, "requester");
        check("first consume seq == 0", Long.toString(firstCr.entry.seq), "0");
        check("first receipt position == 0", Long.toString(firstCr.receipt.position), "0");
        check("second consume of the same approval id rejected AlreadyConsumed (first-append-wins)",
                errKind(() -> casLedger.consumeWithReceipt(approvalX, "requester")), "AlreadyConsumed");
        check("ledger has exactly one entry after the CAS", Integer.toString(casLedger.len()), "1");
        casLedger.close();

        // 10. exactly-once under race: N threads call consumeWithReceipt for the same approval id
        //     concurrently on ONE signed ledger; exactly one wins and mints exactly one receipt, the
        //     rest get AlreadyConsumed, and the fork detector sees no fork from the sole winner.
        Approval.Ledger raceCr = Approval.Ledger.openLedgerSigned(tempLedger(), ledgerAId, ALG, ledgerSeed0x41);
        int nCr = 32;
        AtomicInteger crWins = new AtomicInteger(0);
        AtomicInteger crAlready = new AtomicInteger(0);
        CountDownLatch crStart = new CountDownLatch(1);
        CountDownLatch crDone = new CountDownLatch(nCr);
        List<Approval.ConsumeWithReceiptResult> crWinners = Collections.synchronizedList(new ArrayList<>());
        List<Thread> crThreads = new ArrayList<>();
        for (int i = 0; i < nCr; i++) {
            Thread t = new Thread(() -> {
                try {
                    crStart.await();
                    try {
                        crWinners.add(raceCr.consumeWithReceipt(approvalX, "requester"));
                        crWins.incrementAndGet();
                    } catch (NaalpException e) {
                        if (e.kind.equals("AlreadyConsumed")) {
                            crAlready.incrementAndGet();
                        }
                    }
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                } finally {
                    crDone.countDown();
                }
            });
            crThreads.add(t);
            t.start();
        }
        crStart.countDown();
        crDone.await();
        check("consumeWithReceipt exactly-once: 1 of " + nCr + " concurrent consumers wins",
                Integer.toString(crWins.get()), "1");
        check("consumeWithReceipt exactly-once: the other " + (nCr - 1) + " get AlreadyConsumed",
                Integer.toString(crAlready.get()), Integer.toString(nCr - 1));
        check("consumeWithReceipt exactly-once: ledger holds exactly one entry", Integer.toString(raceCr.len()), "1");
        Approval.ConsumeWithReceiptResult soleWinner = crWinners.get(0);
        Approval.ReceiptSet soleRs = Approval.ReceiptSet.newReceiptSet(
                id -> Arrays.equals(id, ledgerAId) ? new Approval.LedgerVerifierKey(ALG, ledgerPk0x41) : null);
        check("the sole winning receipt is not a fork with itself",
                errKindAny(() -> soleRs.observe(soleWinner.receipt, soleWinner.sig)), "no-error");
        raceCr.close();

        // 11. ConsumeForkEvidence + ReceiptSet: two ledger-signed receipts for the SAME approval id at
        //     DIFFERENT positions, signed by the SAME ledger key (a partition), are detected as a
        //     fork; the evidence carries both positions and verifies as a non-repudiable double-spend
        //     proof. A byte-identical re-emission is a benign duplicate, never flagged.
        String forkScope = null;
        for (String fb : crForkBlocks) {
            if (field(fb, "name").equals("same_ledger_diff_position")) {
                forkScope = fb;
            }
        }
        if (forkScope == null) {
            throw new AssertionError("same_ledger_diff_position fork case missing from oracle");
        }
        check("same_ledger_diff_position case marked fork in the oracle", field(forkScope, "expect"), "fork");
        Approval.ConsumeReceipt forkA = crFromScope(objBlock(forkScope, "a"));
        Approval.ConsumeReceipt forkB = crFromScope(objBlock(forkScope, "b"));
        byte[] sigForkA = Approval.signConsumeReceipt(forkA, ALG, ledgerSeed0x41);
        byte[] sigForkB = Approval.signConsumeReceipt(forkB, ALG, ledgerSeed0x41);
        Approval.LedgerKeyResolver resolveA = id -> Arrays.equals(id, ledgerAId) ? new Approval.LedgerVerifierKey(ALG, ledgerPk0x41) : null;
        Approval.ReceiptSet forkRs = Approval.ReceiptSet.newReceiptSet(resolveA);
        check("first fork receipt observed cleanly (not yet a fork)",
                errKindAny(() -> forkRs.observe(forkA, sigForkA)), "no-error");
        Approval.ConsumeForkEvidence fe = null;
        try {
            forkRs.observe(forkB, sigForkB);
        } catch (Approval.ConsumeForkDetected fd) {
            fe = fd.evidence;
        }
        check("second fork receipt detected as ConsumeFork", fe == null ? "no-error" : "ConsumeFork", "ConsumeFork");
        if (fe == null) {
            throw new AssertionError("fork not detected on same approval id / different positions");
        }
        check("fork evidence hides no position conflict (positions differ)",
                Boolean.toString(fe.a.position != fe.b.position), "true");
        Approval.ConsumeForkEvidence feFinal = fe;
        check("fork evidence verifies as a non-repudiable double-spend proof",
                errKind(() -> feFinal.verify(resolveA)), "no-error");
        Approval.ReceiptSet benignRs = Approval.ReceiptSet.newReceiptSet(resolveA);
        benignRs.observe(forkA, sigForkA);
        check("byte-identical re-emission is a benign duplicate, never flagged",
                errKindAny(() -> benignRs.observe(forkA, sigForkA)), "no-error");

        // 12. cross-ledger fork: two DIFFERENT ledgers each sign a receipt for the SAME approval id (a
        //     single-use approval spent twice), consumed concurrently on independent ledgers; each
        //     succeeds locally, and comparing the two receipts surfaces the fork.
        byte[] ledgerSeed0x42 = seedOf((byte) 0x42);
        byte[] ledgerPk0x42 = Cose.mldsaKeygen("ML-DSA-65", ledgerSeed0x42);
        Approval.Ledger lA = Approval.Ledger.openLedgerSigned(tempLedger(), ledgerAId, ALG, ledgerSeed0x41);
        Approval.Ledger lB = Approval.Ledger.openLedgerSigned(tempLedger(), ledgerBId, ALG, ledgerSeed0x42);
        List<Approval.ConsumeWithReceiptResult> crossResults = Collections.synchronizedList(new ArrayList<>());
        Thread ta = new Thread(() -> crossResults.add(lA.consumeWithReceipt(approvalX, "requester")));
        Thread tb = new Thread(() -> crossResults.add(lB.consumeWithReceipt(approvalX, "requester")));
        ta.start();
        tb.start();
        ta.join();
        tb.join();
        check("cross-ledger: both independent consumes succeeded", Integer.toString(crossResults.size()), "2");
        Approval.LedgerKeyResolver crossResolve = id -> {
            if (Arrays.equals(id, ledgerAId)) {
                return new Approval.LedgerVerifierKey(ALG, ledgerPk0x41);
            }
            if (Arrays.equals(id, ledgerBId)) {
                return new Approval.LedgerVerifierKey(ALG, ledgerPk0x42);
            }
            return null;
        };
        Approval.ReceiptSet crossRs = Approval.ReceiptSet.newReceiptSet(crossResolve);
        Approval.ConsumeForkEvidence crossFe = null;
        for (Approval.ConsumeWithReceiptResult res : crossResults) {
            try {
                crossRs.observe(res.receipt, res.sig);
            } catch (Approval.ConsumeForkDetected fd) {
                crossFe = fd.evidence;
            }
        }
        if (crossFe == null) {
            throw new AssertionError("cross-ledger double spend not detected");
        }
        check("cross-ledger fork evidence names two distinct ledgers",
                Boolean.toString(!Arrays.equals(crossFe.a.ledger, crossFe.b.ledger)), "true");
        Approval.ConsumeForkEvidence crossFeFinal = crossFe;
        check("cross-ledger fork evidence verifies",
                errKind(() -> crossFeFinal.verify(crossResolve)), "no-error");
        lA.close();
        lB.close();

        // 13. R-TDCS-5 audience: an approval naming an audience encodes byte-identically to the
        //     oracle; naming NO audience encodes byte-identically to a 5-field approval; VerifyAudience
        //     enforces the binding (mismatch rejected, absent passes any context).
        String tdcsJson = Files.readString(findVectorNamed("trust_decision"), StandardCharsets.UTF_8);
        String audScope = objBlock(tdcsJson, "audience");
        byte[] audApproves = Hex.decode(field(audScope, "approves_hex"));
        String audApprover = field(audScope, "approver");
        long audGrant = intField(audScope, "grant");
        byte[] audNonce = Hex.decode(field(audScope, "nonce_hex"));
        long audNotAfter = intField(audScope, "not_after");
        String useContextMatch = field(audScope, "use_context_match");
        String useContextMismatch = field(audScope, "use_context_mismatch");
        for (String cb : splitObjects(arrayBlock(audScope, "cases"))) {
            Approval.ApprovalRecord rec = new Approval.ApprovalRecord(
                    audApproves, audApprover, audGrant, audNonce, audNotAfter, field(cb, "audience"));
            String name = field(cb, "name");
            check("audience " + name + " record == oracle", Hex.encode(rec.bytes()), field(cb, "record_hex"));
            check("audience " + name + " id == oracle", Hex.encode(rec.id()), field(cb, "approval_id_hex"));
        }
        Approval.ApprovalRecord audPresent = new Approval.ApprovalRecord(audApproves, audApprover, audGrant, audNonce, audNotAfter, useContextMatch);
        Approval.ApprovalRecord audAbsent = new Approval.ApprovalRecord(audApproves, audApprover, audGrant, audNonce, audNotAfter);
        check("naming an audience changes the approval bytes",
                Boolean.toString(!Hex.encode(audPresent.bytes()).equals(Hex.encode(audAbsent.bytes()))), "true");
        check("matching audience verifies", errKind(() -> Approval.verifyAudience(audPresent, useContextMatch)), "no-error");
        check("mismatched audience rejected AudienceMismatch",
                errKind(() -> Approval.verifyAudience(audPresent, useContextMismatch)), "AudienceMismatch");
        check("an approval naming no audience passes any use context",
                errKind(() -> Approval.verifyAudience(audAbsent, useContextMismatch)), "no-error");

        // 14. R-TDCS-3 refusal: RefusalFromRecord yields the exact oracle bytes for each closed-set
        //     outcome, carries the full record's content id, and NEVER carries the record's
        //     discriminating detail. ParseRefusal round-trips a conformant refusal and rejects every
        //     non-conformant shape: an unknown outcome, an extra field, a missing/empty record id.
        String refScope = objBlock(tdcsJson, "refusal");
        byte[] fullRecord = Hex.decode(field(refScope, "full_record_hex"));
        byte[] fullRecordId = Hex.decode(field(refScope, "full_record_id_hex"));
        byte[] leakedReasonBytes = field(refScope, "leaked_reason").getBytes(StandardCharsets.UTF_8);
        for (String cb : splitObjects(arrayBlock(refScope, "cases"))) {
            long outcome = intField(cb, "outcome");
            Approval.Refusal ref = Approval.refusalFromRecord(outcome, fullRecord);
            byte[] rb = ref.bytes();
            String name = field(cb, "name");
            check("refusal " + name + " bytes == oracle", Hex.encode(rb), field(cb, "record_hex"));
            check("refusal " + name + " does not leak the record's reason",
                    Boolean.toString(!containsBytes(rb, leakedReasonBytes)), "true");
            check("refusal " + name + " carries the full-record content id",
                    Boolean.toString(containsBytes(rb, fullRecordId)), "true");
            Approval.Refusal parsed = Approval.parseRefusal(rb);
            check("refusal " + name + " round-trips outcome", Long.toString(parsed.outcome), Long.toString(outcome));
            check("refusal " + name + " round-trips record id", Hex.encode(parsed.record), Hex.encode(fullRecordId));
        }
        String rejScope = objBlock(refScope, "reject");
        check("unknown refusal outcome rejected",
                errKind(() -> Approval.parseRefusal(Hex.decode(field(rejScope, "unknown_outcome_hex")))), "UnknownRefusalOutcome");
        check("extra field (leaked detail) rejected",
                errKind(() -> Approval.parseRefusal(Hex.decode(field(rejScope, "detail_leak_extra_field_hex")))), "RefusalDetailLeak");
        check("missing record id rejected",
                errKind(() -> Approval.parseRefusal(Hex.decode(field(rejScope, "missing_record_hex")))), "RefusalDetailLeak");
        check("empty record id rejected",
                errKind(() -> Approval.parseRefusal(Hex.decode(field(rejScope, "empty_record_hex")))), "RefusalDetailLeak");
        check("isKnownRefusalOutcome(denied=0)", Boolean.toString(Approval.isKnownRefusalOutcome(0)), "true");
        check("isKnownRefusalOutcome(held=1)", Boolean.toString(Approval.isKnownRefusalOutcome(1)), "true");
        check("isKnownRefusalOutcome(unverifiable=2)", Boolean.toString(Approval.isKnownRefusalOutcome(2)), "true");
        check("isKnownRefusalOutcome(3) is outside the closed set", Boolean.toString(Approval.isKnownRefusalOutcome(3)), "false");

        // 15. R-TDCS-4 freshness independence: a distinct ordering authority verifies; self-asserted
        //     freshness (party == ledger) is rejected FreshnessSelfAsserted -- the load-bearing
        //     distinctness the closure property requires; the distinctness check does not weaken the
        //     underlying checks (an expired approval still fails under a distinct authority); an
        //     unnamed ordering authority is not accepted as freshness evidence.
        byte[] approverSeed0x11 = seedOf((byte) 0x11);
        byte[] approverPk0x11 = Cose.mldsaKeygen("ML-DSA-65", approverSeed0x11);
        byte[] freshLedgerSeed0x22 = seedOf((byte) 0x22);
        byte[] freshLedgerPk0x22 = Cose.mldsaKeygen("ML-DSA-65", freshLedgerSeed0x22);
        byte[] freshArgsId = "the-exact-canonical-args-content-id".getBytes(StandardCharsets.UTF_8);
        byte[] freshApproverId = "approver-authenticated-party-id".getBytes(StandardCharsets.UTF_8);
        byte[] freshLedgerId = "ordering-authority-ledger-id".getBytes(StandardCharsets.UTF_8);
        Approval.ApprovalRecord freshA = new Approval.ApprovalRecord(
                freshArgsId, "approver-authenticated-party-id", 1, "anti-replay-nonce".getBytes(StandardCharsets.UTF_8), 1000);
        byte[] freshASig = Approval.signApproval(freshA, ALG, approverSeed0x11);
        Approval.ConsumeReceipt freshReceipt = new Approval.ConsumeReceipt(freshLedgerId, freshA.id(), 7);
        byte[] freshRSig = Approval.signConsumeReceipt(freshReceipt, ALG, freshLedgerSeed0x22);
        check("distinct ordering authority verifies",
                errKind(() -> Approval.verifyFreshIndependent(freshA, ALG, approverPk0x11, freshASig, freshArgsId, 1000L,
                        freshReceipt, ALG, freshLedgerPk0x22, freshRSig, freshApproverId)),
                "no-error");
        check("self-asserted freshness (party == ordering authority) rejected",
                errKind(() -> Approval.verifyFreshIndependent(freshA, ALG, approverPk0x11, freshASig, freshArgsId, 1000L,
                        freshReceipt, ALG, freshLedgerPk0x22, freshRSig, freshLedgerId)),
                "FreshnessSelfAsserted");
        check("expired approval still rejected under a distinct authority",
                errKind(() -> Approval.verifyFreshIndependent(freshA, ALG, approverPk0x11, freshASig, freshArgsId, freshA.notAfter + 1,
                        freshReceipt, ALG, freshLedgerPk0x22, freshRSig, freshApproverId)),
                "ApprovalExpired");
        Approval.ConsumeReceipt unnamedFreshReceipt = new Approval.ConsumeReceipt(new byte[0], freshA.id(), 7);
        byte[] unnamedRSig = Approval.signConsumeReceipt(unnamedFreshReceipt, ALG, seedOf((byte) 0x33));
        check("unnamed ordering authority is not accepted as freshness evidence",
                errKind(() -> Approval.verifyFreshIndependent(freshA, ALG, approverPk0x11, freshASig, freshArgsId, 1000L,
                        unnamedFreshReceipt, ALG, freshLedgerPk0x22, unnamedRSig, freshApproverId)),
                "ConsumeReceiptUnsigned");

        // 16. port extra: openLedger (Go/Rust-naming-parity for the unsigned constructor) behaves
        //     exactly like open() -- consumes and tracks state, but offers no signed-receipt path.
        Approval.Ledger openLedgerCheck = Approval.Ledger.openLedger(tempLedger());
        Approval.LedgerEntry openLedgerEntry = openLedgerCheck.consume(recA.id(), "opener");
        check("openLedger consume seq == 0", Long.toString(openLedgerEntry.seq), "0");
        check("openLedger: consumeWithReceipt on an unsigned ledger rejected LedgerUnsigned",
                errKind(() -> openLedgerCheck.consumeWithReceipt(Hex.decode(field(baseScope, "approval_id_hex")), "opener")),
                "LedgerUnsigned");
        openLedgerCheck.close();

        // 17. consumeApproval: the composed choke point runs the table's precedence in ONE place.
        //     Exercises every reaction and the two precedence rules (mismatch over every cell; expiry
        //     over AlreadyConsumed), plus the effect-ceiling / grant-range / bad-signature refusals, and
        //     asserts the ledger length so a mutant that returns the right Kind but still appends is
        //     caught. Reactions are the draft's, not read off the code (mirrors the Go/Rust
        //     ConsumeApproval / consume_approval precedence test).
        byte[] caApproverSeed = seedOf((byte) 7);
        byte[] caApproverPk = Cose.mldsaKeygen("ML-DSA-65", caApproverSeed);
        byte[] caArgsCid = "args-content-id-A".getBytes(StandardCharsets.UTF_8);
        byte[] caWrongCid = "args-content-id-B".getBytes(StandardCharsets.UTF_8);

        // approved + consume -> consumed (len 1); a second consume -> AlreadyConsumed (len stays 1).
        {
            Approval.ApprovalRecord a = new Approval.ApprovalRecord(caArgsCid, "approver-1",
                    Policy.DESTRUCTIVE, new byte[]{0x01, 0x02}, 1000);
            byte[] caSig = Approval.signApproval(a, ALG, caApproverSeed);
            Approval.Ledger l = Approval.Ledger.open(tempLedger());
            Approval.consumeApproval(a, ALG, caApproverPk, caSig, caArgsCid, 500, Policy.READ_ONLY, l, "by");
            check("consumeApproval: valid consume succeeds, len 1", Integer.toString(l.len()), "1");
            check("consumeApproval: second consume of the same id rejected AlreadyConsumed",
                    errKind(() -> Approval.consumeApproval(a, ALG, caApproverPk, caSig, caArgsCid, 500, Policy.READ_ONLY, l, "by")),
                    "AlreadyConsumed");
            check("consumeApproval: ledger len stays 1 after the rejected replay", Integer.toString(l.len()), "1");
            l.close();
        }
        // expired + consume -> ApprovalExpired; nothing appended.
        {
            Approval.ApprovalRecord a = new Approval.ApprovalRecord(caArgsCid, "approver-1",
                    Policy.DESTRUCTIVE, new byte[]{0x01, 0x02}, 1000);
            byte[] caSig = Approval.signApproval(a, ALG, caApproverSeed);
            Approval.Ledger l = Approval.Ledger.open(tempLedger());
            check("consumeApproval: expired approval rejected ApprovalExpired",
                    errKind(() -> Approval.consumeApproval(a, ALG, caApproverPk, caSig, caArgsCid, 2000, Policy.READ_ONLY, l, "by")),
                    "ApprovalExpired");
            check("consumeApproval: expired rejection appends nothing", Integer.toString(l.len()), "0");
            l.close();
        }
        // expiry over consume: success, then a second past not_after -> ApprovalExpired (never
        // AlreadyConsumed), ledger untouched (len stays 1).
        {
            Approval.ApprovalRecord a = new Approval.ApprovalRecord(caArgsCid, "approver-1",
                    Policy.DESTRUCTIVE, new byte[]{0x01, 0x02}, 1000);
            byte[] caSig = Approval.signApproval(a, ALG, caApproverSeed);
            Approval.Ledger l = Approval.Ledger.open(tempLedger());
            Approval.consumeApproval(a, ALG, caApproverPk, caSig, caArgsCid, 500, Policy.READ_ONLY, l, "by");
            check("consumeApproval: expiry takes precedence over AlreadyConsumed",
                    errKind(() -> Approval.consumeApproval(a, ALG, caApproverPk, caSig, caArgsCid, 2000, Policy.READ_ONLY, l, "by")),
                    "ApprovalExpired");
            check("consumeApproval: expiry-over-consume leaves ledger untouched (len 1)", Integer.toString(l.len()), "1");
            l.close();
        }
        // mismatch over every cell (fresh, and over an also-expired approval); no append.
        {
            Approval.ApprovalRecord a = new Approval.ApprovalRecord(caArgsCid, "approver-1",
                    Policy.DESTRUCTIVE, new byte[]{0x01, 0x02}, 1000);
            byte[] caSig = Approval.signApproval(a, ALG, caApproverSeed);
            Approval.Ledger l = Approval.Ledger.open(tempLedger());
            check("consumeApproval: mismatch (fresh) rejected ApprovalMismatch",
                    errKind(() -> Approval.consumeApproval(a, ALG, caApproverPk, caSig, caWrongCid, 500, Policy.READ_ONLY, l, "by")),
                    "ApprovalMismatch");
            check("consumeApproval: mismatch takes precedence over expiry",
                    errKind(() -> Approval.consumeApproval(a, ALG, caApproverPk, caSig, caWrongCid, 2000, Policy.READ_ONLY, l, "by")),
                    "ApprovalMismatch");
            check("consumeApproval: mismatch rejections append nothing", Integer.toString(l.len()), "0");
            l.close();
        }
        // a rejected mismatch leaves the ledger clean, so a later valid consume still succeeds.
        {
            Approval.ApprovalRecord a = new Approval.ApprovalRecord(caArgsCid, "approver-1",
                    Policy.DESTRUCTIVE, new byte[]{0x01, 0x02}, 1000);
            byte[] caSig = Approval.signApproval(a, ALG, caApproverSeed);
            Approval.Ledger l = Approval.Ledger.open(tempLedger());
            check("consumeApproval: reject-then-valid, mismatch first rejected",
                    errKind(() -> Approval.consumeApproval(a, ALG, caApproverPk, caSig, caWrongCid, 500, Policy.READ_ONLY, l, "by")),
                    "ApprovalMismatch");
            check("consumeApproval: reject-then-valid, ledger still 0 after the reject", Integer.toString(l.len()), "0");
            Approval.consumeApproval(a, ALG, caApproverPk, caSig, caArgsCid, 500, Policy.READ_ONLY, l, "by");
            check("consumeApproval: reject-then-valid, the valid consume succeeds afterwards", Integer.toString(l.len()), "1");
            l.close();
        }
        // effect ceiling: granted effect below the action's required effect -> ApprovalRequired.
        {
            Approval.ApprovalRecord a = new Approval.ApprovalRecord(caArgsCid, "approver-1",
                    Policy.READ_ONLY, new byte[]{0x01, 0x02}, 1000);
            byte[] caSig = Approval.signApproval(a, ALG, caApproverSeed);
            Approval.Ledger l = Approval.Ledger.open(tempLedger());
            check("consumeApproval: insufficient grant rejected ApprovalRequired",
                    errKind(() -> Approval.consumeApproval(a, ALG, caApproverPk, caSig, caArgsCid, 500, Policy.DESTRUCTIVE, l, "by")),
                    "ApprovalRequired");
            check("consumeApproval: insufficient-grant rejection appends nothing", Integer.toString(l.len()), "0");
            l.close();
        }
        // grant-range guard: a grant outside the closed 0..3 vocabulary authorizes nothing.
        {
            Approval.ApprovalRecord a = new Approval.ApprovalRecord(caArgsCid, "approver-1",
                    7, new byte[]{0x01, 0x02}, 1000);
            byte[] caSig = Approval.signApproval(a, ALG, caApproverSeed);
            Approval.Ledger l = Approval.Ledger.open(tempLedger());
            check("consumeApproval: malformed grant (7) rejected ApprovalRequired",
                    errKind(() -> Approval.consumeApproval(a, ALG, caApproverPk, caSig, caArgsCid, 500, Policy.READ_ONLY, l, "by")),
                    "ApprovalRequired");
            check("consumeApproval: malformed-grant rejection appends nothing", Integer.toString(l.len()), "0");
            l.close();
        }
        // bad signature (checked first) -> BadSignature.
        {
            Approval.ApprovalRecord a = new Approval.ApprovalRecord(caArgsCid, "approver-1",
                    Policy.DESTRUCTIVE, new byte[]{0x01, 0x02}, 1000);
            byte[] caSig = Approval.signApproval(a, ALG, caApproverSeed);
            byte[] caBadSig = caSig.clone();
            caBadSig[caBadSig.length - 1] ^= 0x01;
            Approval.Ledger l = Approval.Ledger.open(tempLedger());
            check("consumeApproval: bad signature rejected BadSignature",
                    errKind(() -> Approval.consumeApproval(a, ALG, caApproverPk, caBadSig, caArgsCid, 500, Policy.READ_ONLY, l, "by")),
                    "BadSignature");
            check("consumeApproval: bad-signature rejection appends nothing", Integer.toString(l.len()), "0");
            l.close();
        }
    }

    public static void main(String[] args) throws Exception {
        System.out.println("approval conformance (Java) — graded vs vectors/approval/cases.json");
        run();
        System.out.println(fails == 0 ? "ApprovalKatTest: PASS" : "ApprovalKatTest: FAIL (" + fails + ")");
        System.exit(fails == 0 ? 0 : 1);
    }
}
