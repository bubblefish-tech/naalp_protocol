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
 * C17 N-AALP-CONT flow-continuation known-answer test for the Java SDK (design.md §20; R-CONT-1..7),
 * graded against the shared independent corpus vectors/continuation/cases.json (NOT produced by this
 * code): the one signed FlowOpen's body/head/id, the cheap Continuation hash-chain links, the
 * VerifyChain final head, the Checkpoint prefix confirmation and gap detection, the 2-field FlowCommit,
 * and the closed-lattice / wrong-flow / non-canonical / look-alike / u64-overflow rejections.
 *
 * <p>CORPUS-GRADED (pure bytes / verdicts): every FlowOpen/Continuation/Checkpoint/FlowCommit body and
 * head, the final chain head, the big-seq (&gt;2^53) round-trip, and the AboveCeiling / RangeError /
 * WrongFlow / GapDetected / NonCanonical / ContMalformed rejections — reproduced byte-for-byte or
 * verdict-for-verdict from the corpus. FULL-SIGNATURE DEMONSTRATED IN ISOLATION: FlowOpen and
 * FlowCommit are signed with real FIPS-204 ML-DSA-65 (COSE_Sign1) and verified back; the corpus
 * carries no signature vector for this channel, so the sign/verify is demonstrated, the bytes graded.
 *
 * <p>Written test-first: {@link Continuation} is absent until Continuation.java lands, so this fails
 * RED with a javac "cannot find symbol Continuation"; the recorded mutation drops the AboveCeiling
 * ceiling check in {@code verifyContinuation}, which flips the named "above-ceiling continuation
 * rejected AboveCeiling" check (the cheap path could then escalate past the one full signature).
 */
public final class ContinuationKatTest {
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
            Path p = d.resolve("vectors").resolve("continuation").resolve("cases.json");
            if (Files.isRegularFile(p)) {
                return p;
            }
            d = d.getParent();
        }
        throw new AssertionError("vectors/continuation/cases.json not found from " + System.getProperty("user.dir"));
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

    private static List<String> topStrings(String arrayInner) {
        List<String> out = new ArrayList<>();
        Matcher m = Pattern.compile("\"([^\"]*)\"").matcher(arrayInner);
        while (m.find()) {
            out.add(m.group(1));
        }
        return out;
    }

    private static List<byte[]> hexList(String scope, String key) {
        List<byte[]> out = new ArrayList<>();
        for (String h : topStrings(arrayBlock(scope, key))) {
            out.add(Hex.decode(h));
        }
        return out;
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

    private static String errKind(Runnable r) {
        try {
            r.run();
            return "no-error";
        } catch (NaalpException e) {
            return e.kind;
        }
    }

    private static final int ALG = Cose.ALG_MLDSA65;

    private static void run() throws Exception {
        String json = Files.readString(findVector(), StandardCharsets.UTF_8);

        // 1. FlowOpen — the one signed object whose body/head/id fix the flow's authority.
        String fo = objBlock(json, "flow_open");
        Continuation.FlowOpen open = new Continuation.FlowOpen(
                Hex.decode(field(fo, "flow_id_hex")), intField(fo, "effect_ceiling"), hexList(fo, "approvals_hex"));
        check("flow_open body == oracle", Hex.encode(open.bytes()), field(fo, "body_hex"));
        check("flow_open head == oracle", Hex.encode(open.head()), field(fo, "head_hex"));
        check("flow_open id == oracle", Hex.encode(open.id()), field(fo, "id_hex"));
        byte[] flowId = open.id();

        // 2. the cheap Continuation hash-chain links reproduce the oracle body + head.
        List<Continuation> conts = new ArrayList<>();
        for (String cb : splitObjects(arrayBlock(json, "continuations"))) {
            long seq = intField(cb, "seq");
            Continuation c = new Continuation(flowId, seq, intField(cb, "effect"),
                    Hex.decode(field(cb, "payload_id_hex")), Hex.decode(field(cb, "prev_hex")));
            check("continuation seq=" + seq + " body == oracle", Hex.encode(c.bytes()), field(cb, "body_hex"));
            check("continuation seq=" + seq + " head == oracle", Hex.encode(c.head()), field(cb, "head_hex"));
            conts.add(c);
        }

        // 3. VerifyChain reconstructs the final head, and the ceiling comes from the FlowOpen alone.
        check("verify chain no-error", errKind(() -> Continuation.verifyChain(open, conts)), "no-error");
        check("verify chain final head == oracle",
                Hex.encode(Continuation.verifyChain(open, conts)), field(json, "final_head_hex"));

        // 4. Checkpoint confirms a contiguous prefix (seq 0..1) and reproduces the oracle body.
        String cp = objBlock(json, "checkpoint");
        Continuation.Checkpoint checkpoint = new Continuation.Checkpoint(
                flowId, intField(cp, "through_seq"), Hex.decode(field(cp, "head_hex")));
        check("checkpoint body == oracle", Hex.encode(checkpoint.bytes()), field(cp, "body_hex"));
        check("checkpoint verifies prefix [0,1]",
                errKind(() -> Continuation.verifyCheckpoint(checkpoint, open, conts.subList(0, 2))), "no-error");

        // 5. FlowCommit — the second full signature's 2-field body.
        String fc = objBlock(json, "flow_commit");
        Continuation.FlowCommit commit = new Continuation.FlowCommit(flowId, Hex.decode(field(fc, "final_head_hex")));
        check("flow_commit body == oracle", Hex.encode(commit.bytes()), field(fc, "body_hex"));

        // 6. above_ceiling — a cheap link whose effect exceeds the FlowOpen ceiling is refused
        //    AboveCeiling (the mutation drops this check; the cheap path could then escalate).
        String ac = objBlock(json, "above_ceiling");
        byte[] finalHead = Hex.decode(field(json, "final_head_hex"));
        Continuation acCont = new Continuation(flowId, intField(ac, "seq"), intField(ac, "effect"),
                Hex.decode(field(ac, "payload_id_hex")), Hex.decode(field(ac, "prev_hex")));
        check("above_ceiling body == oracle", Hex.encode(acCont.bytes()), field(ac, "body_hex"));
        check("above_ceiling head == oracle", Hex.encode(acCont.head()), field(ac, "head_hex"));
        check("above-ceiling continuation rejected " + field(ac, "reject"),
                errKind(() -> Continuation.verifyContinuation(
                        acCont, flowId, finalHead, intField(ac, "seq"), intField(ac, "ceiling"))),
                field(ac, "reject"));

        // 7. minimal — the smallest valid FlowOpen (empty flow_id, ceiling read_only, no approvals).
        String min = objBlock(json, "minimal");
        Continuation.FlowOpen minOpen = new Continuation.FlowOpen(
                Hex.decode(field(min, "flow_id_hex")), intField(min, "effect_ceiling"), hexList(min, "approvals_hex"));
        check("minimal flow_open body == oracle", Hex.encode(minOpen.bytes()), field(min, "body_hex"));
        check("minimal flow_open head == oracle", Hex.encode(minOpen.head()), field(min, "head_hex"));
        check("minimal flow_open id == oracle", Hex.encode(minOpen.id()), field(min, "id_hex"));

        // 8. an empty approvals[] is distinct on the wire and by content-id from a populated one.
        String evn = objBlock(json, "empty_vs_nonempty");
        byte[] foFlowId = Hex.decode(field(fo, "flow_id_hex"));
        long foCeiling = intField(fo, "effect_ceiling");
        List<byte[]> foApprovals = hexList(fo, "approvals_hex");
        Continuation.FlowOpen emptyApp = new Continuation.FlowOpen(foFlowId, foCeiling, List.of());
        Continuation.FlowOpen oneApp = new Continuation.FlowOpen(foFlowId, foCeiling, foApprovals);
        check("empty-approvals body == oracle", Hex.encode(emptyApp.bytes()), field(objBlock(evn, "empty_approvals"), "body_hex"));
        check("empty-approvals id == oracle", Hex.encode(emptyApp.id()), field(objBlock(evn, "empty_approvals"), "id_hex"));
        check("one-approval body == oracle", Hex.encode(oneApp.bytes()), field(objBlock(evn, "one_approval"), "body_hex"));
        check("one-approval id == oracle", Hex.encode(oneApp.id()), field(objBlock(evn, "one_approval"), "id_hex"));

        // 9. big_seq — a seq > 2^53 round-trips byte-exact (carried as a JSON string).
        String bs = objBlock(json, "big_seq");
        long bigSeq = Long.parseLong(field(bs, "seq_str"));
        Continuation bigCont = new Continuation(flowId, bigSeq, intField(bs, "effect"),
                Hex.decode(field(bs, "payload_id_hex")), Hex.decode(field(bs, "prev_hex")));
        check("big_seq body == oracle", Hex.encode(bigCont.bytes()), field(bs, "body_hex"));
        check("big_seq head == oracle", Hex.encode(bigCont.head()), field(bs, "head_hex"));

        // 10. range_reject — effect / effect_ceiling are the closed effect enum 0..3; 4 is RangeError,
        //     never normalized to destructive (a normalized ceiling would be a silent fail-open).
        String rr = objBlock(json, "range_reject");
        Continuation.FlowOpen ceil4 = new Continuation.FlowOpen(foFlowId, intField(rr, "out_of_lattice_value"), foApprovals);
        check("range_reject flow_open ceiling=4 body == oracle",
                Hex.encode(ceil4.bytes()), field(rr, "flow_open_ceiling_body_hex"));
        check("range_reject parseFlowOpen(ceiling=4) rejected " + field(rr, "reject"),
                errKind(() -> Continuation.parseFlowOpen(Hex.decode(field(rr, "flow_open_ceiling_body_hex")))), field(rr, "reject"));
        check("range_reject parseContinuation(effect=4) rejected " + field(rr, "reject"),
                errKind(() -> Continuation.parseContinuation(Hex.decode(field(rr, "continuation_effect_body_hex")))), field(rr, "reject"));

        // 11. keys_out_of_order — a strict decoder rejects a descending-key (2 then 1) FlowCommit body.
        String ko = objBlock(json, "keys_out_of_order");
        check("canonical commit body == oracle", Hex.encode(commit.bytes()), field(ko, "canonical_commit_body_hex"));
        check("non-canonical commit decode rejected " + field(ko, "reject"),
                errKind(() -> Cbor.decode(Hex.decode(field(ko, "noncanonical_commit_body_hex")))), field(ko, "reject"));

        // 12. look_alike — a 2-field FlowCommit body fed to ParseCheckpoint is rejected (3 fields required).
        String la = objBlock(json, "look_alike");
        check("flow_commit fed to parseCheckpoint rejected ContMalformed",
                errKind(() -> Continuation.parseCheckpoint(Hex.decode(field(la, "flow_commit_body_hex")))), "ContMalformed");

        // 13. gap — a non-contiguous prefix (seq 0 then seq 2, missing seq 1) is GapDetected.
        String gap = objBlock(json, "gap");
        List<Continuation> gapPrefix = List.of(conts.get(0), conts.get(2));
        Continuation.Checkpoint gapCp = new Continuation.Checkpoint(
                flowId, intField(gap, "through_seq"), Hex.decode(field(gap, "claimed_head_hex")));
        check("gap (seq 0 then 2) rejected " + field(gap, "detect"),
                errKind(() -> Continuation.verifyCheckpoint(gapCp, open, gapPrefix)), field(gap, "detect"));

        // 14. replay — a continuation carrying flow_open_id = A, verified under FlowOpen B, is WrongFlow.
        String rp = objBlock(json, "replay");
        Continuation.FlowOpen openB = new Continuation.FlowOpen(
                Hex.decode("f100000000000000000000000000000b"), foCeiling, foApprovals);
        check("flow_open_b head == oracle", Hex.encode(openB.head()), field(rp, "flow_open_b_head_hex"));
        check("flow_open_b id == oracle", Hex.encode(openB.id()), field(rp, "flow_open_b_id_hex"));
        check("continuation replayed under FlowOpen B rejected " + field(rp, "detect"),
                errKind(() -> Continuation.verifyContinuation(conts.get(0), openB.id(), openB.head(), 0, foCeiling)),
                field(rp, "detect"));

        // 15. checkpoint_overflow — through_seq = u64::MAX admits no contiguous prefix -> GapDetected.
        //     The body carries a full 8-byte uint; it is DECODE-graded (the shortest-form uint encoder
        //     refuses a >=2^63 value), then verified. The decoded through_seq round-trips as u64::MAX.
        String ov = objBlock(json, "checkpoint_overflow");
        Continuation.Checkpoint ovCp = Continuation.parseCheckpoint(Hex.decode(field(ov, "body_hex")));
        check("checkpoint_overflow through_seq round-trips u64::MAX",
                Long.toUnsignedString(ovCp.throughSeq), field(ov, "through_seq_str"));
        check("checkpoint_overflow rejected " + field(ov, "reject"),
                errKind(() -> Continuation.verifyCheckpoint(ovCp, open, List.of())), field(ov, "reject"));

        // 16. full-signature demonstrated in isolation (real ML-DSA-65 COSE_Sign1): FlowOpen signs and
        //     verifies back to the same authority; a tampered object is BadSignature; FlowCommit binds
        //     the recomputed chain.
        byte[] zeroSeed = new byte[32];
        byte[] pk = Cose.mldsaKeygen("ML-DSA-65", zeroSeed);
        byte[] signedOpen = Continuation.signFlowOpen(open, ALG, zeroSeed);
        check("signed FlowOpen verifies to the same authority id",
                Hex.encode(Continuation.verifyFlowOpen(signedOpen, Cose.PROFILE_PUBLIC, ALG, pk).id()),
                Hex.encode(open.id()));
        byte[] tampered = signedOpen.clone();
        tampered[tampered.length - 1] ^= 1;
        check("tampered FlowOpen rejected BadSignature",
                errKind(() -> Continuation.verifyFlowOpen(tampered, Cose.PROFILE_PUBLIC, ALG, pk)), "BadSignature");
        byte[] signedCommit = Continuation.signFlowCommit(commit, ALG, zeroSeed);
        check("signed FlowCommit binds the recomputed chain",
                errKind(() -> Continuation.verifyFlowCommit(signedCommit, Cose.PROFILE_PUBLIC, ALG, pk, open, conts)), "no-error");
    }

    public static void main(String[] args) throws Exception {
        System.out.println("continuation conformance (Java) — graded vs vectors/continuation/cases.json");
        run();
        System.out.println(fails == 0 ? "ContinuationKatTest: PASS" : "ContinuationKatTest: FAIL (" + fails + ")");
        System.exit(fails == 0 ? 0 : 1);
    }
}
