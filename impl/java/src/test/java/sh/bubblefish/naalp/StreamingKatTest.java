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
 * C9 native-streaming conformance for the Java SDK (design.md §10; R-10.1..10.6), graded against the
 * shared independent corpus vectors/stream/cases.json (NOT produced by this code). Note the NAME
 * MISMATCH: the module is {@code streaming} but the oracle directory is {@code stream}.
 *
 * <p>CORPUS-GRADED (pure bytes / digests): the rolling SHA-384 commitment over the chunks in
 * absolute-offset order, each mid-stream checkpoint's digest_so_far, the StreamOpen/StreamCommit/
 * StreamCheckpoint body bytes, and the tampered-stream digest. VERDICTS graded against the corpus:
 * a valid commitment verifies; altering one delivered byte invalidates it (StreamDigestMismatch); a
 * checkpoint confirms a prefix; a stream whose effect exceeds the grant is refused at open
 * (EffectNotAuthorized). REAL BEHAVIOUR DEMONSTRATED IN ISOLATION (not corpus-graded): the
 * one-signature-covers-the-whole-stream commitment is signed with real deterministic ML-DSA-65
 * (BouncyCastle) and verified, and a tampered signature is rejected.
 *
 * <p>The commitment is a SHA-384 known-answer test — the expected digests are the shared corpus, an
 * independent authority (not this code) — so the byte parity is non-circular. There is no
 * cross-language SIGNED pin for C9 (the shared corpus carries none): the signed commitment is a real,
 * demonstrated-in-isolation signature, matching the Go/Rust reference which likewise only demonstrate
 * (do not pin) the C9 signature.
 *
 * <p>Written test-first: {@link Streaming} is absent until Streaming.java lands, so this fails RED with
 * a javac "cannot find symbol Streaming"; the recorded mutation forces {@link Streaming#verifyCommit}
 * to skip its digest comparison, which flips the named "tampered stream rejected StreamDigestMismatch"
 * check on its assertion.
 */
public final class StreamingKatTest {
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
            Path p = d.resolve("vectors").resolve("stream").resolve("cases.json");
            if (Files.isRegularFile(p)) {
                return p;
            }
            d = d.getParent();
        }
        throw new AssertionError("vectors/stream/cases.json not found from " + System.getProperty("user.dir"));
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

    private static String objBlock(String s, String key) {
        Matcher m = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*\\{").matcher(s);
        if (!m.find()) {
            throw new AssertionError("obj key not found: " + key);
        }
        int open = m.end() - 1;
        int close = matchClose(s, open);
        return s.substring(open + 1, close - 1);
    }

    private static String arrayBlock(String s, String key) {
        Matcher m = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*\\[").matcher(s);
        if (!m.find()) {
            throw new AssertionError("array key not found: " + key);
        }
        int open = m.end() - 1;
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

    private static byte[] seed(int b) {
        byte[] s = new byte[32];
        java.util.Arrays.fill(s, (byte) b);
        return s;
    }

    private static String json;

    private static List<Streaming.Chunk> chunks() {
        List<Streaming.Chunk> out = new ArrayList<>();
        for (String c : splitObjects(arrayBlock(json, "chunks"))) {
            out.add(new Streaming.Chunk(intField(c, "offset"), hb(field(c, "data_hex"))));
        }
        return out;
    }

    private static void run() throws Exception {
        json = Files.readString(findVector(), StandardCharsets.UTF_8);
        byte[] streamId = hb(field(json, "stream_id_hex"));
        long substream = intField(json, "substream");
        long effect = intField(json, "effect");
        byte[] approval = hb(field(json, "approval_hex"));
        String finalDigest = field(json, "final_digest_hex");
        List<Streaming.Chunk> chunks = chunks();
        List<String> cps = splitObjects(arrayBlock(json, "checkpoints"));

        check("StreamChannel == 0x000C", Long.toString(Streaming.STREAM_CHANNEL), "12");

        // 1. rolling commitment, checkpoints, and the three body encodings == oracle.
        check("commit digest == oracle", Hex.encode(Streaming.commitDigest(chunks)), finalDigest);
        Streaming.StreamDigest sd = Streaming.newStreamDigest();
        for (int i = 0; i < chunks.size(); i++) {
            sd.update(chunks.get(i).data);
            if (i < cps.size()) {
                check("rolling digest_so_far[" + i + "] == oracle", Hex.encode(sd.digestSoFar()), field(cps.get(i), "digest_so_far_hex"));
            }
        }
        check("rolling final digest == oracle", Hex.encode(sd.digestSoFar()), finalDigest);

        Streaming.StreamOpen open = new Streaming.StreamOpen(streamId, effect, approval, substream);
        check("StreamOpen body == oracle", Hex.encode(open.bytes()), field(json, "open_body_hex"));
        Streaming.StreamCommit commit = new Streaming.StreamCommit(streamId, hb(finalDigest));
        check("StreamCommit body == oracle", Hex.encode(commit.bytes()), field(json, "commit_body_hex"));
        Streaming.StreamCheckpoint cp0 = new Streaming.StreamCheckpoint(streamId, intField(cps.get(0), "through_offset"), hb(field(cps.get(0), "digest_so_far_hex")));
        check("StreamCheckpoint body == oracle", Hex.encode(cp0.bytes()), field(json, "checkpoint_body_hex"));

        // 2. a valid commitment verifies; altering one delivered byte invalidates it.  <<< MUTATION TARGET >>>
        check("valid stream verifies", errKind(() -> Streaming.verifyCommit(commit, chunks)), "no-error");
        String tamper = objBlock(json, "tamper");
        int tamperIdx = (int) intField(tamper, "chunk_index");
        List<Streaming.Chunk> tampered = chunks();
        tampered.set(tamperIdx, new Streaming.Chunk(tampered.get(tamperIdx).offset, hb(field(tamper, "flipped_data_hex"))));
        check("tampered stream digest == oracle", Hex.encode(Streaming.commitDigest(tampered)), field(tamper, "digest_hex"));
        check("tampered stream rejected StreamDigestMismatch",
                errKind(() -> Streaming.verifyCommit(commit, tampered)), "StreamDigestMismatch");

        // 3. a checkpoint confirms a prefix without the end; a wrong-length prefix is rejected.
        for (int i = 0; i < cps.size(); i++) {
            Streaming.StreamCheckpoint cp = new Streaming.StreamCheckpoint(streamId,
                    intField(cps.get(i), "through_offset"), hb(field(cps.get(i), "digest_so_far_hex")));
            List<Streaming.Chunk> prefix = new ArrayList<>(chunks.subList(0, i + 1));
            check("checkpoint[" + i + "] verifies its prefix", errKind(() -> Streaming.verifyCheckpoint(cp, prefix)), "no-error");
        }
        Streaming.StreamCheckpoint cpFirst = new Streaming.StreamCheckpoint(streamId,
                intField(cps.get(0), "through_offset"), hb(field(cps.get(0), "digest_so_far_hex")));
        check("checkpoint given the full stream rejected (wrong length)",
                errKind(() -> Streaming.verifyCheckpoint(cpFirst, chunks)), "StreamDigestMismatch");

        // 4. a stream whose effect exceeds the grant is refused BEFORE any chunk (R-10.3).
        Streaming.StreamOpen destructive = new Streaming.StreamOpen(streamId, Policy.DESTRUCTIVE, null, 1);
        check("destructive under read-only refused EffectNotAuthorized",
                errKind(() -> Streaming.openStream(destructive, Policy.READ_ONLY)), "EffectNotAuthorized");
        check("corpus stream under idempotent grant authorized",
                errKind(() -> Streaming.openStream(open, Policy.IDEMPOTENT_WRITE)), "no-error");
        Streaming.StreamOpen unknown = new Streaming.StreamOpen(streamId, 99, null, 1);
        check("unknown effect fails closed and is refused",
                errKind(() -> Streaming.openStream(unknown, Policy.NON_IDEMPOTENT_WRITE)), "EffectNotAuthorized");

        // 5. one end-commitment signature covers the whole stream (real deterministic ML-DSA-65).
        byte[] sseed = seed(0x3C);
        byte[] pk = Cose.mldsaKeygen("ML-DSA-65", sseed);
        byte[] sig = Streaming.signCommit(commit, ALG, sseed);
        check("commit signature verifies", Boolean.toString(Streaming.verifyCommitSig(commit, ALG, pk, sig)), "true");
        byte[] bad = sig.clone();
        bad[0] ^= 0x01;
        check("tampered commit signature rejected", Boolean.toString(Streaming.verifyCommitSig(commit, ALG, pk, bad)), "false");

        // 6. the commitment is over ABSOLUTE-OFFSET order: input order is irrelevant, but swapping which
        //    data sits at which offset changes the digest.
        List<Streaming.Chunk> reversed = new ArrayList<>();
        for (int i = chunks.size() - 1; i >= 0; i--) {
            reversed.add(chunks.get(i));
        }
        check("reversed input yields the same digest (sorts by offset)",
                Hex.encode(Streaming.commitDigest(reversed)), finalDigest);
        List<Streaming.Chunk> swapped = chunks();
        byte[] d0 = swapped.get(0).data;
        byte[] d1 = swapped.get(1).data;
        swapped.set(0, new Streaming.Chunk(swapped.get(0).offset, d1));
        swapped.set(1, new Streaming.Chunk(swapped.get(1).offset, d0));
        check("swapping data across offsets changes the digest",
                Boolean.toString(Hex.encode(Streaming.commitDigest(swapped)).equals(finalDigest)), "false");
    }

    public static void main(String[] args) throws Exception {
        System.out.println("streaming conformance (Java) — graded vs vectors/stream/cases.json");
        run();
        System.out.println(fails == 0 ? "StreamingKatTest: PASS" : "StreamingKatTest: FAIL (" + fails + ")");
        System.exit(fails == 0 ? 0 : 1);
    }
}
