// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * C19 name-bindings + signed A2A task-state profile conformance for the Java SDK (design §22),
 * graded against the shared independent corpus vectors/naming/cases.json (NOT produced by this code):
 * the name-binding and task-transition body/head/content-id byte parity, the A2A Agent Card
 * attestation content-id (a C18 naalp-description-import), the offline name-history walk, hole/fork
 * detection with the non-repudiable {@link Naming.NameForkProof}, the A2A legal-edge table (every legal
 * edge accepted, every illegal edge rejected), the signed task-chain verifier (illegal edge /
 * non-contiguous / bad start / foreign card / gap / bad signature), the &gt;2^53 seq round-trip, the
 * minimal encodings, the strict canonical-key rejection, and the look-alike cross-parse rejection.
 *
 * <p>CORPUS-GRADED (pure bytes / verdicts): every binding/transition body/head/id, the card import
 * body/id, the legal + illegal edge tables, the walk succession, the hole/fork/gap positions, the
 * &gt;2^53 seq, the minimal/canonical/look-alike cases. CRYPTO-DEMONSTRATED IN ISOLATION with real
 * FIPS-204 ML-DSA-65 (via BouncyCastle): the chain verifiers, the fork proof, and the task-chain
 * verifier run over real deterministic COSE_Sign1 objects. The two CROSS-LANGUAGE PINS (SHA-384 of the
 * seq-0 signed binding and transition, seed = 0x11*32) are the Go+Rust+Python reference constants;
 * asserting them proves Java == Go == Rust == Python byte-identical signed objects.
 *
 * <p>KAT convention (a standalone {@code main} exiting non-zero on any failure); named "…KatTest" so
 * the filename carries the "test" token the ten-language-parity gate indexes. Written test-first:
 * {@link Naming} is absent until Naming.java lands, so this fails RED with a javac "cannot find symbol
 * Naming"; the recorded mutation forces {@link Naming#legalEdge} to accept every edge, which flips the
 * named "illegal edge f->t rejected IllegalTransition" check on its assertion.
 */
public final class NamingKatTest {
    private static int fails = 0;

    // The Go + Rust + Python reference pins for the deterministic signed seq-0 binding/transition (seed=0x11*32).
    private static final String PIN_SIGNED_BINDING_SHA384 =
            "a9179b939fffb1bce6abb4cd594b20e08f9d855729047ce4cb287da191234c10fecc9b232f80be902f70a3da490bcb91";
    private static final String PIN_SIGNED_TRANSITION_SHA384 =
            "60a9902f51e3308149cf2ace5cb65cd4541b4cc7bd4ec5f9a120dd44f93560b6358dcb96cb04b0daedd4cbbdf31f5787";

    private static void check(String name, String got, String want) {
        if (got.equals(want)) {
            System.out.println("  ok   " + name);
        } else {
            fails++;
            System.out.println("  FAIL " + name + "\n       got  " + got + "\n       want " + want);
        }
    }

    // ---- nesting-aware JSON access (Java has no JSON library) ------------------------------

    private static Path findVector() {
        Path d = Path.of(System.getProperty("user.dir")).toAbsolutePath();
        for (int i = 0; i < 6 && d != null; i++) {
            Path p = d.resolve("vectors").resolve("naming").resolve("cases.json");
            if (Files.isRegularFile(p)) {
                return p;
            }
            d = d.getParent();
        }
        throw new AssertionError("vectors/naming/cases.json not found from " + System.getProperty("user.dir"));
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

    private static List<long[]> intPairs(String arrayInner) {
        List<long[]> out = new ArrayList<>();
        Matcher m = Pattern.compile("\\[\\s*(\\d+)\\s*,\\s*(\\d+)\\s*\\]").matcher(arrayInner);
        while (m.find()) {
            out.add(new long[]{Long.parseLong(m.group(1)), Long.parseLong(m.group(2))});
        }
        return out;
    }

    private static List<Long> intList(String arrayInner) {
        List<Long> out = new ArrayList<>();
        Matcher m = Pattern.compile("(\\d+)").matcher(arrayInner);
        while (m.find()) {
            out.add(Long.parseLong(m.group(1)));
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

    private static byte[] seed(int b) {
        byte[] s = new byte[32];
        java.util.Arrays.fill(s, (byte) b);
        return s;
    }

    private static String sha384Hex(byte[] b) throws Exception {
        return Hex.encode(MessageDigest.getInstance("SHA-384").digest(b));
    }

    // ---- corpus-derived builders --------------------------------------------------------

    private static String nameScope;
    private static String a2aScope;

    private static List<Naming.NameBinding> bindings() {
        String nu = field(nameScope, "name_utf8");
        List<Naming.NameBinding> out = new ArrayList<>();
        for (String b : splitObjects(arrayBlock(nameScope, "bindings"))) {
            out.add(new Naming.NameBinding(nu, hb(field(b, "signer_hex")), intField(b, "seq"), hb(field(b, "prev_hex"))));
        }
        return out;
    }

    private static List<Naming.Transition> transitions() {
        byte[] task = field(a2aScope, "task_utf8").getBytes(StandardCharsets.UTF_8);
        byte[] card = hb(field(objBlock(a2aScope, "card"), "card_id_hex"));
        List<Naming.Transition> out = new ArrayList<>();
        for (String t : splitObjects(arrayBlock(a2aScope, "transitions"))) {
            out.add(new Naming.Transition(task, card, intField(t, "from"), intField(t, "to"),
                    intField(t, "seq"), hb(field(t, "prev_hex"))));
        }
        return out;
    }

    private static Description.Import cardImport() {
        String c = objBlock(a2aScope, "card");
        List<Description.Operation> ops = new ArrayList<>();
        for (String o : splitObjects(arrayBlock(c, "operations"))) {
            ops.add(new Description.Operation(field(o, "name"), intField(o, "effect"), intField(o, "requires_approval")));
        }
        return new Description.Import(hb(field(c, "importer_hex")), intField(c, "format"), hb(field(c, "foreign_hex")), ops);
    }

    private static void run() throws Exception {
        String json = Files.readString(findVector(), StandardCharsets.UTF_8);
        nameScope = objBlock(json, "name");
        a2aScope = objBlock(json, "a2a");

        byteParity();
        walkHistory();
        holeDetected();
        forkDetected();
        chainVerifyFailClosed();
        transitionTable();       // the mutation-target assertion
        taskChain();
        taskGap();
        cardBindsProfile();
        malformedRejected();
        crossLangPins();
        oversizedSeq();
        minimal();
        keysOutOfOrder();
        lookAlike();
    }

    // ---- byte parity (design §22) -------------------------------------------------------

    private static void byteParity() {
        List<String> bs = splitObjects(arrayBlock(nameScope, "bindings"));
        check("bindings count == 3", Integer.toString(bs.size()), "3");
        List<Naming.NameBinding> bindings = bindings();
        for (int i = 0; i < bindings.size(); i++) {
            Naming.NameBinding nb = bindings.get(i);
            String bv = bs.get(i);
            check("binding[" + i + "].bytes == oracle", Hex.encode(nb.bytes()), field(bv, "body_hex"));
            check("binding[" + i + "].head == oracle", Hex.encode(nb.head()), field(bv, "head_hex"));
            check("binding[" + i + "].id == oracle", Hex.encode(nb.id()), field(bv, "id_hex"));
        }
        // The fork sibling b' at seq 1 also encodes byte-identically.
        String fp = objBlock(objBlock(nameScope, "fork"), "b_prime");
        Naming.NameBinding bp = new Naming.NameBinding(field(nameScope, "name_utf8"),
                hb(field(fp, "signer_hex")), intField(fp, "seq"), hb(field(fp, "prev_hex")));
        check("fork b_prime body == oracle", Hex.encode(bp.bytes()), field(fp, "body_hex"));

        List<String> ts = splitObjects(arrayBlock(a2aScope, "transitions"));
        check("transitions count == 4", Integer.toString(ts.size()), "4");
        List<Naming.Transition> trs = transitions();
        for (int i = 0; i < trs.size(); i++) {
            Naming.Transition tr = trs.get(i);
            String tv = ts.get(i);
            check("transition[" + i + "].bytes == oracle", Hex.encode(tr.bytes()), field(tv, "body_hex"));
            check("transition[" + i + "].head == oracle", Hex.encode(tr.head()), field(tv, "head_hex"));
            check("transition[" + i + "].id == oracle", Hex.encode(tr.id()), field(tv, "id_hex"));
        }

        String c = objBlock(a2aScope, "card");
        Description.Import im = cardImport();
        check("card import body == oracle", Hex.encode(im.bytes()), field(c, "import_body_hex"));
        check("card import id (the bound card) == oracle", Hex.encode(im.id()), field(c, "card_id_hex"));
    }

    // ---- name-history walk --------------------------------------------------------------

    private static void walkHistory() {
        List<Naming.NameBinding> bindings = bindings();
        List<Naming.NameEvent> events = Naming.walkHistory(bindings);
        List<String> walk = splitObjects(arrayBlock(nameScope, "walk"));
        check("walk length == oracle", Integer.toString(events.size()), Integer.toString(walk.size()));
        for (int i = 0; i < events.size(); i++) {
            check("walk[" + i + "].seq == oracle", Long.toString(events.get(i).seq), Long.toString(intField(walk.get(i), "seq")));
            check("walk[" + i + "].signer == oracle", Hex.encode(events.get(i).signer), field(walk.get(i), "signer_hex"));
        }
        List<String> bs = splitObjects(arrayBlock(nameScope, "bindings"));
        check("current signer == last binding's signer",
                Hex.encode(events.get(events.size() - 1).signer), field(bs.get(bs.size() - 1), "signer_hex"));
        // A name change mid-chain breaks the walk (one name per chain).
        Naming.NameBinding b1 = bindings.get(1);
        Naming.NameBinding renamed = new Naming.NameBinding("other.name", b1.signer, b1.seq, b1.prev);
        check("name change mid-chain breaks the walk",
                errKind(() -> Naming.walkHistory(List.of(bindings.get(0), renamed))), "NameChainBroken");
    }

    private static void holeDetected() {
        List<Naming.NameBinding> bindings = bindings();
        check("contiguous chain has no hole", Boolean.toString(Naming.detectHole(bindings).broken), "false");
        Naming.Break br = Naming.detectHole(List.of(bindings.get(0), bindings.get(2))); // seq 1 deleted
        check("deleted binding leaves a hole", Boolean.toString(br.broken), "true");
        check("hole position == oracle", Integer.toString(br.position),
                Long.toString(intField(objBlock(nameScope, "hole"), "first_hole_position")));
    }

    private static void forkDetected() {
        List<Naming.NameBinding> bindings = bindings();
        String forkScope = objBlock(nameScope, "fork");
        String fp = objBlock(forkScope, "b_prime");
        Naming.NameBinding bp = new Naming.NameBinding(field(nameScope, "name_utf8"),
                hb(field(fp, "signer_hex")), intField(fp, "seq"), hb(field(fp, "prev_hex")));
        Naming.Break f = Naming.detectFork(bindings.get(1), bp);
        check("fork detected", Boolean.toString(f.broken), "true");
        check("fork position == oracle", Integer.toString(f.position), Long.toString(intField(forkScope, "position")));
        check("identical bindings are not a fork", Boolean.toString(Naming.detectFork(bindings.get(1), bindings.get(1)).broken), "false");
        check("different-seq bindings are not a fork", Boolean.toString(Naming.detectFork(bindings.get(1), bindings.get(2)).broken), "false");

        // Signed non-repudiable proof: one authority signs BOTH conflicting bindings.
        byte[] seed = seed(0x11);
        byte[] pk = Cose.mldsaKeygen("ML-DSA-65", seed);
        byte[] fpk = Cose.mldsaKeygen("ML-DSA-65", seed(0x22));
        String sid = Identity.signerId(ALG, pk);
        byte[] signedA = Naming.signBinding(bindings.get(1), ALG, seed);
        byte[] signedB = Naming.signBinding(bp, ALG, seed);
        Naming.NameForkProof proof = new Naming.NameForkProof(sid.getBytes(StandardCharsets.UTF_8), signedA, signedB);
        check("signed fork proof verifies at the fork position",
                Integer.toString(proof.verify(PROFILE, ALG, pk)), Long.toString(intField(forkScope, "position")));
        check("a foreign key does not verify the accused's signatures",
                errKind(() -> proof.verify(PROFILE, ALG, fpk)), "BadSignature");
        check("an unnamed accused is NameForkProofInvalid",
                errKind(() -> new Naming.NameForkProof(new byte[0], signedA, signedB).verify(PROFILE, ALG, pk)), "NameForkProofInvalid");
        check("identical signed bodies are NameForkProofInvalid",
                errKind(() -> new Naming.NameForkProof(sid.getBytes(StandardCharsets.UTF_8), signedA, signedA).verify(PROFILE, ALG, pk)),
                "NameForkProofInvalid");
    }

    private static void chainVerifyFailClosed() {
        byte[] seed = seed(0x11);
        byte[] pk = Cose.mldsaKeygen("ML-DSA-65", seed);
        byte[] fpk = Cose.mldsaKeygen("ML-DSA-65", seed(0x22));
        String nu = field(nameScope, "name_utf8");
        List<String> bs = splitObjects(arrayBlock(nameScope, "bindings"));
        // Build a signed chain via the Registrar (rotation A -> B -> C).
        Naming.Registrar reg = new Naming.Registrar(nu, ALG, seed);
        List<byte[]> objs = new ArrayList<>();
        for (int i = 0; i < bs.size(); i++) {
            Naming.SignedBinding sb = reg.append(hb(field(bs.get(i), "signer_hex")));
            check("registrar reproduces oracle body[" + i + "]", Hex.encode(sb.binding.bytes()), field(bs.get(i), "body_hex"));
            objs.add(sb.obj);
        }
        List<Naming.NameBinding> verified = Naming.verifyChain(objs, PROFILE, ALG, pk);
        check("verified chain walks fully", Integer.toString(Naming.walkHistory(verified).size()), Integer.toString(bs.size()));
        // A reordered chain breaks the prev/seq linkage.
        check("reordered chain rejected NameChainBroken",
                errKind(() -> Naming.verifyChain(List.of(objs.get(0), objs.get(2), objs.get(1)), PROFILE, ALG, pk)), "NameChainBroken");
        // A tampered object fails its signature.
        byte[] corrupt = objs.get(1).clone();
        corrupt[corrupt.length - 1] ^= 0x01;
        check("tampered object rejected BadSignature",
                errKind(() -> Naming.verifyChain(List.of(objs.get(0), corrupt, objs.get(2)), PROFILE, ALG, pk)), "BadSignature");
        // A foreign verifier authenticates none of the bindings.
        check("foreign verifier rejects the chain BadSignature",
                errKind(() -> Naming.verifyChain(objs, PROFILE, ALG, fpk)), "BadSignature");
        check("foreign verifier rejects a single binding BadSignature",
                errKind(() -> Naming.verifyBinding(objs.get(0), PROFILE, ALG, fpk)), "BadSignature");
    }

    // ---- A2A legal-edge table (THIS is the mutation-target assertion) --------------------

    private static void transitionTable() {
        List<long[]> legal = intPairs(arrayBlock(a2aScope, "legal_edges"));
        List<long[]> illegal = intPairs(arrayBlock(a2aScope, "illegal_edges"));
        check("legal-edge table size == oracle", Integer.toString(Naming.legalEdges().size()), Integer.toString(legal.size()));
        for (long[] e : legal) {
            check("legal edge " + e[0] + "->" + e[1] + " accepted", Boolean.toString(Naming.legalEdge(e[0], e[1])), "true");
            check("legal edge " + e[0] + "->" + e[1] + " verifyTransition no-error",
                    errKind(() -> Naming.verifyTransition(e[0], e[1])), "no-error");
        }
        for (long[] e : illegal) {
            check("illegal edge " + e[0] + "->" + e[1] + " not legal", Boolean.toString(Naming.legalEdge(e[0], e[1])), "false");
            check("illegal edge " + e[0] + "->" + e[1] + " rejected IllegalTransition",
                    errKind(() -> Naming.verifyTransition(e[0], e[1])), "IllegalTransition");
        }
        // Categories match the oracle.
        String states = objBlock(a2aScope, "states");
        check("start state == oracle", Long.toString(Naming.START_STATE), Long.toString(intField(states, "start")));
        for (long s : intList(arrayBlock(states, "terminal"))) {
            check("state " + s + " is terminal", Boolean.toString(Naming.isTerminal(s)), "true");
        }
        for (long s : intList(arrayBlock(states, "interrupted"))) {
            check("state " + s + " is interrupted", Boolean.toString(Naming.isInterrupted(s)), "true");
        }
        // A terminal state has no legal out-edge.
        for (long s : intList(arrayBlock(states, "terminal"))) {
            for (long to = 0; to < 8; to++) {
                check("terminal " + s + " has no out-edge to " + to, Boolean.toString(Naming.legalEdge(s, to)), "false");
            }
        }
    }

    private static void taskChain() {
        byte[] seed = seed(0x11);
        byte[] pk = Cose.mldsaKeygen("ML-DSA-65", seed);
        byte[] card = hb(field(objBlock(a2aScope, "card"), "card_id_hex"));
        byte[] task = field(a2aScope, "task_utf8").getBytes(StandardCharsets.UTF_8);
        List<Naming.Transition> trs = transitions();
        List<byte[]> objs = new ArrayList<>();
        for (Naming.Transition t : trs) {
            objs.add(Naming.signTransition(t, ALG, seed));
        }
        check("legal ordered lifecycle verifies (4 transitions)",
                Integer.toString(Naming.verifyTaskChain(objs, card, PROFILE, ALG, pk).size()), "4");

        byte[] genesis = Naming.genesis();
        Naming.Transition t0 = new Naming.Transition(task, card, Naming.STATE_SUBMITTED, Naming.STATE_WORKING, 0, genesis);
        // ILLEGAL edge inside a chain: working -> submitted.
        Naming.Transition illegal = new Naming.Transition(task, card, Naming.STATE_WORKING, Naming.STATE_SUBMITTED, 1, t0.head());
        check("illegal edge inside a chain rejected", chainErr(List.of(t0, illegal), card, seed, pk), "IllegalTransition");
        // NON-CONTIGUOUS from: input-required -> working after a working->? gap.
        Naming.Transition noncontig = new Naming.Transition(task, card, Naming.STATE_INPUT_REQUIRED, Naming.STATE_WORKING, 1, t0.head());
        check("non-contiguous from rejected", chainErr(List.of(t0, noncontig), card, seed, pk), "IllegalTransition");
        // BAD START: seq-0 does not leave the start state.
        Naming.Transition badstart = new Naming.Transition(task, card, Naming.STATE_WORKING, Naming.STATE_INPUT_REQUIRED, 0, genesis);
        check("bad start state rejected", chainErr(List.of(badstart), card, seed, pk), "IllegalTransition");
        // FOREIGN CARD.
        Naming.Transition fc = new Naming.Transition(task, hb(field(a2aScope, "foreign_card_id_hex")),
                Naming.STATE_SUBMITTED, Naming.STATE_WORKING, 0, genesis);
        check("foreign card rejected", chainErr(List.of(fc), card, seed, pk), "ForeignCard");
        // GAP: present [t0, t2].
        check("gapped chain rejected TaskChainBroken",
                errKind(() -> Naming.verifyTaskChain(List.of(objs.get(0), objs.get(2)), card, PROFILE, ALG, pk)), "TaskChainBroken");
        // BAD SIGNATURE.
        byte[] corrupt = objs.get(0).clone();
        corrupt[corrupt.length - 1] ^= 0x01;
        check("tampered transition rejected BadSignature",
                errKind(() -> Naming.verifyTaskChain(List.of(corrupt, objs.get(1), objs.get(2), objs.get(3)), card, PROFILE, ALG, pk)),
                "BadSignature");
    }

    private static String chainErr(List<Naming.Transition> trs, byte[] card, byte[] seed, byte[] pk) {
        List<byte[]> objs = new ArrayList<>();
        for (Naming.Transition t : trs) {
            objs.add(Naming.signTransition(t, ALG, seed));
        }
        return errKind(() -> Naming.verifyTaskChain(objs, card, PROFILE, ALG, pk));
    }

    private static void taskGap() {
        List<Naming.Transition> trs = transitions();
        check("contiguous transitions have no gap", Boolean.toString(Naming.detectTaskGap(trs).broken), "false");
        Naming.Break g = Naming.detectTaskGap(List.of(trs.get(0), trs.get(2)));
        check("gapped transitions detected", Boolean.toString(g.broken), "true");
        check("task gap position == oracle", Integer.toString(g.position),
                Long.toString(intField(objBlock(a2aScope, "gap"), "first_gap_position")));
    }

    private static void cardBindsProfile() {
        byte[] seed = seed(0x11);
        byte[] pk = Cose.mldsaKeygen("ML-DSA-65", seed);
        Description.Import im = cardImport();
        byte[] card = im.id();
        check("card id == oracle", Hex.encode(card), field(objBlock(a2aScope, "card"), "card_id_hex"));
        Description.Operation submit = im.operation("submit");
        check("submit op effect == idempotent_write", Long.toString(submit.effectClass()), Long.toString(Policy.IDEMPOTENT_WRITE));
        check("submit op requires approval", Boolean.toString(submit.requiresApprovalFlag()), "true");
        // A chain bound to this card verifies.
        List<byte[]> objs = new ArrayList<>();
        for (Naming.Transition t : transitions()) {
            objs.add(Naming.signTransition(t, ALG, seed));
        }
        check("chain bound to the card verifies",
                Integer.toString(Naming.verifyTaskChain(objs, card, PROFILE, ALG, pk).size()), "4");
        // A different importer yields a different card id; a chain carrying it is refused.
        Description.Import other = new Description.Import("IMPORTER_ID_B".getBytes(StandardCharsets.UTF_8),
                im.format, im.foreign, im.operations);
        check("a different importer yields a different card id", Boolean.toString(java.util.Arrays.equals(other.id(), card)), "false");
        byte[] task = field(a2aScope, "task_utf8").getBytes(StandardCharsets.UTF_8);
        Naming.Transition foreignT = new Naming.Transition(task, other.id(), Naming.STATE_SUBMITTED, Naming.STATE_WORKING, 0, Naming.genesis());
        check("a chain carrying a foreign card is refused ForeignCard",
                errKind(() -> Naming.verifyTaskChain(List.of(Naming.signTransition(foreignT, ALG, seed)), card, PROFILE, ALG, pk)),
                "ForeignCard");
    }

    private static void malformedRejected() {
        check("empty CBOR array is NameMalformed (binding)", errKind(() -> Naming.parseNameBinding(new byte[]{(byte) 0x80})), "NameMalformed");
        check("bare uint is NameMalformed (transition)", errKind(() -> Naming.parseTransition(new byte[]{0x00})), "NameMalformed");
    }

    // ---- cross-language signed-object byte parity (Java == Go == Rust == Python) ---------

    private static void crossLangPins() throws Exception {
        byte[] seed = seed(0x11);
        Naming.NameBinding nb = bindings().get(0);
        check("cross-lang signed name-binding pin (SHA-384)", sha384Hex(Naming.signBinding(nb, ALG, seed)), PIN_SIGNED_BINDING_SHA384);
        Naming.Transition tr = transitions().get(0);
        check("cross-lang signed task-transition pin (SHA-384)", sha384Hex(Naming.signTransition(tr, ALG, seed)), PIN_SIGNED_TRANSITION_SHA384);
    }

    // ---- >2^53 seq round-trip, minimal, canonical-key, look-alike ------------------------

    private static void oversizedSeq() {
        String bn = objBlock(nameScope, "big_seq");
        long bseq = Long.parseLong(field(bn, "seq_str"));
        check("name big_seq > 2^53", Boolean.toString(bseq > (1L << 53)), "true");
        Naming.NameBinding nb = new Naming.NameBinding(field(nameScope, "name_utf8"),
                hb(field(bn, "signer_hex")), bseq, hb(field(bn, "prev_hex")));
        check("name big_seq body == oracle", Hex.encode(nb.bytes()), field(bn, "body_hex"));
        check("name big_seq round-trips", Long.toString(Naming.parseNameBinding(nb.bytes()).seq), Long.toString(bseq));

        String ba = objBlock(a2aScope, "big_seq");
        long tseq = Long.parseLong(field(ba, "seq_str"));
        Naming.Transition tr = new Naming.Transition(field(a2aScope, "task_utf8").getBytes(StandardCharsets.UTF_8),
                hb(field(objBlock(a2aScope, "card"), "card_id_hex")), intField(ba, "from"), intField(ba, "to"), tseq, hb(field(ba, "prev_hex")));
        check("a2a big_seq body == oracle", Hex.encode(tr.bytes()), field(ba, "body_hex"));
        check("a2a big_seq round-trips", Long.toString(Naming.parseTransition(tr.bytes()).seq), Long.toString(tseq));
    }

    private static void minimal() {
        String n = objBlock(nameScope, "minimal");
        Naming.NameBinding nb = new Naming.NameBinding(field(n, "name_utf8"), hb(field(n, "signer_hex")), intField(n, "seq"), hb(field(n, "prev_hex")));
        check("name minimal body == oracle", Hex.encode(nb.bytes()), field(n, "body_hex"));
        check("name minimal id == oracle", Hex.encode(nb.id()), field(n, "id_hex"));
        check("name minimal parses", Boolean.toString(Naming.parseNameBinding(nb.bytes()) != null), "true");
        String a = objBlock(a2aScope, "minimal");
        Naming.Transition tr = new Naming.Transition(hb(field(a, "task_hex")), hb(field(a, "card_hex")),
                intField(a, "from"), intField(a, "to"), intField(a, "seq"), hb(field(a, "prev_hex")));
        check("a2a minimal body == oracle", Hex.encode(tr.bytes()), field(a, "body_hex"));
        check("a2a minimal parses", Boolean.toString(Naming.parseTransition(tr.bytes()) != null), "true");
    }

    private static void keysOutOfOrder() {
        String koo = objBlock(nameScope, "keys_out_of_order");
        String b0 = splitObjects(arrayBlock(nameScope, "bindings")).get(0);
        Naming.NameBinding nb = new Naming.NameBinding(field(nameScope, "name_utf8"),
                hb(field(b0, "signer_hex")), intField(b0, "seq"), hb(field(b0, "prev_hex")));
        check("canonical binding body == oracle", Hex.encode(nb.bytes()), field(koo, "canonical_binding_body_hex"));
        check("canonical body decodes", errKind(() -> Cbor.decode(hb(field(koo, "canonical_binding_body_hex")))), "no-error");
        check("non-canonical (keys 4,3,2,1) rejected NonCanonical",
                errKind(() -> Cbor.decode(hb(field(koo, "noncanonical_binding_body_hex")))), "NonCanonical");
    }

    private static void lookAlike() {
        String la = objBlock(nameScope, "look_alike");
        check("a 4-field binding fed to parseTransition is NameMalformed",
                errKind(() -> Naming.parseTransition(hb(field(la, "binding_body_hex")))), "NameMalformed");
        check("a 6-field transition fed to parseNameBinding is NameMalformed",
                errKind(() -> Naming.parseNameBinding(hb(field(la, "transition_body_hex")))), "NameMalformed");
    }

    public static void main(String[] args) throws Exception {
        System.out.println("naming conformance (Java) — graded vs vectors/naming/cases.json");
        run();
        System.out.println(fails == 0 ? "NamingKatTest: PASS" : "NamingKatTest: FAIL (" + fails + ")");
        System.exit(fails == 0 ? 0 : 1);
    }
}
