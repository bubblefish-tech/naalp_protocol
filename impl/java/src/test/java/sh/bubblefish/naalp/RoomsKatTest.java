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
 * Rooms membership conformance (feature #64) for the Java SDK, graded against the shared independent
 * corpus vectors/rooms/cases.json (NOT produced by this code): the membership op body/content-id byte
 * parity, the receipt-chained room log (bodies + heads via the C7 audit authority) with the epoch
 * progression and the final membership/ownership state, the principal-binding wire bodies + per-principal
 * chain heads, and the fail-closed behavioural surface (StaleEpoch, Unauthorized, OwnerImmutable,
 * add-only ownership, RebindUnauthorized) exercised with REAL ML-DSA-65 signed objects and a REAL
 * co-signed key rotation.
 *
 * <p>CORPUS-GRADED (pure bytes / values): every op body + content id, every room-log receipt body +
 * head, the final log head + epoch + members + owners, and every principal binding body + head —
 * reproduced byte-for-byte or value-for-value from the corpus. SECURITY/BEHAVIOUR DEMONSTRATED IN
 * ISOLATION with real crypto (the corpus carries no signature vector): the signed membership object
 * verifies end-to-end through the spine (real ML-DSA-65 + signer-id binding) while a baseline verifier
 * rejects the tier-1 kind UnknownKind; the rebind is a REAL co-signed identity rotation.
 *
 * <p>KAT convention (a standalone {@code main} exiting non-zero on any failure); named "…KatTest" so
 * the filename carries the "test" token the ten-language-parity gate indexes. Written test-first:
 * {@link Rooms} is absent until Rooms.java lands, so this fails RED with a javac "cannot find symbol
 * Rooms"; the recorded mutation disables the epoch-bump check in {@link Rooms.Room#apply}, which flips
 * the named "second op against a stale epoch rejected StaleEpoch" check on its assertion.
 */
public final class RoomsKatTest {
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
            Path p = d.resolve("vectors").resolve("rooms").resolve("cases.json");
            if (Files.isRegularFile(p)) {
                return p;
            }
            d = d.getParent();
        }
        throw new AssertionError("vectors/rooms/cases.json not found from " + System.getProperty("user.dir"));
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

    /** The named kind thrown by {@code r}, or "no-error". */
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

    private static void run() throws Exception {
        String json = Files.readString(findVector(), StandardCharsets.UTF_8);
        String rj = objBlock(json, "rooms");
        String reg = objBlock(json, "registry");
        byte[] room = Hex.decode(field(rj, "room_id_hex"));
        List<String> ops = splitObjects(arrayBlock(rj, "ops"));
        List<String> log = splitObjects(arrayBlock(rj, "room_log"));

        // 1. membership op body + content-id byte parity (design §2.3).
        for (String oj : ops) {
            Rooms.RoomOp op = new Rooms.RoomOp(room, intField(oj, "op"), intField(oj, "epoch_at_build"),
                    field(oj, "subject"), intField(oj, "role"));
            String nm = field(oj, "op_name");
            check("op " + nm + " body == oracle", Hex.encode(op.bytes()), field(oj, "body_hex"));
            check("op " + nm + " content id == oracle", Hex.encode(op.contentId()), field(oj, "op_content_id_hex"));
        }

        // 2. the full run: receipt-chained log + state machine (byte + value).
        byte[] aseed = seed(90);
        byte[] apk = Cose.mldsaKeygen("ML-DSA-65", aseed);
        Audit.Authority auth = new Audit.Authority(ALG, aseed);
        String create = ops.get(0);
        Rooms.RoomOp cop = new Rooms.RoomOp(room, intField(create, "op"), intField(create, "epoch_at_build"),
                field(create, "subject"), intField(create, "role"));
        String creator = field(create, "subject");
        Rooms.Created c0 = Rooms.createRoom(cop, creator, auth, intField(log.get(0), "at"));
        Rooms.Room rm = c0.room;
        check("create cursor == 0", Long.toString(c0.cursor), "0");
        check("room epoch after create == 1", Long.toString(rm.epoch()), "1");
        checkReceipt(c0.receipt, log.get(0));

        for (int i = 1; i < ops.size(); i++) {
            String oj = ops.get(i);
            Rooms.RoomOp op = new Rooms.RoomOp(room, intField(oj, "op"), intField(oj, "epoch_at_build"),
                    field(oj, "subject"), intField(oj, "role"));
            check("built epoch tracks room epoch (seq " + intField(oj, "seq") + ")",
                    Long.toString(intField(oj, "epoch_at_build")), Long.toString(rm.epoch()));
            Rooms.Applied ap = rm.apply(op, creator, intField(log.get(i), "at"));
            check("cursor == oracle seq " + intField(oj, "seq"), Long.toString(ap.cursor), Long.toString(intField(oj, "seq")));
            check("epoch bumped to " + intField(oj, "epoch_after"), Long.toString(rm.epoch()), Long.toString(intField(oj, "epoch_after")));
            checkReceipt(ap.receipt, log.get(i));
        }

        check("final epoch == oracle", Long.toString(rm.epoch()), Long.toString(intField(rj, "final_epoch")));
        check("final owners == oracle", String.join(",", rm.owners()), String.join(",", topStrings(arrayBlock(rj, "final_owners"))));
        for (String mj : splitObjects(arrayBlock(rj, "final_members"))) {
            Rooms.RoleResult rr = rm.roleOf(field(mj, "subject"));
            check("final member " + field(mj, "subject") + " is a member", Boolean.toString(rr.member), "true");
            check("final member " + field(mj, "subject") + " role == oracle", Long.toString(rr.role), Long.toString(intField(mj, "role")));
        }
        check("room log verifies offline", errKind(() -> Audit.verifyChain(rm.receipts(), rm.sigs(), ALG, apk)), "no-error");
        check("final log head == oracle",
                Hex.encode(rm.receipts().get(rm.receipts().size() - 1).head()), field(rj, "final_log_head_hex"));

        // 3. signed membership end-to-end (REAL ML-DSA-65 through the spine).
        signedMembershipEndToEnd();

        // 4. EPOCH-BUMPING: StaleEpoch (THIS is the mutation-target assertion).
        staleEpochRejected();

        // 5. only an owner may change membership (fail-closed).
        unauthorizedActorRejected();

        // 6. O2: add-only ownership, never ownerless.
        addOnlyOwnership();

        // 7. Delivery Model B: principal-binding wire bytes (byte parity).
        for (String bj : splitObjects(arrayBlock(reg, "bindings"))) {
            Rooms.Binding b = new Rooms.Binding(field(bj, "principal"), field(bj, "handle"),
                    intField(bj, "epoch"), Hex.decode(field(bj, "prev_hex")));
            check("binding " + field(bj, "principal") + "@" + intField(bj, "epoch") + " body == oracle",
                    Hex.encode(b.bytes()), field(bj, "body_hex"));
            check("binding " + field(bj, "principal") + "@" + intField(bj, "epoch") + " head == oracle",
                    Hex.encode(b.head()), field(bj, "head_after_hex"));
        }

        // 8. Delivery Model B: rebind-on-rotation (REAL co-signed rotation).
        rebindOnRotation();

        // 9. double-bind refused; first binding is genesis (prev == zero).
        bindDuplicateAndGenesis();
    }

    private static void checkReceipt(Audit.Receipt rec, String want) {
        long sq = intField(want, "seq");
        check("receipt body seq=" + sq + " == oracle", Hex.encode(rec.bytes()), field(want, "body_hex"));
        check("receipt head seq=" + sq + " == oracle", Hex.encode(rec.head()), field(want, "head_after_hex"));
        check("receipt obj seq=" + sq + " == oracle", Hex.encode(rec.obj), field(want, "obj_hex"));
    }

    private static String signerId(int b) {
        return Identity.signerId(ALG, Cose.mldsaKeygen("ML-DSA-65", seed(b)));
    }

    private static void signedMembershipEndToEnd() {
        byte[] room = new byte[]{0x20, 0x30, 1, 2, 3, 4};
        byte[] oseed = seed(50);
        byte[] opk = Cose.mldsaKeygen("ML-DSA-65", oseed);
        String oid = Identity.signerId(ALG, opk);
        String bobid = signerId(51);
        Audit.Authority auth = new Audit.Authority(ALG, seed(91));

        Rooms.Created c = Rooms.createRoom(new Rooms.RoomOp(room, Rooms.OP_CREATE, 0, oid, Rooms.ROLE_OWNER), oid, auth, 1000);
        Rooms.Room rm = c.room;

        Rooms.RoomOp add = new Rooms.RoomOp(room, Rooms.OP_ADD_MEMBER, rm.epoch(), bobid, Rooms.ROLE_MEMBER);
        Envelope.Object obj = add.envelopeObject(oid.getBytes(StandardCharsets.UTF_8), 1001, PROFILE, List.of());
        byte[] signed = Envelope.sign(obj, ALG, oseed);
        Rooms.Applied ap = rm.applySigned(PROFILE, ALG, opk, signed, 1001);
        check("signed add_member cursor == 1", Long.toString(ap.cursor), "1");
        Rooms.RoleResult rr = rm.roleOf(bobid);
        check("signed add_member: bob is a member", Boolean.toString(rr.member), "true");
        check("signed add_member: bob role == member", Long.toString(rr.role), Long.toString(Rooms.ROLE_MEMBER));

        // A baseline-only verifier (no tier licensed) rejects the tier-1 room kind as UnknownKind.
        Envelope.KindValidator baseline = (ch, k) -> {
            try {
                Channels.lookup(ch, k);
                return true;
            } catch (NaalpException e) {
                return false;
            }
        };
        check("baseline verifier rejects the tier-1 kind UnknownKind",
                errKind(() -> Envelope.verify(PROFILE, ALG, opk, baseline, signed, null)), "UnknownKind");
    }

    private static void staleEpochRejected() {
        byte[] room = new byte[]{9, 9, 9};
        String oid = signerId(52);
        String bobid = signerId(53);
        String carolid = signerId(54);
        Audit.Authority auth = new Audit.Authority(ALG, seed(92));
        Rooms.Room rm = Rooms.createRoom(new Rooms.RoomOp(room, Rooms.OP_CREATE, 0, oid, Rooms.ROLE_OWNER), oid, auth, 1).room;
        long e = rm.epoch(); // both ops build against this epoch
        rm.apply(new Rooms.RoomOp(room, Rooms.OP_ADD_MEMBER, e, bobid, Rooms.ROLE_MEMBER), oid, 2);
        check("second op against a stale epoch rejected StaleEpoch",
                errKind(() -> rm.apply(new Rooms.RoomOp(room, Rooms.OP_ADD_MEMBER, e, carolid, Rooms.ROLE_MEMBER), oid, 3)),
                "StaleEpoch");
        check("no state change on a rejected stale-epoch op", Boolean.toString(rm.roleOf(carolid).member), "false");
        // The same op rebuilt against the CURRENT epoch is accepted.
        rm.apply(new Rooms.RoomOp(room, Rooms.OP_ADD_MEMBER, rm.epoch(), carolid, Rooms.ROLE_MEMBER), oid, 4);
        check("op rebuilt against the current epoch is accepted", Boolean.toString(rm.roleOf(carolid).member), "true");
    }

    private static void unauthorizedActorRejected() {
        byte[] room = new byte[]{7, 7};
        String oid = signerId(55);
        String bobid = signerId(56);
        String malloryid = signerId(57);
        Audit.Authority auth = new Audit.Authority(ALG, seed(93));
        Rooms.Room rm = Rooms.createRoom(new Rooms.RoomOp(room, Rooms.OP_CREATE, 0, oid, Rooms.ROLE_OWNER), oid, auth, 1).room;
        rm.apply(new Rooms.RoomOp(room, Rooms.OP_ADD_MEMBER, rm.epoch(), bobid, Rooms.ROLE_MEMBER), oid, 2);
        // mallory (not even a member) tries to add themselves as owner.
        check("non-owner actor rejected Unauthorized",
                errKind(() -> rm.apply(new Rooms.RoomOp(room, Rooms.OP_ADD_OWNER, rm.epoch(), malloryid, Rooms.ROLE_OWNER), malloryid, 3)),
                "Unauthorized");
        // bob (a member, not an owner) also cannot add a member.
        check("member (non-owner) actor rejected Unauthorized",
                errKind(() -> rm.apply(new Rooms.RoomOp(room, Rooms.OP_ADD_MEMBER, rm.epoch(), malloryid, Rooms.ROLE_MEMBER), bobid, 4)),
                "Unauthorized");
        check("owner count unchanged on rejected ops", Integer.toString(rm.ownerCount()), "1");
    }

    private static void addOnlyOwnership() {
        byte[] room = new byte[]{5};
        String aliceid = signerId(58);
        String bobid = signerId(59);
        Audit.Authority auth = new Audit.Authority(ALG, seed(94));
        Rooms.Room rm = Rooms.createRoom(new Rooms.RoomOp(room, Rooms.OP_CREATE, 0, aliceid, Rooms.ROLE_OWNER), aliceid, auth, 1).room;
        check("one owner after create", Integer.toString(rm.ownerCount()), "1");
        rm.apply(new Rooms.RoomOp(room, Rooms.OP_ADD_OWNER, rm.epoch(), bobid, Rooms.ROLE_OWNER), aliceid, 2);
        check("two owners after add_owner", Integer.toString(rm.ownerCount()), "2");
        check("bob is an owner", Boolean.toString(rm.isOwner(bobid)), "true");
        // remove_member(alice) — an owner — is refused OwnerImmutable.
        check("remove of an owner refused OwnerImmutable",
                errKind(() -> rm.apply(new Rooms.RoomOp(room, Rooms.OP_REMOVE_MEMBER, rm.epoch(), aliceid, Rooms.ROLE_MEMBER), bobid, 3)),
                "OwnerImmutable");
        // change_role(alice -> member) — demoting an owner — is refused OwnerImmutable.
        check("demotion of an owner refused OwnerImmutable",
                errKind(() -> rm.apply(new Rooms.RoomOp(room, Rooms.OP_CHANGE_ROLE, rm.epoch(), aliceid, Rooms.ROLE_MEMBER), bobid, 4)),
                "OwnerImmutable");
        // re-add of an existing owner is refused OwnerExists.
        check("re-add of an existing owner refused OwnerExists",
                errKind(() -> rm.apply(new Rooms.RoomOp(room, Rooms.OP_ADD_OWNER, rm.epoch(), bobid, Rooms.ROLE_OWNER), aliceid, 5)),
                "OwnerExists");
        check("room is never ownerless (>= 1 owner)", Boolean.toString(rm.ownerCount() >= 1), "true");
    }

    private static void rebindOnRotation() {
        byte[] v1seed = seed(60);
        byte[] v1pk = Cose.mldsaKeygen("ML-DSA-65", v1seed);
        String v1id = Identity.signerId(ALG, v1pk);
        byte[] v2seed = seed(61);
        byte[] v2pk = Cose.mldsaKeygen("ML-DSA-65", v2seed);
        String v2id = Identity.signerId(ALG, v2pk);
        String evilid = signerId(62);

        Rooms.PrincipalRegistry pr = new Rooms.PrincipalRegistry();
        pr.bind("agent:alice", v1id);
        check("resolve after first bind == v1", pr.resolve("agent:alice"), v1id);

        // A valid co-signed rotation v1 -> v2 authorises the rebind; the semantic id survives.
        Identity.RotationRecord rot = new Identity.RotationRecord(v1id, v2id, 100);
        byte[][] sigs = Identity.signRotation(rot, ALG, v1seed, v2seed);
        pr.rebind("agent:alice", v2id, rot, ALG, v1pk, ALG, v2pk, sigs[0], sigs[1]);
        check("resolve after a valid rebind == v2", pr.resolve("agent:alice"), v2id);

        // A hijack: a rotation whose old leg is NOT signed by the current handle is refused, unchanged.
        Identity.RotationRecord bad = new Identity.RotationRecord(v2id, evilid, 200);
        byte[][] bsigs = Identity.signRotation(bad, ALG, v1seed, v2seed); // old leg signed by v1, not v2
        check("hijack rebind refused RebindUnauthorized",
                errKind(() -> pr.rebind("agent:alice", evilid, bad, ALG, v1pk, ALG, v2pk, bsigs[0], bsigs[1])),
                "RebindUnauthorized");
        check("registry unchanged after a refused rebind", pr.resolve("agent:alice"), v2id);

        // An unknown principal resolves fail-closed.
        check("unknown principal resolves PrincipalUnknown", errKind(() -> pr.resolve("agent:nobody")), "PrincipalUnknown");
    }

    private static void bindDuplicateAndGenesis() {
        String aid = signerId(63);
        Rooms.PrincipalRegistry pr = new Rooms.PrincipalRegistry();
        Rooms.Binding b = pr.bind("agent:alice", aid);
        check("first binding epoch == 0", Long.toString(b.epoch), "0");
        check("first binding prev == genesis (all-zero)", Hex.encode(b.prev), Hex.encode(Rooms.genesisHead()));
        check("double-bind refused PrincipalExists", errKind(() -> pr.bind("agent:alice", aid)), "PrincipalExists");
    }

    public static void main(String[] args) throws Exception {
        System.out.println("rooms conformance (Java) — graded vs vectors/rooms/cases.json");
        run();
        System.out.println(fails == 0 ? "RoomsKatTest: PASS" : "RoomsKatTest: FAIL (" + fails + ")");
        System.exit(fails == 0 ? 0 : 1);
    }
}
