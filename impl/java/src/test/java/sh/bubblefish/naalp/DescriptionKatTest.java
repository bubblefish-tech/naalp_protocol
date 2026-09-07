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
 * C18 signed description / directory / import known-answer test for the Java SDK (design.md §21;
 * R-DESC-1..8), graded against the shared independent corpus vectors/description/cases.json (NOT
 * produced by this code): the description operation-table bytes/head/id, each operation body, the
 * directory bytes/head/id and its fork position (first-differing member), the length-fork position,
 * the legitimate-succession non-fork, and the import attestation bytes/head/id + foreign-id binding +
 * closed-format rejection.
 *
 * <p>CORPUS-GRADED (pure bytes / positions / verdicts): the description + directory + import bodies,
 * heads, ids; every operation body; the fork first-differing position (1) for member-substitution and
 * length-fork; the different-version non-fork; and the UnknownDescriptionFormat rejection.
 * SECURITY-CRITICAL, DEMONSTRATED IN ISOLATION (the corpus carries no signed vector): offline
 * verification (a signed Description re-verifies byte-identically — authority is the signature, not the
 * host), the non-repudiable DirectoryForkProof under real ML-DSA-65, and the confused-deputy rule of
 * VerifyImport (the wrapping signer is the SOLE authorization identity; a foreign identity named in the
 * carried bytes is rejected ImporterMismatch, R-14.6).
 *
 * <p>Written test-first: {@link Description} is absent until Description.java lands, so this fails RED
 * with a javac "cannot find symbol Description"; the recorded mutation removes the ImporterMismatch
 * guard in {@code Description.verifyImport}, which flips the named "import naming a FOREIGN importer
 * rejected ImporterMismatch" check (the confused-deputy containment R-14.6 exists to enforce).
 */
public final class DescriptionKatTest {
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
            Path p = d.resolve("vectors").resolve("description").resolve("cases.json");
            if (Files.isRegularFile(p)) {
                return p;
            }
            d = d.getParent();
        }
        throw new AssertionError("vectors/description/cases.json not found from " + System.getProperty("user.dir"));
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

    /** The inner content (brackets stripped) of the array value that follows "key":, and the index in
     *  {@code s} just past its closing bracket (so a sibling scalar after the array can be read). */
    private static int[] arraySpan(String s, String key) {
        int open = s.indexOf('[', afterKey(s, key));
        int close = matchClose(s, open);
        return new int[]{open + 1, close - 1, close};
    }

    private static String arrayBlock(String s, String key) {
        int[] span = arraySpan(s, key);
        return s.substring(span[0], span[1]);
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

    /** The quoted hex strings inside a string array's inner content, in order. */
    private static List<byte[]> splitHexStrings(String arrayInner) {
        List<byte[]> out = new ArrayList<>();
        Matcher m = Pattern.compile("\"([0-9a-fA-F]*)\"").matcher(arrayInner);
        while (m.find()) {
            out.add(Hex.decode(m.group(1)));
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
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*(-?\\d+)").matcher(scope);
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

    private static List<Description.Operation> parseOps(String opsInner) {
        List<Description.Operation> ops = new ArrayList<>();
        for (String ob : splitObjects(opsInner)) {
            ops.add(new Description.Operation(field(ob, "name"), intField(ob, "effect"), intField(ob, "requires_approval")));
        }
        return ops;
    }

    private static void run() throws Exception {
        String json = Files.readString(findVector(), StandardCharsets.UTF_8);

        // ---- 1. Description: the signed operation table -----------------------------------------
        String descScope = objBlock(json, "description");
        byte[] service = Hex.decode(field(descScope, "service_hex"));
        String opsInner = arrayBlock(descScope, "operations");
        String descTail = descScope.substring(arraySpan(descScope, "operations")[2]);
        List<Description.Operation> ops = parseOps(opsInner);

        // each operation body reproduces the oracle, with its effect + approval-declaration accessors.
        List<String> opBlocks = splitObjects(opsInner);
        for (int i = 0; i < opBlocks.size(); i++) {
            Description.Operation op = ops.get(i);
            check("operation " + op.name + " body == oracle", Hex.encode(op.bytes()), field(opBlocks.get(i), "body_hex"));
            check("operation " + op.name + " effect_class == oracle",
                    Long.toString(op.effectClass()), Long.toString(intField(opBlocks.get(i), "effect")));
            check("operation " + op.name + " requires_approval flag == oracle",
                    Boolean.toString(op.requiresApprovalFlag()), (intField(opBlocks.get(i), "requires_approval") == 1) ? "true" : "false");
        }

        Description d = new Description(service, ops);
        check("description body == oracle", Hex.encode(d.bytes()), field(descTail, "body_hex"));
        check("description head == oracle", Hex.encode(d.head()), field(descTail, "head_hex"));
        check("description id == oracle", Hex.encode(d.id()), field(descTail, "id_hex"));

        // parseDescription reconstructs the whole table from the bytes ALONE (offline-verifiable).
        Description parsed = Description.parseDescription(d.bytes());
        check("parseDescription recovers operation count", Integer.toString(parsed.operations.size()), Integer.toString(ops.size()));
        Description.Operation purge = parsed.operation("purge");
        check("parseDescription recovers purge effect (destructive)", Long.toString(purge.effectClass()), "3");
        check("parseDescription recovers purge requires_approval", Boolean.toString(purge.requiresApprovalFlag()), "true");

        // ---- 2. Directory: fork detection at the first-differing member position -----------------
        String dirScope = objBlock(json, "directory");
        byte[] dirId = Hex.decode(field(dirScope, "directory_hex"));
        long version = intField(dirScope, "version");
        List<byte[]> membersA = splitHexStrings(arrayBlock(dirScope, "members_a_hex"));
        String aScope = objBlock(dirScope, "a");
        Description.Directory dirA = new Description.Directory(dirId, version, membersA);
        check("directory A body == oracle", Hex.encode(dirA.bytes()), field(aScope, "body_hex"));
        check("directory A head == oracle", Hex.encode(dirA.head()), field(aScope, "head_hex"));
        check("directory A id == oracle", Hex.encode(dirA.id()), field(aScope, "id_hex"));

        String forkScope = objBlock(dirScope, "fork");
        List<byte[]> membersB = splitHexStrings(arrayBlock(forkScope, "members_b_hex"));
        String bScope = objBlock(forkScope, "b");
        Description.Directory dirB = new Description.Directory(dirId, version, membersB);
        check("directory B body == oracle", Hex.encode(dirB.bytes()), field(bScope, "body_hex"));
        check("directory B id == oracle", Hex.encode(dirB.id()), field(bScope, "id_hex"));

        Description.Fork fork = Description.detectFork(dirA, dirB);
        check("member-substitution fork detected", Boolean.toString(fork.isFork), "true");
        check("member-substitution fork position == oracle",
                Integer.toString(fork.position), Long.toString(intField(forkScope, "first_differing_position")));

        // a truncated member list forks at the length of the shorter list.
        String lenScope = objBlock(dirScope, "length_fork");
        List<byte[]> membersShort = splitHexStrings(arrayBlock(lenScope, "members_short_hex"));
        Description.Directory dirShort = new Description.Directory(dirId, version, membersShort);
        check("length_fork directory body == oracle", Hex.encode(dirShort.bytes()), field(lenScope, "body_hex"));
        Description.Fork lenFork = Description.detectFork(dirA, dirShort);
        check("length_fork detected", Boolean.toString(lenFork.isFork), "true");
        check("length_fork position == oracle",
                Integer.toString(lenFork.position), Long.toString(intField(lenScope, "first_differing_position")));

        // a different version is a legitimate succession, not a fork (same members set B at version 8).
        String dvScope = objBlock(dirScope, "different_version");
        Description.Directory dirV8 = new Description.Directory(dirId, intField(dvScope, "version"), membersB);
        check("different_version directory body == oracle", Hex.encode(dirV8.bytes()), field(dvScope, "body_hex"));
        check("different version is NOT a fork", Boolean.toString(Description.detectFork(dirA, dirV8).isFork), "false");

        // an identical duplicate is not a fork (corpus duplicate_first_differing_position = -1).
        check("identical directories are NOT a fork", Boolean.toString(Description.detectFork(dirA, dirA).isFork), "false");

        // ---- 3. Import: foreign carriage as a signed attestation --------------------------------
        String impScope = objBlock(json, "import");
        byte[] importer = Hex.decode(field(impScope, "importer_hex"));
        long format = intField(impScope, "format");
        byte[] foreign = Hex.decode(field(impScope, "foreign_hex"));
        List<Description.Operation> impOps = parseOps(arrayBlock(impScope, "operations"));
        String impTail = impScope.substring(arraySpan(impScope, "operations")[2]);
        Description.Import im = new Description.Import(importer, format, foreign, impOps);
        check("import body == oracle", Hex.encode(im.bytes()), field(impTail, "body_hex"));
        check("import head == oracle", Hex.encode(im.head()), field(impTail, "head_hex"));
        check("import id == oracle", Hex.encode(im.id()), field(impTail, "id_hex"));
        check("import foreign_id (bound content id) == oracle", Hex.encode(im.foreignId()), field(impScope, "foreign_id_hex"));

        Description.Import impParsed = Description.parseImport(im.bytes());
        check("parseImport recovers format", Long.toString(impParsed.format), Long.toString(format));
        check("parseImport recovers foreign_id", Hex.encode(impParsed.foreignId()), field(impScope, "foreign_id_hex"));

        // a format code outside the closed naalp-description-format set {1,2,3} is rejected on decode.
        String unknownScope = objBlock(impScope, "unknown_format");
        check("import with format 99 rejected " + field(unknownScope, "reject"),
                errKind(() -> Description.parseImport(Hex.decode(field(unknownScope, "body_hex")))), field(unknownScope, "reject"));

        // ---- 4. DEMONSTRATED IN ISOLATION — the signed paths with real ML-DSA-65 ----------------
        signedPaths(dirA, dirB, dirV8, d, im, field(impScope, "foreign_asserted_identity"), foreign, format);
    }

    private static void signedPaths(Description.Directory dirA, Description.Directory dirB,
                                    Description.Directory dirV8, Description d, Description.Import corpusIm,
                                    String foreignIdentity, byte[] foreign, long format) throws Exception {
        byte[] seed = seed(0x33);
        byte[] otherSeed = seed(0x44);
        byte[] pk = Cose.mldsaKeygen("ML-DSA-65", seed);
        byte[] otherPk = Cose.mldsaKeygen("ML-DSA-65", otherSeed);
        String signerId = Identity.signerId(ALG, pk);

        // offline verification: a signed Description re-verifies byte-identically (authority = signature,
        // not the serving host). The verify returns the SAME operation table from the bytes alone.
        byte[] signedDesc = Description.signDescription(d, ALG, seed);
        Description vd = Description.verifyDescription(signedDesc, Cose.PROFILE_PUBLIC, ALG, pk);
        check("verifyDescription returns byte-identical table (offline-verifiable)",
                Hex.encode(vd.bytes()), Hex.encode(d.bytes()));
        byte[] tamperedDesc = signedDesc.clone();
        tamperedDesc[tamperedDesc.length - 1] ^= 1;
        check("tampered signed Description rejected BadSignature",
                errKind(() -> Description.verifyDescription(tamperedDesc, Cose.PROFILE_PUBLIC, ALG, pk)), "BadSignature");

        // the non-repudiable DirectoryForkProof: two validly-signed directories by ONE signer at the
        // same (directory, version) with different members prove a fork at the first-differing position.
        byte[] signedA = Description.signDirectory(dirA, ALG, seed);
        byte[] signedB = Description.signDirectory(dirB, ALG, seed);
        Description.DirectoryForkProof proof = new Description.DirectoryForkProof(
                signerId.getBytes(StandardCharsets.UTF_8), signedA, signedB);
        check("DirectoryForkProof verifies and reports position 1",
                Integer.toString(proof.verify(Cose.PROFILE_PUBLIC, ALG, pk)), "1");
        Description.DirectoryForkProof unnamed = new Description.DirectoryForkProof(new byte[0], signedA, signedB);
        check("fork proof with an unnamed accused rejected DirForkProofInvalid",
                errKind(() -> unnamed.verify(Cose.PROFILE_PUBLIC, ALG, pk)), "DirForkProofInvalid");
        byte[] signedV8 = Description.signDirectory(dirV8, ALG, seed);
        Description.DirectoryForkProof notFork = new Description.DirectoryForkProof(
                signerId.getBytes(StandardCharsets.UTF_8), signedA, signedV8);
        check("fork proof across a legitimate succession rejected DirForkProofInvalid",
                errKind(() -> notFork.verify(Cose.PROFILE_PUBLIC, ALG, pk)), "DirForkProofInvalid");
        byte[] tamperedB = signedB.clone();
        tamperedB[tamperedB.length - 1] ^= 1;
        Description.DirectoryForkProof badSig = new Description.DirectoryForkProof(
                signerId.getBytes(StandardCharsets.UTF_8), signedA, tamperedB);
        check("fork proof with a bad signature rejected BadSignature",
                errKind(() -> badSig.verify(Cose.PROFILE_PUBLIC, ALG, pk)), "BadSignature");

        // the confused-deputy rule: the wrapping signer is the SOLE authorization identity. An import
        // whose declared importer IS the wrapping key's own id verifies; the authority id is that key.
        Description.Import selfIm = new Description.Import(
                signerId.getBytes(StandardCharsets.UTF_8), format, foreign, corpusIm.operations);
        byte[] signedSelf = Description.signImport(selfIm, ALG, seed);
        Description.ResolvedImport ri = Description.verifyImport(signedSelf, Cose.PROFILE_PUBLIC, ALG, pk);
        check("verifyImport authority id is the wrapping signer's own key id",
                ri.authorityId, signerId);
        check("verifyImport binds the foreign content id",
                Hex.encode(ri.foreignId), Hex.encode(corpusIm.foreignId()));

        // a FOREIGN identity named in the import (the did: in the carried bytes) is NOT authorized: the
        // signer can only import AS ITSELF (R-14.6). (mutation target: the ImporterMismatch guard.)
        Description.Import foreignIm = new Description.Import(
                foreignIdentity.getBytes(StandardCharsets.UTF_8), format, foreign, corpusIm.operations);
        byte[] signedForeign = Description.signImport(foreignIm, ALG, seed);
        check("import naming a FOREIGN importer rejected ImporterMismatch",
                errKind(() -> Description.verifyImport(signedForeign, Cose.PROFILE_PUBLIC, ALG, pk)), "ImporterMismatch");

        // verifying the self-import under the WRONG key is BadSignature (real crypto).
        check("verifyImport under the wrong key rejected BadSignature",
                errKind(() -> Description.verifyImport(signedSelf, Cose.PROFILE_PUBLIC, ALG, otherPk)), "BadSignature");
    }

    private static byte[] seed(int b) {
        byte[] s = new byte[32];
        java.util.Arrays.fill(s, (byte) b);
        return s;
    }

    public static void main(String[] args) throws Exception {
        System.out.println("description conformance (Java) — graded vs vectors/description/cases.json");
        run();
        System.out.println(fails == 0 ? "DescriptionKatTest: PASS" : "DescriptionKatTest: FAIL (" + fails + ")");
        System.exit(fails == 0 ? 0 : 1);
    }
}
