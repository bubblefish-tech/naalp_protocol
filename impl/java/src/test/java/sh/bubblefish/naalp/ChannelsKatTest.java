// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * C10 channel-surface known-answer test for the Java SDK (design-channels.md §1..§20; R-11.1..
 * 11.4, R-15A.1..15A.3), graded against the shared independent per-channel corpus
 * vectors/channels/&lt;name&gt;/cases.json (NOT produced by this code): the full frozen twenty-channel
 * registry (id, name, kinds, states, transitions, errors) reproduces the oracle exactly for every
 * channel (⟹ Go == Rust == Java), {@link Channels#allowedTransition} accepts every declared
 * transition and rejects the rest, {@link Channels#checkFrameTree} accepts an acyclic coordinate
 * frame tree and rejects a cyclic one (TransformCycle), and the durable Workflow input/approval
 * gate ({@link Channels#openWorkflowGate}) proves InputGateBypass cannot occur -- including across
 * a simulated crash (close, then reopen with no input yet supplied).
 *
 * <p>KAT convention (a standalone {@code main} exiting non-zero on any failure); named "…KatTest" so
 * the filename carries the "test" token the ten-language-parity gate indexes. Written test-first:
 * {@code Channels.allowedTransition}/{@code checkFrameTree}/{@code openWorkflowGate}/
 * {@code Channels.WorkflowGate}/{@code Channels.ChannelSpec}/{@code Channels.channel} are absent
 * until this wave lands, so this fails RED with a javac "cannot find symbol". The recorded mutation
 * neuters the input-gate check in {@code WorkflowGate.run} so a task may run before its input/
 * approval gate is passed; this flips the InputGateBypass reject checks below to FAIL (a task ran
 * before input, and a task ran after a simulated crash without passing the gate).
 */
public final class ChannelsKatTest {
    private static int fails = 0;

    private static void check(String name, String got, String want) {
        if (got.equals(want)) {
            System.out.println("  ok   " + name);
        } else {
            fails++;
            System.out.println("  FAIL " + name + "\n       got  " + got + "\n       want " + want);
        }
    }

    // ---- nesting-aware JSON access (Java has no JSON library; mirrors ApprovalKatTest) ----

    private static Path findVector(String dir) {
        Path d = Path.of(System.getProperty("user.dir")).toAbsolutePath();
        for (int i = 0; i < 6 && d != null; i++) {
            Path p = d.resolve("vectors").resolve("channels").resolve(dir).resolve("cases.json");
            if (Files.isRegularFile(p)) {
                return p;
            }
            d = d.getParent();
        }
        throw new AssertionError("vectors/channels/" + dir + "/cases.json not found from " + System.getProperty("user.dir"));
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

    /** Plain-string array elements (states / errors are JSON arrays of bare strings, no braces). */
    private static List<String> splitStrings(String arrayInner) {
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
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*(-?\\d+)").matcher(scope);
        if (!m.find()) {
            throw new AssertionError("int key not found: " + key);
        }
        return Long.parseLong(m.group(1));
    }

    private static boolean boolField(String scope, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*(true|false)").matcher(scope);
        if (!m.find()) {
            throw new AssertionError("bool key not found: " + key);
        }
        return m.group(1).equals("true");
    }

    private static String errKind(Runnable r) {
        try {
            r.run();
            return "no-error";
        } catch (NaalpException e) {
            return e.kind;
        }
    }

    private static void run() throws Exception {
        // 1. the full frozen twenty-channel registry reproduces the independent per-channel oracle,
        //    in both directions (id, name, every kind's code/name/effect/variable, states,
        //    transitions, errors) -- ⟹ Go == Rust == Java (mirrors Go TestTableMatchesOracle).
        List<Channels.ChannelSpec> table = Channels.table();
        check("registry has all 20 channels", Integer.toString(table.size()), "20");
        for (Channels.ChannelSpec ch : table) {
            String json = Files.readString(findVector(ch.name.toLowerCase(java.util.Locale.ROOT)), StandardCharsets.UTF_8);
            check(ch.name + " id == oracle", Long.toString(ch.id), Long.toString(intField(json, "channel_id")));
            check(ch.name + " name == oracle", ch.name, field(json, "name"));

            List<String> kindBlocks = splitObjects(arrayBlock(json, "kinds"));
            check(ch.name + " kind count == oracle", Integer.toString(ch.kindCount()), Integer.toString(kindBlocks.size()));
            for (int i = 0; i < kindBlocks.size() && i < ch.kindCount(); i++) {
                String kb = kindBlocks.get(i);
                check(ch.name + " kind " + i + " code", Long.toString(ch.kindCode(i)), Long.toString(intField(kb, "code")));
                check(ch.name + " kind " + i + " name", ch.kindName(i), field(kb, "name"));
                check(ch.name + " kind " + i + " effect", Integer.toString(ch.kindEffect(i)), Long.toString(intField(kb, "effect")));
                check(ch.name + " kind " + i + " variable", Boolean.toString(ch.kindVariable(i)), Boolean.toString(boolField(kb, "variable")));
            }

            List<String> oracleStates = splitStrings(arrayBlock(json, "states"));
            check(ch.name + " states == oracle", String.join(",", ch.states), String.join(",", oracleStates));

            List<String> transBlocks = splitObjects(arrayBlock(json, "transitions"));
            check(ch.name + " transition count == oracle", Integer.toString(ch.transitions.length), Integer.toString(transBlocks.size()));
            for (int i = 0; i < transBlocks.size() && i < ch.transitions.length; i++) {
                check(ch.name + " transition " + i + " from", ch.transitions[i][0], field(transBlocks.get(i), "from"));
                check(ch.name + " transition " + i + " to", ch.transitions[i][1], field(transBlocks.get(i), "to"));
            }

            List<String> oracleErrors = splitStrings(arrayBlock(json, "errors"));
            check(ch.name + " errors == oracle", String.join(",", ch.errors), String.join(",", oracleErrors));
        }

        // 2. channel(id) returns the registered spec for a known id and null for an unregistered one
        //    -- mirrors Go channels.Channel(id) / Rust channels::channel(id).
        Channels.ChannelSpec wf = Channels.channel(0x0011);
        check("channel(0x0011) is Workflow", wf == null ? "null" : wf.name, "Workflow");
        check("channel(0x00FF) is unregistered", Channels.channel(0x00FF) == null ? "null" : "present", "null");

        // 3. AllowedTransition: representative channels permit their declared transitions and reject
        //    others (mirrors Go/Rust TestStateMachine), plus a full sweep of every declared transition
        //    for every channel in the oracle (every declared pair must be allowed).
        check("Memory offered->accepted allowed", Boolean.toString(Channels.allowedTransition(0x0001, "offered", "accepted")), "true");
        check("Memory live->revoked allowed", Boolean.toString(Channels.allowedTransition(0x0001, "live", "revoked")), "true");
        check("Memory revoked->live (regression) denied", Boolean.toString(Channels.allowedTransition(0x0001, "revoked", "live")), "false");
        check("Commerce order->fulfil allowed", Boolean.toString(Channels.allowedTransition(0x000E, "order", "fulfil")), "true");
        check("Commerce offer->fulfil (skip) denied", Boolean.toString(Channels.allowedTransition(0x000E, "offer", "fulfil")), "false");
        check("Workflow awaiting-input->running allowed", Boolean.toString(Channels.allowedTransition(0x0011, "awaiting-input", "running")), "true");
        check("Workflow created->running (gate skip) denied", Boolean.toString(Channels.allowedTransition(0x0011, "created", "running")), "false");
        check("unregistered channel transition denied", Boolean.toString(Channels.allowedTransition(0x00FF, "a", "b")), "false");
        for (Channels.ChannelSpec ch : table) {
            for (String[] t : ch.transitions) {
                check(ch.name + " declared " + t[0] + "->" + t[1] + " allowed",
                        Boolean.toString(Channels.allowedTransition(ch.id, t[0], t[1])), "true");
            }
        }

        // 4. CheckFrameTree: Spatial's TransformCycle -- a valid acyclic tree accepts, a cyclic one
        //    rejects fail-closed (mirrors Go/Rust TestTransformCycle).
        Map<String, String> tree = new HashMap<>();
        tree.put("base", "");
        tree.put("arm", "base");
        tree.put("hand", "arm");
        check("valid frame tree accepted", errKind(() -> Channels.checkFrameTree(tree)), "no-error");
        Map<String, String> cyclic = new HashMap<>();
        cyclic.put("a", "b");
        cyclic.put("b", "c");
        cyclic.put("c", "a");
        check("cyclic frame tree rejected TransformCycle", errKind(() -> Channels.checkFrameTree(cyclic)), "TransformCycle");
        Map<String, String> selfLoop = new HashMap<>();
        selfLoop.put("x", "x");
        check("self-loop frame rejected TransformCycle", errKind(() -> Channels.checkFrameTree(selfLoop)), "TransformCycle");

        // 5. WorkflowGate: the gated crash test (design-channels.md §18) -- a task cannot reach
        //    "running" without passing the input/approval gate, and a crash (close -> reopen)
        //    recovers to the pre-gate status rather than bypassing it. THIS IS THE FAIL-CLOSED
        //    MUTATION ANCHOR (mirrors Go/Rust TestWorkflowInputGateBypass / workflow_input_gate_bypass).
        Path gatePath = Files.createTempFile("naalp-channels-wf-", ".wal");
        Files.deleteIfExists(gatePath); // start absent so the first create lands seq 0
        gatePath.toFile().deleteOnExit();

        Channels.WorkflowGate g = Channels.openWorkflowGate(gatePath);
        g.create("t1", false);
        check("running before input is InputGateBypass", errKind(() -> g.run("t1")), "InputGateBypass");
        g.close();

        Channels.WorkflowGate g2 = Channels.openWorkflowGate(gatePath);
        check("crash recovers to the pre-gate status (not bypassed)", g2.status("t1"), "awaiting-input");
        check("running after crash without the gate is still InputGateBypass", errKind(() -> g2.run("t1")), "InputGateBypass");
        g2.supplyInput("t1");
        check("running after supplyInput succeeds", errKind(() -> g2.run("t1")), "no-error");
        check("status after run is running", g2.status("t1"), "running");
        g2.close();

        // 6. the approval-gated path: Create(needsApproval=true) lands in awaiting-approval, is also
        //    InputGateBypass-guarded, and SupplyInput opens it via the approval branch (-> approved).
        Path gatePath2 = Files.createTempFile("naalp-channels-wf2-", ".wal");
        Files.deleteIfExists(gatePath2);
        gatePath2.toFile().deleteOnExit();
        Channels.WorkflowGate g3 = Channels.openWorkflowGate(gatePath2);
        g3.create("t2", true);
        check("approval-gated task lands awaiting-approval", g3.status("t2"), "awaiting-approval");
        check("running before approval is InputGateBypass", errKind(() -> g3.run("t2")), "InputGateBypass");
        g3.supplyInput("t2");
        check("status after supplyInput (approval branch) is approved", g3.status("t2"), "approved");
        g3.run("t2");
        check("status after run (approval branch) is running", g3.status("t2"), "running");
        g3.close();

        // 7. duplicate create on an existing task is TaskStateError (fail-closed, not a silent
        //    overwrite), and an unknown task's status is unknown (null).
        Channels.WorkflowGate g4 = Channels.openWorkflowGate(Files.createTempFile("naalp-channels-wf3-", ".wal"));
        g4.create("dup", false);
        check("duplicate create rejected TaskStateError", errKind(() -> g4.create("dup", false)), "TaskStateError");
        check("supplyInput on an unknown task rejected TaskStateError", errKind(() -> g4.supplyInput("ghost")), "TaskStateError");
        check("unknown task status is null", g4.status("ghost") == null ? "null" : g4.status("ghost"), "null");
        g4.close();
    }

    public static void main(String[] args) throws Exception {
        System.out.println("channels conformance (Java) — graded vs vectors/channels/*/cases.json");
        run();
        System.out.println(fails == 0 ? "ChannelsKatTest: PASS" : "ChannelsKatTest: FAIL (" + fails + ")");
        System.exit(fails == 0 ? 0 : 1);
    }
}
