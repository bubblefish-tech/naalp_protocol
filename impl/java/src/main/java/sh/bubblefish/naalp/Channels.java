// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

/**
 * N-AALP C10 channel registry for the Java SDK — the frozen twenty-channel baseline surface
 * (design-channels.md §1..§20): all 20 channels (0x0000..0x0013), 74 kinds, each with a declared
 * effect (variable-effect for Stream StreamOpen / Bridge Carriage). An independent transcription of
 * the design, cross-checked against the shared conformance corpus (== Go == Rust == oracle).
 *
 * <p>Also carries each channel's states, declared transitions, and named errors (design-channels.md
 * §1..§20), the per-channel state-transition guard ({@link #allowedTransition}), Spatial's
 * TransformCycle structural check ({@link #checkFrameTree}), and the durable Workflow input/approval
 * gate whose crash test proves InputGateBypass cannot occur ({@link #openWorkflowGate},
 * {@link WorkflowGate}) — mirrors Go {@code impl/go/channels/channels.go} and Rust
 * {@code impl/rust/src/channels.rs}. {@link #channel(long)} is the Java-idiom (lowerCamelCase)
 * counterpart of Go's {@code Channel(id)} / Rust's {@code channel(id)} lookup; {@link #table()}
 * mirrors Go's exported {@code Table} slice / Rust's {@code table()} function for full-registry
 * enumeration.
 */
public final class Channels {
    private static final int RO = 0;
    private static final int IW = 1;
    private static final int NIW = 2;
    private static final int DE = 3;

    /** The looked-up kind: its name, declared effect, and whether its effect is caller-variable. */
    public static final class KindSpec {
        public final String name;
        public final int effect;
        public final boolean variable;
        KindSpec(String name, int effect, boolean variable) {
            this.name = name;
            this.effect = effect;
            this.variable = variable;
        }
    }

    /** One baseline object kind of a channel: its code, name, declared effect, and whether the
     * effect is caller-variable (Stream StreamOpen, Bridge Carriage). Package-visible so the KAT
     * grades every field against the independent per-channel oracle. */
    static final class Kind {
        final int code;
        final String name;
        final int effect;
        final boolean variable;
        Kind(int code, String name, int effect, boolean variable) {
            this.code = code;
            this.name = name;
            this.effect = effect;
            this.variable = variable;
        }
    }

    /** One channel's frozen baseline surface: id, name, kinds, states, declared transitions, and
     * named errors (design-channels.md §1..§20). Mirrors Go/Rust {@code ChannelSpec}. */
    public static final class ChannelSpec {
        public final long id;
        public final String name;
        final Kind[] kinds;
        public final String[] states;
        /** Each element is a {@code {from, to}} pair. */
        public final String[][] transitions;
        public final String[] errors;

        ChannelSpec(long id, String name, Kind[] kinds, String[] states, String[][] transitions, String[] errors) {
            this.id = id;
            this.name = name;
            this.kinds = kinds;
            this.states = states;
            this.transitions = transitions;
            this.errors = errors;
        }

        public int kindCount() {
            return kinds.length;
        }

        public long kindCode(int i) {
            return kinds[i].code;
        }

        public String kindName(int i) {
            return kinds[i].name;
        }

        public int kindEffect(int i) {
            return kinds[i].effect;
        }

        public boolean kindVariable(int i) {
            return kinds[i].variable;
        }
    }

    private static final List<ChannelSpec> SPECS = new ArrayList<>();
    private static final Map<Integer, ChannelSpec> BY_ID = new LinkedHashMap<>();

    private static Kind k(int code, String name, int effect, boolean variable) {
        return new Kind(code, name, effect, variable);
    }

    private static void ch(int code, String name, String[] states, String[][] transitions, String[] errors, Kind... kinds) {
        ChannelSpec spec = new ChannelSpec(code, name, kinds, states, transitions, errors);
        SPECS.add(spec);
        BY_ID.put(code, spec);
    }

    static {
        ch(0x0000, "Control",
                new String[]{"open", "closing"},
                new String[][]{{"open", "closing"}},
                new String[]{"UnknownKind", "ProfileMismatch"},
                k(0, "Hello", RO, false), k(1, "Bye", IW, false), k(2, "Ack", RO, false), k(3, "Error", RO, false));
        ch(0x0001, "Memory",
                new String[]{"offered", "accepted", "live", "expired", "revoked"},
                new String[][]{{"offered", "accepted"}, {"accepted", "live"}, {"live", "expired"}, {"live", "revoked"}},
                new String[]{"AccessDenied", "MemoryError"},
                k(0, "MemoryOffer", IW, false), k(1, "MemoryAccept", IW, false), k(2, "MemoryWrite", NIW, false),
                k(3, "MemoryRead", RO, false), k(4, "MemoryExpire", DE, false), k(5, "MemoryRevoke", DE, false));
        ch(0x0002, "Capability",
                new String[]{"issued", "delegated", "revoked", "expired"},
                new String[][]{{"issued", "delegated"}, {"delegated", "delegated"}, {"issued", "revoked"},
                        {"delegated", "revoked"}, {"issued", "expired"}, {"delegated", "expired"}},
                new String[]{"CapExceedsParent", "CapRevoked"},
                k(0, "CapIssue", NIW, false), k(1, "CapDelegate", NIW, false), k(2, "CapRevoke", DE, false), k(3, "CapLookup", RO, false));
        ch(0x0003, "Identity",
                new String[]{"active", "rotated", "revoked"},
                new String[][]{{"active", "rotated"}, {"rotated", "rotated"}, {"active", "revoked"}, {"rotated", "revoked"}},
                new String[]{"RotationUnauthorized", "KeyRevoked", "SignerMismatch"},
                k(0, "Rotation", NIW, false), k(1, "Revocation", DE, false), k(2, "ForeignLink", IW, false), k(3, "KeyAnnounce", RO, false));
        ch(0x0004, "Governance",
                new String[]{"requested", "held", "approved", "consumed", "expired"},
                new String[][]{{"requested", "held"}, {"requested", "approved"}, {"approved", "consumed"},
                        {"held", "approved"}, {"requested", "expired"}, {"approved", "expired"}},
                new String[]{"ApprovalRequired", "ApprovalMismatch", "AlreadyConsumed", "EffectNotAuthorized"},
                k(0, "PolicyPublish", NIW, false), k(1, "Approval", NIW, false), k(2, "ApprovalHeld", RO, false), k(3, "Consume", NIW, false), k(4, "GatewayDecision", NIW, false), k(5, "DecisionRecord", NIW, false), k(6, "EgressAttestation", NIW, false), k(7, "HazardAuthorization", NIW, false));
        ch(0x0005, "Immune",
                new String[]{"normal", "quarantined", "lifted", "permanent"},
                new String[][]{{"normal", "quarantined"}, {"quarantined", "lifted"}, {"quarantined", "permanent"}},
                new String[]{"AccessDenied"},
                k(0, "AnomalyReport", RO, false), k(1, "Quarantine", DE, false), k(2, "QuarantineLift", NIW, false));
        ch(0x0006, "Federation",
                new String[]{"announced", "ordering"},
                new String[][]{{"announced", "ordering"}},
                new String[]{"AuthorityUnknown", "ScopeOverlapConflict"},
                k(0, "AuthorityAnnounce", RO, false), k(1, "ScopeReceipt", NIW, false));
        ch(0x0007, "Settlement",
                new String[]{"intent", "receipt", "reject"},
                new String[][]{{"intent", "receipt"}, {"intent", "reject"}},
                new String[]{"ValueMismatch", "SettleExpired"},
                k(0, "SettleIntent", NIW, false), k(1, "SettleReceipt", NIW, false), k(2, "SettleReject", IW, false), k(3, "PaymentImport", NIW, false), k(4, "PaymentChargeBinding", NIW, false));
        ch(0x0008, "Compliance",
                new String[]{"appended"},
                new String[0][],
                new String[]{"RecordUnsigned", "JurisdictionUnknown"},
                k(0, "ComplianceRecord", NIW, false), k(1, "ComplianceQuery", RO, false), k(2, "ComplianceReport", RO, false));
        ch(0x0009, "Sensory",
                new String[]{"active", "cancelled"},
                new String[][]{{"active", "cancelled"}},
                new String[]{"SubscriptionUnknown"},
                k(0, "Observation", RO, false), k(1, "Subscribe", IW, false), k(2, "Unsubscribe", IW, false));
        ch(0x000A, "Telemetry",
                new String[]{"stateless"},
                new String[0][],
                new String[]{"MetricMalformed"},
                k(0, "Metric", RO, false), k(1, "HealthReport", RO, false));
        ch(0x000B, "Audit",
                new String[]{"appended"},
                new String[0][],
                new String[]{"ChainBroken", "Equivocation", "ReceiptUnsigned"},
                k(0, "Receipt", NIW, false), k(1, "AuditQuery", RO, false), k(2, "ForkProof", RO, false), k(3, "CheckpointRoot", NIW, false), k(4, "WitnessCosign", NIW, false), k(5, "InclusionProof", RO, false));
        ch(0x000C, "Stream",
                new String[]{"open", "committed"},
                new String[][]{{"open", "committed"}},
                new String[]{"StreamDigestMismatch", "FlowControlError"},
                k(0, "StreamOpen", RO, true), k(1, "StreamCommit", RO, false), k(2, "StreamCheckpoint", RO, false));
        ch(0x000D, "Bridge",
                new String[]{"carried"},
                new String[0][],
                new String[]{"EnvelopeMalformed", "ProtocolUnsupported", "MethodUnsupported", "NotDelivered", "EffectNotAuthorized"},
                k(0, "Carriage", RO, true));
        ch(0x000E, "Commerce",
                new String[]{"offer", "order", "fulfil", "cancel"},
                new String[][]{{"offer", "order"}, {"order", "fulfil"}, {"order", "cancel"}},
                new String[]{"OfferExpired", "ApprovalRequired", "OrderMismatch"},
                k(0, "Offer", RO, false), k(1, "Order", NIW, false), k(2, "Fulfil", NIW, false), k(3, "Cancel", DE, false));
        ch(0x000F, "Interaction",
                new String[]{"elicit", "respond", "confirm", "timeout"},
                new String[][]{{"elicit", "respond"}, {"elicit", "confirm"}, {"elicit", "timeout"}},
                new String[]{"InteractionTimeout", "ElicitUnauthorized"},
                k(0, "Elicit", RO, false), k(1, "Respond", IW, false), k(2, "Confirm", NIW, false), k(3, "UiEvent", NIW, false));
        ch(0x0010, "Discovery",
                new String[]{"fresh", "stale"},
                new String[][]{{"fresh", "stale"}},
                new String[]{"RecordExpired", "TrustAnchorUnknown"},
                k(0, "DiscoveryRecord", RO, false), k(1, "DiscoveryQuery", RO, false));
        ch(0x0011, "Workflow",
                new String[]{"created", "awaiting-input", "awaiting-approval", "running", "result", "cancelled"},
                new String[][]{{"created", "awaiting-input"}, {"created", "awaiting-approval"}, {"awaiting-input", "running"},
                        {"awaiting-approval", "running"}, {"running", "result"}, {"created", "cancelled"},
                        {"awaiting-input", "cancelled"}, {"awaiting-approval", "cancelled"}, {"running", "cancelled"}},
                new String[]{"TaskStateError", "InputGateBypass", "ApprovalRequired"},
                k(0, "TaskCreate", NIW, false), k(1, "TaskInput", NIW, false), k(2, "TaskCancel", DE, false), k(3, "TaskResult", NIW, false));
        ch(0x0012, "Knowledge",
                new String[]{"asserted", "retracted"},
                new String[][]{{"asserted", "retracted"}},
                new String[]{"FactUnsigned", "RetractUnknown"},
                k(0, "Assert", NIW, false), k(1, "Retract", DE, false), k(2, "KnowledgeQuery", RO, false));
        ch(0x0013, "Spatial",
                new String[]{"defined", "observed"},
                new String[][]{{"defined", "observed"}},
                new String[]{"FrameUnknown", "TransformCycle"},
                k(0, "FrameDefine", IW, false), k(1, "Pose", RO, false), k(2, "StateUpdate", RO, false), k(3, "SnapshotQuery", RO, false));
    }

    private Channels() {}

    /** The full frozen twenty-channel registry, in declaration order (design-channels.md §1..§20).
     * Mirrors Go's exported {@code Table} slice / Rust's {@code table()} function. */
    public static List<ChannelSpec> table() {
        return Collections.unmodifiableList(SPECS);
    }

    /** The channel spec for a channel id, or {@code null} if unregistered. Java-idiom counterpart
     * of Go's {@code Channel(id) (*ChannelSpec, bool)} / Rust's {@code channel(id) -> Option<ChannelSpec>}. */
    public static ChannelSpec channel(long id) {
        return BY_ID.get((int) id);
    }

    /** Return (name, effect, variable) for a (channel, kind), or raise UnknownKind. */
    public static KindSpec lookup(long channel, long kind) {
        ChannelSpec ch = BY_ID.get((int) channel);
        if (ch == null) {
            throw new NaalpException("UnknownKind", String.format("channel 0x%04x not registered", channel));
        }
        for (Kind kd : ch.kinds) {
            if (kd.code == kind) {
                return new KindSpec(kd.name, kd.effect, kd.variable);
            }
        }
        throw new NaalpException("UnknownKind", String.format("kind %d not in channel 0x%04x", kind, channel));
    }

    /** A fixed-effect kind's object must carry its declared effect; a variable kind accepts 0..3. */
    public static void checkEffect(long channel, long kind, long effect) {
        KindSpec spec = lookup(channel, kind);
        if (spec.variable) {
            if (effect > DE) {
                throw new NaalpException("EffectDeclarationMismatch", "effect " + effect + " out of range");
            }
            return;
        }
        if (effect != spec.effect) {
            throw new NaalpException("EffectDeclarationMismatch",
                    "object effect " + effect + " != declared " + spec.effect);
        }
    }

    /** Whether a channel permits a state transition from -> to (design-channels.md §1..§20). An
     * unregistered channel permits nothing. */
    public static boolean allowedTransition(long channel, String from, String to) {
        ChannelSpec ch = BY_ID.get((int) channel);
        if (ch == null) {
            return false;
        }
        for (String[] t : ch.transitions) {
            if (t[0].equals(from) && t[1].equals(to)) {
                return true;
            }
        }
        return false;
    }

    /** Spatial's TransformCycle (design-channels.md §20): the coordinate-frame child->parent links
     * must form a tree (acyclic). A frame mapping to {@code ""} (or absent) is a root. Throws
     * TransformCycle on a cycle; returns normally on a valid (acyclic) tree. */
    public static void checkFrameTree(Map<String, String> parent) {
        Map<String, Integer> color = new HashMap<>();
        for (String f : parent.keySet()) {
            if (color.getOrDefault(f, 0) == 0 && visit(f, parent, color)) {
                throw new NaalpException("TransformCycle", "coordinate frame tree contains a cycle");
            }
        }
    }

    private static boolean visit(String f, Map<String, String> parent, Map<String, Integer> color) {
        final int white = 0;
        final int gray = 1;
        final int black = 2;
        color.put(f, gray);
        String p = parent.get(f);
        if (p != null && !p.isEmpty()) {
            int pc = color.getOrDefault(p, white);
            if (pc == gray) {
                return true;
            }
            if (pc == white && visit(p, parent, color)) {
                return true;
            }
        }
        color.put(f, black);
        return false;
    }

    // ---- Workflow input gate (design-channels.md §18): the crash test that InputGateBypass cannot occur.

    /** A durable, WAL-backed task-status tracker. A task's status is persisted (and fsynced) before
     * it is acknowledged (spine §9.2), so a crash recovers to the last durable status and can NEVER
     * bypass the input/approval gate: reaching "running" requires an explicit input/approval step
     * that a crash cannot manufacture. Mirrors Go/Rust {@code WorkflowGate}. Use
     * {@link Channels#openWorkflowGate} to construct one. */
    public static final class WorkflowGate implements AutoCloseable {
        private final ReentrantLock lock = new ReentrantLock();
        private final FileChannel ch;
        private final Map<String, String> status = new HashMap<>();

        private WorkflowGate(FileChannel ch) {
            this.ch = ch;
        }

        private static int readFully(FileChannel ch, ByteBuffer buf) throws IOException {
            int total = 0;
            while (buf.hasRemaining()) {
                int r = ch.read(buf);
                if (r < 0) {
                    return total == 0 ? -1 : total;
                }
                total += r;
            }
            return total;
        }

        private void replay() throws IOException {
            ch.position(0);
            ByteBuffer lenBuf = ByteBuffer.allocate(4);
            while (true) {
                lenBuf.clear();
                int r = readFully(ch, lenBuf);
                if (r == -1) {
                    break; // clean EOF at a record boundary
                }
                if (r != 4) {
                    throw new NaalpException("Malformed", "workflow gate record");
                }
                lenBuf.flip();
                int n = lenBuf.getInt();
                ByteBuffer recBuf = ByteBuffer.allocate(n);
                if (readFully(ch, recBuf) != n) {
                    throw new NaalpException("Malformed", "workflow gate record");
                }
                byte[] rec = recBuf.array();
                int nul = -1;
                for (int i = 0; i < rec.length; i++) {
                    if (rec[i] == 0) {
                        nul = i;
                        break;
                    }
                }
                if (nul < 0) {
                    throw new NaalpException("Malformed", "workflow gate record");
                }
                String task = new String(rec, 0, nul, StandardCharsets.UTF_8);
                String st = new String(rec, nul + 1, rec.length - nul - 1, StandardCharsets.UTF_8);
                status.put(task, st);
            }
        }

        /** Opens (creating if needed) a WAL-backed gate at {@code path} and replays it. */
        static WorkflowGate open(Path path) {
            try {
                FileChannel fc = FileChannel.open(path,
                        StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE);
                WorkflowGate g = new WorkflowGate(fc);
                g.replay();
                return g;
            } catch (IOException e) {
                throw new NaalpException("GateIO", e.toString());
            }
        }

        private void persist(String task, String st) {
            try {
                byte[] taskB = task.getBytes(StandardCharsets.UTF_8);
                byte[] stB = st.getBytes(StandardCharsets.UTF_8);
                byte[] rec = new byte[taskB.length + 1 + stB.length];
                System.arraycopy(taskB, 0, rec, 0, taskB.length);
                rec[taskB.length] = 0;
                System.arraycopy(stB, 0, rec, taskB.length + 1, stB.length);
                ByteBuffer framed = ByteBuffer.allocate(4 + rec.length);
                framed.putInt(rec.length);
                framed.put(rec);
                framed.flip();
                ch.position(ch.size());
                while (framed.hasRemaining()) {
                    ch.write(framed);
                }
                ch.force(true); // persist-before-ack (spine §9.2)
                status.put(task, st);
            } catch (IOException e) {
                throw new NaalpException("GateIO", e.toString());
            }
        }

        /** Records a new task in a non-terminal pre-gate status. TaskCreate never lands in
         * "running": it lands in "awaiting-input" (or "awaiting-approval"), persisted before returning. */
        public void create(String task, boolean needsApproval) {
            lock.lock();
            try {
                if (status.containsKey(task)) {
                    throw new NaalpException("TaskStateError", "workflow task state transition not permitted");
                }
                persist(task, needsApproval ? "awaiting-approval" : "awaiting-input");
            } finally {
                lock.unlock();
            }
        }

        /** Advances a task past its input gate (awaiting-input -> input-supplied) or approval gate
         * (awaiting-approval -> approved). Only these transitions may precede {@link #run}. */
        public void supplyInput(String task) {
            lock.lock();
            try {
                String s = status.get(task);
                if ("awaiting-input".equals(s)) {
                    persist(task, "input-supplied");
                } else if ("awaiting-approval".equals(s)) {
                    persist(task, "approved");
                } else {
                    throw new NaalpException("TaskStateError", "workflow task state transition not permitted");
                }
            } finally {
                lock.unlock();
            }
        }

        /** Moves a task to "running" only if it has passed the gate. A task still "awaiting-input"
         * or "awaiting-approval" (or unknown) cannot run: that is InputGateBypass, and it is forbidden. */
        public void run(String task) {
            lock.lock();
            try {
                String s = status.get(task);
                if ("input-supplied".equals(s) || "approved".equals(s)) {
                    persist(task, "running");
                } else if ("awaiting-input".equals(s) || "awaiting-approval".equals(s)) {
                    throw new NaalpException("InputGateBypass", "a task reached running without passing the input/approval gate");
                } else {
                    throw new NaalpException("TaskStateError", "workflow task state transition not permitted");
                }
            } finally {
                lock.unlock();
            }
        }

        /** The task's durable status, or {@code null} if unknown. */
        public String status(String task) {
            lock.lock();
            try {
                return status.get(task);
            } finally {
                lock.unlock();
            }
        }

        /** Flushes and closes the WAL. */
        @Override
        public void close() {
            lock.lock();
            try {
                ch.close();
            } catch (IOException e) {
                throw new NaalpException("GateIO", e.toString());
            } finally {
                lock.unlock();
            }
        }
    }

    /** Opens (creating if needed) a durable WAL-backed Workflow input/approval gate at {@code path}
     * and replays it (design-channels.md §18). Mirrors Go/Rust {@code OpenWorkflowGate}. */
    public static WorkflowGate openWorkflowGate(Path path) {
        return WorkflowGate.open(path);
    }
}
