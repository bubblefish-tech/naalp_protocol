// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * N-AALP C10 channel registry for the Java SDK — the frozen twenty-channel baseline surface
 * (design-channels.md §1..§20): all 20 channels (0x0000..0x0013), 65 kinds, each with a declared
 * effect (variable-effect for Stream StreamOpen / Bridge Carriage). An independent transcription of
 * the design, cross-checked against the shared conformance corpus (== Go == Rust == Python == oracle).
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

    private static final class Kind {
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

    private static final Map<Integer, Kind[]> TABLE = new LinkedHashMap<>();

    private static void ch(int code, Kind... kinds) {
        TABLE.put(code, kinds);
    }

    private static Kind k(int code, String name, int effect, boolean variable) {
        return new Kind(code, name, effect, variable);
    }

    static {
        ch(0x0000, k(0, "Hello", RO, false), k(1, "Bye", IW, false), k(2, "Ack", RO, false), k(3, "Error", RO, false));
        ch(0x0001, k(0, "MemoryOffer", IW, false), k(1, "MemoryAccept", IW, false), k(2, "MemoryWrite", NIW, false),
                k(3, "MemoryRead", RO, false), k(4, "MemoryExpire", DE, false), k(5, "MemoryRevoke", DE, false));
        ch(0x0002, k(0, "CapIssue", NIW, false), k(1, "CapDelegate", NIW, false), k(2, "CapRevoke", DE, false), k(3, "CapLookup", RO, false));
        ch(0x0003, k(0, "Rotation", NIW, false), k(1, "Revocation", DE, false), k(2, "ForeignLink", IW, false), k(3, "KeyAnnounce", RO, false));
        ch(0x0004, k(0, "PolicyPublish", NIW, false), k(1, "Approval", NIW, false), k(2, "ApprovalHeld", RO, false), k(3, "Consume", NIW, false));
        ch(0x0005, k(0, "AnomalyReport", RO, false), k(1, "Quarantine", DE, false), k(2, "QuarantineLift", NIW, false));
        ch(0x0006, k(0, "AuthorityAnnounce", RO, false), k(1, "ScopeReceipt", NIW, false));
        ch(0x0007, k(0, "SettleIntent", NIW, false), k(1, "SettleReceipt", NIW, false), k(2, "SettleReject", IW, false));
        ch(0x0008, k(0, "ComplianceRecord", NIW, false), k(1, "ComplianceQuery", RO, false), k(2, "ComplianceReport", RO, false));
        ch(0x0009, k(0, "Observation", RO, false), k(1, "Subscribe", IW, false), k(2, "Unsubscribe", IW, false));
        ch(0x000A, k(0, "Metric", RO, false), k(1, "HealthReport", RO, false));
        ch(0x000B, k(0, "Receipt", NIW, false), k(1, "AuditQuery", RO, false), k(2, "ForkProof", RO, false));
        ch(0x000C, k(0, "StreamOpen", RO, true), k(1, "StreamCommit", RO, false), k(2, "StreamCheckpoint", RO, false));
        ch(0x000D, k(0, "Carriage", RO, true));
        ch(0x000E, k(0, "Offer", RO, false), k(1, "Order", NIW, false), k(2, "Fulfil", NIW, false), k(3, "Cancel", DE, false));
        ch(0x000F, k(0, "Elicit", RO, false), k(1, "Respond", IW, false), k(2, "Confirm", NIW, false));
        ch(0x0010, k(0, "DiscoveryRecord", RO, false), k(1, "DiscoveryQuery", RO, false));
        ch(0x0011, k(0, "TaskCreate", NIW, false), k(1, "TaskInput", NIW, false), k(2, "TaskCancel", DE, false), k(3, "TaskResult", NIW, false));
        ch(0x0012, k(0, "Assert", NIW, false), k(1, "Retract", DE, false), k(2, "KnowledgeQuery", RO, false));
        ch(0x0013, k(0, "FrameDefine", IW, false), k(1, "Pose", RO, false), k(2, "StateUpdate", RO, false), k(3, "SnapshotQuery", RO, false));
    }

    private Channels() {}

    /** Return (name, effect, variable) for a (channel, kind), or raise UnknownKind. */
    public static KindSpec lookup(long channel, long kind) {
        Kind[] ch = TABLE.get((int) channel);
        if (ch == null) {
            throw new NaalpException("UnknownKind", String.format("channel 0x%04x not registered", channel));
        }
        for (Kind kd : ch) {
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
}
