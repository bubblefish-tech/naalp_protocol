// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System.Collections.Generic;

namespace Naalp
{
    /// <summary>
    /// N-AALP C10 channel registry for the C# SDK — the frozen twenty-channel baseline surface
    /// (design-channels.md §1..§20): all 20 channels (0x0000..0x0013), 65 kinds, each with a declared
    /// effect (variable-effect for Stream StreamOpen / Bridge Carriage). An independent transcription of
    /// the design, cross-checked against the shared conformance corpus (== Go == Rust == Python == Java
    /// == oracle).
    /// </summary>
    public static class Channels
    {
        private const int RO = 0, IW = 1, NIW = 2, DE = 3; // read_only, idempotent_write, non_idempotent_write, destructive

        /// <summary>The (name, effect, variable) result of a channel+kind lookup.</summary>
        public sealed class KindSpec
        {
            public readonly string Name;
            public readonly int Effect;
            public readonly bool Variable;
            public KindSpec(string name, int effect, bool variable)
            {
                Name = name;
                Effect = effect;
                Variable = variable;
            }
        }

        private sealed class Kind
        {
            public readonly int Code;
            public readonly string Name;
            public readonly int Effect;
            public readonly bool Variable;
            public Kind(int code, string name, int effect, bool variable)
            {
                Code = code;
                Name = name;
                Effect = effect;
                Variable = variable;
            }
        }

        private sealed class Channel
        {
            public readonly string Name;
            public readonly Kind[] Kinds;
            public Channel(string name, Kind[] kinds)
            {
                Name = name;
                Kinds = kinds;
            }
        }

        private static Kind K(int code, string name, int effect, bool variable = false)
            => new Kind(code, name, effect, variable);

        // each kind: (code, name, effect, variable)
        private static readonly Dictionary<int, Channel> Table = new Dictionary<int, Channel>
        {
            [0x0000] = new Channel("Control", new[]
            {
                K(0, "Hello", RO), K(1, "Bye", IW), K(2, "Ack", RO), K(3, "Error", RO),
            }),
            [0x0001] = new Channel("Memory", new[]
            {
                K(0, "MemoryOffer", IW), K(1, "MemoryAccept", IW), K(2, "MemoryWrite", NIW),
                K(3, "MemoryRead", RO), K(4, "MemoryExpire", DE), K(5, "MemoryRevoke", DE),
            }),
            [0x0002] = new Channel("Capability", new[]
            {
                K(0, "CapIssue", NIW), K(1, "CapDelegate", NIW), K(2, "CapRevoke", DE), K(3, "CapLookup", RO),
            }),
            [0x0003] = new Channel("Identity", new[]
            {
                K(0, "Rotation", NIW), K(1, "Revocation", DE), K(2, "ForeignLink", IW), K(3, "KeyAnnounce", RO),
            }),
            [0x0004] = new Channel("Governance", new[]
            {
                K(0, "PolicyPublish", NIW), K(1, "Approval", NIW), K(2, "ApprovalHeld", RO), K(3, "Consume", NIW),
            }),
            [0x0005] = new Channel("Immune", new[]
            {
                K(0, "AnomalyReport", RO), K(1, "Quarantine", DE), K(2, "QuarantineLift", NIW),
            }),
            [0x0006] = new Channel("Federation", new[]
            {
                K(0, "AuthorityAnnounce", RO), K(1, "ScopeReceipt", NIW),
            }),
            [0x0007] = new Channel("Settlement", new[]
            {
                K(0, "SettleIntent", NIW), K(1, "SettleReceipt", NIW), K(2, "SettleReject", IW),
            }),
            [0x0008] = new Channel("Compliance", new[]
            {
                K(0, "ComplianceRecord", NIW), K(1, "ComplianceQuery", RO), K(2, "ComplianceReport", RO),
            }),
            [0x0009] = new Channel("Sensory", new[]
            {
                K(0, "Observation", RO), K(1, "Subscribe", IW), K(2, "Unsubscribe", IW),
            }),
            [0x000A] = new Channel("Telemetry", new[]
            {
                K(0, "Metric", RO), K(1, "HealthReport", RO),
            }),
            [0x000B] = new Channel("Audit", new[]
            {
                K(0, "Receipt", NIW), K(1, "AuditQuery", RO), K(2, "ForkProof", RO),
            }),
            [0x000C] = new Channel("Stream", new[]
            {
                K(0, "StreamOpen", RO, true), K(1, "StreamCommit", RO), K(2, "StreamCheckpoint", RO),
            }),
            [0x000D] = new Channel("Bridge", new[]
            {
                K(0, "Carriage", RO, true),
            }),
            [0x000E] = new Channel("Commerce", new[]
            {
                K(0, "Offer", RO), K(1, "Order", NIW), K(2, "Fulfil", NIW), K(3, "Cancel", DE),
            }),
            [0x000F] = new Channel("Interaction", new[]
            {
                K(0, "Elicit", RO), K(1, "Respond", IW), K(2, "Confirm", NIW),
            }),
            [0x0010] = new Channel("Discovery", new[]
            {
                K(0, "DiscoveryRecord", RO), K(1, "DiscoveryQuery", RO),
            }),
            [0x0011] = new Channel("Workflow", new[]
            {
                K(0, "TaskCreate", NIW), K(1, "TaskInput", NIW), K(2, "TaskCancel", DE), K(3, "TaskResult", NIW),
            }),
            [0x0012] = new Channel("Knowledge", new[]
            {
                K(0, "Assert", NIW), K(1, "Retract", DE), K(2, "KnowledgeQuery", RO),
            }),
            [0x0013] = new Channel("Spatial", new[]
            {
                K(0, "FrameDefine", IW), K(1, "Pose", RO), K(2, "StateUpdate", RO), K(3, "SnapshotQuery", RO),
            }),
        };

        /// <summary>Return (name, effect, variable) for a (channel, kind), or throw UnknownKind.</summary>
        public static KindSpec Lookup(long channel, long kind)
        {
            if (!Table.TryGetValue((int)channel, out Channel? ch))
            {
                throw new NaalpException("UnknownKind",
                    string.Format("channel 0x{0:x4} not registered", channel));
            }
            foreach (Kind k in ch.Kinds)
            {
                if (k.Code == kind)
                {
                    return new KindSpec(k.Name, k.Effect, k.Variable);
                }
            }
            throw new NaalpException("UnknownKind",
                string.Format("kind {0} not in channel 0x{1:x4}", kind, channel));
        }

        /// <summary>A fixed-effect kind's object must carry its declared effect; a variable kind accepts 0..3.</summary>
        public static void CheckEffect(long channel, long kind, long effect)
        {
            KindSpec spec = Lookup(channel, kind);
            if (spec.Variable)
            {
                if (effect > DE)
                {
                    throw new NaalpException("EffectDeclarationMismatch", "effect " + effect + " out of range");
                }
                return;
            }
            if (effect != spec.Effect)
            {
                throw new NaalpException("EffectDeclarationMismatch",
                    "object effect " + effect + " != declared " + spec.Effect);
            }
        }
    }
}
