// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Naalp
{
    /// <summary>
    /// N-AALP C10 channel registry for the C# SDK — the frozen twenty-channel baseline surface
    /// (design-channels.md §1..§20): all 20 channels (0x0000..0x0013), 74 kinds, each with a declared
    /// effect (variable-effect for Stream StreamOpen / Bridge Carriage). An independent transcription of
    /// the design, cross-checked against the shared conformance corpus (== Go == Rust == Python == Java
    /// == oracle).
    /// </summary>
    public static class Channels
    {
        private const int RO = 0, IW = 1, NIW = 2, DE = 3; // read_only, idempotent_write, non_idempotent_write, destructive

        /// <summary>The (code, name, effect, variable) result of a channel+kind lookup. <c>Code</c> is
        /// additive (C10 channels wave, task #174) so this type doubles as the element type of
        /// <see cref="ChannelSpec.Kinds"/> — non-breaking, since every existing call site reads Name/
        /// Effect/Variable by property, never positionally.</summary>
        public sealed class KindSpec
        {
            public readonly long Code;
            public readonly string Name;
            public readonly int Effect;
            public readonly bool Variable;
            public KindSpec(long code, string name, int effect, bool variable)
            {
                Code = code;
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

        /// <summary>The channel descriptor: kinds plus the C10 §18 state-machine surface (states,
        /// transitions, named errors) added for the channels wave (task #174; design-channels.md
        /// §1..§20). Reused in place, not rebuilt — this type already existed (Name+Kinds only) for
        /// <see cref="Lookup"/>/<see cref="CheckEffect"/>; States/Transitions/Errors are additive so no
        /// existing caller is affected.</summary>
        private sealed class Channel
        {
            public readonly string Name;
            public readonly Kind[] Kinds;
            public readonly string[] States;
            public readonly (string From, string To)[] Transitions;
            public readonly string[] Errors;
            public Channel(string name, Kind[] kinds, string[] states, (string, string)[] transitions, string[] errors)
            {
                Name = name;
                Kinds = kinds;
                States = states;
                Transitions = transitions;
                Errors = errors;
            }
        }

        private static Kind K(int code, string name, int effect, bool variable = false)
            => new Kind(code, name, effect, variable);

        private static (string, string) T(string from, string to) => (from, to);

        // each kind: (code, name, effect, variable). States/transitions/errors mirror
        // impl/go/channels/channels.go Table and impl/rust/src/channels.rs table() verbatim
        // (design-channels.md §1..§20), cross-checked against vectors/channels/<name>/cases.json.
        private static readonly Dictionary<int, Channel> Table = new Dictionary<int, Channel>
        {
            [0x0000] = new Channel("Control", new[]
            {
                K(0, "Hello", RO), K(1, "Bye", IW), K(2, "Ack", RO), K(3, "Error", RO),
            },
                new[] { "open", "closing" },
                new[] { T("open", "closing") },
                new[] { "UnknownKind", "ProfileMismatch" }),
            [0x0001] = new Channel("Memory", new[]
            {
                K(0, "MemoryOffer", IW), K(1, "MemoryAccept", IW), K(2, "MemoryWrite", NIW),
                K(3, "MemoryRead", RO), K(4, "MemoryExpire", DE), K(5, "MemoryRevoke", DE),
            },
                new[] { "offered", "accepted", "live", "expired", "revoked" },
                new[] { T("offered", "accepted"), T("accepted", "live"), T("live", "expired"), T("live", "revoked") },
                new[] { "AccessDenied", "MemoryError" }),
            [0x0002] = new Channel("Capability", new[]
            {
                K(0, "CapIssue", NIW), K(1, "CapDelegate", NIW), K(2, "CapRevoke", DE), K(3, "CapLookup", RO),
            },
                new[] { "issued", "delegated", "revoked", "expired" },
                new[] { T("issued", "delegated"), T("delegated", "delegated"), T("issued", "revoked"), T("delegated", "revoked"), T("issued", "expired"), T("delegated", "expired") },
                new[] { "CapExceedsParent", "CapRevoked" }),
            [0x0003] = new Channel("Identity", new[]
            {
                K(0, "Rotation", NIW), K(1, "Revocation", DE), K(2, "ForeignLink", IW), K(3, "KeyAnnounce", RO),
            },
                new[] { "active", "rotated", "revoked" },
                new[] { T("active", "rotated"), T("rotated", "rotated"), T("active", "revoked"), T("rotated", "revoked") },
                new[] { "RotationUnauthorized", "KeyRevoked", "SignerMismatch" }),
            [0x0004] = new Channel("Governance", new[]
            {
                K(0, "PolicyPublish", NIW), K(1, "Approval", NIW), K(2, "ApprovalHeld", RO), K(3, "Consume", NIW), K(4, "GatewayDecision", NIW), K(5, "DecisionRecord", NIW), K(6, "EgressAttestation", NIW), K(7, "HazardAuthorization", NIW),
            },
                new[] { "requested", "held", "approved", "consumed", "expired" },
                new[] { T("requested", "held"), T("requested", "approved"), T("approved", "consumed"), T("held", "approved"), T("requested", "expired"), T("approved", "expired") },
                new[] { "ApprovalRequired", "ApprovalMismatch", "AlreadyConsumed", "EffectNotAuthorized" }),
            [0x0005] = new Channel("Immune", new[]
            {
                K(0, "AnomalyReport", RO), K(1, "Quarantine", DE), K(2, "QuarantineLift", NIW),
            },
                new[] { "normal", "quarantined", "lifted", "permanent" },
                new[] { T("normal", "quarantined"), T("quarantined", "lifted"), T("quarantined", "permanent") },
                new[] { "AccessDenied" }),
            [0x0006] = new Channel("Federation", new[]
            {
                K(0, "AuthorityAnnounce", RO), K(1, "ScopeReceipt", NIW),
            },
                new[] { "announced", "ordering" },
                new[] { T("announced", "ordering") },
                new[] { "AuthorityUnknown", "ScopeOverlapConflict" }),
            [0x0007] = new Channel("Settlement", new[]
            {
                K(0, "SettleIntent", NIW), K(1, "SettleReceipt", NIW), K(2, "SettleReject", IW), K(3, "PaymentImport", NIW), K(4, "PaymentChargeBinding", NIW),
            },
                new[] { "intent", "receipt", "reject" },
                new[] { T("intent", "receipt"), T("intent", "reject") },
                new[] { "ValueMismatch", "SettleExpired" }),
            [0x0008] = new Channel("Compliance", new[]
            {
                K(0, "ComplianceRecord", NIW), K(1, "ComplianceQuery", RO), K(2, "ComplianceReport", RO),
            },
                new[] { "appended" },
                Array.Empty<(string, string)>(),
                new[] { "RecordUnsigned", "JurisdictionUnknown" }),
            [0x0009] = new Channel("Sensory", new[]
            {
                K(0, "Observation", RO), K(1, "Subscribe", IW), K(2, "Unsubscribe", IW),
            },
                new[] { "active", "cancelled" },
                new[] { T("active", "cancelled") },
                new[] { "SubscriptionUnknown" }),
            [0x000A] = new Channel("Telemetry", new[]
            {
                K(0, "Metric", RO), K(1, "HealthReport", RO),
            },
                new[] { "stateless" },
                Array.Empty<(string, string)>(),
                new[] { "MetricMalformed" }),
            [0x000B] = new Channel("Audit", new[]
            {
                K(0, "Receipt", NIW), K(1, "AuditQuery", RO), K(2, "ForkProof", RO), K(3, "CheckpointRoot", NIW), K(4, "WitnessCosign", NIW), K(5, "InclusionProof", RO),
            },
                new[] { "appended" },
                Array.Empty<(string, string)>(),
                new[] { "ChainBroken", "Equivocation", "ReceiptUnsigned" }),
            [0x000C] = new Channel("Stream", new[]
            {
                K(0, "StreamOpen", RO, true), K(1, "StreamCommit", RO), K(2, "StreamCheckpoint", RO),
            },
                new[] { "open", "committed" },
                new[] { T("open", "committed") },
                new[] { "StreamDigestMismatch", "FlowControlError" }),
            [0x000D] = new Channel("Bridge", new[]
            {
                K(0, "Carriage", RO, true),
            },
                new[] { "carried" },
                Array.Empty<(string, string)>(),
                new[] { "EnvelopeMalformed", "ProtocolUnsupported", "MethodUnsupported", "NotDelivered", "EffectNotAuthorized" }),
            [0x000E] = new Channel("Commerce", new[]
            {
                K(0, "Offer", RO), K(1, "Order", NIW), K(2, "Fulfil", NIW), K(3, "Cancel", DE),
            },
                new[] { "offer", "order", "fulfil", "cancel" },
                new[] { T("offer", "order"), T("order", "fulfil"), T("order", "cancel") },
                new[] { "OfferExpired", "ApprovalRequired", "OrderMismatch" }),
            [0x000F] = new Channel("Interaction", new[]
            {
                K(0, "Elicit", RO), K(1, "Respond", IW), K(2, "Confirm", NIW), K(3, "UiEvent", NIW),
            },
                new[] { "elicit", "respond", "confirm", "timeout" },
                new[] { T("elicit", "respond"), T("elicit", "confirm"), T("elicit", "timeout") },
                new[] { "InteractionTimeout", "ElicitUnauthorized" }),
            [0x0010] = new Channel("Discovery", new[]
            {
                K(0, "DiscoveryRecord", RO), K(1, "DiscoveryQuery", RO),
            },
                new[] { "fresh", "stale" },
                new[] { T("fresh", "stale") },
                new[] { "RecordExpired", "TrustAnchorUnknown" }),
            [0x0011] = new Channel("Workflow", new[]
            {
                K(0, "TaskCreate", NIW), K(1, "TaskInput", NIW), K(2, "TaskCancel", DE), K(3, "TaskResult", NIW),
            },
                new[] { "created", "awaiting-input", "awaiting-approval", "running", "result", "cancelled" },
                new[]
                {
                    T("created", "awaiting-input"), T("created", "awaiting-approval"),
                    T("awaiting-input", "running"), T("awaiting-approval", "running"),
                    T("running", "result"), T("created", "cancelled"), T("awaiting-input", "cancelled"),
                    T("awaiting-approval", "cancelled"), T("running", "cancelled"),
                },
                new[] { "TaskStateError", "InputGateBypass", "ApprovalRequired" }),
            [0x0012] = new Channel("Knowledge", new[]
            {
                K(0, "Assert", NIW), K(1, "Retract", DE), K(2, "KnowledgeQuery", RO),
            },
                new[] { "asserted", "retracted" },
                new[] { T("asserted", "retracted") },
                new[] { "FactUnsigned", "RetractUnknown" }),
            [0x0013] = new Channel("Spatial", new[]
            {
                K(0, "FrameDefine", IW), K(1, "Pose", RO), K(2, "StateUpdate", RO), K(3, "SnapshotQuery", RO),
            },
                new[] { "defined", "observed" },
                new[] { T("defined", "observed") },
                new[] { "FrameUnknown", "TransformCycle" }),
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
                    return new KindSpec(k.Code, k.Name, k.Effect, k.Variable);
                }
            }
            throw new NaalpException("UnknownKind",
                string.Format("kind {0} not in channel 0x{1:x4}", kind, channel));
        }

        /// <summary>Whether (channel, kind) is a registered baseline surface — the envelope
        /// <see cref="Envelope.KindValidator"/> built from the frozen registry: accepts exactly the
        /// registered (channel, kind) pairs and rejects everything else (the envelope then fires
        /// UnknownKind). Mirrors impl/go/channels/channels.go KindValidator.</summary>
        public static bool KindValidator(long channel, long kind)
        {
            try
            {
                Lookup(channel, kind);
                return true;
            }
            catch (NaalpException)
            {
                return false;
            }
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

        /// <summary>Whether channel <paramref name="channel"/> permits a state transition from -&gt; to
        /// (design-channels.md §1..§20). An unregistered channel permits nothing. Mirrors
        /// impl/go/channels/channels.go AllowedTransition and impl/rust/src/channels.rs
        /// allowed_transition byte-for-byte on the verdict, graded against
        /// vectors/channels/&lt;name&gt;/cases.json (F3, non-circular).</summary>
        public static bool AllowedTransition(long channel, string from, string to)
        {
            if (!Table.TryGetValue((int)channel, out Channel? ch))
            {
                return false;
            }
            foreach ((string From, string To) t in ch.Transitions)
            {
                if (t.From == from && t.To == to)
                {
                    return true;
                }
            }
            return false;
        }

        /// <summary>The full channel descriptor: id, name, kinds (with codes), states, transitions, and
        /// named errors — the public parity surface mirroring Go's exported <c>ChannelSpec</c> struct /
        /// Rust's <c>ChannelSpec</c> struct (the private <see cref="Channel"/> type above is the
        /// internal, pre-existing storage; this is the new public accessor over it, per task #174).</summary>
        public sealed class ChannelSpec
        {
            public readonly long Id;
            public readonly string Name;
            public readonly KindSpec[] Kinds;
            public readonly string[] States;
            public readonly (string From, string To)[] Transitions;
            public readonly string[] Errors;

            public ChannelSpec(long id, string name, KindSpec[] kinds, string[] states, (string, string)[] transitions, string[] errors)
            {
                Id = id;
                Name = name;
                Kinds = kinds;
                States = states;
                Transitions = transitions;
                Errors = errors;
            }
        }

        /// <summary>The registered <see cref="ChannelSpec"/> for a channel id, or null if unregistered —
        /// mirrors Go's <c>Channel(id) (*ChannelSpec, bool)</c> / Rust's <c>channel(id) -&gt;
        /// Option&lt;ChannelSpec&gt;</c>.</summary>
        public static ChannelSpec? GetChannel(long id)
        {
            if (!Table.TryGetValue((int)id, out Channel? ch))
            {
                return null;
            }
            var kinds = new KindSpec[ch.Kinds.Length];
            for (int i = 0; i < ch.Kinds.Length; i++)
            {
                Kind k = ch.Kinds[i];
                kinds[i] = new KindSpec(k.Code, k.Name, k.Effect, k.Variable);
            }
            return new ChannelSpec(id, ch.Name, kinds, ch.States, ch.Transitions, ch.Errors);
        }

        /// <summary>Spatial's TransformCycle (design-channels.md §20): the coordinate-frame
        /// child-&gt;parent links in <paramref name="parent"/> must form a tree (acyclic); a frame
        /// mapping to "" (or absent) is a root. Throws TransformCycle on a cyclic tree; returns
        /// normally on a valid one. Mirrors impl/go/channels/channels.go CheckFrameTree and
        /// impl/rust/src/channels.rs check_frame_tree byte-for-byte on the accept/reject verdict.</summary>
        public static void CheckFrameTree(IReadOnlyDictionary<string, string> parent)
        {
            const int White = 0, Gray = 1, Black = 2;
            var color = new Dictionary<string, int>();

            bool Visit(string f)
            {
                color[f] = Gray;
                if (parent.TryGetValue(f, out string? p) && !string.IsNullOrEmpty(p))
                {
                    int pc = color.TryGetValue(p, out int v) ? v : White;
                    if (pc == Gray)
                    {
                        return true;
                    }
                    if (pc == White && Visit(p))
                    {
                        return true;
                    }
                }
                color[f] = Black;
                return false;
            }

            foreach (string f in parent.Keys)
            {
                int c = color.TryGetValue(f, out int v) ? v : White;
                if (c == White && Visit(f))
                {
                    throw new NaalpException("TransformCycle", "coordinate frame tree contains a cycle");
                }
            }
        }

        // ---- Workflow input gate (design-channels.md §18): the crash test that InputGateBypass
        // cannot occur. Mirrors impl/go/channels/channels.go WorkflowGate and
        // impl/rust/src/channels.rs WorkflowGate byte-for-byte on the WAL record format (big-endian
        // u32 length prefix + NUL-separated task/status UTF-8 record) and on every verdict.

        /// <summary>
        /// A durable, WAL-backed Workflow task-status tracker. A task's status is persisted
        /// (written + fsynced) BEFORE it is acknowledged (spine §9.2 persist-before-ack), so a crash
        /// recovers to the last durable status and can NEVER bypass the input/approval gate: reaching
        /// "running" requires an explicit input/approval step that a crash cannot manufacture.
        /// </summary>
        public sealed class WorkflowGate : IDisposable
        {
            private readonly object _mu = new object();
            private readonly FileStream _f;
            private readonly Dictionary<string, string> _status = new Dictionary<string, string>();

            internal WorkflowGate(string path)
            {
                _f = new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
                try
                {
                    Replay();
                }
                catch
                {
                    // Do not leak the exclusive FileShare.None handle on a failed open: the
                    // constructor throws before the object is returned, so nothing can Dispose it
                    // (mirrors Approval.Ledger's same discipline).
                    _f.Dispose();
                    throw;
                }
            }

            private void Replay()
            {
                _f.Seek(0, SeekOrigin.Begin);
                var lenBuf = new byte[4];
                while (true)
                {
                    if (!ReadFull(lenBuf))
                    {
                        break; // clean EOF at a record boundary
                    }
                    int n = (lenBuf[0] << 24) | (lenBuf[1] << 16) | (lenBuf[2] << 8) | lenBuf[3];
                    var rec = new byte[n];
                    if (!ReadFull(rec))
                    {
                        throw new NaalpException("Malformed", "workflow gate record");
                    }
                    int nul = Array.IndexOf(rec, (byte)0);
                    if (nul < 0)
                    {
                        throw new NaalpException("Malformed", "workflow gate record");
                    }
                    string task = Encoding.UTF8.GetString(rec, 0, nul);
                    string status = Encoding.UTF8.GetString(rec, nul + 1, rec.Length - nul - 1);
                    _status[task] = status;
                }
                _f.Seek(0, SeekOrigin.End);
            }

            private bool ReadFull(byte[] buf)
            {
                int off = 0;
                while (off < buf.Length)
                {
                    int r = _f.Read(buf, off, buf.Length - off);
                    if (r == 0)
                    {
                        if (off == 0)
                        {
                            return false;
                        }
                        throw new NaalpException("Malformed", "truncated workflow gate WAL record");
                    }
                    off += r;
                }
                return true;
            }

            private void Persist(string task, string status)
            {
                byte[] taskB = Encoding.UTF8.GetBytes(task);
                byte[] statusB = Encoding.UTF8.GetBytes(status);
                var rec = new byte[taskB.Length + 1 + statusB.Length];
                Array.Copy(taskB, 0, rec, 0, taskB.Length);
                Array.Copy(statusB, 0, rec, taskB.Length + 1, statusB.Length);
                var lenBuf = new byte[4];
                lenBuf[0] = (byte)(rec.Length >> 24);
                lenBuf[1] = (byte)(rec.Length >> 16);
                lenBuf[2] = (byte)(rec.Length >> 8);
                lenBuf[3] = (byte)rec.Length;
                _f.Write(lenBuf, 0, 4);
                _f.Write(rec, 0, rec.Length);
                _f.Flush(flushToDisk: true); // persist-before-ack (spine §9.2)
                _status[task] = status;
            }

            /// <summary>Records a new task in a non-terminal pre-gate status. TaskCreate never lands in
            /// "running": it lands in "awaiting-input" (or "awaiting-approval"), persisted before
            /// returning. Throws TaskStateError if the task id already exists.</summary>
            public void Create(string task, bool needsApproval)
            {
                lock (_mu)
                {
                    if (_status.ContainsKey(task))
                    {
                        throw new NaalpException("TaskStateError", "workflow task state transition not permitted");
                    }
                    Persist(task, needsApproval ? "awaiting-approval" : "awaiting-input");
                }
            }

            /// <summary>Advances a task past its input gate (awaiting-input -&gt; input-supplied) or
            /// approval gate (awaiting-approval -&gt; approved). Only these transitions may precede
            /// <see cref="Run"/>; any other current status throws TaskStateError.</summary>
            public void SupplyInput(string task)
            {
                lock (_mu)
                {
                    if (!_status.TryGetValue(task, out string? s))
                    {
                        throw new NaalpException("TaskStateError", "workflow task state transition not permitted");
                    }
                    switch (s)
                    {
                        case "awaiting-input":
                            Persist(task, "input-supplied");
                            break;
                        case "awaiting-approval":
                            Persist(task, "approved");
                            break;
                        default:
                            throw new NaalpException("TaskStateError", "workflow task state transition not permitted");
                    }
                }
            }

            /// <summary>
            /// Moves a task to "running" only if it has passed the gate. A task still
            /// "awaiting-input" or "awaiting-approval" (or unknown) cannot run: that is
            /// InputGateBypass, and it is forbidden.
            ///
            /// THIS IS THE RECORDED MUTATION ANCHOR: neutering this method to persist "running"
            /// unconditionally (skipping the awaiting-input/awaiting-approval check) would let a task
            /// run before its input/approval gate was passed — flipping
            /// ChannelsKat.WorkflowInputGateBypassMirrorsGoCrash from pass to fail.
            /// </summary>
            public void Run(string task)
            {
                lock (_mu)
                {
                    if (!_status.TryGetValue(task, out string? s))
                    {
                        throw new NaalpException("TaskStateError", "workflow task state transition not permitted");
                    }
                    switch (s)
                    {
                        case "input-supplied":
                        case "approved":
                            Persist(task, "running");
                            break;
                        case "awaiting-input":
                        case "awaiting-approval":
                            throw new NaalpException("InputGateBypass", "a task reached running without passing the input/approval gate");
                        default:
                            throw new NaalpException("TaskStateError", "workflow task state transition not permitted");
                    }
                }
            }

            /// <summary>The task's durable status, or null if the task id is unknown.</summary>
            public string? Status(string task)
            {
                lock (_mu)
                {
                    return _status.TryGetValue(task, out string? s) ? s : null;
                }
            }

            /// <summary>Flushes and closes the WAL.</summary>
            public void Close()
            {
                lock (_mu)
                {
                    _f.Dispose();
                }
            }

            public void Dispose() => Close();
        }

        /// <summary>Opens (creating if needed) a WAL-backed Workflow gate at <paramref name="path"/>
        /// and replays it. Mirrors impl/go/channels/channels.go OpenWorkflowGate and
        /// impl/rust/src/channels.rs open_workflow_gate.</summary>
        public static WorkflowGate OpenWorkflowGate(string path) => new WorkflowGate(path);
    }
}
