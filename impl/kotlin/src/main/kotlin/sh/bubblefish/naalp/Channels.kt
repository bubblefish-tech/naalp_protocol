// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

import java.io.EOFException
import java.io.RandomAccessFile

/**
 * N-AALP C10 channel registry for the Kotlin SDK — the frozen twenty-channel baseline surface
 * (design-channels.md §1..§20): all 20 channels (0x0000..0x0013), 74 kinds, each with a declared
 * effect (variable-effect for Stream StreamOpen / Bridge Carriage); each channel's state machine
 * (states + permitted transitions) and named errors; the Spatial coordinate-frame cycle check
 * (TransformCycle); and the durable Workflow input/approval gate whose crash test proves
 * InputGateBypass cannot occur (design-channels.md §18). An independent transcription of the
 * design, cross-checked against the shared conformance corpus (== Go == Rust == oracle).
 */
object Channels {
    private const val RO = 0
    private const val IW = 1
    private const val NIW = 2
    private const val DE = 3

    /** One baseline object kind of a channel: its code, name, declared effect, and whether the
     *  effect is caller-variable (Stream StreamOpen / Bridge Carriage — authorized by C5). */
    class KindSpec(val code: Int, val name: String, val effect: Int, val variable: Boolean)

    /** One channel's frozen baseline surface: kinds, states, permitted state transitions, and the
     *  channel's named errors. Mirrors Go channels.ChannelSpec. */
    class ChannelSpec(
        val id: Int,
        val name: String,
        val kinds: List<KindSpec>,
        val states: List<String>,
        val transitions: List<Pair<String, String>>,
        val errors: List<String>,
    )

    private val TABLE = LinkedHashMap<Int, ChannelSpec>()

    private fun k(code: Int, name: String, effect: Int, variable: Boolean) = KindSpec(code, name, effect, variable)

    private fun ch(
        id: Int,
        name: String,
        kinds: List<KindSpec>,
        states: List<String>,
        transitions: List<Pair<String, String>>,
        errors: List<String>,
    ) {
        TABLE[id] = ChannelSpec(id, name, kinds, states, transitions, errors)
    }

    init {
        ch(
            0x0000, "Control",
            listOf(k(0, "Hello", RO, false), k(1, "Bye", IW, false), k(2, "Ack", RO, false), k(3, "Error", RO, false)),
            listOf("open", "closing"),
            listOf("open" to "closing"),
            listOf("UnknownKind", "ProfileMismatch"),
        )
        ch(
            0x0001, "Memory",
            listOf(
                k(0, "MemoryOffer", IW, false), k(1, "MemoryAccept", IW, false), k(2, "MemoryWrite", NIW, false),
                k(3, "MemoryRead", RO, false), k(4, "MemoryExpire", DE, false), k(5, "MemoryRevoke", DE, false),
            ),
            listOf("offered", "accepted", "live", "expired", "revoked"),
            listOf("offered" to "accepted", "accepted" to "live", "live" to "expired", "live" to "revoked"),
            listOf("AccessDenied", "MemoryError"),
        )
        ch(
            0x0002, "Capability",
            listOf(k(0, "CapIssue", NIW, false), k(1, "CapDelegate", NIW, false), k(2, "CapRevoke", DE, false), k(3, "CapLookup", RO, false)),
            listOf("issued", "delegated", "revoked", "expired"),
            listOf(
                "issued" to "delegated", "delegated" to "delegated", "issued" to "revoked",
                "delegated" to "revoked", "issued" to "expired", "delegated" to "expired",
            ),
            listOf("CapExceedsParent", "CapRevoked"),
        )
        ch(
            0x0003, "Identity",
            listOf(k(0, "Rotation", NIW, false), k(1, "Revocation", DE, false), k(2, "ForeignLink", IW, false), k(3, "KeyAnnounce", RO, false)),
            listOf("active", "rotated", "revoked"),
            listOf("active" to "rotated", "rotated" to "rotated", "active" to "revoked", "rotated" to "revoked"),
            listOf("RotationUnauthorized", "KeyRevoked", "SignerMismatch"),
        )
        ch(
            0x0004, "Governance",
            listOf(k(0, "PolicyPublish", NIW, false), k(1, "Approval", NIW, false), k(2, "ApprovalHeld", RO, false), k(3, "Consume", NIW, false), k(4, "GatewayDecision", NIW, false), k(5, "DecisionRecord", NIW, false), k(6, "EgressAttestation", NIW, false), k(7, "HazardAuthorization", NIW, false)),
            listOf("requested", "held", "approved", "consumed", "expired"),
            listOf(
                "requested" to "held", "requested" to "approved", "approved" to "consumed",
                "held" to "approved", "requested" to "expired", "approved" to "expired",
            ),
            listOf("ApprovalRequired", "ApprovalMismatch", "AlreadyConsumed", "EffectNotAuthorized"),
        )
        ch(
            0x0005, "Immune",
            listOf(k(0, "AnomalyReport", RO, false), k(1, "Quarantine", DE, false), k(2, "QuarantineLift", NIW, false)),
            listOf("normal", "quarantined", "lifted", "permanent"),
            listOf("normal" to "quarantined", "quarantined" to "lifted", "quarantined" to "permanent"),
            listOf("AccessDenied"),
        )
        ch(
            0x0006, "Federation",
            listOf(k(0, "AuthorityAnnounce", RO, false), k(1, "ScopeReceipt", NIW, false)),
            listOf("announced", "ordering"),
            listOf("announced" to "ordering"),
            listOf("AuthorityUnknown", "ScopeOverlapConflict"),
        )
        ch(
            0x0007, "Settlement",
            listOf(k(0, "SettleIntent", NIW, false), k(1, "SettleReceipt", NIW, false), k(2, "SettleReject", IW, false), k(3, "PaymentImport", NIW, false), k(4, "PaymentChargeBinding", NIW, false)),
            listOf("intent", "receipt", "reject"),
            listOf("intent" to "receipt", "intent" to "reject"),
            listOf("ValueMismatch", "SettleExpired"),
        )
        ch(
            0x0008, "Compliance",
            listOf(k(0, "ComplianceRecord", NIW, false), k(1, "ComplianceQuery", RO, false), k(2, "ComplianceReport", RO, false)),
            listOf("appended"),
            emptyList(),
            listOf("RecordUnsigned", "JurisdictionUnknown"),
        )
        ch(
            0x0009, "Sensory",
            listOf(k(0, "Observation", RO, false), k(1, "Subscribe", IW, false), k(2, "Unsubscribe", IW, false)),
            listOf("active", "cancelled"),
            listOf("active" to "cancelled"),
            listOf("SubscriptionUnknown"),
        )
        ch(
            0x000A, "Telemetry",
            listOf(k(0, "Metric", RO, false), k(1, "HealthReport", RO, false)),
            listOf("stateless"),
            emptyList(),
            listOf("MetricMalformed"),
        )
        ch(
            0x000B, "Audit",
            listOf(k(0, "Receipt", NIW, false), k(1, "AuditQuery", RO, false), k(2, "ForkProof", RO, false), k(3, "CheckpointRoot", NIW, false), k(4, "WitnessCosign", NIW, false), k(5, "InclusionProof", RO, false)),
            listOf("appended"),
            emptyList(),
            listOf("ChainBroken", "Equivocation", "ReceiptUnsigned"),
        )
        ch(
            0x000C, "Stream",
            listOf(k(0, "StreamOpen", RO, true), k(1, "StreamCommit", RO, false), k(2, "StreamCheckpoint", RO, false)),
            listOf("open", "committed"),
            listOf("open" to "committed"),
            listOf("StreamDigestMismatch", "FlowControlError"),
        )
        ch(
            0x000D, "Bridge",
            listOf(k(0, "Carriage", RO, true)),
            listOf("carried"),
            emptyList(),
            listOf("EnvelopeMalformed", "ProtocolUnsupported", "MethodUnsupported", "NotDelivered", "EffectNotAuthorized"),
        )
        ch(
            0x000E, "Commerce",
            listOf(k(0, "Offer", RO, false), k(1, "Order", NIW, false), k(2, "Fulfil", NIW, false), k(3, "Cancel", DE, false)),
            listOf("offer", "order", "fulfil", "cancel"),
            listOf("offer" to "order", "order" to "fulfil", "order" to "cancel"),
            listOf("OfferExpired", "ApprovalRequired", "OrderMismatch"),
        )
        ch(
            0x000F, "Interaction",
            listOf(k(0, "Elicit", RO, false), k(1, "Respond", IW, false), k(2, "Confirm", NIW, false), k(3, "UiEvent", NIW, false)),
            listOf("elicit", "respond", "confirm", "timeout"),
            listOf("elicit" to "respond", "elicit" to "confirm", "elicit" to "timeout"),
            listOf("InteractionTimeout", "ElicitUnauthorized"),
        )
        ch(
            0x0010, "Discovery",
            listOf(k(0, "DiscoveryRecord", RO, false), k(1, "DiscoveryQuery", RO, false)),
            listOf("fresh", "stale"),
            listOf("fresh" to "stale"),
            listOf("RecordExpired", "TrustAnchorUnknown"),
        )
        ch(
            0x0011, "Workflow",
            listOf(k(0, "TaskCreate", NIW, false), k(1, "TaskInput", NIW, false), k(2, "TaskCancel", DE, false), k(3, "TaskResult", NIW, false)),
            listOf("created", "awaiting-input", "awaiting-approval", "running", "result", "cancelled"),
            listOf(
                "created" to "awaiting-input", "created" to "awaiting-approval",
                "awaiting-input" to "running", "awaiting-approval" to "running",
                "running" to "result",
                "created" to "cancelled", "awaiting-input" to "cancelled", "awaiting-approval" to "cancelled", "running" to "cancelled",
            ),
            listOf("TaskStateError", "InputGateBypass", "ApprovalRequired"),
        )
        ch(
            0x0012, "Knowledge",
            listOf(k(0, "Assert", NIW, false), k(1, "Retract", DE, false), k(2, "KnowledgeQuery", RO, false)),
            listOf("asserted", "retracted"),
            listOf("asserted" to "retracted"),
            listOf("FactUnsigned", "RetractUnknown"),
        )
        ch(
            0x0013, "Spatial",
            listOf(k(0, "FrameDefine", IW, false), k(1, "Pose", RO, false), k(2, "StateUpdate", RO, false), k(3, "SnapshotQuery", RO, false)),
            listOf("defined", "observed"),
            listOf("defined" to "observed"),
            listOf("FrameUnknown", "TransformCycle"),
        )
    }

    /** Returns the frozen spec for a channel id, or null if unregistered. Mirrors Go channels.Channel. */
    fun channel(id: Long): ChannelSpec? = TABLE[id.toInt()]

    /** Return (code, name, effect, variable) for a (channel, kind), or raise UnknownKind. */
    fun lookup(channel: Long, kind: Long): KindSpec {
        val c = TABLE[channel.toInt()]
            ?: throw NaalpException("UnknownKind", String.format("channel 0x%04x not registered", channel))
        for (kd in c.kinds) {
            if (kd.code.toLong() == kind) return kd
        }
        throw NaalpException("UnknownKind", String.format("kind %d not in channel 0x%04x", kind, channel))
    }

    /** A fixed-effect kind's object must carry its declared effect; a variable kind accepts 0..3. */
    fun checkEffect(channel: Long, kind: Long, effect: Long) {
        val spec = lookup(channel, kind)
        if (spec.variable) {
            if (effect > DE) throw NaalpException("EffectDeclarationMismatch", "effect $effect out of range")
            return
        }
        if (effect != spec.effect.toLong()) {
            throw NaalpException("EffectDeclarationMismatch", "object effect $effect != declared ${spec.effect}")
        }
    }

    /** Whether a channel permits a state transition from -> to. Mirrors Go channels.AllowedTransition. */
    fun allowedTransition(channel: Long, from: String, to: String): Boolean {
        val c = TABLE[channel.toInt()] ?: return false
        return c.transitions.any { it.first == from && it.second == to }
    }

    /** Spatial TransformCycle (design-channels.md §20): the coordinate-frame child->parent links
     *  must form a tree (acyclic). A frame mapping to "" (or absent) is a root. Accepts a valid
     *  tree silently; throws TransformCycle on a cycle. Mirrors Go channels.CheckFrameTree. */
    fun checkFrameTree(parent: Map<String, String>) {
        val white = 0
        val gray = 1
        val black = 2
        val color = HashMap<String, Int>()

        fun visit(f: String): Boolean {
            color[f] = gray
            val p = parent[f]
            if (!p.isNullOrEmpty()) {
                when (color[p] ?: white) {
                    gray -> return true
                    white -> if (visit(p)) return true
                }
            }
            color[f] = black
            return false
        }

        for (f in parent.keys) {
            if ((color[f] ?: white) == white && visit(f)) {
                throw NaalpException("TransformCycle", "coordinate frame tree contains a cycle")
            }
        }
    }

    // ---- Workflow input gate (design-channels.md §18): the crash test that InputGateBypass cannot occur.

    /**
     * A durable, WAL-backed Workflow task-status tracker. A task's status is persisted (and
     * fsynced) before it is acknowledged (spine §9.2), so a crash recovers to the last durable
     * status and can NEVER bypass the input/approval gate: reaching "running" requires an explicit
     * input/approval step that a crash cannot manufacture. Mirrors Go channels.WorkflowGate.
     */
    class WorkflowGate internal constructor(private val f: RandomAccessFile) {
        private val lock = Any()
        private val taskStatus = HashMap<String, String>()

        internal fun replay() {
            f.seek(0)
            val lenBuf = ByteArray(4)
            while (true) {
                val n0 = f.read(lenBuf)
                if (n0 == -1) break
                if (n0 != 4) throw NaalpException("Malformed", "truncated workflow gate length prefix")
                val n = ((lenBuf[0].toInt() and 0xFF) shl 24) or ((lenBuf[1].toInt() and 0xFF) shl 16) or
                    ((lenBuf[2].toInt() and 0xFF) shl 8) or (lenBuf[3].toInt() and 0xFF)
                val rec = ByteArray(n)
                try {
                    f.readFully(rec)
                } catch (e: EOFException) {
                    throw NaalpException("Malformed", "truncated workflow gate record")
                }
                var nul = -1
                for (i in rec.indices) {
                    if (rec[i] == 0.toByte()) {
                        nul = i
                        break
                    }
                }
                if (nul < 0) throw NaalpException("Malformed", "workflow gate record")
                val task = String(rec, 0, nul, Charsets.UTF_8)
                val st = String(rec, nul + 1, rec.size - nul - 1, Charsets.UTF_8)
                taskStatus[task] = st
            }
        }

        private fun persist(task: String, st: String) {
            val taskB = task.toByteArray(Charsets.UTF_8)
            val stB = st.toByteArray(Charsets.UTF_8)
            val rec = ByteArray(taskB.size + 1 + stB.size)
            System.arraycopy(taskB, 0, rec, 0, taskB.size)
            rec[taskB.size] = 0
            System.arraycopy(stB, 0, rec, taskB.size + 1, stB.size)
            val framed = ByteArray(4 + rec.size)
            framed[0] = (rec.size ushr 24).toByte()
            framed[1] = (rec.size ushr 16).toByte()
            framed[2] = (rec.size ushr 8).toByte()
            framed[3] = rec.size.toByte()
            System.arraycopy(rec, 0, framed, 4, rec.size)
            f.seek(f.length())
            f.write(framed)
            f.fd.sync() // persist-before-ack (spine §9.2)
            taskStatus[task] = st
        }

        /** Records a new task in a non-terminal pre-gate status. TaskCreate never lands in
         *  "running": it lands in "awaiting-input" (or "awaiting-approval"), persisted before
         *  returning. */
        fun create(task: String, needsApproval: Boolean) {
            synchronized(lock) {
                if (taskStatus.containsKey(task)) throw NaalpException("TaskStateError", "task already exists")
                persist(task, if (needsApproval) "awaiting-approval" else "awaiting-input")
            }
        }

        /** Advances a task past its input gate (awaiting-input -> input-supplied) or approval gate
         *  (awaiting-approval -> approved). Only these transitions may precede run(). */
        fun supplyInput(task: String) {
            synchronized(lock) {
                when (taskStatus[task]) {
                    "awaiting-input" -> persist(task, "input-supplied")
                    "awaiting-approval" -> persist(task, "approved")
                    else -> throw NaalpException("TaskStateError", "task not awaiting input/approval")
                }
            }
        }

        /** Moves a task to "running" only if it has passed the gate. A task still
         *  "awaiting-input"/"awaiting-approval" (or unknown) cannot run: that is InputGateBypass,
         *  which is forbidden. A task may not execute on input that was never supplied/authorized. */
        fun run(task: String) {
            synchronized(lock) {
                when (taskStatus[task]) {
                    "input-supplied", "approved" -> persist(task, "running")
                    "awaiting-input", "awaiting-approval" ->
                        throw NaalpException("InputGateBypass", "a task reached running without passing the input/approval gate")
                    else -> throw NaalpException("TaskStateError", "workflow task state transition not permitted")
                }
            }
        }

        /** Returns a task's durable status, or null if the task is unknown. */
        fun status(task: String): String? = synchronized(lock) { taskStatus[task] }

        /** Flushes and closes the WAL. */
        fun close() {
            synchronized(lock) { f.close() }
        }
    }

    /** Opens (creating if needed) a WAL-backed workflow gate and replays it. Mirrors Go
     *  channels.OpenWorkflowGate. */
    fun openWorkflowGate(path: String): WorkflowGate {
        val raf = RandomAccessFile(path, "rw")
        val g = WorkflowGate(raf)
        g.replay()
        return g
    }
}
