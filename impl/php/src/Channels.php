<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
/**
 * N-AALP C10 channel registry for the PHP SDK — the frozen twenty-channel baseline surface
 * (design-channels.md §1..§20): all 20 channels (0x0000..0x0013), 74 kinds, each with a declared
 * effect (variable-effect for Stream StreamOpen / Bridge Carriage). An independent transcription of
 * the design, cross-checked against the shared conformance corpus (== Python == Go == Rust == oracle).
 *
 * Also carries the per-channel state-machine transition guard (AllowedTransition), the Spatial
 * coordinate-frame acyclicity check (CheckFrameTree / TransformCycle), and the durable Workflow
 * input/approval gate (design-channels.md §18) whose crash test proves a task can NEVER reach
 * "running" without first passing SupplyInput — the InputGateBypass fail-closed anchor. An independent
 * transcription of impl/go/channels/channels.go (cross-read against impl/rust/src/channels.rs), graded
 * against the shared vectors/channels/<name>/cases.json.
 */

declare(strict_types=1);

namespace Naalp;

class UnknownKind extends \RuntimeException
{
    public string $kind = "UnknownKind";
}

class EffectDeclarationMismatch extends \RuntimeException
{
    public string $kind = "EffectDeclarationMismatch";
}

/** Spatial's named error (design-channels.md §20): the coordinate-frame child->parent links form a
 * cycle rather than a tree. */
class TransformCycle extends \RuntimeException
{
    public string $kind = "TransformCycle";
}

/** Workflow's named error (design-channels.md §18): a task reached "running" without passing the
 * input/approval gate — the fail-closed anchor this port's mutation targets. */
class InputGateBypass extends \RuntimeException
{
    public string $kind = "InputGateBypass";
}

/** Workflow's named error: a task state transition not permitted by the gate (re-creating an
 * existing task, supplying input to a task that is not awaiting it, running a task in no runnable
 * state). */
class TaskStateError extends \RuntimeException
{
    public string $kind = "TaskStateError";
}

/** A named, fail-closed workflow-gate WAL error; $kind mirrors the Go "Malformed" gate-record kind. */
class WorkflowGateError extends \RuntimeException
{
    public string $kind;

    public function __construct(string $kind, string $msg = "")
    {
        $this->kind = $kind;
        parent::__construct($msg === "" ? $kind : "$kind: $msg");
    }
}

/**
 * The channel descriptor (mirrors Go's ChannelSpec; Channels::channel() mirrors Go's Channel(id)):
 * the full frozen baseline surface for one channel — id, name, kinds, states, transitions, errors.
 * Each kinds entry is [code, name, effect, variable]; each transitions entry is [from, to].
 */
final class ChannelSpec
{
    public int $id;
    public string $name;
    /** @var array<int,array{0:int,1:string,2:int,3:bool}> */
    public array $kinds;
    /** @var string[] */
    public array $states;
    /** @var array<int,array{0:string,1:string}> */
    public array $transitions;
    /** @var string[] */
    public array $errors;

    /**
     * @param array<int,array{0:int,1:string,2:int,3:bool}> $kinds
     * @param string[] $states
     * @param array<int,array{0:string,1:string}> $transitions
     * @param string[] $errors
     */
    public function __construct(int $id, string $name, array $kinds, array $states, array $transitions, array $errors)
    {
        $this->id = $id;
        $this->name = $name;
        $this->kinds = $kinds;
        $this->states = $states;
        $this->transitions = $transitions;
        $this->errors = $errors;
    }
}

final class Channels
{
    private const RO = 0;
    private const IW = 1;
    private const NIW = 2;
    private const DE = 3;

    /**
     * channel code => [name, kinds, states, transitions, errors] (design-channels.md §1..§20); each
     * kind: [code, name, effect, variable]; each transition: [from, to]. Built once in table().
     *
     * @return array<int,array{0:string,1:array<int,array{0:int,1:string,2:int,3:bool}>,2:string[],3:array<int,array{0:string,1:string}>,4:string[]}>
     */
    private static function table(): array
    {
        static $t = null;
        if ($t !== null) {
            return $t;
        }
        $RO = self::RO;
        $IW = self::IW;
        $NIW = self::NIW;
        $DE = self::DE;
        $t = [
            0x0000 => ["Control", [[0, "Hello", $RO, false], [1, "Bye", $IW, false], [2, "Ack", $RO, false], [3, "Error", $RO, false]],
                ["open", "closing"], [["open", "closing"]], ["UnknownKind", "ProfileMismatch"]],
            0x0001 => ["Memory", [[0, "MemoryOffer", $IW, false], [1, "MemoryAccept", $IW, false], [2, "MemoryWrite", $NIW, false],
                [3, "MemoryRead", $RO, false], [4, "MemoryExpire", $DE, false], [5, "MemoryRevoke", $DE, false]],
                ["offered", "accepted", "live", "expired", "revoked"],
                [["offered", "accepted"], ["accepted", "live"], ["live", "expired"], ["live", "revoked"]],
                ["AccessDenied", "MemoryError"]],
            0x0002 => ["Capability", [[0, "CapIssue", $NIW, false], [1, "CapDelegate", $NIW, false], [2, "CapRevoke", $DE, false], [3, "CapLookup", $RO, false]],
                ["issued", "delegated", "revoked", "expired"],
                [["issued", "delegated"], ["delegated", "delegated"], ["issued", "revoked"], ["delegated", "revoked"], ["issued", "expired"], ["delegated", "expired"]],
                ["CapExceedsParent", "CapRevoked"]],
            0x0003 => ["Identity", [[0, "Rotation", $NIW, false], [1, "Revocation", $DE, false], [2, "ForeignLink", $IW, false], [3, "KeyAnnounce", $RO, false]],
                ["active", "rotated", "revoked"],
                [["active", "rotated"], ["rotated", "rotated"], ["active", "revoked"], ["rotated", "revoked"]],
                ["RotationUnauthorized", "KeyRevoked", "SignerMismatch"]],
            0x0004 => ["Governance", [[0, "PolicyPublish", $NIW, false], [1, "Approval", $NIW, false], [2, "ApprovalHeld", $RO, false], [3, "Consume", $NIW, false], [4, "GatewayDecision", $NIW, false], [5, "DecisionRecord", $NIW, false], [6, "EgressAttestation", $NIW, false], [7, "HazardAuthorization", $NIW, false]],
                ["requested", "held", "approved", "consumed", "expired"],
                [["requested", "held"], ["requested", "approved"], ["approved", "consumed"], ["held", "approved"], ["requested", "expired"], ["approved", "expired"]],
                ["ApprovalRequired", "ApprovalMismatch", "AlreadyConsumed", "EffectNotAuthorized"]],
            0x0005 => ["Immune", [[0, "AnomalyReport", $RO, false], [1, "Quarantine", $DE, false], [2, "QuarantineLift", $NIW, false]],
                ["normal", "quarantined", "lifted", "permanent"],
                [["normal", "quarantined"], ["quarantined", "lifted"], ["quarantined", "permanent"]],
                ["AccessDenied"]],
            0x0006 => ["Federation", [[0, "AuthorityAnnounce", $RO, false], [1, "ScopeReceipt", $NIW, false]],
                ["announced", "ordering"], [["announced", "ordering"]], ["AuthorityUnknown", "ScopeOverlapConflict"]],
            0x0007 => ["Settlement", [[0, "SettleIntent", $NIW, false], [1, "SettleReceipt", $NIW, false], [2, "SettleReject", $IW, false], [3, "PaymentImport", $NIW, false], [4, "PaymentChargeBinding", $NIW, false]],
                ["intent", "receipt", "reject"], [["intent", "receipt"], ["intent", "reject"]], ["ValueMismatch", "SettleExpired"]],
            0x0008 => ["Compliance", [[0, "ComplianceRecord", $NIW, false], [1, "ComplianceQuery", $RO, false], [2, "ComplianceReport", $RO, false]],
                ["appended"], [], ["RecordUnsigned", "JurisdictionUnknown"]],
            0x0009 => ["Sensory", [[0, "Observation", $RO, false], [1, "Subscribe", $IW, false], [2, "Unsubscribe", $IW, false]],
                ["active", "cancelled"], [["active", "cancelled"]], ["SubscriptionUnknown"]],
            0x000A => ["Telemetry", [[0, "Metric", $RO, false], [1, "HealthReport", $RO, false]],
                ["stateless"], [], ["MetricMalformed"]],
            0x000B => ["Audit", [[0, "Receipt", $NIW, false], [1, "AuditQuery", $RO, false], [2, "ForkProof", $RO, false], [3, "CheckpointRoot", $NIW, false], [4, "WitnessCosign", $NIW, false], [5, "InclusionProof", $RO, false]],
                ["appended"], [], ["ChainBroken", "Equivocation", "ReceiptUnsigned"]],
            0x000C => ["Stream", [[0, "StreamOpen", $RO, true], [1, "StreamCommit", $RO, false], [2, "StreamCheckpoint", $RO, false]],
                ["open", "committed"], [["open", "committed"]], ["StreamDigestMismatch", "FlowControlError"]],
            0x000D => ["Bridge", [[0, "Carriage", $RO, true]],
                ["carried"], [], ["EnvelopeMalformed", "ProtocolUnsupported", "MethodUnsupported", "NotDelivered", "EffectNotAuthorized"]],
            0x000E => ["Commerce", [[0, "Offer", $RO, false], [1, "Order", $NIW, false], [2, "Fulfil", $NIW, false], [3, "Cancel", $DE, false]],
                ["offer", "order", "fulfil", "cancel"], [["offer", "order"], ["order", "fulfil"], ["order", "cancel"]], ["OfferExpired", "ApprovalRequired", "OrderMismatch"]],
            0x000F => ["Interaction", [[0, "Elicit", $RO, false], [1, "Respond", $IW, false], [2, "Confirm", $NIW, false], [3, "UiEvent", $NIW, false]],
                ["elicit", "respond", "confirm", "timeout"], [["elicit", "respond"], ["elicit", "confirm"], ["elicit", "timeout"]], ["InteractionTimeout", "ElicitUnauthorized"]],
            0x0010 => ["Discovery", [[0, "DiscoveryRecord", $RO, false], [1, "DiscoveryQuery", $RO, false]],
                ["fresh", "stale"], [["fresh", "stale"]], ["RecordExpired", "TrustAnchorUnknown"]],
            0x0011 => ["Workflow", [[0, "TaskCreate", $NIW, false], [1, "TaskInput", $NIW, false], [2, "TaskCancel", $DE, false], [3, "TaskResult", $NIW, false]],
                ["created", "awaiting-input", "awaiting-approval", "running", "result", "cancelled"],
                [["created", "awaiting-input"], ["created", "awaiting-approval"], ["awaiting-input", "running"], ["awaiting-approval", "running"],
                    ["running", "result"], ["created", "cancelled"], ["awaiting-input", "cancelled"], ["awaiting-approval", "cancelled"], ["running", "cancelled"]],
                ["TaskStateError", "InputGateBypass", "ApprovalRequired"]],
            0x0012 => ["Knowledge", [[0, "Assert", $NIW, false], [1, "Retract", $DE, false], [2, "KnowledgeQuery", $RO, false]],
                ["asserted", "retracted"], [["asserted", "retracted"]], ["FactUnsigned", "RetractUnknown"]],
            0x0013 => ["Spatial", [[0, "FrameDefine", $IW, false], [1, "Pose", $RO, false], [2, "StateUpdate", $RO, false], [3, "SnapshotQuery", $RO, false]],
                ["defined", "observed"], [["defined", "observed"]], ["FrameUnknown", "TransformCycle"]],
        ];
        return $t;
    }

    /**
     * Return [name, effect, variable] for a (channel, kind), or raise UnknownKind.
     *
     * @return array{0:string,1:int,2:bool}
     */
    public static function lookup(int $channel, int $kind): array
    {
        $table = self::table();
        if (!\array_key_exists($channel, $table)) {
            throw new UnknownKind(\sprintf("channel 0x%04x not registered", $channel));
        }
        foreach ($table[$channel][1] as $entry) {
            if ($entry[0] === $kind) {
                return [$entry[1], $entry[2], $entry[3]];
            }
        }
        throw new UnknownKind(\sprintf("kind %d not in channel 0x%04x", $kind, $channel));
    }

    /** A fixed-effect kind's object must carry its declared effect; a variable kind accepts 0..3. */
    public static function checkEffect(int $channel, int $kind, int $effect): void
    {
        [$name, $declared, $variable] = self::lookup($channel, $kind);
        if ($variable) {
            if ($effect > self::DE) {
                throw new EffectDeclarationMismatch("effect " . $effect . " out of range");
            }
            return;
        }
        if ($effect !== $declared) {
            throw new EffectDeclarationMismatch("object effect " . $effect . " != declared " . $declared);
        }
    }

    /** The full descriptor for a channel id, or null if unregistered (mirrors Go Channel(id)). */
    public static function channel(int $id): ?ChannelSpec
    {
        $table = self::table();
        if (!\array_key_exists($id, $table)) {
            return null;
        }
        [$name, $kinds, $states, $transitions, $errors] = $table[$id];
        return new ChannelSpec($id, $name, $kinds, $states, $transitions, $errors);
    }

    /** Whether a channel permits a state transition from -> to. An unregistered channel permits none. */
    public static function allowedTransition(int $channel, string $from, string $to): bool
    {
        $table = self::table();
        if (!\array_key_exists($channel, $table)) {
            return false;
        }
        foreach ($table[$channel][3] as [$f, $t]) {
            if ($f === $from && $t === $to) {
                return true;
            }
        }
        return false;
    }

    /**
     * Enforces Spatial's TransformCycle (design-channels.md §20): the coordinate-frame child->parent
     * links (a map of frame name => parent frame name, "" or absent meaning root) must form a tree
     * (acyclic). Throws TransformCycle on a cycle; returns (does nothing) on a valid tree.
     *
     * @param array<string,string> $parent
     */
    public static function checkFrameTree(array $parent): void
    {
        $white = 0;
        $gray = 1;
        $black = 2;
        $color = [];
        $visit = function (string $f) use (&$visit, &$color, $parent, $white, $gray, $black): bool {
            $color[$f] = $gray;
            $p = $parent[$f] ?? '';
            if ($p !== '') {
                $c = $color[$p] ?? $white;
                if ($c === $gray) {
                    return true;
                }
                if ($c === $white && $visit($p)) {
                    return true;
                }
            }
            $color[$f] = $black;
            return false;
        };
        foreach (\array_keys($parent) as $f) {
            if (($color[$f] ?? $white) === $white && $visit($f)) {
                throw new TransformCycle("coordinate frame tree contains a cycle");
            }
        }
    }

    /**
     * Opens (creating if needed) a WAL-backed, durable Workflow input/approval gate at $path and
     * replays any existing log to recover the last durable status per task (design-channels.md §18).
     * A task's status is persisted (fsynced) before it is acknowledged, so a crash recovers to the
     * last durable status and can NEVER bypass the input/approval gate.
     */
    public static function openWorkflowGate(string $path): WorkflowGate
    {
        $f = \is_file($path) ? \fopen($path, 'r+b') : \fopen($path, 'w+b');
        if ($f === false) {
            throw new WorkflowGateError("Malformed", "cannot open workflow gate WAL at $path");
        }
        return new WorkflowGate($f);
    }
}

/**
 * A durable, WAL-backed Workflow task-status tracker (design-channels.md §18). A task's status is
 * persisted (written and fsynced) before it is acknowledged, so a crash recovers to the last durable
 * status and can NEVER bypass the input/approval gate: reaching "running" requires an explicit
 * SupplyInput step that a crash cannot manufacture. Mirrors Go/Rust WorkflowGate. Construct via
 * Channels::openWorkflowGate().
 */
final class WorkflowGate
{
    /** @var resource the WAL file handle */
    private $f;
    /** @var array<string,string> task name -> durable status */
    private array $status = [];

    /** @param resource $f an opened, seekable read+write binary stream */
    public function __construct($f)
    {
        $this->f = $f;
        $this->replay();
    }

    /**
     * Read the WAL from the start, rebuilding the per-task status map. Each record is length-prefixed
     * (uint32 big-endian), body "<task>\0<status>" — self-framing so a truncated tail is refused
     * rather than trusted.
     */
    private function replay(): void
    {
        \fseek($this->f, 0, \SEEK_SET);
        while (true) {
            $lb = \fread($this->f, 4);
            if ($lb === "" || $lb === false) {
                break; // clean EOF
            }
            if (\strlen($lb) !== 4) {
                throw new WorkflowGateError("Malformed", "truncated workflow gate length prefix");
            }
            $n = \unpack("N", $lb)[1];
            $rec = $n === 0 ? "" : \fread($this->f, $n);
            if ($rec === false || \strlen($rec) !== $n) {
                throw new WorkflowGateError("Malformed", "truncated workflow gate record");
            }
            $nul = \strpos($rec, "\x00");
            if ($nul === false) {
                throw new WorkflowGateError("Malformed", "workflow gate record");
            }
            $this->status[\substr($rec, 0, $nul)] = \substr($rec, $nul + 1);
        }
    }

    /** Append + fsync one status record before updating the in-memory map (persist-before-ack). */
    private function persist(string $task, string $status): void
    {
        $rec = $task . "\x00" . $status;
        $framed = \pack("N", \strlen($rec)) . $rec;
        \fseek($this->f, 0, \SEEK_END);
        if (\fwrite($this->f, $framed) !== \strlen($framed)) {
            throw new WorkflowGateError("Malformed", "short write to the workflow gate WAL");
        }
        \fflush($this->f);
        \fsync($this->f); // persist-before-ack (spine §9.2)
        $this->status[$task] = $status;
    }

    /**
     * Records a new task in a non-terminal pre-gate status, persisted before returning. TaskCreate
     * never lands in "running": it lands in "awaiting-input" (or "awaiting-approval" when
     * $needsApproval). Re-creating an existing task is TaskStateError.
     */
    public function create(string $task, bool $needsApproval): void
    {
        if (\array_key_exists($task, $this->status)) {
            throw new TaskStateError("task already exists");
        }
        $this->persist($task, $needsApproval ? "awaiting-approval" : "awaiting-input");
    }

    /**
     * Advances a task past its input gate (awaiting-input -> input-supplied) or approval gate
     * (awaiting-approval -> approved). Only these transitions may precede run(). Any other current
     * status (including unknown) is TaskStateError.
     */
    public function supplyInput(string $task): void
    {
        $st = $this->status[$task] ?? null;
        if ($st === "awaiting-input") {
            $this->persist($task, "input-supplied");
            return;
        }
        if ($st === "awaiting-approval") {
            $this->persist($task, "approved");
            return;
        }
        throw new TaskStateError("task is not awaiting input or approval");
    }

    /**
     * Moves a task to "running" only if it has passed the gate. A task still "awaiting-input" or
     * "awaiting-approval" is InputGateBypass — a task may not execute on input that was never
     * supplied/authorized, and this holds across a crash (replay recovers the pre-gate status, never
     * "running"). Any other status (including unknown) is TaskStateError.
     */
    public function run(string $task): void
    {
        $st = $this->status[$task] ?? null;
        if ($st === "input-supplied" || $st === "approved") {
            $this->persist($task, "running");
            return;
        }
        if ($st === "awaiting-input" || $st === "awaiting-approval") {
            throw new InputGateBypass("a task reached running without passing the input/approval gate");
        }
        throw new TaskStateError("task is in no runnable state");
    }

    /** The task's durable status, or null if the task is unknown. */
    public function status(string $task): ?string
    {
        return $this->status[$task] ?? null;
    }

    /** Flush and close the WAL. */
    public function close(): void
    {
        if (\is_resource($this->f)) {
            \fclose($this->f);
        }
    }
}
