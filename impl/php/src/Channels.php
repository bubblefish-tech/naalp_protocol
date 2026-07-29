<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
/**
 * N-AALP C10 channel registry for the PHP SDK — the frozen twenty-channel baseline surface
 * (design-channels.md §1..§20): all 20 channels (0x0000..0x0013), 65 kinds, each with a declared
 * effect (variable-effect for Stream StreamOpen / Bridge Carriage). An independent transcription of
 * the design, cross-checked against the shared conformance corpus (== Python == Go == Rust == oracle).
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

final class Channels
{
    private const RO = 0;
    private const IW = 1;
    private const NIW = 2;
    private const DE = 3;

    /**
     * channel code => [name, kinds]; each kind: [code, name, effect, variable].
     * Built once in table().
     *
     * @return array<int,array{0:string,1:array<int,array{0:int,1:string,2:int,3:bool}>}>
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
            0x0000 => ["Control", [[0, "Hello", $RO, false], [1, "Bye", $IW, false], [2, "Ack", $RO, false], [3, "Error", $RO, false]]],
            0x0001 => ["Memory", [[0, "MemoryOffer", $IW, false], [1, "MemoryAccept", $IW, false], [2, "MemoryWrite", $NIW, false],
                [3, "MemoryRead", $RO, false], [4, "MemoryExpire", $DE, false], [5, "MemoryRevoke", $DE, false]]],
            0x0002 => ["Capability", [[0, "CapIssue", $NIW, false], [1, "CapDelegate", $NIW, false], [2, "CapRevoke", $DE, false], [3, "CapLookup", $RO, false]]],
            0x0003 => ["Identity", [[0, "Rotation", $NIW, false], [1, "Revocation", $DE, false], [2, "ForeignLink", $IW, false], [3, "KeyAnnounce", $RO, false]]],
            0x0004 => ["Governance", [[0, "PolicyPublish", $NIW, false], [1, "Approval", $NIW, false], [2, "ApprovalHeld", $RO, false], [3, "Consume", $NIW, false]]],
            0x0005 => ["Immune", [[0, "AnomalyReport", $RO, false], [1, "Quarantine", $DE, false], [2, "QuarantineLift", $NIW, false]]],
            0x0006 => ["Federation", [[0, "AuthorityAnnounce", $RO, false], [1, "ScopeReceipt", $NIW, false]]],
            0x0007 => ["Settlement", [[0, "SettleIntent", $NIW, false], [1, "SettleReceipt", $NIW, false], [2, "SettleReject", $IW, false]]],
            0x0008 => ["Compliance", [[0, "ComplianceRecord", $NIW, false], [1, "ComplianceQuery", $RO, false], [2, "ComplianceReport", $RO, false]]],
            0x0009 => ["Sensory", [[0, "Observation", $RO, false], [1, "Subscribe", $IW, false], [2, "Unsubscribe", $IW, false]]],
            0x000A => ["Telemetry", [[0, "Metric", $RO, false], [1, "HealthReport", $RO, false]]],
            0x000B => ["Audit", [[0, "Receipt", $NIW, false], [1, "AuditQuery", $RO, false], [2, "ForkProof", $RO, false]]],
            0x000C => ["Stream", [[0, "StreamOpen", $RO, true], [1, "StreamCommit", $RO, false], [2, "StreamCheckpoint", $RO, false]]],
            0x000D => ["Bridge", [[0, "Carriage", $RO, true]]],
            0x000E => ["Commerce", [[0, "Offer", $RO, false], [1, "Order", $NIW, false], [2, "Fulfil", $NIW, false], [3, "Cancel", $DE, false]]],
            0x000F => ["Interaction", [[0, "Elicit", $RO, false], [1, "Respond", $IW, false], [2, "Confirm", $NIW, false]]],
            0x0010 => ["Discovery", [[0, "DiscoveryRecord", $RO, false], [1, "DiscoveryQuery", $RO, false]]],
            0x0011 => ["Workflow", [[0, "TaskCreate", $NIW, false], [1, "TaskInput", $NIW, false], [2, "TaskCancel", $DE, false], [3, "TaskResult", $NIW, false]]],
            0x0012 => ["Knowledge", [[0, "Assert", $NIW, false], [1, "Retract", $DE, false], [2, "KnowledgeQuery", $RO, false]]],
            0x0013 => ["Spatial", [[0, "FrameDefine", $IW, false], [1, "Pose", $RO, false], [2, "StateUpdate", $RO, false], [3, "SnapshotQuery", $RO, false]]],
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
}
