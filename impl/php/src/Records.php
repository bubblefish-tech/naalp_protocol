<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
/**
 * N-AALP body builders for the PHP SDK — the deterministic-CBOR bodies of the spine records:
 * approval + consume ledger (C6, §7), audit receipt (C7, §8), delivery update (C8, §9), stream
 * open/commit/checkpoint + rolling commitment (C9, §10), foreign carriage (C12, §13), and the
 * transport confidentiality boundary (C11, §12). Each body is exactly what the Python, Go, and
 * Rust reference implementations encode, so the bytes are byte-identical.
 */

declare(strict_types=1);

namespace Naalp;

class MappingError extends \RuntimeException
{
    public string $kind = "MappingError";
}

class UnknownTransport extends \RuntimeException
{
    public string $kind = "UnknownTransport";
}

final class Records
{
    // --- C6 approval + consume ledger (§7) ---

    public static function approvalBody(string $approves, string $approver, int $grant, string $nonce, int $notAfter): string
    {
        return Cbor::encode(new M([
            [new U(1), new B($approves)],
            [new U(2), new T($approver)],
            [new U(3), new U($grant)],
            [new U(4), new B($nonce)],
            [new U(5), new U($notAfter)],
        ]));
    }

    public static function approvalId(string $approves, string $approver, int $grant, string $nonce, int $notAfter): string
    {
        return Cbor::contentId(self::approvalBody($approves, $approver, $grant, $nonce, $notAfter));
    }

    public static function ledgerEntry(int $seq, string $prev, string $approvalId, string $by): string
    {
        return Cbor::encode(new M([
            [new U(1), new U($seq)],
            [new U(2), new B($prev)],
            [new U(3), new B($approvalId)],
            [new U(4), new T($by)],
        ]));
    }

    // --- C7 audit receipt (§8) ---

    public static function receiptBody(string $prev, string $obj, int $seq, int $at): string
    {
        return Cbor::encode(new M([
            [new U(1), new B($prev)],
            [new U(2), new B($obj)],
            [new U(3), new U($seq)],
            [new U(4), new U($at)],
        ]));
    }

    public static function receiptHead(string $body): string
    {
        return \hash('sha384', $body, true);
    }

    // --- C8 delivery (§9) ---

    public static function deliveryUpdate(string $obj, int $stage, int $at): string
    {
        return Cbor::encode(new M([
            [new U(1), new B($obj)],
            [new U(2), new U($stage)],
            [new U(3), new U($at)],
        ]));
    }

    // --- C9 streaming (§10) ---

    /**
     * Rolling SHA-384 over the chunk data in absolute-offset order (R-10.2).
     *
     * @param array<int,array{0:int,1:string}> $chunks list of [offset, data]
     */
    public static function streamDigest(array $chunks): string
    {
        $sorted = $chunks;
        \usort($sorted, static fn(array $a, array $b): int => $a[0] <=> $b[0]);
        $ctx = \hash_init('sha384');
        foreach ($sorted as $c) {
            \hash_update($ctx, $c[1]);
        }
        return \hash_final($ctx, true);
    }

    public static function streamOpenBody(string $streamId, int $effect, string $approval, int $substream): string
    {
        $pairs = [
            [new U(1), new B($streamId)],
            [new U(2), new U($effect)],
            [new U(4), new U($substream)],
        ];
        if ($approval !== "") { // field 3 present only when an approval binding exists
            $pairs[] = [new U(3), new B($approval)];
        }
        return Cbor::encode(new M($pairs));
    }

    public static function streamCommitBody(string $streamId, string $digest): string
    {
        return Cbor::encode(new M([
            [new U(1), new B($streamId)],
            [new U(2), new B($digest)],
        ]));
    }

    public static function streamCheckpointBody(string $streamId, int $throughOffset, string $digestSoFar): string
    {
        return Cbor::encode(new M([
            [new U(1), new B($streamId)],
            [new U(2), new U($throughOffset)],
            [new U(3), new B($digestSoFar)],
        ]));
    }

    // --- C12 foreign carriage (§13) ---

    public const CLASS_JSONRPC = 0;
    public const CLASS_HTTP = 1;
    public const CLASS_MSG = 2;
    public const CLASS_STREAM = 3;
    public const CLASS_DOC = 4;
    public const CLASS_OPAQUE = 5;

    public static function carriageBody(int $protocolId, int $cls, int $contentType, string $correlation, string $method, string $foreign): string
    {
        if ($cls > self::CLASS_OPAQUE) {
            throw new MappingError("carriage class " . $cls . " is not defined");
        }
        return Cbor::encode(new M([
            [new U(1), new U($protocolId)],
            [new U(2), new U($cls)],
            [new U(3), new U($contentType)],
            [new U(4), new B($correlation)],
            [new U(5), new T($method)],
            [new U(6), new B($foreign)],
        ]));
    }

    // --- C11 transport confidentiality boundary (§12) ---

    /** name => [confidential, peerAuthenticated] */
    private const TRANSPORTS = [
        "npamp" => [true, true],
        "quic" => [true, true],
        "websocket+wss" => [true, false],
        "websocket+ws" => [false, false],
        "https" => [true, false],
        "http" => [false, false],
    ];

    /** Apply the §12.3 confidentiality boundary + §12.4 peer-auth rule; returns the result label. */
    public static function transportEmit(string $name, bool $sensitive, bool $requirePeerAuth): string
    {
        if (!\array_key_exists($name, self::TRANSPORTS)) {
            throw new UnknownTransport("unknown transport " . $name);
        }
        [$confidential, $peerAuthenticated] = self::TRANSPORTS[$name];
        if ($sensitive && !$confidential) {
            return "ConfidentialTransportRequired";
        }
        if ($requirePeerAuth && !$peerAuthenticated) {
            return "PeerUnauthenticated";
        }
        return "ok";
    }
}
