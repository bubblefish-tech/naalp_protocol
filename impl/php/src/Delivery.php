<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
/**
 * N-AALP C8 delivery for the PHP SDK — delivery as four signed monotonic stages, the
 * persist-before-acknowledge discipline, the full-duplex switchboard, and the content-free relay
 * (design.md §9; R-9.1..9.4).
 *
 * Delivery is four distinct, separately-observable stages, each a signed delivery.update naming the
 * target object's content id and the stage reached — there is no single "sent" boolean (§9.1):
 * persisted_origin -> accepted_relay -> persisted_target -> presented. A stage is advanced only after
 * the object is durably persisted (WAL fsync), so a crash right after an acknowledgment loses nothing
 * (§9.2). Observing a stage earlier than the one already reached is StageOutOfOrder (§9.4). The
 * switchboard holds two connections open and passes objects through both directions (§9.3); a relay
 * that holds objects only in transit writes an audit trail over content ids while retaining no payload
 * (§9.4, R-9.4).
 *
 * An independent transcription of impl/go/delivery (cross-read against impl/python/naalp/delivery.py),
 * graded against the shared vectors/delivery/cases.json. The content-id framing and the relay's
 * retained trail reuse the shared Naalp\Cbor and Naalp\Audit.
 *
 * CRYPTO SCOPE (PURE-ONLY): the corpus-graded surfaces (the four stage names, the delivery.update body
 * byte-for-byte, and the T1 content-id framing) are pure. PHP has no deterministic ML-DSA (FIPS 204),
 * so the reference's ML-DSA delivery.update signature is demonstrated here with a real Ed25519
 * (RFC 8032) round-trip (signUpdate / verifyUpdate), exercised in isolation, NOT corpus-graded.
 *
 * CONCURRENCY SCOPE: PHP CLI is single-threaded (no pthreads), so the reference's two concurrent pump
 * threads are expressed here as a SYNCHRONOUS full-duplex relay — an object submitted to one endpoint
 * is immediately available at the peer's, in both directions. This demonstrates the §9.3 routing
 * (both directions, content-free in transit); it does not reproduce OS-thread scheduling.
 */

declare(strict_types=1);

namespace Naalp;

/**
 * A named, fail-closed delivery error; $kind is a stable string mirroring the Go/Rust/Python/Ruby
 * error kinds (StageOutOfOrder, Malformed).
 */
class DeliveryError extends \RuntimeException
{
    public string $kind;

    public function __construct(string $kind, string $msg = "")
    {
        $this->kind = $kind;
        parent::__construct($msg === "" ? $kind : "$kind: $msg");
    }
}

/**
 * One signed delivery-stage notification (§9.1): `obj` is the content id of the object whose delivery
 * this reports; `stage` is the stage reached (0..3); `at` is observer time, epoch ms.
 */
final class DeliveryUpdate
{
    public string $obj;
    public int $stage;
    public int $at;

    public function __construct(string $obj, int $stage, int $at)
    {
        $this->obj = $obj;
        $this->stage = $stage;
        $this->at = $at;
    }

    /** Deterministic-CBOR encoding {1: obj, 2: stage, 3: at}. */
    public function bytes(): string
    {
        return Cbor::encode(new M([
            [new U(1), new B($this->obj)],
            [new U(2), new U($this->stage)],
            [new U(3), new U($this->at)],
        ]));
    }
}

/**
 * A durable, per-object delivery-stage tracker enforcing monotonic stages and persist-before-ack. Each
 * advance persists to the write-ahead log and fsyncs before returning the acknowledging update, so a
 * crash after the ack loses nothing (§9.2). WAL records are length-prefixed (4-byte big-endian)
 * deterministic-CBOR update bodies.
 */
final class Tracker
{
    /** @var resource */
    private $f;
    /** @var array<string,int> object-id (hex) -> highest stage reached */
    private array $current = [];

    /** @param resource $f an opened, seekable read+write binary stream */
    public function __construct($f)
    {
        $this->f = $f;
        $this->replay();
    }

    private function replay(): void
    {
        \fseek($this->f, 0);
        while (true) {
            $lenBuf = \fread($this->f, 4);
            if ($lenBuf === "" || $lenBuf === false) {
                break;
            }
            if (\strlen($lenBuf) !== 4) {
                throw new DeliveryError("Malformed", "truncated WAL length prefix");
            }
            $n = \unpack('N', $lenBuf)[1];
            $rec = \fread($this->f, $n);
            if ($rec === false || \strlen($rec) !== $n) {
                throw new DeliveryError("Malformed", "truncated WAL record");
            }
            $u = Delivery::parseUpdate($rec);
            $this->current[\bin2hex($u->obj)] = $u->stage; // last durable stage wins (monotonic on write)
        }
    }

    /**
     * Record that obj reached stage at time at, returning the acknowledging update. A stage earlier
     * than the one already reached is StageOutOfOrder (no state change); re-reporting the current stage
     * is an idempotent no-op; a later stage is persisted (WAL fsync) before the update is returned.
     * Skipping ahead is permitted; only regression is an error.
     */
    public function advance(string $obj, int $stage, int $at): DeliveryUpdate
    {
        $key = \bin2hex($obj);
        if (\array_key_exists($key, $this->current)) {
            $cur = $this->current[$key];
            if ($stage < $cur) {
                throw new DeliveryError("StageOutOfOrder", "a delivery stage regressed to an earlier stage");
            }
            if ($stage === $cur) {
                return new DeliveryUpdate($obj, $stage, $at);
            }
        }
        $u = new DeliveryUpdate($obj, $stage, $at);
        $rec = $u->bytes();
        \fwrite($this->f, \pack('N', \strlen($rec)) . $rec);
        \fflush($this->f);
        \fsync($this->f); // persist-before-ack (R-9.2)
        $this->current[$key] = $stage;
        return $u;
    }

    /**
     * The highest stage reached for obj and whether it has been seen.
     *
     * @return array{0:int,1:bool}
     */
    public function stage(string $obj): array
    {
        $key = \bin2hex($obj);
        return \array_key_exists($key, $this->current) ? [$this->current[$key], true] : [0, false];
    }

    /** Flush and close the WAL file. */
    public function close(): void
    {
        \fclose($this->f);
    }
}

/**
 * One side of a switchboard connection: objects written to send are relayed to the peer's recv. On the
 * single-threaded PHP port the relay is synchronous — send deposits directly into the peer's recv
 * queue, so the object is immediately available at the peer.
 */
final class Endpoint
{
    /** @var \SplQueue toward the peer's recv */
    private \SplQueue $out;
    /** @var \SplQueue from the peer's send */
    private \SplQueue $in;

    public function __construct(\SplQueue $out, \SplQueue $in)
    {
        $this->out = $out;
        $this->in = $in;
    }

    /** Submit an object into the switchboard toward the peer. */
    public function send(string $obj): void
    {
        $this->out->enqueue($obj);
    }

    /** Receive the next object relayed from the peer, or null if none is waiting. */
    public function recv(): ?string
    {
        return $this->in->isEmpty() ? null : $this->in->dequeue();
    }
}

/**
 * Holds two connections open and relays objects through in both directions (design §9.3) — a
 * full-duplex relay, not a one-object mailbox. On the single-threaded PHP port the two directions are
 * two independent queues forwarded synchronously (see the CONCURRENCY SCOPE note); a forwarded object
 * is retained nowhere (content-free in transit).
 */
final class Switchboard
{
    private Endpoint $left;
    private Endpoint $right;

    /** @param int $capacity kept for interface parity with the threaded reference; unused synchronously. */
    public function __construct(int $capacity = 0)
    {
        $lr = new \SplQueue(); // left -> right
        $rl = new \SplQueue(); // right -> left
        $this->left = new Endpoint($lr, $rl);
        $this->right = new Endpoint($rl, $lr);
    }

    public function left(): Endpoint
    {
        return $this->left;
    }

    public function right(): Endpoint
    {
        return $this->right;
    }

    /** No pumps to stop on the synchronous port; present for interface parity. */
    public function close(): void
    {
    }
}

/**
 * Routes objects while retaining no payload at rest: for each routed object it appends a C7 audit
 * receipt over the object's content id and returns the object for immediate forwarding, keeping only
 * the receipt chain (content ids), never the payload (§9.4, R-9.4). The retained audit trail alone
 * verifies as a valid chain. PURE-ONLY PHP: the receipts are Ed25519-signed by the shared Authority.
 */
final class ContentFreeRelay
{
    private Authority $auth;
    /** @var array<int,Receipt> */
    private array $receipts = [];
    /** @var array<int,string> */
    private array $sigs = [];

    public function __construct(string $seed)
    {
        $this->auth = new Authority($seed);
    }

    /**
     * Record an audit receipt over obj's content id and return obj for forwarding. The relay keeps the
     * receipt only; it does not store obj.
     */
    public function route(string $obj, int $at): string
    {
        [$rec, $sig] = $this->auth->append(Delivery::contentId($obj), $at);
        $this->receipts[] = $rec;
        $this->sigs[] = $sig;
        return $obj;
    }

    /**
     * The receipts and signatures the relay retained (its only persistent state), for offline chain
     * verification.
     *
     * @return array{0:array<int,Receipt>,1:array<int,string>}
     */
    public function auditTrail(): array
    {
        return [$this->receipts, $this->sigs];
    }
}

final class Delivery
{
    // Delivery stages (§9.1), monotonic in this order.
    public const STAGE_PERSISTED_ORIGIN = 0;
    public const STAGE_ACCEPTED_RELAY = 1;
    public const STAGE_PERSISTED_TARGET = 2;
    public const STAGE_PRESENTED = 3;

    private const STAGE_NAMES = ["persisted_origin", "accepted_relay", "persisted_target", "presented"];

    /** The name of a stage value (0..3), or "unknown". */
    public static function stageName(int $stage): string
    {
        return ($stage >= 0 && $stage < \count(self::STAGE_NAMES)) ? self::STAGE_NAMES[$stage] : "unknown";
    }

    /**
     * The T1 content-id framing multihash(0x20 sha2-384, 0x30 len-48) || SHA-384(bytes) (§2.3),
     * identical to the spine framing (Naalp\Cbor::contentId over raw bytes).
     */
    public static function contentId(string $b): string
    {
        return Cbor::contentId($b);
    }

    /**
     * Sign a delivery.update with the observer's key. PURE-ONLY PHP: a real Ed25519 (RFC 8032)
     * signature over the update body, standing in for the reference's ML-DSA signature.
     */
    public static function signUpdate(DeliveryUpdate $update, string $seed): string
    {
        return Cose::ed25519Sign($seed, $update->bytes());
    }

    /** Verify a raw Ed25519 delivery.update signature under the observer's public key. */
    public static function verifyUpdate(DeliveryUpdate $update, string $pubkey, string $sig): bool
    {
        return Cose::ed25519Verify($pubkey, $update->bytes(), $sig);
    }

    /**
     * Reconstruct a DeliveryUpdate from a record body; fail-closed (Malformed) on a non-canonical
     * encoding, a non-map, a non-uint key, a mistyped/unknown field, or a missing mandatory field.
     */
    public static function parseUpdate(string $rec): DeliveryUpdate
    {
        try {
            $v = Cbor::decode($rec);
        } catch (NonCanonical $e) {
            throw new DeliveryError("Malformed", "delivery update is not canonical");
        }
        if (!($v instanceof M)) {
            throw new DeliveryError("Malformed", "delivery update is not a map");
        }
        $obj = null;
        $stage = null;
        $at = null;
        foreach ($v->pairs as $pair) {
            [$k, $val] = $pair;
            if (!($k instanceof U)) {
                throw new DeliveryError("Malformed", "non-uint key");
            }
            if ($k->v === 1 && $val instanceof B) {
                $obj = $val->v;
            } elseif ($k->v === 2 && $val instanceof U) {
                $stage = $val->v;
            } elseif ($k->v === 3 && $val instanceof U) {
                $at = $val->v;
            } else {
                throw new DeliveryError("Malformed", "unknown or mistyped delivery-update field {$k->v}");
            }
        }
        if ($obj === null || $stage === null || $at === null) {
            throw new DeliveryError("Malformed", "delivery update missing a mandatory field");
        }
        return new DeliveryUpdate($obj, $stage, $at);
    }

    /**
     * Open (creating if needed) a WAL-backed tracker and replay it to recover the last durable stage
     * for every object.
     */
    public static function openTracker(string $path): Tracker
    {
        $f = \is_file($path) ? \fopen($path, 'r+b') : \fopen($path, 'w+b');
        if ($f === false) {
            throw new DeliveryError("Malformed", "cannot open WAL at $path");
        }
        return new Tracker($f);
    }
}
