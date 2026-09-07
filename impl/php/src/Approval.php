<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
/**
 * N-AALP C6 approval object + durable single-use consume ledger for the PHP SDK (design.md §7;
 * requirements R-7.1..7.4).
 *
 * An ApprovalRecord binds, under signature, the content id of the exact canonical argument object it
 * approves (§7.1); because the args are named by content id, mutating any argument changes the id and
 * the approval no longer matches (ApprovalMismatch). The consume ledger is a durable compare-and-set
 * set keyed by approval content id: the FIRST consumer of an id wins and every later consume of the
 * same id is rejected AlreadyConsumed (§7.2). Atomicity is honest, not decorative — the membership
 * check AND the append run in ONE path. PHP CLI is single-threaded (no OS-thread race to model), so
 * the single-writer discipline is structural: there is no read-then-write TOCTOU window because
 * nothing else runs between the check and the append, and a repeated consume of an already-consumed
 * id is rejected fail-closed with no ledger append. Each winning consume is written and fsynced to a
 * write-ahead log before it returns (persist-before-ack), so the spend survives process exit. A held
 * outcome is a distinct signed non-success result (HeldResult, §7.4). Every rejection is fail-closed
 * and causes no ledger append. An approval consumable twice is a replay skeleton key — this module
 * exists to make that impossible.
 *
 * An independent transcription of impl/go/approval (cross-read against impl/python/naalp/approval.py),
 * graded against the shared vectors/approval/cases.json. The approval body and the consume-ledger
 * chain (genesis, entry bytes, head_after, final head) are signature-independent and pure.
 *
 * CRYPTO SCOPE (PURE-ONLY): PHP has no deterministic ML-DSA (FIPS 204) signer, so the approval and
 * held-result signatures the reference makes with ML-DSA are demonstrated here with a real Ed25519
 * (RFC 8032) signature via ext-sodium — the signature gate (VerifyApproval) takes an injected verify
 * closure. The corpus-graded surfaces (approval body/head/content-id, the consume-ledger hash chain,
 * the AlreadyConsumed single-use verdict) are all signature-independent and pure.
 *
 * NOT PORTED (out of scope, honest status F2/F4): the T1.5 §7.5 ledger-signed ConsumeReceipt /
 * ConsumeFork / ReceiptSet double-spend-evidence surface (approval.go §7.5). It is graded by a
 * SEPARATE corpus, vectors/consume_receipt/cases.json — not this port's grade target — and is tracked
 * as its own deliverable, exactly as the Python port defers it. The single-use replay guarantee this
 * port DOES cover (AlreadyConsumed) is the core §7.2 property.
 */

declare(strict_types=1);

namespace Naalp;

// Named, fail-closed errors; $kind is a stable string mirroring the Go/Rust/Python error kinds.
// BadSignature is reused from Gateway.php (kind "BadSignature") — the same kind the reference's
// cose.ErrBadSignature carries.
class ApprovalMismatch extends \RuntimeException
{
    public string $kind = "ApprovalMismatch";
}
class ApprovalExpired extends \RuntimeException
{
    public string $kind = "ApprovalExpired";
}
class AlreadyConsumed extends \RuntimeException
{
    public string $kind = "AlreadyConsumed";
}
class ApprovalRequired extends \RuntimeException
{
    public string $kind = "ApprovalRequired";
}
class LedgerCorrupt extends \RuntimeException
{
    public string $kind = "LedgerCorrupt";
}
class LedgerUnsigned extends \RuntimeException
{
    public string $kind = "LedgerUnsigned";
}
// T1.5 (NAALP-REQ-121) — the ledger-signed consume receipt with forward-only position.
class ConsumeReceiptUnsigned extends \RuntimeException
{
    public string $kind = "ConsumeReceiptUnsigned";
}
class ConsumeForkInvalid extends \RuntimeException
{
    public string $kind = "ConsumeForkInvalid";
}
// R-TDCS-4 (design.md §25, C22) — the ordering authority that stamps freshness must be structurally
// distinct from the party being authenticated.
class FreshnessSelfAsserted extends \RuntimeException
{
    public string $kind = "FreshnessSelfAsserted";
}
// R-TDCS-5 (design.md §25, C22) — an approval naming an audience is valid only in that context.
class AudienceMismatch extends \RuntimeException
{
    public string $kind = "AudienceMismatch";
}
// R-TDCS-3 (design.md §25, C22) — the party-visible coarse refusal object: a closed outcome vocabulary
// plus a reference (never the reason) to the full signed record.
class UnknownRefusalOutcome extends \RuntimeException
{
    public string $kind = "UnknownRefusalOutcome";
}
class RefusalDetailLeak extends \RuntimeException
{
    public string $kind = "RefusalDetailLeak";
}

/**
 * The body of an Approval object (§7.1). Signed over its deterministic-CBOR bytes. `approves` is the
 * content id of the exact canonical args object; a changed argument changes the id and the approval
 * no longer matches (ApprovalMismatch).
 */
final class ApprovalRecord
{
    public string $approves; // content id of the exact canonical args object (§7.1)
    public string $approver; // approver signer id
    public int $grant;       // granted effect class (0..3), the C5 effect
    public string $nonce;    // anti-replay nonce (§7.3)
    public int $notAfter;    // expiry, epoch ms (§7.3)
    public string $audience; // OPTIONAL valid-context (R-TDCS-5); "" == absent (field 6 omitted)

    public function __construct(string $approves, string $approver, int $grant, string $nonce, int $notAfter, string $audience = '')
    {
        $this->approves = $approves;
        $this->approver = $approver;
        $this->grant = $grant;
        $this->nonce = $nonce;
        $this->notAfter = $notAfter;
        $this->audience = $audience;
    }

    /**
     * Deterministic-CBOR encoding of the approval body {1..5, ?6:audience} (R-TDCS-5). Field 6 is
     * OMITTED when audience is "" — an empty string is not a distinct value, so an approval naming no
     * audience encodes byte-identically to the 5-field body (Records::approvalBody), additive by
     * design. Field 6 present encodes to distinct bytes, so a verdict cannot be silently moved to
     * another context.
     */
    public function bytes(): string
    {
        if ($this->audience === '') {
            return Records::approvalBody($this->approves, $this->approver, $this->grant, $this->nonce, $this->notAfter);
        }
        return Cbor::encode(new M([
            [new U(1), new B($this->approves)],
            [new U(2), new T($this->approver)],
            [new U(3), new U($this->grant)],
            [new U(4), new B($this->nonce)],
            [new U(5), new U($this->notAfter)],
            [new U(6), new T($this->audience)],
        ]));
    }

    /** The approval content id (the ledger key): multihash(0x20, SHA-384(body)) (50 octets). */
    public function id(): string
    {
        return Cbor::contentId($this->bytes());
    }
}

/**
 * The distinct, signed, non-success result returned when an action requires an approval that has not
 * been granted (§7.4). It is never a silent success or a silent denial.
 */
final class HeldResult
{
    public string $approves; // content id of the args whose approval is pending
    public string $reason;

    public function __construct(string $approves, string $reason)
    {
        $this->approves = $approves;
        $this->reason = $reason;
    }

    /** Deterministic-CBOR encoding {1: approves, 2: reason}. */
    public function bytes(): string
    {
        return Cbor::encode(new M([
            [new U(1), new B($this->approves)],
            [new U(2), new T($this->reason)],
        ]));
    }
}

/**
 * T1.5 (NAALP-REQ-121) — the draft-01 ledger-signed evidence that a consuming ledger (the ORDERING
 * AUTHORITY) bound an approval content id to its own forward-only position. The anti-double-spend
 * counter (position) rides under the LEDGER's signature, never the requester's: the requester cannot
 * forge the ledger's position or its signature. A partition that spends one approval twice therefore
 * leaves two ledger-signed receipts against one approval id, each carrying a position drawn from
 * forked state — a contradiction authored by neither the requester nor a thief, provable the instant
 * the two receipts are compared (see ConsumeForkEvidence). It does not PREVENT the second spend; it
 * makes the double-spend detectable in bytes neither party could repudiate.
 */
final class ConsumeReceipt
{
    public string $ledger;     // the consuming ledger's signer id (the ordering authority; REQ-121)
    public string $approvalId; // the approval content id consumed (the compare-and-set key)
    public int $position;      // the ledger's forward-only position bound to this consume (uint64)

    public function __construct(string $ledger, string $approvalId, int $position)
    {
        $this->ledger = $ledger;
        $this->approvalId = $approvalId;
        $this->position = $position;
    }

    /** Deterministic-CBOR encoding of the receipt body {1: ledger, 2: approval_id, 3: position} — the
     * exact bytes the ledger signs (T1.5). */
    public function bytes(): string
    {
        return Cbor::encode(new M([
            [new U(1), new B($this->ledger)],
            [new U(2), new B($this->approvalId)],
            [new U(3), new U($this->position)],
        ]));
    }
}

/**
 * R-TDCS-3 (design.md §25, C22) — the party-visible coarse refusal object. A refusal returned to the
 * authenticated party carries ONLY a single value from a closed vocabulary and the content id of the
 * full signed record that carries the discriminating detail — a reference, not the reason. The detail
 * exists, is signed, and is auditor-resolvable through the record channel, but never reaches the
 * adversary-facing surface, so repeated refusals cannot serve an adaptive party as an oracle.
 */
final class Refusal
{
    public const OUTCOME_DENIED = 0;       // the action is refused
    public const OUTCOME_HELD = 1;         // the action requires a further step not yet taken
    public const OUTCOME_UNVERIFIABLE = 2; // required evidence did not verify

    public int $outcome;   // denied / held / unverifiable (closed set)
    public string $record; // content id of the full signed record carrying the discriminating detail

    public function __construct(int $outcome, string $record)
    {
        $this->outcome = $outcome;
        $this->record = $record;
    }

    /** Deterministic-CBOR encoding {1: outcome, 2: record}. */
    public function bytes(): string
    {
        return Cbor::encode(new M([
            [new U(1), new U($this->outcome)],
            [new U(2), new B($this->record)],
        ]));
    }
}

/**
 * T1.5 (NAALP-REQ-121) — non-repudiable evidence that ONE approval content id received TWO
 * conflicting ledger-signed consume receipts, a double spend made provable on comparison. It carries
 * both receipts and both ledger signatures; because a verifier checks each signature under the key its
 * receipt names, the contradiction is authored by neither the requester nor a thief.
 */
final class ConsumeForkEvidence
{
    public string $approvalId;   // the one approval content id spent twice
    public ConsumeReceipt $a;    // first receipt
    public string $sigA;         // ledger A's signature over a->bytes()
    public ConsumeReceipt $b;    // second receipt (same approval id; different position and/or ledger)
    public string $sigB;         // ledger B's signature over b->bytes()

    public function __construct(string $approvalId, ConsumeReceipt $a, string $sigA, ConsumeReceipt $b, string $sigB)
    {
        $this->approvalId = $approvalId;
        $this->a = $a;
        $this->sigA = $sigA;
        $this->b = $b;
        $this->sigB = $sigB;
    }

    /**
     * Checks this is a genuine fork: (1) the disputed approval id is present and BOTH receipts name it;
     * (2) the two receipts actually conflict — they are NOT byte-identical (a byte-identical
     * re-emission is a benign duplicate, not a fork); and (3) BOTH ledger signatures verify under the
     * keys their receipts name, resolved through $resolve. Any failure rejects the whole thing
     * (fail-closed): a mismatched/absent approval id or a byte-identical pair is ConsumeForkInvalid, and
     * an unnamed/unresolvable ledger or a signature that does not verify is ConsumeReceiptUnsigned. On a
     * clean pass the double spend is proven and non-repudiable.
     *
     * @param callable(string):?callable $resolve ledgerId(raw) -> verify closure fn(msg,sig):bool, or
     *                                             null if the ledger id is unresolvable
     */
    public function verify(callable $resolve): void
    {
        if ($this->approvalId === '') {
            throw new ConsumeForkInvalid("no disputed approval id");
        }
        if ($this->a->approvalId !== $this->approvalId || $this->b->approvalId !== $this->approvalId) {
            throw new ConsumeForkInvalid("both receipts must name the one disputed approval id");
        }
        if ($this->a->bytes() === $this->b->bytes()) {
            throw new ConsumeForkInvalid("byte-identical receipts are a benign duplicate, not a fork");
        }
        $va = $this->a->ledger !== '' ? $resolve($this->a->ledger) : null;
        if ($va === null) {
            throw new ConsumeReceiptUnsigned("receipt A names no resolvable ledger");
        }
        $vb = $this->b->ledger !== '' ? $resolve($this->b->ledger) : null;
        if ($vb === null) {
            throw new ConsumeReceiptUnsigned("receipt B names no resolvable ledger");
        }
        if (!$va($this->a->bytes(), $this->sigA) || !$vb($this->b->bytes(), $this->sigB)) {
            throw new ConsumeReceiptUnsigned("a ledger signature does not verify");
        }
    }
}

/**
 * T1.5 (NAALP-REQ-121) — observes ledger-signed consume receipts, keyed by approval content id, and
 * detects a fork (a double spend) from the signed receipts alone; the consume-layer analogue of the
 * audit Auditor's equivocation detection (Naalp\Auditor). It resolves each receipt's ledger verifier
 * through the injected resolver, rejects any receipt whose ledger signature does not verify, and on a
 * conflicting second receipt for one approval id mints a non-repudiable ConsumeForkEvidence.
 */
final class ReceiptSet
{
    /** @var callable(string):?callable */
    private $resolve;
    /** @var array<string,array{0:ConsumeReceipt,1:string}> approval-id(raw) -> [first receipt, sig] */
    private array $seen = [];

    /** @param callable(string):?callable $resolve ledgerId(raw) -> verify closure fn(msg,sig):bool, or
     *                                              null if the ledger id is unresolvable (NewReceiptSet). */
    public function __construct(callable $resolve)
    {
        $this->resolve = $resolve;
    }

    /**
     * Records a ledger-signed consume receipt. Throws ConsumeReceiptUnsigned if the ledger is
     * unnamed/unresolvable or the signature does not verify. Returns a ConsumeForkEvidence when a
     * previously-seen receipt for the same approval id conflicts (different position and/or ledger);
     * returns null otherwise (including a benign byte-identical duplicate).
     */
    public function observe(ConsumeReceipt $r, string $sig): ?ConsumeForkEvidence
    {
        $v = $r->ledger !== '' ? ($this->resolve)($r->ledger) : null;
        if ($v === null || !$v($r->bytes(), $sig)) {
            throw new ConsumeReceiptUnsigned("ledger-signed receipt does not verify");
        }
        $key = $r->approvalId;
        if (\array_key_exists($key, $this->seen)) {
            [$prevR, $prevSig] = $this->seen[$key];
            if ($prevR->bytes() === $r->bytes()) {
                return null; // benign byte-identical duplicate
            }
            return new ConsumeForkEvidence($r->approvalId, $prevR, $prevSig, $r, $sig);
        }
        $this->seen[$key] = [$r, $sig];
        return null;
    }
}

/** One append to the consume ledger (§7.2). */
final class LedgerEntry
{
    public int $seq;           // ledger sequence position
    public string $prev;       // prior chain head (Approval::HEAD_SIZE bytes; genesis is all-zero)
    public string $approvalId; // the approval content id being consumed
    public string $by;         // consumer signer id

    public function __construct(int $seq, string $prev, string $approvalId, string $by)
    {
        $this->seq = $seq;
        $this->prev = $prev;
        $this->approvalId = $approvalId;
        $this->by = $by;
    }

    /**
     * Deterministic-CBOR encoding {1: seq, 2: prev, 3: approval-id, 4: by} (reuses the spine records
     * builder). The head after this entry is SHA-384(bytes()); because bytes() carries prev, editing
     * any entry breaks the next entry's linkage.
     */
    public function bytes(): string
    {
        return Records::ledgerEntry($this->seq, $this->prev, $this->approvalId, $this->by);
    }

    /** This entry's chain head — the prev of the next entry (48 octets). */
    public function head(): string
    {
        return \hash('sha384', $this->bytes(), true);
    }
}

/**
 * The durable, hash-chained, single-use consume set (§7.2). All state mutation goes through consume()
 * in a single path (the single-writer discipline — PHP CLI is single-threaded, so nothing runs
 * between the membership check and the append), and each winning consume is written and fsynced to
 * the WAL before it returns. Use Approval::openLedger() to construct one.
 */
final class Ledger
{
    /** @var resource the WAL file handle */
    private $f;
    /** @var array<string,int> approval-id bytes (as a raw-string key) -> seq */
    private array $consumed = [];
    private string $head;
    private int $seq = 0;
    /** consuming-authority NAME (§2.5.3 audience target); also, when $signerSeed is set, the T1.5
     * REQ-121 ordering-authority id embedded/signed in a ConsumeReceipt (the same identity serves
     * both purposes, exactly as impl/go/approval's Ledger.ledgerID). */
    private string $ledgerId = '';
    /** T1.5 (NAALP-REQ-121): the ledger's own ed25519 signing key (32-byte seed) for ledger-signed
     * consume receipts. Empty ("") means the ledger was opened WITHOUT a signing key (Approval::openLedger)
     * — ConsumeWithReceipt then refuses fail-closed (LedgerUnsigned). Set only by Approval::openLedgerSigned. */
    private string $signerSeed = '';

    /** @param resource $f */
    public function __construct($f, string $authority = '', string $signerSeed = '')
    {
        $this->f = $f;
        $this->head = \str_repeat("\x00", Approval::HEAD_SIZE);
        $this->ledgerId = $authority;
        $this->signerSeed = $signerSeed;
    }

    /**
     * Read the WAL from the start, rebuilding state and verifying the chain. Each record is
     * length-prefixed (uint32 big-endian) so the log is self-framing. An out-of-order seq or a broken
     * prev linkage is refused LedgerCorrupt rather than trusted.
     */
    public function replay(): void
    {
        \fseek($this->f, 0, \SEEK_SET);
        $head = \str_repeat("\x00", Approval::HEAD_SIZE);
        $seq = 0;
        while (true) {
            $lb = \fread($this->f, 4);
            if ($lb === "" || $lb === false) {
                break; // clean EOF
            }
            if (\strlen($lb) !== 4) {
                throw new LedgerCorrupt("truncated length prefix");
            }
            $n = \unpack("N", $lb)[1];
            $rec = $n === 0 ? "" : \fread($this->f, $n);
            if (\strlen($rec) !== $n) {
                throw new LedgerCorrupt("truncated record");
            }
            $e = self::parseEntry($rec);
            if ($e->seq !== $seq || $e->prev !== $head) {
                throw new LedgerCorrupt("out-of-order seq or broken chain linkage");
            }
            $this->consumed[$e->approvalId] = $e->seq;
            $head = \hash('sha384', $rec, true);
            $seq += 1;
        }
        $this->head = $head;
        $this->seq = $seq;
    }

    /**
     * Atomically consume an approval id exactly once (§7.2). The first caller for a given id appends a
     * ledger entry (written and fsynced before returning) and returns it; every later caller for the
     * same id throws AlreadyConsumed with NO append. The check-then-append is one path with nothing
     * running between the two steps (single-writer), so a repeated consume can never win a second
     * time — the single-use replay guarantee.
     */
    public function consume(string $approvalId, string $by): LedgerEntry
    {
        if (\array_key_exists($approvalId, $this->consumed)) {
            throw new AlreadyConsumed("approval already consumed");
        }
        $e = new LedgerEntry($this->seq, $this->head, $approvalId, $by);
        $rec = $e->bytes();
        $framed = \pack("N", \strlen($rec)) . $rec;
        \fseek($this->f, 0, \SEEK_END);
        if (\fwrite($this->f, $framed) !== \strlen($framed)) {
            throw new LedgerCorrupt("short write to the consume WAL"); // nothing recorded: the consume did not happen
        }
        \fflush($this->f);
        \fsync($this->f); // persist-before-ack (R-7.2 durability)
        $this->consumed[$approvalId] = $e->seq;
        $this->head = $e->head();
        $this->seq += 1;
        return $e;
    }

    /**
     * Consume the approval for a consume-once OBJECT, enforcing the §2.5.3 audience binding at the
     * choke point BEFORE the compare-and-set: the object's audience MUST name this ledger's consuming
     * authority, or the object is rejected WrongAudience with no ledger append. An unnamed ledger (no
     * authority) refuses LedgerUnsigned — it cannot be the audience of any object. The audience check
     * is NEVER inside Envelope::verify (a relay/auditor legitimately verifies objects addressed to
     * others). Mirrors Go/Rust Ledger.ConsumeObject — the authority is this port's ledger NAME.
     */
    public function consumeObject(NaalpObject $o, string $approvalId, string $by): LedgerEntry
    {
        if ($this->ledgerId === '') {
            throw new LedgerUnsigned("ledger has no consuming authority");
        }
        // fail-closed, before the CAS: throws EnvelopeError("WrongAudience") and appends nothing
        Envelope::checkAudience($o, $this->ledgerId, true);
        return $this->consume($approvalId, $by);
    }

    /**
     * T1.5 (NAALP-REQ-121) — performs the first-append-wins compare-and-set (exactly as consume()) AND,
     * on the winning append, returns a ledger-signed ConsumeReceipt binding the approval id to the
     * entry's forward-only position (its ledger seq). Requires a SIGNED ledger (opened via
     * Approval::openLedgerSigned); a plain ledger throws LedgerUnsigned. A second consume of the same
     * approval id throws AlreadyConsumed and signs nothing — the first receipt stands
     * (first-append-wins). The receipt is signed BEFORE the WAL write, so a signing failure records
     * nothing.
     *
     * @return array{0:LedgerEntry,1:ConsumeReceipt,2:string} [entry, receipt, signature]
     */
    public function consumeWithReceipt(string $approvalId, string $by): array
    {
        if ($this->signerSeed === '' || $this->ledgerId === '') {
            throw new LedgerUnsigned("ledger was not opened with a signing key");
        }
        if (\array_key_exists($approvalId, $this->consumed)) {
            throw new AlreadyConsumed("approval already consumed"); // first-append-wins: no second receipt
        }
        $e = new LedgerEntry($this->seq, $this->head, $approvalId, $by);
        // The receipt binds the approval id to THIS consume's forward-only position (the entry seq),
        // signed by the ledger key. Sign before touching the WAL so a signing failure records nothing.
        $receipt = new ConsumeReceipt($this->ledgerId, $approvalId, $e->seq);
        $sig = Cose::ed25519Sign($this->signerSeed, $receipt->bytes());
        $rec = $e->bytes();
        $framed = \pack("N", \strlen($rec)) . $rec;
        \fseek($this->f, 0, \SEEK_END);
        if (\fwrite($this->f, $framed) !== \strlen($framed)) {
            throw new LedgerCorrupt("short write to the consume WAL"); // nothing recorded: the consume did not happen
        }
        \fflush($this->f);
        \fsync($this->f); // persist-before-ack (R-7.2 durability)
        $this->consumed[$approvalId] = $e->seq;
        $this->head = $e->head();
        $this->seq += 1;
        return [$e, $receipt, $sig];
    }

    /** Whether an approval id has been consumed. */
    public function isConsumed(string $approvalId): bool
    {
        return \array_key_exists($approvalId, $this->consumed);
    }

    /** The current chain head. */
    public function head(): string
    {
        return $this->head;
    }

    /** The number of consumed approvals. */
    public function len(): int
    {
        return \count($this->consumed);
    }

    /** Flush and close the WAL file. */
    public function close(): void
    {
        if (\is_resource($this->f)) {
            \fclose($this->f);
        }
    }

    /**
     * Decode a ledger entry from its deterministic-CBOR bytes. A malformed shape, a non-uint key, a
     * mistyped field, an unknown field, or a missing field is a corrupt log (LedgerCorrupt); a
     * non-canonical body is caught by the strict decoder and surfaced the same way.
     */
    private static function parseEntry(string $rec): LedgerEntry
    {
        try {
            $v = Cbor::decode($rec);
        } catch (\Throwable $e) {
            throw new LedgerCorrupt("ledger entry is not canonical CBOR");
        }
        if (!($v instanceof M)) {
            throw new LedgerCorrupt("ledger entry is not a map");
        }
        $seq = $prev = $aid = $by = null;
        foreach ($v->pairs as [$k, $val]) {
            if (!($k instanceof U)) {
                throw new LedgerCorrupt("non-uint ledger entry key");
            }
            if ($k->v === 1 && $val instanceof U) {
                $seq = $val->v;
            } elseif ($k->v === 2 && $val instanceof B) {
                $prev = $val->v;
            } elseif ($k->v === 3 && $val instanceof B) {
                $aid = $val->v;
            } elseif ($k->v === 4 && $val instanceof T) {
                $by = $val->v;
            } else {
                throw new LedgerCorrupt("unknown or mistyped ledger entry field " . $k->v);
            }
        }
        if ($seq === null || $prev === null || $aid === null || $by === null) {
            throw new LedgerCorrupt("ledger entry missing a mandatory field");
        }
        return new LedgerEntry($seq, $prev, $aid, $by);
    }
}

final class Approval
{
    /** The width of a chain head / prev link (SHA-384 = 48 bytes); genesis is all-zero. */
    public const HEAD_SIZE = 48;

    /**
     * Open (creating if needed) a WAL-backed consume ledger at $path and replay any existing log to
     * rebuild the consumed set and chain head. A log that does not hash-chain cleanly is refused
     * (LedgerCorrupt) rather than trusted. Opens in "c+b" mode (read/write, create, no truncate).
     */
    public static function openLedger(string $path, string $authority = ''): Ledger
    {
        $f = \fopen($path, "c+b");
        if ($f === false) {
            throw new LedgerCorrupt("cannot open consume WAL at " . $path);
        }
        $l = new Ledger($f, $authority);
        try {
            $l->replay();
        } catch (\Throwable $e) {
            $l->close();
            throw $e;
        }
        return $l;
    }

    /**
     * T1.5 (NAALP-REQ-121) — open a WAL-backed ledger (as openLedger) and bind it to its own
     * ordering-authority identity ($ledgerId, the signer-id form of the ledger key) and signing key
     * ($signerSeed, a 32-byte ed25519 seed), so it can produce ledger-signed consume receipts
     * (design.md §7.5). An empty $ledgerId or an empty $signerSeed is refused fail-closed
     * (LedgerUnsigned): an unnamed or keyless ordering authority cannot sign the anti-double-spend
     * position, so ConsumeWithReceipt would have nothing accountable to emit.
     */
    public static function openLedgerSigned(string $path, string $ledgerId, string $signerSeed): Ledger
    {
        if ($ledgerId === '' || $signerSeed === '') {
            throw new LedgerUnsigned("ledger was not opened with a signing key");
        }
        $f = \fopen($path, "c+b");
        if ($f === false) {
            throw new LedgerCorrupt("cannot open consume WAL at " . $path);
        }
        $l = new Ledger($f, $ledgerId, $signerSeed);
        try {
            $l->replay();
        } catch (\Throwable $e) {
            $l->close();
            throw $e;
        }
        return $l;
    }

    /**
     * Sign the approval body with a real deterministic Ed25519 key derived from a 32-byte seed (the
     * pure-tier stand-in for the reference's ML-DSA signer). The signed input is the approval body
     * bytes DIRECTLY.
     */
    public static function signApproval(ApprovalRecord $a, string $seed): string
    {
        return Cose::ed25519Sign($seed, $a->bytes());
    }

    /**
     * R-TDCS-5 (design.md §25, C22) — enforces the OPTIONAL audience binding. An approval that NAMES an
     * audience ($a->audience !== '') is valid only in that context: a relying party checks it at use and
     * rejects AudienceMismatch on a mismatch. An approval that names NO audience is unrestricted by the
     * issuer's explicit choice and passes for any use context. The check is mandatory WHEN a context is
     * present, never mandatory-presence (the JWT `aud` present-optional / check-mandatory shape).
     */
    public static function verifyAudience(ApprovalRecord $a, string $useContext): void
    {
        if ($a->audience !== '' && $a->audience !== $useContext) {
            throw new AudienceMismatch("approval names an audience other than the use context");
        }
    }

    /** T1.5 (NAALP-REQ-121) — sign a consume receipt with the LEDGER's key (the anti-double-spend
     * counter is under the ordering authority's signature). The signed input is receipt->bytes(). */
    public static function signConsumeReceipt(ConsumeReceipt $r, string $ledgerSeed): string
    {
        return Cose::ed25519Sign($ledgerSeed, $r->bytes());
    }

    /**
     * T1.5 (NAALP-REQ-121) — checks that a consume receipt is a valid ledger-signed statement: the
     * ledger id is present (an unnamed ordering authority is not evidence) and the signature verifies
     * under the ledger's key. Fail-closed: either fault throws ConsumeReceiptUnsigned and authorizes
     * nothing. $verify is `fn(string $msg, string $sig): bool` — the injected signature verifier
     * (Ed25519 on the pure PHP port), resolved for $r->ledger by the caller.
     */
    public static function verifyConsumeReceipt(ConsumeReceipt $r, callable $verify, string $sig): void
    {
        if ($r->ledger === '') {
            throw new ConsumeReceiptUnsigned("an unnamed ordering authority is not evidence");
        }
        if (!$verify($r->bytes(), $sig)) {
            throw new ConsumeReceiptUnsigned("ledger-signed receipt does not verify");
        }
    }

    /**
     * R-TDCS-4 (design.md §25, C22) — judges an approval's present-moment validity using time drawn
     * from an ordering authority STRUCTURALLY DISTINCT from the party being authenticated: (1) verifies
     * the approval binds $argsContentId, is signed by the approver, and is unexpired at $posTime; (2)
     * verifies the consume receipt is ledger-signed (the position rides under the ordering authority's
     * key, never the requester's); and (3) rejects FreshnessSelfAsserted when the ordering authority
     * $r->ledger IS the authenticated party $partyId. Fail-closed: any fault throws its named error and
     * authorizes nothing.
     */
    public static function verifyFreshIndependent(
        ApprovalRecord $a,
        callable $approverVerify,
        string $aSig,
        string $argsContentId,
        int $posTime,
        ConsumeReceipt $r,
        callable $ledgerVerify,
        string $rSig,
        string $partyId
    ): void {
        self::verifyApproval($a, $approverVerify, $aSig, $argsContentId, $posTime);
        self::verifyConsumeReceipt($r, $ledgerVerify, $rSig);
        if ($r->ledger === $partyId) {
            throw new FreshnessSelfAsserted("the ordering authority that stamps freshness is the authenticated party itself");
        }
    }

    /** R-TDCS-3 (design.md §25, C22) — reports whether code is in the closed refusal-outcome set
     * {denied, held, unverifiable}. */
    public static function isKnownRefusalOutcome(int $code): bool
    {
        return $code === Refusal::OUTCOME_DENIED || $code === Refusal::OUTCOME_HELD || $code === Refusal::OUTCOME_UNVERIFIABLE;
    }

    /**
     * R-TDCS-3 — builds the party-visible refusal for a full signed record: it carries the coarse
     * outcome and the content id of $fullRecord, and NOTHING drawn from inside $fullRecord — the
     * discriminating detail stays in the record, referenced only by its id.
     */
    public static function refusalFromRecord(int $outcome, string $fullRecord): Refusal
    {
        return new Refusal($outcome, Cbor::contentId($fullRecord));
    }

    /**
     * R-TDCS-3 — reconstructs a Refusal from its body bytes, enforcing that a party-visible refusal
     * carries ONLY {outcome, record} and nothing more. Rejects, fail-closed: a malformed body, any key
     * other than 1 and 2, a missing or empty record id (RefusalDetailLeak — discriminating detail
     * leaked, or the auditor reference dropped), and an outcome outside the closed set
     * (UnknownRefusalOutcome). Authorizes nothing.
     */
    public static function parseRefusal(string $b): Refusal
    {
        try {
            $v = Cbor::decode($b);
        } catch (\Throwable $e) {
            throw new RefusalDetailLeak("malformed refusal body");
        }
        if (!($v instanceof M)) {
            throw new RefusalDetailLeak("refusal body is not a map");
        }
        $outcome = null;
        $record = null;
        foreach ($v->pairs as [$k, $val]) {
            if (!($k instanceof U)) {
                throw new RefusalDetailLeak("non-uint refusal key");
            }
            if ($k->v === 1 && $val instanceof U) {
                $outcome = $val->v;
            } elseif ($k->v === 2 && $val instanceof B) {
                $record = $val->v;
            } else {
                throw new RefusalDetailLeak("refusal carries a field beyond {1,2} — leaked detail"); // any field beyond {1,2} is leaked detail
            }
        }
        if ($outcome === null || $record === null || $record === '') {
            throw new RefusalDetailLeak("refusal must carry the full-record content id"); // a refusal must carry the full-record content id
        }
        if (!self::isKnownRefusalOutcome($outcome)) {
            throw new UnknownRefusalOutcome("refusal outcome is outside the closed set denied/held/unverifiable");
        }
        return new Refusal($outcome, $record);
    }

    /**
     * Verify an approval: (1) signed by the approver's key over its body bytes, (2) binds the exact
     * args by content id, (3) not expired at $posTime. Returns nothing only if all three hold;
     * otherwise throws the specific named error and authorizes nothing. Check order is fail-closed:
     * BadSignature -> ApprovalMismatch -> ApprovalExpired. It does NOT consume — consumption is the
     * separate atomic ledger step (§7.2). `$verify` is `fn(string $msg, string $sig): bool` — the
     * injected signature verifier (Ed25519 on the pure PHP port).
     */
    public static function verifyApproval(ApprovalRecord $a, callable $verify, string $sig, string $argsContentId, int $posTime): void
    {
        if (!$verify($a->bytes(), $sig)) {
            throw new BadSignature("approval signature does not verify");
        }
        if ($a->approves !== $argsContentId) {
            throw new ApprovalMismatch("approval does not bind these arguments' content id");
        }
        if ($posTime > $a->notAfter) {
            throw new ApprovalExpired("approval is past its not_after");
        }
    }

    /** Sign a held result so the "not yet granted" outcome is itself attributable (Ed25519). */
    public static function signHeld(HeldResult $h, string $seed): string
    {
        return Cose::ed25519Sign($seed, $h->bytes());
    }

    /**
     * The composed, single-call consume choke point for the approval state machine (draft "## Approval
     * state machine"). It runs the table's precedence in ONE impl-owned place — the exact sequence that
     * payment/mcp/agui/delegation each hand-assemble — so a caller (and the conformance suite) drives one
     * realization of the reactions rather than re-deriving the ordering at each call site:
     *
     *  1. verifyApproval checks the signature, then the args-content-id binding (ApprovalMismatch, which
     *     the draft says "takes precedence over every cell"), then expiry (ApprovalExpired) — all BEFORE
     *     the ledger is consulted. So a request both past not_after AND already in the ledger is refused
     *     ApprovalExpired, never AlreadyConsumed (the draft's expiry-over-consume rule), and the ledger is
     *     left untouched by the rejected request.
     *  2. The granted effect must be a valid class (0..3) and must cover the action's required effect; a
     *     grant outside the closed vocabulary, or one below the required effect, authorizes nothing and is
     *     refused ApprovalRequired (fail-closed; the grant-range guard is stricter than the raw callers).
     *  3. The atomic single-use consume through the §7 ledger: the first consumer of the id wins, a
     *     second throws AlreadyConsumed, and neither a rejected earlier step nor a losing race appends.
     *
     * Every rejection is fail-closed and appends nothing; it consumes only when every check holds,
     * returning the ledger entry. It does NOT enforce object audience — that is Ledger::consumeObject's
     * binding (design.md §2.5.3); consumeApproval is the args-content-id/effect/single-use choke point.
     * $verify is fn(string $msg, string $sig): bool — the injected signature verifier (Ed25519 on the
     * pure PHP port), mirroring verifyApproval's own injected verifier.
     */
    public static function consumeApproval(
        ApprovalRecord $a,
        callable $verify,
        string $aSig,
        string $argsContentId,
        int $posTime,
        int $requiredEffect,
        Ledger $ledger,
        string $by
    ): LedgerEntry {
        self::verifyApproval($a, $verify, $aSig, $argsContentId, $posTime); // BadSignature / ApprovalMismatch / ApprovalExpired — all before the ledger
        if ($a->grant > Policy::DESTRUCTIVE) {
            throw new ApprovalRequired("action requires an approval that is not present"); // a grant outside the closed 0..3 effect vocabulary authorizes nothing
        }
        if (!Policy::authorizes($a->grant, $requiredEffect)) {
            throw new ApprovalRequired("action requires an approval that is not present"); // the approval's granted effect does not cover this action
        }
        return $ledger->consume($a->id(), $by);
    }
}
