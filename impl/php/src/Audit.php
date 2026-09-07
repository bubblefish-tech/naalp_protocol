<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
/**
 * N-AALP C7 audit for the PHP SDK — the signed hash-chained receipt (the baseline single-authority
 * ordering tier), the equivocation auditor and its non-repudiable fork proof, and the
 * offline-checkable causal graph (design.md §8; R-8.1..8.6, R-12.2, R-12.3).
 *
 * An ordering authority records each accepted object by appending a signed Receipt
 * {1: prev, 2: obj, 3: seq, 4: at}; the chain is tamper-evident because reordering, omission, or
 * substitution breaks a `prev` link or a `seq` (§8.1). The authority never mutates the origin object
 * to order it — ordering is an outer signed layer, and the object's own signature stays valid (§8.2).
 * The causal graph is the authority-independent foundation: an edge "A causes B" is proven by B's
 * signature over A's content id (envelope field 8) and is checkable offline; a total order is a policy
 * layered over this partial order (§8.2). A cause an effect could not have seen (later position, or a
 * cycle) is rejected (CausalViolation, §8.3). An auditor detects equivocation — two receipts by one
 * authority at one seq naming different objects — from the signed receipts alone (§8.5), and mints a
 * non-repudiable ForkProof carrying BOTH of the accused's signatures and an external monotonic counter
 * (draft-01 finding #70).
 *
 * An independent transcription of impl/go/audit (cross-read against impl/python/naalp/audit.py),
 * graded against the shared vectors/audit/cases.json. The causal partial order is checked by the
 * shared Naalp\Graph (the same C7 foundation the reference reuses).
 *
 * CRYPTO SCOPE (PURE-ONLY): PHP has no deterministic ML-DSA (FIPS 204) signer, so the receipt and
 * fork-proof signatures the reference makes with ML-DSA are demonstrated here with a real Ed25519
 * (RFC 8032) signature via ext-sodium — the signature GATES (Authority signing, Auditor observe,
 * ForkProof verify, VerifyChain) take an injected verify closure. The corpus-graded surfaces (receipt
 * body/head, chain final head, the ChainBroken linkage verdict, the fork-proof framing witness with
 * signatures elided, and the causal verdicts + topological order) are all signature-independent and
 * pure. The full ForkProof body carrying a real ML-DSA signature is not reproducible in the pure tier;
 * the corpus grades the signature-elided preimage, which is.
 */

declare(strict_types=1);

namespace Naalp;

// Named, fail-closed errors; $kind is a stable string mirroring the Go/Rust/Python/Ruby error kinds.
class ChainBroken extends \RuntimeException
{
    public string $kind = "ChainBroken";
}
class ReceiptUnsigned extends \RuntimeException
{
    public string $kind = "ReceiptUnsigned";
}
class ForkProofInvalid extends \RuntimeException
{
    public string $kind = "ForkProofInvalid";
}

/**
 * One signed append to an ordering authority's chain (§8.1): `prev` is the hash of the previous
 * receipt body (Audit::HEAD_SIZE bytes; genesis is zero); `obj` is the content id of the accepted
 * object (never the object itself — §8.2); `seq` is the monotonic position; `at` is the authority's
 * time anchor, epoch ms (independent of the signer's clock, R-8.4).
 */
final class Receipt
{
    public string $prev;
    public string $obj;
    public int $seq;
    public int $at;

    public function __construct(string $prev, string $obj, int $seq, int $at)
    {
        $this->prev = $prev;
        $this->obj = $obj;
        $this->seq = $seq;
        $this->at = $at;
    }

    /** Deterministic-CBOR encoding of the receipt body {1: prev, 2: obj, 3: seq, 4: at}. */
    public function bytes(): string
    {
        return Cbor::encode(new M([
            [new U(1), new B($this->prev)],
            [new U(2), new B($this->obj)],
            [new U(3), new U($this->seq)],
            [new U(4), new U($this->at)],
        ]));
    }

    /**
     * The chain head after this receipt: SHA-384 of the receipt body. Because the body carries prev,
     * editing any receipt breaks the next receipt's linkage.
     */
    public function head(): string
    {
        return \hash('sha384', $this->bytes(), true);
    }
}

/**
 * Non-repudiable evidence of equivocation (draft-01 §8.5, R-8.3): two validly-signed receipts by ONE
 * authority at the SAME seq naming DIFFERENT objects, with the accused's OWN two signatures and an
 * external monotonic counter — self-contained, so any third party verifies both signatures against the
 * accused key with no further evidence and no repudiation.
 */
final class ForkProof
{
    public string $signer;
    public int $extCounter;
    public Receipt $a;
    public string $sigA;
    public Receipt $b;
    public string $sigB;

    public function __construct(string $signer, int $extCounter, Receipt $a, string $sigA, Receipt $b, string $sigB)
    {
        $this->signer = $signer;
        $this->extCounter = $extCounter;
        $this->a = $a;
        $this->sigA = $sigA;
        $this->b = $b;
        $this->sigB = $sigB;
    }

    /**
     * Deterministic-CBOR fork-proof body {1: signer, 2: ext_counter, 3: body_a, 4: sig_a, 5: body_b,
     * 6: sig_b}. The two receipt bodies are embedded as the exact bytes each signature covers.
     */
    public function bytes(): string
    {
        return Cbor::encode(new M([
            [new U(1), new B($this->signer)],
            [new U(2), new U($this->extCounter)],
            [new U(3), new B($this->a->bytes())],
            [new U(4), new B($this->sigA)],
            [new U(5), new B($this->b->bytes())],
            [new U(6), new B($this->sigB)],
        ]));
    }

    /**
     * The deterministic-CBOR framing witness: the fork-proof body with the two signature byte-strings
     * elided to empty. It is the structural authority the independent oracle reproduces byte-for-byte;
     * the two (ML-DSA, in the reference) signatures are graded by cross-implementation byte-parity
     * elsewhere. This is not a wire object; it exists only to grade the framing.
     */
    public function preimage(): string
    {
        return Cbor::encode(new M([
            [new U(1), new B($this->signer)],
            [new U(2), new U($this->extCounter)],
            [new U(3), new B($this->a->bytes())],
            [new U(4), new B("")],
            [new U(5), new B($this->b->bytes())],
            [new U(6), new B("")],
        ]));
    }

    /**
     * Accept iff ALL hold: (1) the signer id is present; (2) the two receipts share one seq; (3) they
     * name DIFFERENT objects; and (4) BOTH signatures verify under the accused key. Any failure rejects
     * the whole proof (fail-closed): a same-object / seq-mismatch / unnamed-signer proof is
     * ForkProofInvalid, and a signature that does not verify is ReceiptUnsigned. Returns nothing on a
     * valid, non-repudiable proof of Equivocation. `$verify` is `fn(string $msg, string $sig): bool`
     * — the injected signature verifier (Ed25519 on the pure PHP port).
     */
    public function verify(callable $verify): void
    {
        if ($this->signer === "") {
            throw new ForkProofInvalid("an unnamed accused is not evidence");
        }
        if ($this->a->seq !== $this->b->seq) {
            throw new ForkProofInvalid("receipts at different sequence positions");
        }
        if ($this->a->obj === $this->b->obj) {
            throw new ForkProofInvalid("same object named twice — no equivocation");
        }
        if (!$verify($this->a->bytes(), $this->sigA) || !$verify($this->b->bytes(), $this->sigB)) {
            throw new ReceiptUnsigned("a signature does not verify under the accused key");
        }
    }
}

/**
 * A baseline single ordering authority (§8.4). It appends monotonic signed receipts over object
 * content ids; it holds no object bodies and mutates none. PURE-ONLY PHP: signs each receipt body with
 * a real Ed25519 (RFC 8032) key derived from a 32-byte seed, standing in for the reference's ML-DSA
 * signer to exercise the signing binding.
 */
final class Authority
{
    private string $seed;
    private string $head;
    private int $seq;

    public function __construct(string $seed)
    {
        $this->seed = $seed;
        $this->head = \str_repeat("\x00", Audit::HEAD_SIZE);
        $this->seq = 0;
    }

    /**
     * Record acceptance of the object named by content id $obj at time $at, returning [Receipt, sig].
     * Seq increases by one per append (monotonic).
     *
     * @return array{0:Receipt,1:string}
     */
    public function append(string $obj, int $at): array
    {
        $r = new Receipt($this->head, $obj, $this->seq, $at);
        $sig = Cose::ed25519Sign($this->seed, $r->bytes());
        $this->head = $r->head();
        $this->seq += 1;
        return [$r, $sig];
    }
}

/**
 * Observes an authority's receipts and detects equivocation from the signed receipts alone (§8.5). On
 * a conflict it mints a non-repudiable ForkProof carrying the accused signer id, both conflicting
 * signatures, and an external monotonic counter (T2.1). The signature gate is an injected verifier
 * (Ed25519 on the pure PHP port).
 */
final class Auditor
{
    /** @var callable(string,string):bool */
    private $verify;
    private string $signer;
    private int $ext;
    /** @var array<int,array{0:Receipt,1:string}> seq => [Receipt, signature] */
    private array $seen = [];

    /** @param callable(string,string):bool $verify fn(msg, sig): bool */
    public function __construct(callable $verify, string $signer, int $extBase = 0)
    {
        $this->verify = $verify;
        $this->signer = $signer;
        $this->ext = $extBase;
    }

    /**
     * Record a signed receipt. Throws ReceiptUnsigned on a bad signature. Returns a ForkProof
     * (Equivocation) if a previously-seen receipt at the same seq named a different object — the proof
     * carries the accused signer id, both signatures, and the auditor's current external counter, which
     * then advances. Returns null otherwise (including a benign exact duplicate).
     */
    public function observe(Receipt $r, string $sig): ?ForkProof
    {
        if (!($this->verify)($r->bytes(), $sig)) {
            throw new ReceiptUnsigned("receipt signature does not verify");
        }
        if (\array_key_exists($r->seq, $this->seen)) {
            [$prevR, $prevSig] = $this->seen[$r->seq];
            if ($prevR->obj !== $r->obj) {
                $fp = Audit::newForkProof($this->signer, $prevR, $prevSig, $r, $sig, $this->ext);
                $this->ext += 1;
                return $fp;
            }
            return null;
        }
        $this->seen[$r->seq] = [$r, $sig];
        return null;
    }
}

final class Audit
{
    /** The width of a chain head / prev link (SHA-384 = 48 bytes); genesis is zero. */
    public const HEAD_SIZE = 48;

    /**
     * Check a receipt chain's LINKAGE offline (signature-independent): each receipt's seq is the next
     * expected value and its prev links to the previous receipt's head (genesis is zero). A broken link
     * or a seq gap is ChainBroken — this alone detects any reorder, omission, or substitution (§8.1).
     * (The signature check is layered on by verifyChain.)
     */
    public static function verifyChainLinks(array $receipts): void
    {
        $head = \str_repeat("\x00", self::HEAD_SIZE);
        foreach ($receipts as $i => $r) {
            if ($r->seq !== $i || $r->prev !== $head) {
                throw new ChainBroken("receipt prev/seq does not chain to the previous receipt");
            }
            $head = $r->head();
        }
    }

    /**
     * Check a receipt chain offline against the authority's key: the linkage (verifyChainLinks) AND,
     * per receipt, that its signature verifies under the injected verifier. A broken link or a seq gap
     * is ChainBroken; a bad signature is ReceiptUnsigned. `$verify` is `fn(msg, sig): bool` (Ed25519 on
     * the pure PHP port).
     *
     * @param array<int,Receipt> $receipts
     * @param array<int,string>  $sigs
     */
    public static function verifyChain(array $receipts, array $sigs, callable $verify): void
    {
        if (\count($receipts) !== \count($sigs)) {
            throw new ChainBroken("receipt/signature count mismatch");
        }
        $head = \str_repeat("\x00", self::HEAD_SIZE);
        foreach ($receipts as $i => $r) {
            if ($r->seq !== $i || $r->prev !== $head) {
                throw new ChainBroken("receipt prev/seq does not chain to the previous receipt");
            }
            if (!$verify($r->bytes(), $sigs[$i])) {
                throw new ReceiptUnsigned("receipt signature does not verify");
            }
            $head = $r->head();
        }
    }

    /**
     * An object cannot be created after the authority ordered it, so `created` MUST NOT exceed `at`
     * (R-8.4). The receipt's `at` is signed and chained, so it is evidence a verifier checks
     * independently of the signer's clock.
     */
    public static function consistentWithAnchor(int $created, int $at): bool
    {
        return $created <= $at;
    }

    /**
     * Assemble a fork proof from two conflicting signed receipts, the accused signer id, and an
     * external monotonic counter. Performs no checks — ForkProof::verify is the fail-closed gate; this
     * is the pure constructor (A9).
     */
    public static function newForkProof(string $signer, Receipt $a, string $sigA, Receipt $b, string $sigB, int $extCounter): ForkProof
    {
        return new ForkProof($signer, $extCounter, $a, $sigA, $b, $sigB);
    }

    /**
     * Check the signed partial order (§8.2, §8.3): no object names a present cause whose position
     * exceeds its own (a future cause it could not have seen), and the graph is acyclic. Either fault
     * is CausalViolation. Delegates to the shared Naalp\Graph, which implements exactly this partial
     * order. A node is a [id, causes[], position] tuple.
     *
     * @param array<int,array{0:string,1:array<int,string>,2:int}> $nodes
     */
    public static function verifyCausal(array $nodes): void
    {
        Graph::verifyCausal(\array_values($nodes));
    }

    /**
     * Return the causal nodes' content ids in a deterministic topological order (a cause before its
     * effects). Ties among ready nodes break by (position, input index), so the order is reproducible.
     * Throws CausalViolation if the graph does not verify. NOTE: the audit tie-break is by POSITION —
     * distinct from the federation reconcile, whose tie-break is the content id (Naalp\Graph::reconcile).
     *
     * @param array<int,array{0:string,1:array<int,string>,2:int}> $nodes
     * @return array<int,string> ordered binary content ids
     */
    public static function topoOrder(array $nodes): array
    {
        $nodes = \array_values($nodes);
        self::verifyCausal($nodes);
        $count = \count($nodes);
        $idx = [];
        foreach ($nodes as $i => $n) {
            $idx[\bin2hex($n[0])] = $i;
        }
        $indeg = \array_fill(0, $count, 0);
        $effects = \array_fill(0, $count, []); // cause index -> effect indices
        foreach ($nodes as $i => $n) {
            foreach ($n[1] as $c) {
                $key = \bin2hex($c);
                if (\array_key_exists($key, $idx)) {
                    $j = $idx[$key];
                    $effects[$j][] = $i;
                    $indeg[$i] += 1;
                }
            }
        }
        $done = \array_fill(0, $count, false);
        $order = [];
        while (\count($order) < $count) {
            $pick = -1;
            for ($i = 0; $i < $count; $i++) {
                if ($done[$i] || $indeg[$i] !== 0) {
                    continue;
                }
                if ($pick === -1 || $nodes[$i][2] < $nodes[$pick][2]) {
                    $pick = $i; // lowest position wins; equal positions keep the lower index (first seen)
                }
            }
            if ($pick === -1) {
                throw new CausalViolation("no ready node (unreachable after verifyCausal)");
            }
            $done[$pick] = true;
            $order[] = $nodes[$pick][0];
            foreach ($effects[$pick] as $e) {
                $indeg[$e] -= 1;
            }
        }
        return $order;
    }
}
