<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
/**
 * N-AALP C17 — N-AALP-CONT flow continuation for the PHP SDK (design.md §20; R-CONT-1..7).
 *
 * N-AALP-CONT generalizes the C9 native-streaming pattern (one signed StreamOpen, cheap per-chunk
 * data, one signed StreamCommit over a rolling digest) into a domain-agnostic flow:
 *
 *   - FlowOpen is the ONE full signature that fixes the flow's authority: its flow_id, its effect
 *     ceiling, and the content-ids of the approvals that authorize it up to that ceiling. The
 *     authority is reconstructable from the FlowOpen bytes ALONE (parseFlowOpen) — no session state.
 *   - Continuation is a CHEAP object: no per-object signature, only a SHA-384 hash-chain link. Each
 *     link's head is SHA-384(link body); its `prev` is the previous link's head; the genesis prev is
 *     the FlowOpen's head, which anchors every link to THIS FlowOpen. A link carries its own effect,
 *     which MUST stay at or below the ceiling (AboveCeiling otherwise — the cheap path can never
 *     escalate past the one full signature + approval).
 *   - Checkpoint lets a verifier confirm a contiguous prefix and DETECT A GAP (GapDetected).
 *   - FlowCommit is a second full signature binding the whole ordered sequence with ONE signature
 *     regardless of the number of continuations (the streaming StreamCommit property).
 *
 * A continuation replayed under a different FlowOpen fails: it carries the originating flow_open_id
 * (WrongFlow) and its prev no longer chains to the other FlowOpen's head (ChainBroken). Domain
 * separation is structural: FlowOpen (3 fields), Continuation (5 fields), Checkpoint (3 fields, a
 * bstr head at 3), and FlowCommit (2 fields) are each a distinct deterministic-CBOR shape.
 *
 * An independent transcription of impl/go/continuation (cross-read against
 * impl/python/naalp/continuation.py), graded against vectors/continuation/cases.json. Every object
 * body/head/id and every cheap-path verdict is signature-independent and pure.
 *
 * CRYPTO SCOPE (PURE-ONLY): PHP has no deterministic ML-DSA (FIPS 204) signer, so the FlowOpen /
 * FlowCommit full signatures the reference makes with ML-DSA (COSE_Sign1) are demonstrated here with
 * a real Ed25519 (RFC 8032) COSE_Sign1 via ext-sodium. The corpus carries no signed vector, so the
 * full-signature gates (signFlowOpen/verifyFlowOpen, signFlowCommit/verifyFlowCommit) are graded in
 * isolation only, NOT corpus-graded. Everything the corpus grades is signature-independent.
 *
 * PLATFORM NOTE (u64, honest): PHP models a u64 as a SIGNED 64-bit int. A seq/through_seq below 2^63
 * round-trips byte-exact via `pack('J')`. A wire value at or above 2^63 (which includes the u64::MAX
 * checkpoint overflow case) decodes to a NEGATIVE PHP int (the wire's top bit set); verifyCheckpoint
 * treats any such through_seq as admitting no realizable contiguous prefix and rejects it GapDetected
 * — the same fail-closed outcome as the reference's exact-u64::MAX guard, reached for the whole
 * unrepresentable range. A u64::MAX through_seq cannot be re-ENCODED from a native int (Cbor U rejects
 * a negative), so that case is exercised by decoding the corpus bytes, not re-encoding them.
 */

declare(strict_types=1);

namespace Naalp;

// Named, fail-closed errors; $kind is a stable string mirroring the Go/Rust/Python error kinds.
// ChainBroken is REUSED from Audit.php (kind "ChainBroken") — the §8.6 note that both the receipt
// chain and the continuation chain share this kind for "a named hash-chain link failed to resolve".
class WrongFlow extends \RuntimeException
{
    public string $kind = "WrongFlow";
}
class SeqGap extends \RuntimeException
{
    public string $kind = "SeqGap";
}
class AboveCeiling extends \RuntimeException
{
    public string $kind = "AboveCeiling";
}
class GapDetected extends \RuntimeException
{
    public string $kind = "GapDetected";
}
class CommitMismatch extends \RuntimeException
{
    public string $kind = "CommitMismatch";
}
class ContMalformed extends \RuntimeException
{
    public string $kind = "ContMalformed";
}
class RangeError extends \RuntimeException
{
    public string $kind = "RangeError";
}

/**
 * FlowOpen fixes a flow's identity, effect ceiling, and approval bindings. It is signed with a full
 * signature (signFlowOpen); its authority is reconstructable from its bytes alone.
 */
final class FlowOpen
{
    public string $flowId;      // opaque, unique per flow (like a stream_id)
    public int $effectCeiling;  // the maximum effect any continuation on the cheap path may cause (C5 lattice)
    /** @var array<int,string> content-ids of the approvals authorizing this flow up to the ceiling */
    public array $approvals;

    /** @param array<int,string> $approvals */
    public function __construct(string $flowId, int $effectCeiling, array $approvals)
    {
        $this->flowId = $flowId;
        $this->effectCeiling = $effectCeiling;
        $this->approvals = \array_values($approvals);
    }

    /** Deterministic-CBOR encoding {1: flow_id, 2: effect_ceiling, 3: approvals[]}. */
    public function bytes(): string
    {
        $arr = [];
        foreach ($this->approvals as $a) {
            $arr[] = new B($a);
        }
        return Cbor::encode(new M([
            [new U(1), new B($this->flowId)],
            [new U(2), new U($this->effectCeiling)],
            [new U(3), new A($arr)],
        ]));
    }

    /** The FlowOpen's SHA-384 head — the genesis prev that anchors the continuation chain. */
    public function head(): string
    {
        return \hash('sha384', $this->bytes(), true);
    }

    /** The FlowOpen's content-id — carried by every child object. */
    public function id(): string
    {
        return Cbor::contentId($this->bytes());
    }
}

/**
 * One cheap link in a flow's chain. It is NOT individually signed; its authenticity derives from the
 * FlowOpen's signature plus the hash chain plus the FlowCommit's signature.
 */
final class Continuation
{
    public string $flowOpenId; // the originating FlowOpen's content-id (WrongFlow if it does not match)
    public int $seq;           // 0-based position in the chain
    public int $effect;        // this step's effect; MUST be <= the FlowOpen ceiling (AboveCeiling otherwise)
    public string $payloadId;  // content-id of this step's payload
    public string $prev;       // the previous link's head (the FlowOpen head for seq 0)

    public function __construct(string $flowOpenId, int $seq, int $effect, string $payloadId, string $prev)
    {
        $this->flowOpenId = $flowOpenId;
        $this->seq = $seq;
        $this->effect = $effect;
        $this->payloadId = $payloadId;
        $this->prev = $prev;
    }

    /** Deterministic-CBOR encoding {1: flow_open_id, 2: seq, 3: effect, 4: payload_id, 5: prev}. */
    public function bytes(): string
    {
        return Cbor::encode(new M([
            [new U(1), new B($this->flowOpenId)],
            [new U(2), new U($this->seq)],
            [new U(3), new U($this->effect)],
            [new U(4), new B($this->payloadId)],
            [new U(5), new B($this->prev)],
        ]));
    }

    /** This link's SHA-384 head — the prev of the next link. */
    public function head(): string
    {
        return \hash('sha384', $this->bytes(), true);
    }

    // ---- the C17 surface (static methods over the value objects) ------------------------------

    /**
     * Whether $v is a value of the closed C5 effect lattice (0..3). An out-of-lattice value is
     * rejected RangeError, NEVER normalized to destructive — normalizing a CEILING to destructive
     * would silently make an out-of-range ceiling the MOST-permissive one (a fail-open).
     */
    private static function inLattice(int $v): bool
    {
        return $v >= 0 && $v <= Policy::DESTRUCTIVE;
    }

    /**
     * Reconstruct a FlowOpen from its body bytes ALONE (the bearer-authority property). An
     * out-of-lattice effect_ceiling is rejected RangeError on decode, never normalized. Fail-closed
     * (ContMalformed) on any malformed shape; a non-canonical body is caught by the strict decoder.
     */
    public static function parseFlowOpen(string $b): FlowOpen
    {
        $m = self::decodeMap($b);
        $fid = self::bstrField($m, 1);
        $ceil = self::uintField($m, 2);
        $appsV = self::field($m, 3);
        if ($fid === null || $ceil === null || $appsV === null || !($appsV instanceof A)) {
            throw new ContMalformed("object is not a well-formed FlowOpen body");
        }
        if (!self::inLattice($ceil)) {
            throw new RangeError("effect_ceiling is outside the closed 0..3 lattice");
        }
        $apps = [];
        foreach ($appsV->items as $e) {
            if (!($e instanceof B)) {
                throw new ContMalformed("approval is not a bstr");
            }
            $apps[] = $e->v;
        }
        return new FlowOpen($fid, $ceil, $apps);
    }

    /**
     * The single audited decode path for untrusted Continuation wire bytes. Reconstructs the 5-field
     * body and range-checks the effect against the closed lattice (0..3): an out-of-lattice effect is
     * rejected RangeError, never carried as an unknown value. Fail-closed (ContMalformed).
     */
    public static function parseContinuation(string $b): Continuation
    {
        $m = self::decodeMap($b);
        $fid = self::bstrField($m, 1);
        $seq = self::uintField($m, 2);
        $effect = self::uintField($m, 3);
        $pid = self::bstrField($m, 4);
        $prev = self::bstrField($m, 5);
        if ($fid === null || $seq === null || $effect === null || $pid === null || $prev === null) {
            throw new ContMalformed("object is not a well-formed Continuation body");
        }
        if (!self::inLattice($effect)) {
            throw new RangeError("effect is outside the closed 0..3 lattice");
        }
        return new Continuation($fid, $seq, $effect, $pid, $prev);
    }

    /**
     * The single audited decode path for untrusted Checkpoint wire bytes: the 3-field body (field 3
     * a bstr head). A 2-field FlowCommit look-alike is rejected here (missing field 3). It does not
     * range-check through_seq (a full-range counter by the CDDL); the overflow guard lives in
     * verifyCheckpoint, where the seq sizes the prefix. Fail-closed (ContMalformed).
     */
    public static function parseCheckpoint(string $b): Checkpoint
    {
        $m = self::decodeMap($b);
        $fid = self::bstrField($m, 1);
        $through = self::uintField($m, 2);
        $h = self::bstrField($m, 3);
        if ($fid === null || $through === null || $h === null) {
            throw new ContMalformed("object is not a well-formed Checkpoint body");
        }
        return new Checkpoint($fid, $through, $h);
    }

    /**
     * The CHEAP-path check of a single link against the flow's fixed authority: the same flow
     * (WrongFlow), the next seq (SeqGap), effect within the ceiling (AboveCeiling), and prev chaining
     * to the previous head (ChainBroken). Performs no signature verification — that is what makes it
     * cheap. Both the ceiling and the link effect are closed effects; an out-of-lattice value is
     * RangeError, never normalized (fail-closed). Returns nothing on success.
     */
    public static function verifyContinuation(Continuation $c, string $flowOpenId, string $prevHead, int $expectedSeq, int $ceiling): void
    {
        if (!self::inLattice($ceiling)) {
            throw new RangeError("ceiling is outside the closed 0..3 lattice");
        }
        if (!self::inLattice($c->effect)) {
            throw new RangeError("effect is outside the closed 0..3 lattice");
        }
        if ($c->flowOpenId !== $flowOpenId) {
            throw new WrongFlow("object's flow_open_id does not match the FlowOpen");
        }
        if ($c->seq !== $expectedSeq) {
            throw new SeqGap("continuation seq is not the next expected value");
        }
        if (!Policy::authorizes($ceiling, $c->effect)) {
            throw new AboveCeiling("continuation effect exceeds the FlowOpen effect ceiling");
        }
        if ($c->prev !== $prevHead) {
            throw new ChainBroken("continuation prev does not chain to the previous head");
        }
    }

    /**
     * Verify a whole ordered continuation sequence starting from the FlowOpen and return the final
     * chain head. The ceiling comes from the FlowOpen, so the cheap path can never exceed what the one
     * full signature authorized. An out-of-lattice ceiling is rejected RangeError (never normalized).
     *
     * @param array<int,Continuation> $conts
     */
    public static function verifyChain(FlowOpen $open, array $conts): string
    {
        if (!self::inLattice($open->effectCeiling)) {
            throw new RangeError("effect_ceiling is outside the closed 0..3 lattice");
        }
        $id = $open->id();
        $prev = $open->head();
        $ceiling = $open->effectCeiling;
        foreach (\array_values($conts) as $i => $c) {
            self::verifyContinuation($c, $id, $prev, $i, $ceiling);
            $prev = $c->head();
        }
        return $prev;
    }

    /**
     * Confirm a prefix is exactly the contiguous sequence seq 0..through_seq and that its recomputed
     * head matches the checkpoint. A dropped or reordered link — a missing seq, a broken prev, or the
     * wrong count — is reported GapDetected. Returns nothing on a clean confirmation.
     *
     * @param array<int,Continuation> $prefix
     */
    public static function verifyCheckpoint(Checkpoint $cp, FlowOpen $open, array $prefix): void
    {
        if ($cp->flowOpenId !== $open->id()) {
            throw new WrongFlow("checkpoint flow_open_id does not match the FlowOpen");
        }
        // through_seq is a 0-based index, so the prefix length is through_seq+1. At through_seq ==
        // u64::MAX that addition would wrap and false-accept an EMPTY prefix as covering the whole
        // counter space. PHP models u64 as signed 64-bit, so any through_seq whose top bit is set
        // (>= 2^63, incl. u64::MAX) decodes NEGATIVE and admits no realizable contiguous prefix —
        // reject it GapDetected (there can be no such contiguous run), the same fail-closed outcome
        // as the reference's exact-MAX guard.
        if ($cp->throughSeq < 0) {
            throw new GapDetected("through_seq exceeds the representable range; no contiguous prefix exists");
        }
        if (\count($prefix) !== $cp->throughSeq + 1) {
            throw new GapDetected("wrong count: a link is missing or extra");
        }
        try {
            $h = self::verifyChain($open, $prefix);
        } catch (\Throwable $e) {
            throw new GapDetected("a seq/prev break inside the prefix is a gap");
        }
        if ($cp->head !== $h) {
            throw new GapDetected("recomputed prefix head does not match the checkpoint");
        }
    }

    // ---- full-signature helpers (Ed25519-demonstrated, PURE-ONLY) -----------------------------

    /** The COSE protected header {1: nint(alg)} as deterministic CBOR (alg is a negative int). */
    private static function protectedHeader(int $alg): string
    {
        return Cbor::encode(new M([[new U(1), new N($alg)]]));
    }

    /** The tagged COSE_Sign1 over the FlowOpen body (the one full signature that opens the flow). */
    public static function signFlowOpen(FlowOpen $o, string $seed): string
    {
        $prot = self::protectedHeader(Cose::ALG_ED25519);
        $payload = $o->bytes();
        $sig = Cose::ed25519Sign($seed, Cose::toBeSignedRaw($prot, $payload));
        return Cose::assembleSign1Raw($prot, $payload, $sig);
    }

    /** The tagged COSE_Sign1 over the FlowCommit body. */
    public static function signFlowCommit(FlowCommit $c, string $seed): string
    {
        $prot = self::protectedHeader(Cose::ALG_ED25519);
        $payload = $c->bytes();
        $sig = Cose::ed25519Sign($seed, Cose::toBeSignedRaw($prot, $payload));
        return Cose::assembleSign1Raw($prot, $payload, $sig);
    }

    /**
     * Verify the FlowOpen's full signature under $pubkey (Ed25519), then reconstruct the authority
     * from the signed body bytes. Fail-closed BadSignature on a bad signature.
     */
    public static function verifyFlowOpen(string $obj, int $profile, string $pubkey): FlowOpen
    {
        [$prot, $payload, $sig] = Cose::parseSign1Raw($obj);
        if (!Cose::ed25519Verify($pubkey, Cose::toBeSignedRaw($prot, $payload), $sig)) {
            throw new BadSignature("flow-open signature does not verify");
        }
        return self::parseFlowOpen($payload);
    }

    /**
     * Verify the FlowCommit's full signature, that it binds this FlowOpen, and that its final_head
     * equals the chain recomputed over the delivered continuations (CommitMismatch otherwise).
     *
     * @param array<int,Continuation> $conts
     */
    public static function verifyFlowCommit(string $obj, int $profile, string $pubkey, FlowOpen $open, array $conts): FlowCommit
    {
        [$prot, $payload, $sig] = Cose::parseSign1Raw($obj);
        if (!Cose::ed25519Verify($pubkey, Cose::toBeSignedRaw($prot, $payload), $sig)) {
            throw new BadSignature("flow-commit signature does not verify");
        }
        $m = self::decodeMap($payload);
        $fid = self::bstrField($m, 1);
        $fh = self::bstrField($m, 2);
        if ($fid === null || $fh === null) {
            throw new ContMalformed("object is not a well-formed FlowCommit body");
        }
        $fc = new FlowCommit($fid, $fh);
        if ($fc->flowOpenId !== $open->id()) {
            throw new WrongFlow("flow-commit does not bind this FlowOpen");
        }
        $final = self::verifyChain($open, $conts);
        if ($fc->finalHead !== $final) {
            throw new CommitMismatch("flow commit final_head does not match the recomputed chain");
        }
        return $fc;
    }

    // ---- small deterministic-CBOR field accessors ---------------------------------------------

    private static function decodeMap(string $b): M
    {
        $v = Cbor::decode($b); // strict decoder: throws NonCanonical on a non-canonical body
        if (!($v instanceof M)) {
            throw new ContMalformed("object is not a map");
        }
        return $v;
    }

    private static function field(M $m, int $k): mixed
    {
        foreach ($m->pairs as [$key, $val]) {
            if ($key instanceof U && $key->v === $k) {
                return $val;
            }
        }
        return null;
    }

    private static function bstrField(M $m, int $k): ?string
    {
        $v = self::field($m, $k);
        return $v instanceof B ? $v->v : null;
    }

    private static function uintField(M $m, int $k): ?int
    {
        $v = self::field($m, $k);
        return $v instanceof U ? $v->v : null;
    }
}

/** Asserts the chain head after a contiguous prefix of continuations (seq 0..through_seq). */
final class Checkpoint
{
    public string $flowOpenId;
    public int $throughSeq;
    public string $head;

    public function __construct(string $flowOpenId, int $throughSeq, string $head)
    {
        $this->flowOpenId = $flowOpenId;
        $this->throughSeq = $throughSeq;
        $this->head = $head;
    }

    /** Deterministic-CBOR encoding {1: flow_open_id, 2: through_seq, 3: head}. */
    public function bytes(): string
    {
        return Cbor::encode(new M([
            [new U(1), new B($this->flowOpenId)],
            [new U(2), new U($this->throughSeq)],
            [new U(3), new B($this->head)],
        ]));
    }
}

/** Binds a completed flow's final chain head under one full signature. */
final class FlowCommit
{
    public string $flowOpenId;
    public string $finalHead;

    public function __construct(string $flowOpenId, string $finalHead)
    {
        $this->flowOpenId = $flowOpenId;
        $this->finalHead = $finalHead;
    }

    /**
     * Deterministic-CBOR encoding {1: flow_open_id, 2: final_head} — the 2-field shape that
     * distinguishes it from the 3-field Checkpoint.
     */
    public function bytes(): string
    {
        return Cbor::encode(new M([
            [new U(1), new B($this->flowOpenId)],
            [new U(2), new B($this->finalHead)],
        ]));
    }
}
