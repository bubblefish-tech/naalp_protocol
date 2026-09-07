<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
/**
 * N-AALP C19 — name bindings and the signed A2A task-state profile for the PHP SDK (design.md §22;
 * R-NAME-1..6, R-A2A-1..7).
 *
 * C19 is two receipt-CHAINED, signed, OFFLINE-WALKABLE surfaces carried on N-AALP's own signed
 * object. Both reuse the C7 audit receipt-chain construction (§8.1) unchanged — head = SHA-384(body),
 * genesis prev = 48 zero bytes, a monotonic seq, the prior head carried in the body so editing or
 * omitting a record breaks the next record's linkage — and they add NO new envelope, encoding,
 * signature, identity, or audit mechanism (R-11.3): each object is an ordinary signed N-AALP body
 * (COSE_Sign1, §4), reusing the T1 content-id framing (§2.3) and the C7 chain.
 *
 * Task 4.1 — name bindings: NameBinding {1:name,2:signer,3:seq,4:prev} maps a name to a signer id and
 * CHAINS onto the prior binding for that name (prev = the prior binding's head; genesis prev is zero).
 * A key rotation is a NEW binding at the next seq naming the new signer. The binding is DATED BY its
 * chain position (seq); the envelope's `created` field is advisory only. A name's history is WALKABLE
 * offline (walkHistory), a deleted/omitted binding leaves a detectable HOLE at the first-broken
 * position (detectHole), and two bindings by ONE authority at the SAME (name, seq) naming DIFFERENT
 * signers are a FORK reported at that seq (detectFork / NameForkProof).
 *
 * Task 4.2 — the signed A2A task-state profile: the eight imported A2A (Agent2Agent) TaskState values
 * (carriage, not adoption): submitted, working, input-required, auth-required, completed, canceled,
 * failed, rejected (A2A §4.1.3: start = submitted; terminal = completed/canceled/failed/rejected;
 * interrupted = input-required/auth-required). A Transition {1:task,2:card,3:from,4:to,5:seq,6:prev}
 * is one receipt-CHAINED signed state transition. The legal-edge table is DERIVED from those
 * documented A2A category rules; verifyTransition rejects an illegal edge, and the task-chain walk
 * enforces the start state, contiguity, the legal-edge table, prev/seq linkage, and the card binding.
 * `card` is the content-id of the A2A Agent Card attestation (a C18 naalp-description-import) that
 * binds the profile to an agent/operation; a transition carrying a foreign card is rejected.
 *
 * An independent transcription of impl/go/naming (cross-read against impl/python/naalp/naming.py),
 * graded against the shared vectors/naming/cases.json. Every check is fail-closed (§15): a failing
 * object is rejected whole, returns its named error, and causes no state change.
 *
 * CRYPTO SCOPE (PURE-ONLY, honest F2/F4): C19's cross-language SIGNED pins are real deterministic
 * ML-DSA (FIPS 204) COSE_Sign1 objects. PHP has no deterministic ML-DSA signer, so those signed pins
 * are NOT reproducible here and are NOT faked. Every surface this port grades against the corpus — the
 * NameBinding/Transition bodies/heads/ids, the walk/hole/fork/gap positions, the A2A legal/illegal
 * edge table, the strict-decoder NonCanonical rejection, the look-alike NameMalformed rejections, and
 * the Agent-Card import content-id — is signature-independent and pure. The signature BINDING
 * (SignBinding/VerifyChain, NameForkProof, SignTransition/VerifyTaskChain) is demonstrated in
 * isolation with a real Ed25519 (RFC 8032) round-trip via ext-sodium; the injected verify closure is
 * the pure-tier stand-in for the reference's ML-DSA verifier. BadSignature is reused from Gateway.php
 * and NonCanonical from Cbor.php (same kinds the reference carries).
 */

declare(strict_types=1);

namespace Naalp;

// Named, fail-closed errors; $kind mirrors the Go/Rust/Python error kinds. BadSignature is reused
// from Gateway.php.
class NameMalformed extends \RuntimeException
{
    public string $kind = "NameMalformed";
}
class NameChainBroken extends \RuntimeException
{
    public string $kind = "NameChainBroken";
}
class NameForkProofInvalid extends \RuntimeException
{
    public string $kind = "NameForkProofInvalid";
}
class IllegalTransition extends \RuntimeException
{
    public string $kind = "IllegalTransition";
}
class TaskChainBroken extends \RuntimeException
{
    public string $kind = "TaskChainBroken";
}
class ForeignCard extends \RuntimeException
{
    public string $kind = "ForeignCard";
}

/**
 * Maps a name to a signer id at a chain position. It chains onto the prior binding for the same name:
 * prev is the prior binding's head (genesis for seq 0). A key rotation is a new binding at the next
 * seq naming the new signer. Dated by seq; the envelope's `created` is advisory.
 */
final class NameBinding
{
    public string $name;   // the name being bound (a durable, human-readable name)
    public string $signer; // the signer id this binding maps the name to (opaque bytes; §5.1)
    public int $seq;       // monotonic per-name chain position; seq 0 is the genesis binding
    public string $prev;   // the prior binding's head (Naming::HEAD_SIZE bytes; genesis is zero)

    public function __construct(string $name, string $signer, int $seq, string $prev)
    {
        $this->name = $name;
        $this->signer = $signer;
        $this->seq = $seq;
        $this->prev = $prev;
    }

    /** Deterministic-CBOR encoding {1:name,2:signer,3:seq,4:prev}. */
    public function bytes(): string
    {
        return Cbor::encode(new M([
            [new U(1), new T($this->name)],
            [new U(2), new B($this->signer)],
            [new U(3), new U($this->seq)],
            [new U(4), new B($this->prev)],
        ]));
    }

    /** The chain head after this binding: SHA-384 of the binding body (48 octets). */
    public function head(): string
    {
        return \hash('sha384', $this->bytes(), true);
    }

    /** The binding's T1 content-id (50 octets): multihash(0x20, SHA-384(body)). */
    public function id(): string
    {
        return Cbor::contentId($this->bytes());
    }
}

/**
 * One step of a walked name history: the chain position and the signer the name mapped to at that
 * position, with the chain head after it.
 */
final class NameEvent
{
    public int $seq;
    public string $signer;
    public string $head;

    public function __construct(int $seq, string $signer, string $head)
    {
        $this->seq = $seq;
        $this->signer = $signer;
        $this->head = $head;
    }
}

/**
 * One signed, receipt-CHAINED A2A task state transition (design §22.4). It chains onto the prior
 * transition of the same task: prev is the prior transition's head (genesis for seq 0). Dated by seq.
 * card is the content-id of the A2A Agent Card attestation (a C18 import) that binds this profile to
 * an agent/operation.
 */
final class Transition
{
    public string $task; // the task id (opaque bytes)
    public string $card; // content-id of the bound A2A Agent Card attestation (the C18 import)
    public int $from;    // the source state
    public int $to;      // the target state
    public int $seq;     // monotonic per-task chain position; seq 0's from MUST be the start state
    public string $prev; // the prior transition's head (Naming::HEAD_SIZE bytes; genesis is zero)

    public function __construct(string $task, string $card, int $from, int $to, int $seq, string $prev)
    {
        $this->task = $task;
        $this->card = $card;
        $this->from = $from;
        $this->to = $to;
        $this->seq = $seq;
        $this->prev = $prev;
    }

    /** Deterministic-CBOR encoding {1:task,2:card,3:from,4:to,5:seq,6:prev}. */
    public function bytes(): string
    {
        return Cbor::encode(new M([
            [new U(1), new B($this->task)],
            [new U(2), new B($this->card)],
            [new U(3), new U($this->from)],
            [new U(4), new U($this->to)],
            [new U(5), new U($this->seq)],
            [new U(6), new B($this->prev)],
        ]));
    }

    /** The chain head after this transition: SHA-384 of the transition body (48 octets). */
    public function head(): string
    {
        return \hash('sha384', $this->bytes(), true);
    }

    /** The transition's T1 content-id (50 octets). */
    public function id(): string
    {
        return Cbor::contentId($this->bytes());
    }
}

/**
 * Non-repudiable evidence of a name fork: two validly-signed NameBinding objects by ONE authority at
 * the SAME (name, seq) naming DIFFERENT signers, carried as the accused authority's OWN two signed
 * objects (the tagged COSE_Sign1 bytes). Because a single verifier checks BOTH signed objects, the
 * proof is self-contained.
 */
final class NameForkProof
{
    public string $signer;  // accused authority signer id (both objects verify under its key)
    public string $signedA;
    public string $signedB;

    public function __construct(string $signer, string $signedA, string $signedB)
    {
        $this->signer = $signer;
        $this->signedA = $signedA;
        $this->signedB = $signedB;
    }

    /**
     * Accept iff ALL hold: (1) the signer id is present; (2) BOTH signed objects verify under the
     * injected verifier (which, because one verifier checks both, proves one authority); (3) the two
     * bindings share one name and seq; and (4) their bodies differ. Returns the seq position at which
     * it forks. An unnamed signer, a different name/seq, or identical bodies is NameForkProofInvalid;
     * a signature that does not verify is BadSignature. Fail-closed. `$verify` is fn(msg,sig):bool.
     */
    public function verify(callable $verify): int
    {
        if ($this->signer === "") {
            throw new NameForkProofInvalid("an unnamed accused is not evidence");
        }
        $a = Naming::verifyBinding($this->signedA, $verify);
        $b = Naming::verifyBinding($this->signedB, $verify);
        [$pos, $fork] = Naming::detectFork($a, $b);
        if (!$fork) {
            throw new NameForkProofInvalid("not the same (name, seq) or identical bodies");
        }
        return $pos;
    }
}

/**
 * A naming authority that appends monotonic signed bindings for ONE name (mirroring the C7 audit
 * authority). Each append records a name -> signer mapping at the next chain position; a rotation is
 * simply an append naming the new signer. Signs with a real Ed25519 (RFC 8032) key from $seed (the
 * pure-tier stand-in for the reference's deterministic ML-DSA signer).
 */
final class Registrar
{
    private string $name;
    private string $seed;
    private string $head;
    private int $seq;

    public function __construct(string $name, string $seed)
    {
        $this->name = $name;
        $this->seed = $seed;
        $this->head = Naming::genesis();
        $this->seq = 0;
    }

    /**
     * Record a binding of the registrar's name to $subject at the next chain position, returning
     * [binding, tagged COSE_Sign1 object]. Seq increases by one per append (monotonic); the chain
     * head advances to the new binding's head.
     *
     * @return array{0: NameBinding, 1: string}
     */
    public function append(string $subject): array
    {
        $nb = new NameBinding($this->name, $subject, $this->seq, $this->head);
        $obj = Naming::signBinding($nb, $this->seed);
        $this->head = $nb->head();
        $this->seq++;
        return [$nb, $obj];
    }
}

/**
 * The C19 static surface: chain helpers, the name-binding walk/hole/fork detectors, the A2A state
 * vocabulary + legal-edge table, the task-chain walk, and the Ed25519-demonstrated signed verifiers.
 */
final class Naming
{
    /** The width of a chain head / prev link (SHA-384 = 48 bytes), matching the C7 audit chain. */
    public const HEAD_SIZE = 48;

    // A2A TaskState codes (stable N-AALP wire codes for the imported A2A vocabulary; A2A §4.1.3).
    public const STATE_SUBMITTED = 0;      // acknowledged, not yet started (the start state)
    public const STATE_WORKING = 1;        // actively processed
    public const STATE_INPUT_REQUIRED = 2; // interrupted, awaiting client input
    public const STATE_AUTH_REQUIRED = 3;  // interrupted, awaiting authentication
    public const STATE_COMPLETED = 4;      // terminal success
    public const STATE_CANCELED = 5;       // terminal, canceled before completion
    public const STATE_FAILED = 6;         // terminal, finished with an error
    public const STATE_REJECTED = 7;       // terminal, the agent declined the task
    public const START_STATE = 0;

    private const STATE_NAMES = [
        0 => "submitted", 1 => "working", 2 => "input-required", 3 => "auth-required",
        4 => "completed", 5 => "canceled", 6 => "failed", 7 => "rejected",
    ];

    /** A fresh 48-octet zero prev — the empty-chain link (the C7 chain genesis). */
    public static function genesis(): string
    {
        return \str_repeat("\x00", self::HEAD_SIZE);
    }

    // ---- Task 4.1: name bindings -------------------------------------------------------------

    /**
     * Reconstruct a NameBinding from its body bytes alone. A body that is not exactly the {1,2,3,4}
     * map with the right value types (or is non-canonical) is NameMalformed (fail-closed).
     */
    public static function parseNameBinding(string $b): NameBinding
    {
        $m = self::decodeMap($b);
        if ($m === null) {
            throw new NameMalformed("body is not a well-formed name binding");
        }
        $name = self::tstrField($m, 1);
        $signer = self::bstrField($m, 2);
        $seq = self::uintField($m, 3);
        $prev = self::bstrField($m, 4);
        if ($name === null || $signer === null || $seq === null || $prev === null) {
            throw new NameMalformed("body is not a well-formed name binding");
        }
        return new NameBinding($name, $signer, $seq, $prev);
    }

    /**
     * Verify a name-binding chain's structural continuity OFFLINE (no signatures) and return the
     * ordered signer succession. Requires every binding to name the SAME name, seq i to equal its
     * index, and prev to link to the previous binding's head (genesis zero for seq 0). A gap, reorder,
     * omitted binding, or a name change is NameChainBroken (fail-closed). The CURRENT signer is the
     * last event's signer.
     *
     * @param array<int,NameBinding> $bindings
     * @return array<int,NameEvent>
     */
    public static function walkHistory(array $bindings): array
    {
        $bindings = \array_values($bindings);
        $events = [];
        $h = self::genesis();
        $name = null;
        foreach ($bindings as $i => $nb) {
            if ($i === 0) {
                $name = $nb->name;
            } elseif ($nb->name !== $name) {
                throw new NameChainBroken("a chain is for exactly one name");
            }
            if ($nb->seq !== $i || $nb->prev !== $h) {
                throw new NameChainBroken("prev/seq does not chain to the previous binding");
            }
            $h = $nb->head();
            $events[] = new NameEvent($nb->seq, $nb->signer, $h);
        }
        return $events;
    }

    /**
     * Report whether a presented (possibly gappy) binding list breaks contiguity — a deleted/omitted
     * binding — and, if so, the FIRST-BROKEN position: the index i where the i-th presented binding's
     * seq is not i or its prev does not link to the previous binding's head. A contiguous list returns
     * [0, false].
     *
     * @param array<int,NameBinding> $bindings
     * @return array{0:int,1:bool}
     */
    public static function detectHole(array $bindings): array
    {
        $bindings = \array_values($bindings);
        $h = self::genesis();
        foreach ($bindings as $i => $nb) {
            if ($nb->seq !== $i || $nb->prev !== $h) {
                return [$i, true];
            }
            $h = $nb->head();
        }
        return [0, false];
    }

    /**
     * Compare two bindings for the SAME name and report whether they equivocate — the SAME name and
     * seq but DIFFERENT bodies — and, if so, the seq position. A different name or seq is a legitimate
     * distinct binding; byte-identical bindings are a benign duplicate. Both non-fork cases return
     * [0, false].
     *
     * @return array{0:int,1:bool}
     */
    public static function detectFork(NameBinding $a, NameBinding $b): array
    {
        if ($a->name !== $b->name || $a->seq !== $b->seq) {
            return [0, false];
        }
        if ($a->bytes() === $b->bytes()) {
            return [0, false];
        }
        return [$a->seq, true];
    }

    /** The bare {1: nint(alg)} COSE_Sign1 protected header (as the reference cose.Sign1 emits). */
    private static function protectedHeader(int $alg): string
    {
        return Cbor::encode(new M([[new U(1), new N($alg)]]));
    }

    /**
     * Produce the tagged COSE_Sign1 object over the binding body with a real Ed25519 (RFC 8032)
     * signature (the pure-tier stand-in for the reference's deterministic ML-DSA signer).
     */
    public static function signBinding(NameBinding $nb, string $seed): string
    {
        $prot = self::protectedHeader(Cose::ALG_ED25519);
        $payload = $nb->bytes();
        $sig = Cose::ed25519Sign($seed, Cose::toBeSignedRaw($prot, $payload));
        return Cose::assembleSign1Raw($prot, $payload, $sig);
    }

    /**
     * Verify a signed binding's signature via the injected verifier, then reconstruct it from the
     * signed body bytes. A bad signature is BadSignature; a malformed body is NameMalformed.
     * `$verify` is fn(msg,sig):bool (Ed25519 on the pure PHP port).
     */
    public static function verifyBinding(string $obj, callable $verify): NameBinding
    {
        [$prot, $payload, $sig] = Cose::parseSign1Raw($obj);
        if (!$verify(Cose::toBeSignedRaw($prot, $payload), $sig)) {
            throw new BadSignature("signature does not verify");
        }
        return self::parseNameBinding($payload);
    }

    /**
     * Check a name-binding chain offline against the authority's key. Each element is the tagged
     * COSE_Sign1 object for one binding. Verifies every signature (verifyBinding), then enforces
     * structural continuity (walkHistory) — same name, seq i == index, prev links to the previous
     * head — returning the verified, ordered bindings. A bad signature is BadSignature; a broken link,
     * a seq gap, or a name change is NameChainBroken. Fail-closed. `$verify` is fn(msg,sig):bool.
     *
     * @param array<int,string> $objs
     * @return array<int,NameBinding>
     */
    public static function verifyChain(array $objs, callable $verify): array
    {
        $bindings = [];
        foreach ($objs as $obj) {
            $bindings[] = self::verifyBinding($obj, $verify);
        }
        self::walkHistory($bindings); // structural continuity (throws NameChainBroken)
        return $bindings;
    }

    // ---- Task 4.2: the signed A2A task-state profile -----------------------------------------

    /** The A2A state name for a code, or "unknown". */
    public static function stateName(int $s): string
    {
        return self::STATE_NAMES[$s] ?? "unknown";
    }

    /** Whether $s is one of the eight defined A2A states. */
    public static function isState(int $s): bool
    {
        return \array_key_exists($s, self::STATE_NAMES);
    }

    /** Whether $s is a terminal state (completed/canceled/failed/rejected). */
    public static function isTerminal(int $s): bool
    {
        return $s === self::STATE_COMPLETED || $s === self::STATE_CANCELED
            || $s === self::STATE_FAILED || $s === self::STATE_REJECTED;
    }

    /** Whether $s is an interrupted state (input-required/auth-required). */
    public static function isInterrupted(int $s): bool
    {
        return $s === self::STATE_INPUT_REQUIRED || $s === self::STATE_AUTH_REQUIRED;
    }

    /**
     * The A2A legal transition table, derived from the documented category rules (design §22.3),
     * memoized. Keyed "from,to" for O(1) membership.
     *
     * @return array<string,array{0:int,1:int}>
     */
    private static function legalEdgeSet(): array
    {
        static $set = null;
        if ($set !== null) {
            return $set;
        }
        $active = [self::STATE_SUBMITTED, self::STATE_WORKING];
        $interrupted = [self::STATE_INPUT_REQUIRED, self::STATE_AUTH_REQUIRED];
        $terminal = [self::STATE_COMPLETED, self::STATE_CANCELED, self::STATE_FAILED, self::STATE_REJECTED];
        $set = [];
        $add = static function (int $f, int $t) use (&$set): void {
            $set["$f,$t"] = [$f, $t];
        };
        $add(self::STATE_SUBMITTED, self::STATE_WORKING); // begin processing (the only active->active edge)
        foreach ($active as $s) {                        // active -> interrupted
            foreach ($interrupted as $t) {
                $add($s, $t);
            }
        }
        foreach ($active as $s) {                        // active -> terminal
            foreach ($terminal as $t) {
                $add($s, $t);
            }
        }
        foreach ($interrupted as $s) {                   // interrupted -> working (client acted)
            $add($s, self::STATE_WORKING);
        }
        foreach ($interrupted as $s) {                   // interrupted -> terminal
            foreach ($terminal as $t) {
                $add($s, $t);
            }
        }
        return $set;
    }

    /**
     * Whether (from -> to) is a legal A2A transition edge per the table. A self-loop, an edge out of a
     * terminal state, an edge touching an undefined state, and any edge not in the table are all false.
     */
    public static function legalEdge(int $from, int $to): bool
    {
        if (!self::isState($from) || !self::isState($to)) {
            return false;
        }
        return \array_key_exists("$from,$to", self::legalEdgeSet());
    }

    /**
     * A copy of the legal transition table as a sorted list of [from, to] pairs.
     *
     * @return array<int,array{0:int,1:int}>
     */
    public static function legalEdges(): array
    {
        $out = \array_values(self::legalEdgeSet());
        \usort($out, static fn(array $a, array $b): int => $a[0] <=> $b[0] ?: $a[1] <=> $b[1]);
        return $out;
    }

    /**
     * The edge-legality gate: returns nothing iff (from -> to) is a legal A2A edge, else throws
     * IllegalTransition (an unknown edge, a self-loop, an edge out of a terminal state, or an edge
     * touching an undefined state). Fail-closed.
     */
    public static function verifyTransition(int $from, int $to): void
    {
        if (!self::legalEdge($from, $to)) {
            throw new IllegalTransition("not a legal A2A transition edge");
        }
    }

    /**
     * Reconstruct a Transition from its body bytes alone. A body that is not exactly the {1,2,3,4,5,6}
     * map with the right value types (or is non-canonical) is NameMalformed (fail-closed).
     */
    public static function parseTransition(string $b): Transition
    {
        $m = self::decodeMap($b);
        if ($m === null) {
            throw new NameMalformed("body is not a well-formed task transition");
        }
        $task = self::bstrField($m, 1);
        $card = self::bstrField($m, 2);
        $from = self::uintField($m, 3);
        $to = self::uintField($m, 4);
        $seq = self::uintField($m, 5);
        $prev = self::bstrField($m, 6);
        if ($task === null || $card === null || $from === null || $to === null || $seq === null || $prev === null) {
            throw new NameMalformed("body is not a well-formed task transition");
        }
        return new Transition($task, $card, $from, $to, $seq, $prev);
    }

    /** Produce the tagged COSE_Sign1 object over the transition body (real Ed25519). */
    public static function signTransition(Transition $t, string $seed): string
    {
        $prot = self::protectedHeader(Cose::ALG_ED25519);
        $payload = $t->bytes();
        $sig = Cose::ed25519Sign($seed, Cose::toBeSignedRaw($prot, $payload));
        return Cose::assembleSign1Raw($prot, $payload, $sig);
    }

    /**
     * Verify a transition's signature via the injected verifier, reconstruct it from the signed body
     * bytes, AND check that its edge is legal. A bad signature is BadSignature; an illegal edge is
     * IllegalTransition. Fail-closed. `$verify` is fn(msg,sig):bool.
     */
    public static function verifyTransitionObject(string $obj, callable $verify): Transition
    {
        $t = self::parseSignedTransition($obj, $verify);
        self::verifyTransition($t->from, $t->to);
        return $t;
    }

    /** Verify a signed transition's signature and parse its body (no edge check). */
    private static function parseSignedTransition(string $obj, callable $verify): Transition
    {
        [$prot, $payload, $sig] = Cose::parseSign1Raw($obj);
        if (!$verify(Cose::toBeSignedRaw($prot, $payload), $sig)) {
            throw new BadSignature("signature does not verify");
        }
        return self::parseTransition($payload);
    }

    /**
     * Report whether a presented (possibly gappy) transition list breaks contiguity — a
     * deleted/omitted or reordered transition — and, if so, the FIRST-BROKEN position. A contiguous
     * list returns [0, false]. (The gap-evident detector for the task chain, mirroring detectHole.)
     *
     * @param array<int,Transition> $transitions
     * @return array{0:int,1:bool}
     */
    public static function detectTaskGap(array $transitions): array
    {
        $transitions = \array_values($transitions);
        $h = self::genesis();
        foreach ($transitions as $i => $t) {
            if ($t->seq !== $i || $t->prev !== $h) {
                return [$i, true];
            }
            $h = $t->head();
        }
        return [0, false];
    }

    /**
     * Walk a task's transition chain OFFLINE (signature-independent) against the bound card
     * attestation. Enforces, in order and fail-closed: (1) prev/seq linkage (each prev links to the
     * prior head, genesis zero for seq 0; seq i == index) — a gap/reorder is TaskChainBroken; (2) the
     * CARD BINDING (every transition's card equals `$card`) — ForeignCard otherwise; and (3) the START
     * STATE (seq-0's from is START_STATE), CONTIGUITY (each from == the prior to), and the LEGAL-EDGE
     * TABLE at every step (including the terminal-cannot-continue rule, since a from-terminal edge is
     * not in the table) — IllegalTransition otherwise. Returns the verified, ordered transitions.
     *
     * @param array<int,Transition> $transitions
     * @return array<int,Transition>
     */
    public static function verifyTaskChainStructure(array $transitions, string $card): array
    {
        $transitions = \array_values($transitions);
        $h = self::genesis();
        $prevTo = null;
        $out = [];
        foreach ($transitions as $i => $t) {
            if ($t->seq !== $i || $t->prev !== $h) {
                throw new TaskChainBroken("prev/seq does not chain to the previous transition");
            }
            if ($t->card !== $card) {
                throw new ForeignCard("transition binds a card other than the profile's bound card");
            }
            if ($i === 0) {
                if ($t->from !== self::START_STATE) {
                    throw new IllegalTransition("the first transition must leave the start state");
                }
            } elseif ($t->from !== $prevTo) {
                throw new IllegalTransition("non-contiguous: this from must equal the prior to");
            }
            self::verifyTransition($t->from, $t->to); // an illegal edge (incl. from-terminal)
            $h = $t->head();
            $prevTo = $t->to;
            $out[] = $t;
        }
        return $out;
    }

    /**
     * Walk a task's transition chain against the authority's key and the bound card attestation. Each
     * element is the tagged COSE_Sign1 object for one transition: its signature is verified (via the
     * injected verifier) and its body parsed, then the whole chain's structure is checked
     * (verifyTaskChainStructure). A bad signature is BadSignature; the structural verdicts are as
     * verifyTaskChainStructure. `$verify` is fn(msg,sig):bool (Ed25519 on the pure PHP port).
     *
     * @param array<int,string> $objs
     * @return array<int,Transition>
     */
    public static function verifyTaskChain(array $objs, string $card, callable $verify): array
    {
        $transitions = [];
        foreach ($objs as $obj) {
            $transitions[] = self::parseSignedTransition($obj, $verify);
        }
        return self::verifyTaskChainStructure($transitions, $card);
    }

    // ---- small deterministic-CBOR field accessors (strict decode; NonCanonical -> null) ------

    private static function decodeMap(string $b): ?M
    {
        try {
            $v = Cbor::decode($b);
        } catch (NonCanonical $e) {
            return null;
        }
        return $v instanceof M ? $v : null;
    }

    private static function field(M $m, int $k): mixed
    {
        foreach ($m->pairs as [$kk, $vv]) {
            if ($kk instanceof U && $kk->v === $k) {
                return $vv;
            }
        }
        return null;
    }

    private static function bstrField(M $m, int $k): ?string
    {
        $v = self::field($m, $k);
        return $v instanceof B ? $v->v : null;
    }

    private static function tstrField(M $m, int $k): ?string
    {
        $v = self::field($m, $k);
        return $v instanceof T ? $v->v : null;
    }

    private static function uintField(M $m, int $k): ?int
    {
        $v = self::field($m, $k);
        return $v instanceof U ? $v->v : null;
    }
}
