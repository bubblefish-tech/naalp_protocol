<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
/**
 * N-AALP collaboration / rooms membership for the PHP SDK (feature #64): a Phase-3 ADDITIVE higher
 * tier (tier 1) over the frozen draft-00 spine (design.md §2..§10; design-channels.md §21). It
 * introduces NO new envelope, encoding, signature, identity, or audit mechanism — it reuses the
 * spine unchanged (R-11.3, R-15A.2) — and adds only tier-1 object kinds on the Governance channel
 * (0x0004; membership ops) and the Identity channel (0x0003; the principal registry). A frozen
 * baseline verifier that has not licensed the tier rejects a room kind as UnknownKind, fail-closed.
 *
 * It builds three recorded maintainer decisions:
 *
 *   - #4a Membership carriage — every membership change (create, add_member, remove_member,
 *     change_role, add_owner) is a first-class SIGNED object (a normal N-AALP envelope object, §2),
 *     CURSOR-OCCUPYING (a real ordered position in the per-room log), RECEIPT-CHAINED (the room log
 *     IS the C7 append-only signed audit/receipt chain of §8.1 — this port reuses Naalp\Authority /
 *     Naalp\Receipt unchanged, one Receipt per accepted op over the op's content id), and
 *     EPOCH-BUMPING (each accepted op increments the room's membership epoch; an op built against a
 *     superseded epoch is rejected StaleEpoch — serialising concurrent changes so a stale view
 *     cannot win).
 *   - #4b O2 ownership — multi-owner, ADD-ONLY: a room may have many owners; add_owner adds one; an
 *     owner is NEVER removed (remove_member refuses an owner) nor demoted (change_role refuses to
 *     lower an owner). Create seeds exactly one owner and add_owner only grows the set, so the owner
 *     count is monotonically >= 1 — a room can never become ownerless.
 *   - #3  Delivery Model B — PrincipalRegistry maps a stable semantic principal id to a durable
 *     Handle (the current signer id), resolved at send time. The binding survives key rotation (a
 *     rebind is authorised only by a verified co-signed rotation from the current handle, R-1.4 —
 *     this port composes on the C4 Identity::signRotation/verifyRotation primitive added additively
 *     to Identity.php), so the semantic id is a durable layer above the connection-scoped handle
 *     while a hijack to an unrelated key is refused RebindUnauthorized.
 *
 * An independent transcription of impl/go/rooms (cross-read against impl/python/naalp/rooms.py),
 * graded against the shared vectors/rooms/cases.json. Every check is fail-closed (§15): an op that
 * fails any check is rejected whole, returns its named error, and causes no state change.
 *
 * CRYPTO SCOPE (PURE-ONLY): PHP has no deterministic ML-DSA (FIPS 204) signer. The corpus-graded
 * surfaces (op bodies/content-ids, the receipt-chained room-log bodies/heads/objs, the cursor/epoch
 * progression, the final membership/ownership state, and the principal-binding bodies/heads) are all
 * signature-independent and pure. The room-log ordering authority signs each receipt with a real
 * Ed25519 (RFC 8032) key (Naalp\Authority, the pure-tier stand-in for the reference's ML-DSA
 * authority) and the log verifies offline; the rebind rotation is a real co-signed Ed25519 rotation.
 * The signed membership object's ML-DSA signature is the one un-exercised leg — it is verified
 * STRUCTURALLY on the ML-DSA-65 path (level 3 clears the Public floor), exactly as the Delegation
 * port documents.
 */

declare(strict_types=1);

namespace Naalp;

// Named, fail-closed errors; $kind is a stable string mirroring the Go/Rust/Python error kinds.
// NonNFC and SignerMismatch are reused from Identity.php (identical kinds); UnknownKind from
// Channels.php.
class StaleEpoch extends \RuntimeException
{
    public string $kind = "StaleEpoch";
}
class Unauthorized extends \RuntimeException
{
    public string $kind = "Unauthorized";
}
class OwnerImmutable extends \RuntimeException
{
    public string $kind = "OwnerImmutable";
}
class MemberExists extends \RuntimeException
{
    public string $kind = "MemberExists";
}
class MemberUnknown extends \RuntimeException
{
    public string $kind = "MemberUnknown";
}
class OwnerExists extends \RuntimeException
{
    public string $kind = "OwnerExists";
}
class RoleInvalid extends \RuntimeException
{
    public string $kind = "RoleInvalid";
}
class RoomOpMismatch extends \RuntimeException
{
    public string $kind = "RoomOpMismatch";
}
class OpUnknown extends \RuntimeException
{
    public string $kind = "OpUnknown";
}
class PrincipalUnknown extends \RuntimeException
{
    public string $kind = "PrincipalUnknown";
}
class PrincipalExists extends \RuntimeException
{
    public string $kind = "PrincipalExists";
}
class RebindUnauthorized extends \RuntimeException
{
    public string $kind = "RebindUnauthorized";
}

/**
 * One membership operation body carried in envelope field 10. Its content id (multihash(0x20,
 * SHA-384(body))) is what the room log orders (the cursor position), so the op is content-addressed
 * and its ordering is tamper-evident.
 */
final class RoomOp
{
    public string $room;   // room id (bstr)
    public int $op;        // 0 create | 1 add_member | 2 remove_member | 3 change_role | 4 add_owner
    public int $epoch;     // the membership epoch this op is built against (bumps on accept)
    public string $subject; // the affected member's signer id (the creator, for create); MUST be NFC
    public int $role;      // 0 member | 1 admin | 2 owner

    public function __construct(string $room, int $op, int $epoch, string $subject, int $role)
    {
        $this->room = $room;
        $this->op = $op;
        $this->epoch = $epoch;
        $this->subject = $subject;
        $this->role = $role;
    }

    public function toMap(): M
    {
        return new M([
            [new U(1), new B($this->room)],
            [new U(2), new U($this->op)],
            [new U(3), new U($this->epoch)],
            [new U(4), new T($this->subject)],
            [new U(5), new U($this->role)],
        ]);
    }

    /** Deterministic-CBOR encoding of the op body {1:room,2:op,3:epoch,4:subject,5:role}. */
    public function bytes(): string
    {
        return Cbor::encode($this->toMap());
    }

    /** The op's content id in the T1 framing (design §2.3): multihash(0x20, SHA-384(body)). */
    public function contentId(): string
    {
        return Cbor::contentId($this->bytes());
    }

    /**
     * Build the (unsigned) N-AALP envelope object that carries this op: tier 1, Governance channel,
     * the op's kind and declared effect, the op body as field 10. The caller signs it to produce the
     * first-class signed membership object. A non-NFC subject or an unknown op is rejected
     * fail-closed.
     */
    public function envelopeObject(string $signer, int $created, int $profile, array $causes): NaalpObject
    {
        [$kind, $eff, $ok] = Rooms::kindForOp($this->op);
        if (!$ok) {
            throw new OpUnknown("unknown room op code");
        }
        Identity::requireNfc($this->subject); // throws NonNFC (kind "NonNFC")
        return new NaalpObject(
            kind: $kind,
            channel: Rooms::CHANNEL_GOVERNANCE,
            signer: $signer,
            created: $created,
            effect: $eff,
            body: $this->toMap(),
            tier: Rooms::TIER,
            profile: $profile,
            causes: $causes,
        );
    }
}

/**
 * Delivery Model B: one principal-registry record — a semantic principal id bound to a durable
 * Handle at a monotonic per-principal epoch, chained to the prior binding's head (SHA-384). Signed
 * as an Identity-channel (0x0003) tier-1 object; here it is the wire body (byte-graded) and the
 * PrincipalRegistry below is the policy (behaviour-graded).
 */
final class Binding
{
    public string $principal; // the stable semantic principal id (MUST be NFC)
    public string $handle;    // the current durable Handle (a signer id) this principal resolves to
    public int $epoch;        // monotonic per-principal binding epoch (0 for the first bind)
    public string $prev;      // prior binding chain head (48 bytes; genesis = zero)

    public function __construct(string $principal, string $handle, int $epoch, string $prev)
    {
        $this->principal = $principal;
        $this->handle = $handle;
        $this->epoch = $epoch;
        $this->prev = $prev;
    }

    public function toMap(): M
    {
        return new M([
            [new U(1), new T($this->principal)],
            [new U(2), new T($this->handle)],
            [new U(3), new U($this->epoch)],
            [new U(4), new B($this->prev)],
        ]);
    }

    /** Deterministic-CBOR encoding {1:principal,2:handle,3:epoch,4:prev}. */
    public function bytes(): string
    {
        return Cbor::encode($this->toMap());
    }

    /**
     * The per-principal chain head after this binding: SHA-384(binding body). Because the body
     * carries the prior head, editing any binding breaks the next binding's linkage.
     */
    public function head(): string
    {
        return \hash('sha384', $this->bytes(), true);
    }
}

/**
 * A collaboration room's live membership state and its signed, append-only log. The log is a C7
 * audit receipt chain (Naalp\Authority): each accepted op is ordered at a cursor (the receipt seq)
 * over the op's content id, weaving membership into the tamper-evident chain.
 */
final class Room
{
    private string $id;
    private int $epoch;
    /** @var array<string,int> subject => role */
    private array $members;
    /** @var array<string,bool> subject => true */
    private array $owners;
    private Authority $auth;
    /** @var array<int,Receipt> */
    private array $receipts;
    /** @var array<int,string> */
    private array $sigs;

    public function __construct(string $id, Authority $auth)
    {
        $this->id = $id;
        $this->epoch = 0;
        $this->members = [];
        $this->owners = [];
        $this->auth = $auth;
        $this->receipts = [];
        $this->sigs = [];
    }

    /**
     * Build a room from a verified create op signed by the creator. The creator (the op subject)
     * becomes the first and, at creation, only owner+member. The create op occupies cursor 0 in the
     * log; the room advances to epoch 1. A non-create op, a non-zero epoch, an empty/non-NFC subject,
     * or an actor that is not the subject is rejected fail-closed. Returns [Room, Receipt, cursor].
     *
     * @return array{0:Room,1:Receipt,2:int}
     */
    public static function create(RoomOp $op, string $actor, Authority $auth, int $at): array
    {
        if ($op->op !== Rooms::OP_CREATE) {
            throw new RoomOpMismatch("create requires a create op");
        }
        if ($op->epoch !== 0) {
            throw new StaleEpoch("a create op must be built against epoch 0");
        }
        if ($op->subject === "") {
            throw new RoomOpMismatch("empty subject");
        }
        Identity::requireNfc($op->subject); // throws NonNFC
        if ($actor !== $op->subject) { // the creator seeds itself as the first owner
            throw new Unauthorized("the create actor must be the seeded owner (the subject)");
        }
        $r = new Room($op->room, $auth);
        $r->members[$op->subject] = Rooms::ROLE_OWNER;
        $r->owners[$op->subject] = true;
        [$rec, $sig] = $auth->append($op->contentId(), $at);
        $r->receipts[] = $rec;
        $r->sigs[] = $sig;
        $r->epoch = 1;
        return [$r, $rec, $rec->seq];
    }

    /**
     * Validate and apply one membership op (add_member, remove_member, change_role, add_owner) by an
     * owner `actor`, order it into the room log, and bump the epoch. Check order is fail-closed
     * throughout: room match -> epoch -> subject well-formed -> authorization -> per-op semantics ->
     * order -> mutate -> bump. Any failure returns a named error and leaves the room unchanged.
     * Returns [Receipt, cursor].
     *
     * @return array{0:Receipt,1:int}
     */
    public function apply(RoomOp $op, string $actor, int $at): array
    {
        if ($op->room !== $this->id || $op->op === Rooms::OP_CREATE) {
            throw new RoomOpMismatch("op room id or op code does not match this room/operation");
        }
        if ($op->epoch !== $this->epoch) {
            throw new StaleEpoch("op epoch does not match the room's current membership epoch");
        }
        if ($op->subject === "") {
            throw new RoomOpMismatch("empty subject");
        }
        Identity::requireNfc($op->subject); // throws NonNFC
        if (!isset($this->owners[$actor])) { // only an owner may change membership (R-6.5)
            throw new Unauthorized("actor is not an owner of the room");
        }
        // Per-op semantic validation — NO mutation yet (so a rejection is a true no-op).
        switch ($op->op) {
            case Rooms::OP_ADD_MEMBER:
                if ($op->role !== Rooms::ROLE_MEMBER && $op->role !== Rooms::ROLE_ADMIN) {
                    throw new RoleInvalid("owners are added via add_owner only");
                }
                if (isset($this->members[$op->subject])) {
                    throw new MemberExists("subject is already a member");
                }
                break;
            case Rooms::OP_ADD_OWNER:
                if ($op->role !== Rooms::ROLE_OWNER) {
                    throw new RoleInvalid("add_owner must carry the owner role");
                }
                if (isset($this->owners[$op->subject])) {
                    throw new OwnerExists("subject is already an owner");
                }
                break;
            case Rooms::OP_REMOVE_MEMBER:
                if (!isset($this->members[$op->subject])) {
                    throw new MemberUnknown("subject is not a member of the room");
                }
                if (isset($this->owners[$op->subject])) {
                    throw new OwnerImmutable("an owner cannot be removed (ownership is add-only)");
                }
                break;
            case Rooms::OP_CHANGE_ROLE:
                if (!isset($this->members[$op->subject])) {
                    throw new MemberUnknown("subject is not a member of the room");
                }
                if ($op->role !== Rooms::ROLE_MEMBER && $op->role !== Rooms::ROLE_ADMIN) {
                    throw new RoleInvalid("promote to owner via add_owner only");
                }
                if ($this->members[$op->subject] === Rooms::ROLE_OWNER) {
                    throw new OwnerImmutable("an owner cannot be demoted");
                }
                break;
            default:
                throw new OpUnknown("unknown room op code");
        }
        // Order the op into the log first; if ordering fails there is no state change.
        [$rec, $sig] = $this->auth->append($op->contentId(), $at);
        switch ($op->op) {
            case Rooms::OP_ADD_MEMBER:
                $this->members[$op->subject] = $op->role;
                break;
            case Rooms::OP_ADD_OWNER:
                $this->members[$op->subject] = Rooms::ROLE_OWNER;
                $this->owners[$op->subject] = true;
                break;
            case Rooms::OP_REMOVE_MEMBER:
                unset($this->members[$op->subject]);
                break;
            case Rooms::OP_CHANGE_ROLE:
                $this->members[$op->subject] = $op->role;
                break;
        }
        $this->receipts[] = $rec;
        $this->sigs[] = $sig;
        $this->epoch++;
        return [$rec, $rec->seq];
    }

    /**
     * The behavioural end-to-end path: verify a signed membership object through the spine
     * (Envelope::verify against the composed rooms validator), bind the claimed signer id to the
     * verifying key (a self-asserted id that does not derive from the authenticated key confers no
     * authority, R-1.3/R-5.1), confirm the object is a tier-1 Governance room op whose kind and
     * effect match its op code, then apply it with the authenticated signer id as the actor. Returns
     * [Receipt, cursor].
     *
     * @return array{0:Receipt,1:int}
     */
    public function applySigned(int $profile, int $alg, string $pubkey, string $signedObj, int $at): array
    {
        $o = Envelope::verify($profile, $alg, $pubkey, [Rooms::class, 'composedKindValidator'], $signedObj);
        if ($o->channel !== Rooms::CHANNEL_GOVERNANCE || $o->tier !== Rooms::TIER) {
            throw new RoomOpMismatch("object is not a tier-1 Governance room op");
        }
        $actor = Identity::signerId($alg, $pubkey);
        if ($o->signer !== $actor) { // the object's signer field must be the authenticated id
            throw new SignerMismatch("signer id does not derive from the verifying key");
        }
        $op = Rooms::roomOpFromBody($o->body);
        [$wantKind, $wantEff, $ok] = Rooms::kindForOp($op->op);
        if (!$ok || $o->kind !== $wantKind || $o->effect !== $wantEff) {
            throw new RoomOpMismatch("op kind/effect does not match its op code");
        }
        return $this->apply($op, $actor, $at);
    }

    /** The room id. */
    public function id(): string
    {
        return $this->id;
    }

    /** The room's current membership epoch (the epoch the next op must carry). */
    public function epoch(): int
    {
        return $this->epoch;
    }

    /**
     * A subject's role and whether it is a member.
     *
     * @return array{0:int,1:bool}
     */
    public function roleOf(string $subject): array
    {
        return isset($this->members[$subject]) ? [$this->members[$subject], true] : [0, false];
    }

    /** Whether a subject is an owner of the room. */
    public function isOwner(string $subject): bool
    {
        return isset($this->owners[$subject]);
    }

    /** The number of owners; the add-only invariant keeps this >= 1 after create. */
    public function ownerCount(): int
    {
        return \count($this->owners);
    }

    /**
     * The owner ids in sorted order.
     *
     * @return array<int,string>
     */
    public function owners(): array
    {
        $out = \array_keys($this->owners);
        \sort($out);
        return $out;
    }

    /**
     * The members and their roles (a copy).
     *
     * @return array<string,int>
     */
    public function members(): array
    {
        return $this->members;
    }

    /**
     * The room log's receipts and their signatures (its persistent state); verifies offline with
     * Audit::verifyChain against the ordering authority's key.
     *
     * @return array{0:array<int,Receipt>,1:array<int,string>}
     */
    public function log(): array
    {
        return [$this->receipts, $this->sigs];
    }
}

/**
 * The durable semantic-naming layer of Delivery Model B (R-1.4): it maps each semantic principal id
 * to its current durable Handle, keeping a per-principal signed binding chain. A delivery addresses
 * a semantic id and resolve() returns the Handle at send time. A rebind is authorised ONLY by a
 * verified co-signed rotation from the current handle (Identity::verifyRotation).
 */
final class PrincipalRegistry
{
    /** @var array<string,array<int,Binding>> */
    private array $chain = [];
    /** @var array<string,string> */
    private array $head = [];
    /** @var array<string,string> */
    private array $current = [];
    /** @var array<string,int> */
    private array $epoch = [];

    /**
     * Create the FIRST binding for a principal (epoch 0, prev = genesis). A principal already bound
     * is PrincipalExists (use rebind); an empty or non-NFC principal/handle is rejected.
     */
    public function bind(string $principal, string $handle): Binding
    {
        if ($principal === "" || $handle === "") {
            throw new RoomOpMismatch("empty principal or handle");
        }
        Identity::requireNfc($principal); // throws NonNFC
        Identity::requireNfc($handle);
        if (isset($this->current[$principal])) {
            throw new PrincipalExists("principal already bound; use rebind");
        }
        $b = new Binding($principal, $handle, 0, Rooms::genesisHead());
        $this->chain[$principal] = [$b];
        $this->head[$principal] = $b->head();
        $this->current[$principal] = $handle;
        $this->epoch[$principal] = 0;
        return $b;
    }

    /**
     * Update a principal to a new durable Handle, REQUIRING a verified rotation from the current
     * handle to the new handle (R-1.4): the semantic id survives key rotation, but a rebind to a key
     * not proven continuous with the current handle is refused (RebindUnauthorized). The binding
     * epoch bumps and the chain links to the prior head. `$rot` is the co-signed rotation record and
     * the two keys' algs/pubkeys/signatures (Identity::verifyRotation).
     */
    public function rebind(
        string $principal,
        string $newHandle,
        RotationRecord $rot,
        int $oldAlg,
        string $oldPub,
        int $newAlg,
        string $newPub,
        string $oldSig,
        string $newSig
    ): Binding {
        if (!isset($this->current[$principal])) {
            throw new PrincipalUnknown("no binding for the semantic principal id");
        }
        $cur = $this->current[$principal];
        if ($newHandle === "") {
            throw new RoomOpMismatch("empty new handle");
        }
        Identity::requireNfc($newHandle); // throws NonNFC
        // The rotation MUST carry the current handle as old and the new handle as new, and it MUST be
        // a valid co-signed rotation (both keys derive their ids and both signatures verify).
        if ($rot->old !== $cur || $rot->new !== $newHandle) {
            throw new RebindUnauthorized("a rebind requires a verified rotation from the current handle");
        }
        try {
            Identity::verifyRotation($rot, $oldAlg, $oldPub, $newAlg, $newPub, $oldSig, $newSig);
        } catch (RotationUnauthorized $e) {
            throw new RebindUnauthorized("a rebind requires a verified rotation from the current handle");
        }
        $ep = $this->epoch[$principal] + 1;
        $b = new Binding($principal, $newHandle, $ep, $this->head[$principal]);
        $this->chain[$principal][] = $b;
        $this->head[$principal] = $b->head();
        $this->current[$principal] = $newHandle;
        $this->epoch[$principal] = $ep;
        return $b;
    }

    /**
     * Return the current durable Handle for a semantic principal id (Delivery Model B). An unknown
     * principal is PrincipalUnknown (fail-closed — never a silent empty handle).
     */
    public function resolve(string $principal): string
    {
        if (!isset($this->current[$principal])) {
            throw new PrincipalUnknown("no binding for the semantic principal id");
        }
        return $this->current[$principal];
    }

    /**
     * A principal's ordered binding chain (its persistent state) for offline audit, or null.
     *
     * @return array<int,Binding>|null
     */
    public function chain(string $principal): ?array
    {
        return $this->chain[$principal] ?? null;
    }
}

/**
 * The rooms surface's constants, kind validation, op<->kind mapping, and the create factory /
 * body parser. Static-only.
 */
final class Rooms
{
    // Channel bindings (R-1.2) and the tier for this higher-tier surface.
    public const CHANNEL_GOVERNANCE = 0x0004; // membership ops (who is authorised in the room)
    public const CHANNEL_IDENTITY = 0x0003;   // the principal registry (durable naming, R-1.4)
    public const TIER = 1;                     // a named higher tier over the frozen baseline (tier 0)

    // Room membership operation codes (naalp-room-op field 2).
    public const OP_CREATE = 0;
    public const OP_ADD_MEMBER = 1;
    public const OP_REMOVE_MEMBER = 2;
    public const OP_CHANGE_ROLE = 3;
    public const OP_ADD_OWNER = 4;

    // Role codes (naalp-room-op field 5) — the collaboration role that gates membership ops; NOT an
    // effect and NOT a capability ceiling.
    public const ROLE_MEMBER = 0;
    public const ROLE_ADMIN = 1;
    public const ROLE_OWNER = 2;

    // Tier-1 kind codes. Governance (0x0004) carries the five membership ops; Identity (0x0003)
    // carries the principal binding. They start at 16 to sit clear of the frozen baseline kinds.
    public const KIND_ROOM_CREATE = 16;
    public const KIND_ROOM_ADD_MEMBER = 17;
    public const KIND_ROOM_REMOVE_MEMBER = 18;
    public const KIND_ROOM_CHANGE_ROLE = 19;
    public const KIND_ROOM_ADD_OWNER = 20;
    public const KIND_PRINCIPAL_BIND = 16; // on the Identity channel

    /**
     * Map an op code to its tier-1 Governance kind and its declared effect (design-channels.md §21).
     * remove_member is destructive; the rest are non_idempotent_write. Returns [kind, effect, ok].
     *
     * @return array{0:int,1:int,2:bool}
     */
    public static function kindForOp(int $op): array
    {
        switch ($op) {
            case self::OP_CREATE:
                return [self::KIND_ROOM_CREATE, Policy::NON_IDEMPOTENT_WRITE, true];
            case self::OP_ADD_MEMBER:
                return [self::KIND_ROOM_ADD_MEMBER, Policy::NON_IDEMPOTENT_WRITE, true];
            case self::OP_REMOVE_MEMBER:
                return [self::KIND_ROOM_REMOVE_MEMBER, Policy::DESTRUCTIVE, true];
            case self::OP_CHANGE_ROLE:
                return [self::KIND_ROOM_CHANGE_ROLE, Policy::NON_IDEMPOTENT_WRITE, true];
            case self::OP_ADD_OWNER:
                return [self::KIND_ROOM_ADD_OWNER, Policy::NON_IDEMPOTENT_WRITE, true];
            default:
                return [0, 0, false];
        }
    }

    /**
     * Accept exactly this surface's tier-1 kinds: the five Governance membership kinds and the
     * Identity principal-bind kind. Nothing else.
     */
    public static function kindValidator(int $channel, int $kind): bool
    {
        if ($channel === self::CHANNEL_GOVERNANCE) {
            return $kind >= self::KIND_ROOM_CREATE && $kind <= self::KIND_ROOM_ADD_OWNER;
        }
        if ($channel === self::CHANNEL_IDENTITY) {
            return $kind === self::KIND_PRINCIPAL_BIND;
        }
        return false;
    }

    private static function baselineKindValidator(int $channel, int $kind): bool
    {
        try {
            Channels::lookup($channel, $kind);
            return true;
        } catch (UnknownKind $e) {
            return false;
        }
    }

    /**
     * Accept the frozen baseline kinds OR this surface's tier-1 kinds — the validator a rooms-aware
     * endpoint passes to Envelope::verify. A baseline-only endpoint using the baseline validator
     * alone correctly rejects a room kind as UnknownKind (fail-closed).
     */
    public static function composedKindValidator(int $channel, int $kind): bool
    {
        return self::baselineKindValidator($channel, $kind) || self::kindValidator($channel, $kind);
    }

    /**
     * Build a room from a verified create op signed by the creator (see Room::create). Returns
     * [Room, Receipt, cursor].
     *
     * @return array{0:Room,1:Receipt,2:int}
     */
    public static function createRoom(RoomOp $op, string $actor, Authority $auth, int $at): array
    {
        return Room::create($op, $actor, $auth, $at);
    }

    /**
     * Parse an envelope object body (field 10) back into a RoomOp. A body that is not exactly the
     * {1,2,3,4,5} map with the right value types is RoomOpMismatch (fail-closed).
     */
    public static function roomOpFromBody(mixed $v): RoomOp
    {
        if (!($v instanceof M)) {
            throw new RoomOpMismatch("op body is not a map");
        }
        $room = $op = $epoch = $subject = $role = null;
        $seen = [];
        foreach ($v->pairs as [$k, $val]) {
            if (!($k instanceof U) || $k->v < 1 || $k->v > 5) {
                throw new RoomOpMismatch("op body has an out-of-range field");
            }
            if ($k->v === 1) {
                if (!($val instanceof B)) {
                    throw new RoomOpMismatch("room is not a bstr");
                }
                $room = $val->v;
            } elseif ($k->v === 2) {
                if (!($val instanceof U)) {
                    throw new RoomOpMismatch("op is not a uint");
                }
                $op = $val->v;
            } elseif ($k->v === 3) {
                if (!($val instanceof U)) {
                    throw new RoomOpMismatch("epoch is not a uint");
                }
                $epoch = $val->v;
            } elseif ($k->v === 4) {
                if (!($val instanceof T)) {
                    throw new RoomOpMismatch("subject is not a tstr");
                }
                $subject = $val->v;
            } elseif ($k->v === 5) {
                if (!($val instanceof U)) {
                    throw new RoomOpMismatch("role is not a uint");
                }
                $role = $val->v;
            }
            $seen[$k->v] = true;
        }
        foreach ([1, 2, 3, 4, 5] as $f) {
            if (!isset($seen[$f])) {
                throw new RoomOpMismatch("op body is missing a mandatory field");
            }
        }
        return new RoomOp($room, $op, $epoch, $subject, $role);
    }

    /** The empty per-principal chain head (48 zero bytes) — the C7 chain genesis width. */
    public static function genesisHead(): string
    {
        return \str_repeat("\x00", Audit::HEAD_SIZE);
    }
}
