<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
/**
 * N-AALP NAALP-MCP binding profile for the PHP SDK (design.md §19; Companion-Spec Requirement 6.1) — a
 * draft-01 ADDITIVE tier-1 surface over the frozen spine. It introduces NO new envelope, encoding,
 * signature, identity, or audit mechanism (R-11.3): an MCP tool call is a normal N-AALP object
 * (envelope §2) on the Bridge channel, and it REUSES the closed effect lattice (Policy), the approval +
 * single-use consume ledger (Approval), and the T1 content-id framing (§2.3) unchanged.
 *
 * What the profile adds is the governance MCP itself lacks. The MCP specification states plainly that a
 * tool's annotations are unenforced hints a malicious server can lie about ("clients MUST consider tool
 * annotations to be untrusted unless they come from trusted servers"). This profile turns that
 * anonymous, untrusted hint into a SIGNED effect claim by a named key:
 *   - CARRIAGE, NOT ADOPTION. The MCP tool-definition bytes and the tool-call argument bytes are carried
 *     OCTET-FOR-OCTET; a foreign identity inside them never becomes an N-AALP authorization identity —
 *     the wrapping signer is the authority (R-14.6).
 *   - PUBLISHED MAPPING TABLE. The tool's annotations map to the closed four-effect lattice
 *     (read_only < idempotent_write < non_idempotent_write < destructive). Because the spine carries no
 *     CBOR boolean (design §3.1), each JSON hint is transcribed as the uint 1/0; an ABSENT hint takes
 *     its MCP default. destructiveHint's default of TRUE is why an un-annotated write maps to destructive
 *     — the fail-closed default.
 *   - THE WRAPPING SIGNER IS ACCOUNTABLE. The wrapper's envelope effect (field 7) is the signer's
 *     DECLARED effect, under its signature. A verifier independently recomputes the annotation-derived
 *     effect and enforces the MORE SEVERE of the two (resolveEnforcedEffect — the good-regulator
 *     attenuator: a disagreeing input collapses UP, never down). A signer that DECLARES BELOW its own
 *     carried annotations is rejected fail-closed (EffectUnderDeclared); an annotation set that maps
 *     outside the lattice is rejected (MalformedAnnotation), never defaulted to benign.
 *   - THE APPROVAL BINDS THE EXACT CALL. An approval binds the content id of the call binding
 *     (tool_id + args_id). A changed tool description or changed arguments yields a new content id and
 *     invalidates a prior approval (Requirement 6.1), reusing the §7 approval + consume ledger.
 *
 * An independent transcription of impl/go/mcp (cross-read against impl/python/naalp/mcp.py), graded
 * against the shared vectors/mcp/cases.json. The annotation encoding, the mapping table, the tool-call
 * bodies/content-ids, the call bindings, and the resolution verdicts are signature-independent and pure.
 *
 * CRYPTO SCOPE (PURE-ONLY / STRUCTURAL-ML-DSA): the byte/verdict surfaces are pure and corpus-graded.
 * PHP has no deterministic ML-DSA (FIPS 204) signer, so — exactly as the delegation port — verifyToolCall
 * runs against a structural ML-DSA-65 envelope object (Envelope::verify clears the level-3 floor; the
 * ML-DSA signature itself is not cryptographically verified in PHP, documented not faked). authorizeCall
 * reuses the REAL §7 Approval consume ledger, with an Ed25519-demonstrated human approval (the reference
 * uses ML-DSA). The corpus carries no signed vector, so all signed paths are isolation-only.
 *
 * Every check is fail-closed (§15): an object failing any check is rejected whole, returns its named
 * error, and causes no state change.
 */

declare(strict_types=1);

namespace Naalp;

// Named, fail-closed errors; $kind mirrors the Go/Rust/Python kinds. ApprovalRequired / ApprovalMismatch
// / ApprovalExpired / AlreadyConsumed (Approval.php) and BadSignature (Gateway.php) are reused unchanged.
class McpError extends \RuntimeException
{
    public string $kind;

    public function __construct(string $kind, string $msg = "")
    {
        $this->kind = $kind;
        parent::__construct($msg === "" ? $kind : "$kind: $msg");
    }
}

/**
 * The wrapping signer's transcription of a tool's MCP ToolAnnotations. Each hint is OPTIONAL: null means
 * the hint was absent (the MCP default applies in the mapping), so an absent hint and a present false are
 * distinct on the wire though they may resolve to the same effect. openWorld is carried for
 * accountability but never enters the effect mapping (design §5).
 */
final class Annotations
{
    public ?bool $readOnly;    // MCP readOnlyHint
    public ?bool $destructive; // MCP destructiveHint
    public ?bool $idempotent;  // MCP idempotentHint
    public ?bool $openWorld;   // MCP openWorldHint (advisory only)

    public function __construct(?bool $readOnly = null, ?bool $destructive = null, ?bool $idempotent = null, ?bool $openWorld = null)
    {
        $this->readOnly = $readOnly;
        $this->destructive = $destructive;
        $this->idempotent = $idempotent;
        $this->openWorld = $openWorld;
    }

    /** Encode the annotation set as its CBOR map: present hints only, uint keys -> uint 0/1. */
    public function toValue(): M
    {
        $pairs = [];
        if ($this->readOnly !== null) {
            $pairs[] = [new U(Mcp::KEY_READ_ONLY), new U($this->readOnly ? 1 : 0)];
        }
        if ($this->destructive !== null) {
            $pairs[] = [new U(Mcp::KEY_DESTRUCTIVE), new U($this->destructive ? 1 : 0)];
        }
        if ($this->idempotent !== null) {
            $pairs[] = [new U(Mcp::KEY_IDEMPOTENT), new U($this->idempotent ? 1 : 0)];
        }
        if ($this->openWorld !== null) {
            $pairs[] = [new U(Mcp::KEY_OPEN_WORLD), new U($this->openWorld ? 1 : 0)];
        }
        return new M($pairs);
    }

    /** The deterministic-CBOR bytes of the annotation map (keys sorted by encode). */
    public function encode(): string
    {
        return Cbor::encode($this->toValue());
    }
}

/**
 * The wrapper body (envelope field 10). `tool` and `args` are the foreign MCP bytes, carried
 * octet-for-octet (carriage, not adoption); `annotations` is the wrapping signer's transcription of the
 * tool's hints, on which the mapping operates. The wrapper's OWN effect is envelope field 7, not a body
 * field.
 */
final class ToolCall
{
    public string $tool;
    public string $args;
    public Annotations $annotations;

    public function __construct(string $tool, string $args, Annotations $annotations)
    {
        $this->tool = $tool;
        $this->args = $args;
        $this->annotations = $annotations;
    }

    public function toMap(): M
    {
        return new M([
            [new U(1), new B($this->tool)],
            [new U(2), new B($this->args)],
            [new U(3), $this->annotations->toValue()],
        ]);
    }

    /** Deterministic-CBOR encoding of the tool-call body {1:tool,2:args,3:annotations}. */
    public function bytes(): string
    {
        return Cbor::encode($this->toMap());
    }

    /** The tool-call body's content id (T1 framing). */
    public function contentId(): string
    {
        return Cbor::contentId($this->bytes());
    }

    /** The (tool_id, args_id) binding whose content id an approval binds for this call. */
    public function callBinding(): CallBinding
    {
        return Mcp::newCallBinding($this->tool, $this->args);
    }

    /**
     * Build the (unsigned) N-AALP envelope object carrying this tool call: tier 1, Bridge channel, kind
     * McpToolCall, the wrapping signer's DECLARED effect as field 7, the tool-call body as field 10, and
     * $causes. The caller signs it; the signer BECOMES accountable for the declared effect and the
     * annotation transcription. A declared effect outside the closed lattice is rejected fail-closed.
     * Under-declaration is NOT rejected here — it is a signed, attributable claim whose inconsistency
     * verifyToolCall surfaces as EffectUnderDeclared at the enforcement point.
     *
     * @param array<int,string> $causes
     */
    public function envelopeObject(string $signer, int $created, int $profile, int $declared, array $causes): NaalpObject
    {
        if ($declared > Policy::DESTRUCTIVE) {
            throw new McpError("EffectOutsideLattice", "declared effect outside the closed lattice");
        }
        return new NaalpObject(
            kind: Mcp::KIND_MCP_TOOL_CALL,
            channel: Mcp::CHANNEL_BRIDGE,
            signer: $signer,
            created: $created,
            effect: $declared,
            body: $this->toMap(),
            tier: Mcp::TIER,
            profile: $profile,
            causes: $causes
        );
    }
}

/**
 * Names the exact tool call by content id: the tool bytes' content id AND the args bytes' content id. An
 * approval binds the content id of THIS binding, so a changed tool description (new toolId) OR changed
 * arguments (new argsId) yields a new call content id and invalidates a prior approval bound to the old
 * one (Requirement 6.1 / AC-6.1.2, AC-6.1.3).
 */
final class CallBinding
{
    public string $toolId; // multihash(0x20, SHA-384(tool bytes))
    public string $argsId; // multihash(0x20, SHA-384(args bytes))

    public function __construct(string $toolId, string $argsId)
    {
        $this->toolId = $toolId;
        $this->argsId = $argsId;
    }

    public function toMap(): M
    {
        return new M([
            [new U(1), new B($this->toolId)],
            [new U(2), new B($this->argsId)],
        ]);
    }

    /** Deterministic-CBOR encoding of the call binding {1:tool_id, 2:args_id}. */
    public function bytes(): string
    {
        return Cbor::encode($this->toMap());
    }

    /** The call content id an approval binds: multihash(0x20, SHA-384(binding)). */
    public function contentId(): string
    {
        return Cbor::contentId($this->bytes());
    }
}

/**
 * An MCP tool call that has passed envelope verification and effect resolution. It carries the enforced
 * effect (the more-severe value C5 authorizes on), whether the annotation and declared effect disagreed
 * (mismatch — attributable to signer), and the parsed tool call.
 */
final class McpResolved
{
    public string $contentId;
    public string $signer;
    public ToolCall $toolCall;
    public int $annotationMapped; // the effect the published table derives from the annotations
    public int $declared;         // the wrapping signer's declared envelope effect (field 7)
    public int $enforced;         // the enforced effect: max(annotationMapped, declared) == declared
    public bool $mismatch;        // annotationMapped != declared (attributable to signer)

    public function __construct(string $contentId, string $signer, ToolCall $toolCall, int $annotationMapped, int $declared, int $enforced, bool $mismatch)
    {
        $this->contentId = $contentId;
        $this->signer = $signer;
        $this->toolCall = $toolCall;
        $this->annotationMapped = $annotationMapped;
        $this->declared = $declared;
        $this->enforced = $enforced;
        $this->mismatch = $mismatch;
    }
}

final class Mcp
{
    // Channel binding, the tier-1 kind code, and the tier (design §6.1). McpToolCall is kind 1 on the
    // Bridge channel — a named escalation over the frozen baseline Carriage kind (0) (R-15A.2).
    public const CHANNEL_BRIDGE = 0x000D;
    public const KIND_MCP_TOOL_CALL = 1;
    public const TIER = 1;

    // Annotation CBOR keys inside a naalp-mcp-annotations map (each value is the uint 1/0; no CBOR bool).
    public const KEY_READ_ONLY = 1;    // MCP readOnlyHint
    public const KEY_DESTRUCTIVE = 2;  // MCP destructiveHint
    public const KEY_IDEMPOTENT = 3;   // MCP idempotentHint
    public const KEY_OPEN_WORLD = 4;   // MCP openWorldHint (ADVISORY — not an effect determinant)

    // MCP documented defaults for an ABSENT hint. destructiveHint defaults to TRUE, so an un-annotated
    // write maps to destructive — the fail-closed default.
    public const DEFAULT_READ_ONLY = false;
    public const DEFAULT_DESTRUCTIVE = true;
    public const DEFAULT_IDEMPOTENT = false;

    /**
     * Parse a naalp-mcp-annotations map. Rejects (MalformedAnnotation, fail-closed): a non-map, a
     * non-uint key, a non-uint value, a hint value outside {0,1} (it transcribes no boolean), a duplicate
     * key, or an annotation key outside the closed mapping {1,2,3,4}. Such a set would map outside the
     * closed lattice, so it is rejected, never defaulted to benign (AC-6.1.2).
     */
    public static function annotationsFromValue(mixed $v): Annotations
    {
        if (!($v instanceof M)) {
            throw new McpError("MalformedAnnotation", "annotation set is not a map");
        }
        $a = new Annotations();
        $seen = [];
        foreach ($v->pairs as [$k, $val]) {
            if (!($k instanceof U)) {
                throw new McpError("MalformedAnnotation", "non-uint annotation key");
            }
            if (!($val instanceof U) || $val->v > 1) { // a hint value outside {0,1} maps outside the lattice
                throw new McpError("MalformedAnnotation", "annotation hint value is outside {0,1}");
            }
            if (\array_key_exists($k->v, $seen)) {
                throw new McpError("MalformedAnnotation", "duplicate annotation key");
            }
            $seen[$k->v] = true;
            $flag = $val->v === 1;
            switch ($k->v) {
                case self::KEY_READ_ONLY:
                    $a->readOnly = $flag;
                    break;
                case self::KEY_DESTRUCTIVE:
                    $a->destructive = $flag;
                    break;
                case self::KEY_IDEMPOTENT:
                    $a->idempotent = $flag;
                    break;
                case self::KEY_OPEN_WORLD:
                    $a->openWorld = $flag;
                    break;
                default:
                    throw new McpError("MalformedAnnotation", "annotation key outside the closed mapping");
            }
        }
        return $a;
    }

    /**
     * Map a tool's transcribed annotations to the closed four-effect lattice by the published table,
     * applying the MCP default for each absent hint:
     *   readOnlyHint true                                  -> read_only
     *   readOnlyHint false, destructiveHint true           -> destructive
     *   readOnlyHint false, destructiveHint false, idem T  -> idempotent_write
     *   readOnlyHint false, destructiveHint false, idem F  -> non_idempotent_write
     * An absent readOnlyHint defaults false (a write); an absent destructiveHint defaults TRUE
     * (destructive) — so a tool with no annotations maps to destructive, the fail-closed collapse to the
     * most-severe. openWorldHint is never consulted (design §5).
     */
    public static function mapAnnotationsToEffect(Annotations $a): int
    {
        $ro = $a->readOnly ?? self::DEFAULT_READ_ONLY;
        $de = $a->destructive ?? self::DEFAULT_DESTRUCTIVE;
        $idem = $a->idempotent ?? self::DEFAULT_IDEMPOTENT;
        if ($ro) {
            return Policy::READ_ONLY;
        }
        if ($de) {
            return Policy::DESTRUCTIVE;
        }
        if ($idem) {
            return Policy::IDEMPOTENT_WRITE;
        }
        return Policy::NON_IDEMPOTENT_WRITE;
    }

    /**
     * The more-severe resolution (the good-regulator attenuator). Given the annotation-derived effect and
     * the wrapping signer's declared effect, return [enforced, mismatch] — the enforced effect being the
     * MORE SEVERE (equal to $declared on success), and mismatch whether the two disagreed (attributable
     * to the wrapping signer). A declared value outside the closed lattice is EffectOutsideLattice; a
     * declared value BELOW the annotation-derived effect is EffectUnderDeclared (a wrapper's declared
     * effect can never sit under its own carried annotations' mapping).
     *
     * @return array{0:int,1:bool}
     */
    public static function resolveEnforcedEffect(int $annotationMapped, int $declared): array
    {
        if ($declared > Policy::DESTRUCTIVE) {
            throw new McpError("EffectOutsideLattice", "declared effect outside the closed four-effect lattice");
        }
        if ($declared < $annotationMapped) {
            throw new McpError("EffectUnderDeclared", "declared effect is below the annotation-mapped effect");
        }
        return [$declared, $declared !== $annotationMapped];
    }

    /**
     * Parse an envelope object body (a decoded CBOR value) into a ToolCall. A body that is not exactly
     * {1:tool bstr, 2:args bstr, 3:annotations map} with those value types is ToolCallMalformed; a
     * malformed annotation set is MalformedAnnotation. Fail-closed.
     */
    public static function toolCallFromBody(mixed $v): ToolCall
    {
        if (!($v instanceof M)) {
            throw new McpError("ToolCallMalformed", "tool-call body is not a map");
        }
        $tool = $args = null;
        $ann = null;
        $haveAnn = false;
        foreach ($v->pairs as [$k, $val]) {
            if (!($k instanceof U)) {
                throw new McpError("ToolCallMalformed", "non-uint tool-call body key");
            }
            if ($k->v === 1) {
                if (!($val instanceof B)) {
                    throw new McpError("ToolCallMalformed", "tool is not a bstr");
                }
                $tool = $val->v;
            } elseif ($k->v === 2) {
                if (!($val instanceof B)) {
                    throw new McpError("ToolCallMalformed", "args is not a bstr");
                }
                $args = $val->v;
            } elseif ($k->v === 3) {
                $ann = self::annotationsFromValue($val); // raises MalformedAnnotation
                $haveAnn = true;
            } else {
                throw new McpError("ToolCallMalformed", "unknown tool-call body field " . $k->v);
            }
        }
        if ($tool === null || $args === null || !$haveAnn) {
            throw new McpError("ToolCallMalformed", "tool-call body missing a mandatory field");
        }
        return new ToolCall($tool, $args, $ann);
    }

    /** Compute the call binding from the raw tool and args bytes. */
    public static function newCallBinding(string $tool, string $args): CallBinding
    {
        return new CallBinding(Cbor::contentId($tool), Cbor::contentId($args));
    }

    /** Accepts exactly this surface's tier-1 kind (Bridge channel, McpToolCall). */
    public static function kindValidator(int $channel, int $kind): bool
    {
        return $channel === self::CHANNEL_BRIDGE && $kind === self::KIND_MCP_TOOL_CALL;
    }

    /**
     * Accepts the frozen baseline kinds OR the tier-1 McpToolCall — the validator an MCP-aware endpoint
     * passes to Envelope::verify. A baseline-only endpoint using the baseline validator alone correctly
     * rejects an McpToolCall as UnknownKind (fail-closed).
     */
    public static function composedKindValidator(int $channel, int $kind): bool
    {
        try {
            Channels::lookup($channel, $kind);
            return true;
        } catch (UnknownKind $e) {
            return self::kindValidator($channel, $kind);
        }
    }

    /**
     * Verify a signed MCP wrapper end-to-end and resolve its enforced effect. It (1) verifies the signed
     * object (Envelope::verify against the composed validator — content id, ranges, header/body, kind
     * dispatch, profile floor; structural ML-DSA in the pure tier); (2) confirms it is a tier-1 Bridge
     * McpToolCall; (3) parses the tool-call body (rejecting a malformed annotation set); (4) recomputes
     * the annotation-derived effect from the CARRIED annotations, independent of the declared effect;
     * (5) resolves the enforced effect to the MORE SEVERE, rejecting under-declaration. The enforced
     * effect equals the declared envelope effect on success, so the object's field 7 is the correct C5
     * authorization input. Any failure returns its named error and authorizes nothing (fail-closed).
     */
    public static function verifyToolCall(int $profile, int $alg, string $pubkey, string $signedObj): McpResolved
    {
        $o = Envelope::verify($profile, $alg, $pubkey, [self::class, 'composedKindValidator'], $signedObj);
        if ($o->channel !== self::CHANNEL_BRIDGE || $o->kind !== self::KIND_MCP_TOOL_CALL || $o->tier !== self::TIER) {
            throw new McpError("ToolCallMalformed", "not a tier-1 Bridge McpToolCall");
        }
        $tc = self::toolCallFromBody($o->body);
        $mapped = self::mapAnnotationsToEffect($tc->annotations);
        $declared = $o->effect; // Envelope::verify already range-checked field 7
        [$enforced, $mismatch] = self::resolveEnforcedEffect($mapped, $declared);
        return new McpResolved((string) $o->id, $o->signer, $tc, $mapped, $declared, $enforced, $mismatch);
    }

    /**
     * Enforce the profile's per-call approval gate for a verified tool call. The approval MUST bind the
     * EXACT call binding content id (tool_id + args_id) — so it satisfies neither a call with different
     * arguments nor a call whose tool description changed (Requirement 6.1) — its granted effect must
     * cover the call's ENFORCED (more-severe) effect, it must be unexpired at $now, and it is consumed
     * single-use by $by through the §7 ledger. Precedence and fail-closed behaviour mirror the spine: a
     * non-matching or under-granting approval denies ApprovalRequired with no ledger append; an
     * already-spent approval denies AlreadyConsumed; the consume (the single state change) happens only
     * when every check holds. $approverVerify is `fn(string $msg, string $sig): bool`.
     */
    public static function authorizeCall(McpResolved $r, ApprovalRecord $appr, callable $approverVerify, string $apprSig, string $by, int $now, Ledger $ledger): void
    {
        $callCid = $r->toolCall->callBinding()->contentId();
        try {
            Approval::verifyApproval($appr, $approverVerify, $apprSig, $callCid, $now);
        } catch (ApprovalMismatch $e) {
            // A mismatch on the exact call bytes is a held outcome, not a silent pass (§7.3/§7.4).
            throw new ApprovalRequired("approval does not bind this exact call");
        }
        // BadSignature / ApprovalExpired propagate unchanged (fail-closed).
        if (!Policy::authorizes($appr->grant, $r->enforced)) {
            throw new ApprovalRequired("the approval's granted effect does not cover the call");
        }
        $ledger->consume($appr->id(), $by); // AlreadyConsumed on replay (fail-closed, no double-spend)
    }
}
