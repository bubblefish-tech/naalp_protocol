<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
/**
 * N-AALP C15 — multi-hop AGENT delegation for the PHP SDK (design.md §18; R-DEL-1..8), a Phase-3
 * draft-01 ADDITIVE tier-1 surface over the frozen spine. It introduces NO new envelope, encoding,
 * signature, identity, or audit mechanism (R-11.3): a DelegationGrant is a normal N-AALP object, and
 * the mechanism REUSES the -00 CapDelegate substrate — parent-by-content-id in `causes` (§8.2) and the
 * `CapExceedsParent` attenuation (§6.1 lattice). The only additions over CapDelegate are the body's
 * `subject`, `max_depth`, and validity window.
 *
 * Agent-delegation answers WHO may act on whose behalf, across multiple hops, with a chain that
 * terminates at a trust anchor. The ISSUER is NOT a body field — it is the verified envelope signer
 * (R-DEL-3); the delegation PARENT is named by content id in the envelope `causes`, not in the body.
 *
 * The graded surfaces (an independent transcription of impl/go/delegation, cross-read against
 * impl/python/naalp/delegation.py, graded against vectors/delegation/cases.json):
 *   - the DelegationGrant wire body (byte-graded: Grant::bytes / Grant::contentId == oracle);
 *   - the D2 scope-containment truth table (Delegation::scopeContained == oracle);
 *   - the 12-step leaf->root chain verifier (verdict-graded: verifyChain reproduces the oracle's
 *     verdict for every scenario), driven through the real VerifyGrantObject envelope path.
 *
 * CRYPTO SCOPE (PURE-ONLY): PHP has no deterministic ML-DSA (FIPS 204) verifier, so a DelegationGrant
 * object is verified STRUCTURALLY end-to-end (content-id binding, field ranges, header/body copies,
 * version, kind dispatch, the profile floor — ML-DSA-65 is level 3, clearing the Public floor — and
 * the R-DEL-3 issuer->signer-id binding) with the ML-DSA signature itself NOT verified (documented
 * PURE-ONLY behaviour of Naalp\Envelope::verify). The corpus-graded surfaces (grant bytes, scope
 * containment, chain verdicts) are all signature-independent. The Ed25519 leg is classical (level 0)
 * and below the profile floor, so grants use the ML-DSA structural path exactly as the reference does.
 *
 * Every check is fail-closed (§15): an action that fails any step is rejected whole, returns its
 * named error, and causes no state change. There is no partial credit and no fail-open path.
 */

declare(strict_types=1);

namespace Naalp;

// Named, fail-closed errors; $kind is a stable string mirroring the Go/Rust/Python error kinds.
// REUSED unchanged: ChainBroken (Audit.php), NonNFC + SignerMismatch (Identity.php), ApprovalRequired
// + AlreadyConsumed (Approval.php). New here: the delegation-chain vocabulary + the CapExceedsParent
// and EffectNotAuthorized kinds the reference draws from the channels/policy layers.
class GrantExpired extends \RuntimeException
{
    public string $kind = "GrantExpired";
}
class GrantNotYetValid extends \RuntimeException
{
    public string $kind = "GrantNotYetValid";
}
class GrantRevoked extends \RuntimeException
{
    public string $kind = "GrantRevoked";
}
class UntrustedChainRoot extends \RuntimeException
{
    public string $kind = "UntrustedChainRoot";
}
class DelegationDepthExceeded extends \RuntimeException
{
    public string $kind = "DelegationDepthExceeded";
}
class GrantMalformed extends \RuntimeException
{
    public string $kind = "GrantMalformed";
}
class CapExceedsParent extends \RuntimeException
{
    public string $kind = "CapExceedsParent";
}
class EffectNotAuthorized extends \RuntimeException
{
    public string $kind = "EffectNotAuthorized";
}

/**
 * The signed body of a DelegationGrant. `subject` is the delegatee agent id (signer-id form, MUST be
 * NFC); `effectCap` the max effect this grant conveys; `maxDepth` the max FURTHER delegation hops
 * below it; `notBefore`/`notAfter` the validity window; `scope` an OPTIONAL NFC resource scope
 * ("" = absent/unconstrained, field 6 omitted — an empty scope is not a distinct value).
 */
final class Grant
{
    public string $subject;
    public int $effectCap;
    public int $maxDepth;
    public int $notBefore;
    public int $notAfter;
    public string $scope;

    public function __construct(string $subject, int $effectCap, int $maxDepth, int $notBefore, int $notAfter, string $scope = "")
    {
        $this->subject = $subject;
        $this->effectCap = $effectCap;
        $this->maxDepth = $maxDepth;
        $this->notBefore = $notBefore;
        $this->notAfter = $notAfter;
        $this->scope = $scope;
    }

    /** The grant body as a CBOR map {1:subject,2:effect_cap,3:max_depth,4:not_before,5:not_after,?6:scope}. */
    public function toMap(): M
    {
        $pairs = [
            [new U(1), new T($this->subject)],
            [new U(2), new U($this->effectCap)],
            [new U(3), new U($this->maxDepth)],
            [new U(4), new U($this->notBefore)],
            [new U(5), new U($this->notAfter)],
        ];
        if ($this->scope !== "") { // "" == absent (field 6 omitted); an empty scope is not a distinct value
            $pairs[] = [new U(6), new T($this->scope)];
        }
        return new M($pairs);
    }

    /** Deterministic-CBOR encoding of the grant body. */
    public function bytes(): string
    {
        return Cbor::encode($this->toMap());
    }

    /**
     * The grant body's content id: multihash(0x20, SHA-384(body)). This is the body's self-address;
     * the ENVELOPE content id (from Envelope) is what a delegation chain wires into `causes`.
     */
    public function contentId(): string
    {
        return Cbor::contentId($this->bytes());
    }

    /**
     * Build the (unsigned) N-AALP envelope object carrying this grant: tier 1, Capability channel,
     * kind DelegationGrant, the grant's own effect non_idempotent_write, the grant body as the object
     * body, and `causes` naming the delegation parent by content id (empty for a root grant). The
     * signer BECOMES the grant's issuer (R-DEL-3). A non-NFC subject/scope or an out-of-range
     * effect_cap is rejected fail-closed.
     *
     * @param array<int,string> $causes
     */
    public function envelopeObject(string $issuer, int $created, int $profile, array $causes): NaalpObject
    {
        try {
            Identity::requireNfc($this->subject);
        } catch (NonNFC $e) {
            throw new NonNFC("subject is not Unicode NFC");
        }
        if ($this->scope !== "") {
            try {
                Identity::requireNfc($this->scope);
            } catch (NonNFC $e) {
                throw new NonNFC("scope is not Unicode NFC");
            }
        }
        if ($this->effectCap > Policy::DESTRUCTIVE) {
            throw new GrantMalformed("effect_cap outside the closed lattice");
        }
        return new NaalpObject(
            kind: Delegation::KIND_DELEGATION_GRANT,
            channel: Delegation::CHANNEL_CAPABILITY,
            signer: $issuer,
            created: $created,
            effect: Delegation::GRANT_EFFECT,
            body: $this->toMap(),
            tier: Delegation::TIER,
            profile: $profile,
            causes: $causes
        );
    }
}

/**
 * A DelegationGrant that has passed envelope verification and integrity binding: its ENVELOPE content
 * id (what `causes` point to), its verified issuer id (the envelope signer — NOT a body field,
 * R-DEL-3), the parsed grant body, and the grant's own `causes`.
 */
final class Resolved
{
    public string $contentId;
    public string $issuer;
    public Grant $grant;
    /** @var array<int,string> */
    public array $causes;

    /** @param array<int,string> $causes */
    public function __construct(string $contentId, string $issuer, Grant $grant, array $causes)
    {
        $this->contentId = $contentId;
        $this->issuer = $issuer;
        $this->grant = $grant;
        $this->causes = \array_values($causes);
    }
}

/**
 * The verified action whose delegated authority is being checked. It carries the acting agent (the
 * verified signer of the action object, R-DEL-2), the action's own effect and resource scope (the
 * running child at the leaf hop), and the action's `causes` (from which the leaf grant is located).
 */
final class Action
{
    public string $signer;
    public int $effect;
    public string $scope;
    /** @var array<int,string> */
    public array $causes;

    /** @param array<int,string> $causes */
    public function __construct(string $signer, int $effect, string $scope, array $causes)
    {
        $this->signer = $signer;
        $this->effect = $effect;
        $this->scope = $scope;
        $this->causes = \array_values($causes);
    }
}

final class Delegation
{
    public const CHANNEL_CAPABILITY = 0x0002; // Capability channel (reuses the CapDelegate substrate)
    public const KIND_DELEGATION_GRANT = 4;   // tier-1 kind code (next free after CapIssue/Delegate/Revoke/Lookup)
    public const TIER = 1;                     // a named escalation adding multi-hop capability (R-15A.2)
    public const GRANT_EFFECT = Policy::NON_IDEMPOTENT_WRITE; // a grant's OWN envelope effect (field 7)

    // ---- kind validation (composes with the frozen baseline) ----------------------------------

    /** Accepts exactly this surface's tier-1 kind (Capability channel, DelegationGrant). */
    public static function kindValidator(int $channel, int $kind): bool
    {
        return $channel === self::CHANNEL_CAPABILITY && $kind === self::KIND_DELEGATION_GRANT;
    }

    /**
     * Accepts the frozen baseline kinds OR the tier-1 DelegationGrant — the validator a
     * delegation-aware endpoint passes to Envelope::verify. A baseline-only endpoint using the
     * baseline validator alone correctly rejects a DelegationGrant as UnknownKind (fail-closed).
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

    // ---- verified grants + the trust/revocation inputs ----------------------------------------

    /**
     * Verify a signed DelegationGrant end-to-end (Envelope::verify against the composed validator),
     * confirm it is a tier-1 Capability DelegationGrant whose own effect is non_idempotent_write, bind
     * the claimed issuer id to the verifying key (a self-asserted issuer that does not derive from the
     * authenticated key confers nothing, R-DEL-3), and parse the grant body. Any failure is an
     * unverifiable link (ChainBroken / SignerMismatch / the envelope's named error), fail-closed.
     */
    public static function verifyGrantObject(int $profile, int $alg, string $pubkey, string $signedObj): Resolved
    {
        $o = Envelope::verify($profile, $alg, $pubkey, [self::class, 'composedKindValidator'], $signedObj);
        if ($o->channel !== self::CHANNEL_CAPABILITY || $o->kind !== self::KIND_DELEGATION_GRANT || $o->tier !== self::TIER) {
            throw new ChainBroken("not a tier-1 Capability DelegationGrant");
        }
        if ($o->effect !== self::GRANT_EFFECT) {
            throw new ChainBroken("a DelegationGrant's own effect must be non_idempotent_write");
        }
        $issuer = Identity::signerId($alg, $pubkey);
        if ($o->signer !== $issuer) { // the envelope signer field MUST be the authenticated id
            throw new SignerMismatch("issuer id does not derive from the verifying key");
        }
        $g = self::grantFromBody($o->body);
        return new Resolved((string) $o->id, $issuer, $g, $o->causes);
    }

    /**
     * Parse an envelope object body back into a Grant. A body that is not exactly the {1,2,3,4,5,?6}
     * map with the right value types and an in-range effect_cap is an unverifiable/malformed grant
     * link and is rejected ChainBroken (fail-closed). An out-of-range effect_cap is NEVER normalized
     * up (that would widen a ceiling — fail-open); it is rejected.
     */
    public static function grantFromBody(mixed $v): Grant
    {
        if (!($v instanceof M)) {
            throw new ChainBroken("grant body is not a map");
        }
        $g = new Grant("", 0, 0, 0, 0, "");
        $seen = [];
        foreach ($v->pairs as [$k, $val]) {
            if (!($k instanceof U) || $k->v < 1 || $k->v > 6) {
                throw new ChainBroken("grant body has an out-of-range field");
            }
            switch ($k->v) {
                case 1:
                    if (!($val instanceof T)) {
                        throw new ChainBroken("subject is not a tstr");
                    }
                    $g->subject = $val->v;
                    break;
                case 2:
                    if (!($val instanceof U) || $val->v > Policy::DESTRUCTIVE) {
                        throw new ChainBroken("effect_cap absent or out of range");
                    }
                    $g->effectCap = $val->v;
                    break;
                case 3:
                    if (!($val instanceof U)) {
                        throw new ChainBroken("max_depth is not a uint");
                    }
                    $g->maxDepth = $val->v;
                    break;
                case 4:
                    if (!($val instanceof U)) {
                        throw new ChainBroken("not_before is not a uint");
                    }
                    $g->notBefore = $val->v;
                    break;
                case 5:
                    if (!($val instanceof U)) {
                        throw new ChainBroken("not_after is not a uint");
                    }
                    $g->notAfter = $val->v;
                    break;
                case 6:
                    if (!($val instanceof T)) {
                        throw new ChainBroken("scope is not a tstr");
                    }
                    $g->scope = $val->v;
                    break;
            }
            $seen[$k->v] = true;
        }
        if (!(isset($seen[1]) && isset($seen[2]) && isset($seen[3]) && isset($seen[4]) && isset($seen[5]))) {
            throw new ChainBroken("grant body is missing a mandatory field"); // scope (6) is optional
        }
        return $g;
    }

    /**
     * Whether the grant named by content id $cid is revoked as of $now (a revoke ordered at or before
     * $now). $revoked maps a revoked grant's content id (raw-string key) to its revoke position.
     *
     * @param array<string,int> $revoked
     */
    public static function revokedAt(array $revoked, string $cid, int $now): bool
    {
        return \array_key_exists($cid, $revoked) && $revoked[$cid] <= $now;
    }

    // ---- D2 scope containment (design §18.1) --------------------------------------------------

    /**
     * Whether $child is contained in $parent under the D2 path-prefix rule: an absent parent scope
     * ("") is unconstrained; otherwise the child must equal the parent or begin with parent + "/". A
     * missing child scope ("") under a scoped parent WIDENS authority and is NOT contained.
     */
    public static function scopeContained(string $child, string $parent): bool
    {
        if ($parent === "") {
            return true; // unconstrained parent
        }
        if ($child === "") {
            return false; // missing child scope under a scoped parent widens authority
        }
        if ($child === $parent) {
            return true;
        }
        return \str_starts_with($child, $parent . "/");
    }

    /**
     * The distinct verified grants named in $causes whose subject equals $subject (the parent/leaf
     * resolution predicate). Duplicate content ids are counted once.
     *
     * @param array<int,string>    $causes
     * @param array<string,Resolved> $grants
     * @return array<int,Resolved>
     */
    private static function matchingCauses(array $causes, string $subject, array $grants): array
    {
        $seen = [];
        $out = [];
        foreach ($causes as $c) {
            if (isset($seen[$c])) {
                continue;
            }
            if (isset($grants[$c]) && $grants[$c]->grant->subject === $subject) {
                $seen[$c] = true;
                $out[] = $grants[$c];
            }
        }
        return $out;
    }

    // ---- D3 chain verification (design §18.2) -------------------------------------------------

    /**
     * The 12-step leaf->root delegation-chain walk, fail-closed with no partial credit. $grants are
     * the verified grants keyed by envelope content id; $anchors is the trust-anchor issuer-id set
     * (id => true); $revoked maps a revoked grant's content id to its revoke position; $now is the
     * action's authoritative ordering position (§8.1 receipt seq/at, NOT the signer's clock). Returns
     * nothing iff the chain terminates at a trusted root with every hop holding; otherwise throws the
     * specific named error and authorizes nothing.
     *
     * @param array<string,Resolved> $grants
     * @param array<string,bool>     $anchors
     * @param array<string,int>      $revoked
     */
    public static function verifyChain(Action $action, array $grants, array $anchors, array $revoked, int $now): void
    {
        // step 2 — locate the unique leaf grant among the action's causes whose subject == the actor.
        $leaves = self::matchingCauses($action->causes, $action->signer, $grants);
        if (\count($leaves) === 0) {
            throw new EffectNotAuthorized("no delegation authorizes this action");
        }
        if (\count($leaves) > 1) {
            throw new ChainBroken("more than one authorizing grant is ambiguous");
        }
        $g = $leaves[0];
        $childEffect = $action->effect;
        $childScope = $action->scope;
        $pos = 0; // realized delegation hops beneath the current grant
        $visited = [];

        while (true) {
            $key = $g->contentId;
            if (isset($visited[$key])) { // a content-id cycle (infeasible for a real hash chain)
                throw new ChainBroken("content-id cycle in the delegation chain");
            }
            $visited[$key] = true;

            // step 4 — validity window at $now.
            if ($now < $g->grant->notBefore) {
                throw new GrantNotYetValid("grant is before its not_before at this position");
            }
            if ($now > $g->grant->notAfter) {
                throw new GrantExpired("grant is past its not_after at this position");
            }
            // step 5 — revocation at $now.
            if (self::revokedAt($revoked, $g->contentId, $now)) {
                throw new GrantRevoked("grant is revoked at or before this position");
            }
            // step 6 — attenuation (CapExceedsParent): effect ceiling AND scope containment.
            if (!Policy::authorizes($g->grant->effectCap, $childEffect)) {
                throw new CapExceedsParent("child effect exceeds this grant's effect_cap");
            }
            if (!self::scopeContained($childScope, $g->grant->scope)) {
                throw new CapExceedsParent("child scope is not contained in this grant's scope");
            }
            // step 9 — realized-depth bound: $pos grants sit beneath g, so pos must not exceed max_depth.
            if ($pos > $g->grant->maxDepth) {
                throw new DelegationDepthExceeded("realized delegation depth exceeds max_depth");
            }
            // step 7 — resolve g's delegation parent (the unique cause whose subject == g's issuer).
            $parents = self::matchingCauses($g->causes, $g->issuer, $grants);
            if (\count($parents) > 1) {
                throw new ChainBroken("ambiguous delegation parent");
            }
            if (\count($parents) === 0) {
                // steps 10 / 11 — root test: g has no delegation parent.
                if (isset($anchors[$g->issuer]) && $anchors[$g->issuer]) {
                    return; // terminated at a trusted root: authorized
                }
                throw new UntrustedChainRoot("the chain root's issuer is not a trust anchor");
            }
            $p = $parents[0];
            // step 8 — declared-depth attenuation: g.max_depth <= p.max_depth - 1 (no unsigned
            // underflow; a parent with max_depth 0 admits no child grant).
            if ($p->grant->maxDepth === 0 || $g->grant->maxDepth >= $p->grant->maxDepth) {
                throw new DelegationDepthExceeded("declared delegation depth exceeds parent");
            }
            $childEffect = $g->grant->effectCap;
            $childScope = $g->grant->scope;
            $g = $p;
            $pos += 1;
        }
    }

    // ---- D4 composition with per-action approval (design §18.3, R-DEL-8) -----------------------

    /**
     * The D4 two-gate composition: a destructive-effect action requires BOTH a valid delegation chain
     * (D3) terminating at a trusted root AND a valid, unconsumed, exact-bytes §7 approval whose granted
     * effect covers the action, CONSUMED single-use by the acting agent (accountability binds to it).
     * Precedence: the chain is checked first, so a broken chain denies with its D3 error even when an
     * approval is present; a valid chain with no valid approval denies ApprovalRequired; a
     * valid-but-already-consumed approval denies AlreadyConsumed. The approval is CONSUMED (the single
     * state change) only when both gates hold; a rejected action makes no ledger append. `$verify` is
     * the injected approval-signature verifier `fn(string $msg, string $sig): bool` (Ed25519 here).
     *
     * @param array<string,Resolved> $grants
     * @param array<string,bool>     $anchors
     * @param array<string,int>      $revoked
     */
    public static function authorizeDestructive(
        Action $action,
        array $grants,
        array $anchors,
        array $revoked,
        int $now,
        ApprovalRecord $appr,
        callable $verify,
        string $apprSig,
        string $argsContentId,
        Ledger $ledger
    ): void {
        // Gate 1 — the delegation chain (D3). A broken chain denies with its named D3 error.
        self::verifyChain($action, $grants, $anchors, $revoked, $now);
        // Gate 2 — a valid, unconsumed, exact-bytes approval over the action's args, consumed by the actor.
        try {
            Approval::verifyApproval($appr, $verify, $apprSig, $argsContentId, $now);
        } catch (\Throwable $e) {
            throw new ApprovalRequired("no valid approval on a destructive action (held §7.3)");
        }
        if (!Policy::authorizes($appr->grant, $action->effect)) {
            throw new ApprovalRequired("the approval's granted effect does not cover the action");
        }
        // Consume single-use. The ledger's AlreadyConsumed surfaces fail-closed: a spent approval is
        // not fresh authority. A rejected action above makes no ledger append.
        $ledger->consume($appr->id(), $action->signer);
    }
}
