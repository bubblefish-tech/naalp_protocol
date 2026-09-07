<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
/**
 * N-AALP C5 effect vocabulary and authorization for the PHP SDK (§6).
 *
 * The closed four-value effect set aligned 1:1 with the N-PAMP Bridge SafetyLabel; an
 * unrecognized value fails closed to destructive (R-6.2); authorization is the §6.1 lattice
 * (action <= ceiling). The optional signed safety label is a CBOR map {1:risk, 2:scope}.
 *
 * Also carries the R-6.5 authorization-principal rule (only a signature-derived identity is
 * ever an authorization principal — a transport/foreign-header/client-asserted identity is
 * refused UnauthenticatedPrincipal) and the R-6.3 endpoint policy check (PolicyGrant, an
 * independent transcription of impl/go/policy.Grant — named PolicyGrant here, not Grant,
 * because Naalp\Grant already names the unrelated C15 DelegationGrant body in this flat
 * namespace) that makes the effect an authorization input, not a hint, plus the strict R-6.4
 * SafetyLabelFromExt extraction. Fail-closed throughout (§15): a failing check performs no
 * side effect and returns/throws its named error.
 */

declare(strict_types=1);

namespace Naalp;

// Named, fail-closed errors; $kind mirrors the Go/Rust/Python error kinds (see Naming.php class
// NameMalformed for the idiom). EffectNotAuthorized is REUSED, unchanged, from Delegation.php
// (defined there; loaded later in bootstrap.php, which is safe — PHP resolves a class name used
// inside a method body at call time, not at file-parse time, and every file is required before any
// test runs).
class UnauthenticatedPrincipal extends \RuntimeException
{
    public string $kind = "UnauthenticatedPrincipal";
}
class MalformedSafetyLabel extends \RuntimeException
{
    public string $kind = "MalformedSafetyLabel";
}

final class Policy
{
    public const READ_ONLY = 0;
    public const IDEMPOTENT_WRITE = 1;
    public const NON_IDEMPOTENT_WRITE = 2;
    public const DESTRUCTIVE = 3;

    private const NAMES = ["read_only", "idempotent_write", "non_idempotent_write", "destructive"];

    /** Map a raw effect value to the closed set; anything outside 0..3 is destructive (R-6.2). */
    public static function normalizeEffect(int $v): int
    {
        return ($v >= 0 && $v <= 3) ? $v : self::DESTRUCTIVE;
    }

    public static function safetyLabelName(int $e): string
    {
        return self::NAMES[self::normalizeEffect($e)];
    }

    /** The §6.1 lattice: an action of class `action` is permitted under ceiling iff action <= ceiling. */
    public static function authorizes(int $ceiling, int $action): bool
    {
        return $action <= $ceiling;
    }

    /** The signed safety-label body {1: risk, 2: scope} (R-6.4). */
    public static function safetyLabelBytes(string $risk, string $scope): string
    {
        return Cbor::encode(new M([
            [new U(1), new T($risk)],
            [new U(2), new T($scope)],
        ]));
    }

    // ---- R-6.5: authorization-principal source -----------------------------------------------

    // PrincipalSource: where a claimed identity came from. Only a signature-derived identity is
    // an authorization principal (R-6.5).
    public const SOURCE_SIGNATURE = 0;          // the verified COSE signature's signer id
    public const SOURCE_TRANSPORT_METADATA = 1; // e.g. a TLS peer name / connection tag
    public const SOURCE_FOREIGN_HEADER = 2;     // e.g. an X-Agent-ID or a carried foreign header
    public const SOURCE_CLIENT_NAME = 3;        // e.g. a self-asserted clientInfo.name

    /**
     * Return the authorization principal id iff it is signature-derived and non-empty (R-6.5). A
     * transport-metadata, foreign-header, or client-supplied name is refused with
     * UnauthenticatedPrincipal — it is never treated as an authorization identity.
     */
    public static function resolveAuthPrincipal(int $src, string $id): string
    {
        if ($src !== self::SOURCE_SIGNATURE || $id === "") {
            throw new UnauthenticatedPrincipal(
                "an authorization identity must be signature-derived, not transport/foreign/client-asserted"
            );
        }
        return $id;
    }

    // ---- R-6.4: the optional signed safety label ----------------------------------------------

    /** The non-critical ext key under which the optional safety label is carried (design §6.4). */
    public const SAFETY_LABEL_EXT_KEY = 1;

    /**
     * Extract the optional safety label from an object's ext map. Returns [label, true] when a
     * well-formed label is present, [null, false] when absent, and throws MalformedSafetyLabel
     * when the ext[1] entry is present but not exactly {1:tstr, 2:tstr} — a malformed label is
     * rejected, never silently accepted.
     *
     * @return array{0: ?SafetyLabel, 1: bool}
     */
    public static function safetyLabelFromExt(M $ext): array
    {
        foreach ($ext->pairs as [$k, $v]) {
            if (!($k instanceof U) || $k->v !== self::SAFETY_LABEL_EXT_KEY) {
                continue;
            }
            if (!($v instanceof M)) {
                throw new MalformedSafetyLabel("safety label is not {1:tstr risk, 2:tstr scope}");
            }
            $risk = null;
            $scope = null;
            $haveRisk = false;
            $haveScope = false;
            foreach ($v->pairs as [$kk, $vv]) {
                if (!($kk instanceof U)) {
                    throw new MalformedSafetyLabel("safety label is not {1:tstr risk, 2:tstr scope}");
                }
                if (!($vv instanceof T)) {
                    throw new MalformedSafetyLabel("safety label is not {1:tstr risk, 2:tstr scope}");
                }
                switch ($kk->v) {
                    case 1:
                        $risk = $vv->v;
                        $haveRisk = true;
                        break;
                    case 2:
                        $scope = $vv->v;
                        $haveScope = true;
                        break;
                    default:
                        throw new MalformedSafetyLabel("safety label is not {1:tstr risk, 2:tstr scope}");
                }
            }
            if (!$haveRisk || !$haveScope) {
                throw new MalformedSafetyLabel("safety label is not {1:tstr risk, 2:tstr scope}");
            }
            return [new SafetyLabel($risk, $scope), true];
        }
        return [null, false];
    }
}

/**
 * The OPTIONAL signed safety annotation (R-6.4). It is attributable to the object's signer and
 * auditable. It is an ACCOUNTABLE CLAIM, not a guarantee the content is safe (design.md §6.4).
 */
final class SafetyLabel
{
    public string $risk;  // an accountable risk claim, e.g. "elevated"
    public string $scope; // what the object affects, e.g. "billing-records"

    public function __construct(string $risk, string $scope)
    {
        $this->risk = $risk;
        $this->scope = $scope;
    }
}

/**
 * A capability an endpoint issues to an authenticated signer id: the most dangerous effect that
 * principal is permitted to carry. The default maxEffect (Policy::READ_ONLY) is the
 * least-privilege default, so a bare `new PolicyGrant($principal)` authorizes only read_only.
 *
 * Named PolicyGrant, not Grant: Naalp\Grant already names the unrelated C15 DelegationGrant body
 * (Delegation.php) in this flat namespace, so this port cannot reuse the Go reference's bare
 * `Grant` name without colliding.
 */
final class PolicyGrant
{
    public string $principal; // the signature-derived signer id this grant is issued to
    public int $maxEffect;    // the effect ceiling this grant authorizes

    public function __construct(string $principal, int $maxEffect = Policy::READ_ONLY)
    {
        $this->principal = $principal;
        $this->maxEffect = $maxEffect;
    }

    /**
     * The endpoint policy check that makes the effect an authorization input, not a hint (R-6.3).
     * It (1) resolves the presenter's identity, refusing any non-signature source (R-6.5); (2)
     * requires that identity to match the grant's principal — no matching grant means no
     * authority; (3) normalizes the object's effect fail-closed (R-6.2) and denies it if it
     * exceeds the grant's ceiling. It performs no side effect and throws a named error on any
     * failure (fail-closed).
     */
    public function authorizeObject(int $src, string $presented, int $objectEffect): void
    {
        $who = Policy::resolveAuthPrincipal($src, $presented);
        if ($who !== $this->principal) {
            throw new EffectNotAuthorized("object effect exceeds the granted capability");
        }
        if (!Policy::authorizes($this->maxEffect, Policy::normalizeEffect($objectEffect))) {
            throw new EffectNotAuthorized("object effect exceeds the granted capability");
        }
    }
}
