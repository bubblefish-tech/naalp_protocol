<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
/**
 * N-AALP C5 effect vocabulary and authorization for the PHP SDK (§6).
 *
 * The closed four-value effect set aligned 1:1 with the N-PAMP Bridge SafetyLabel; an
 * unrecognized value fails closed to destructive (R-6.2); authorization is the §6.1 lattice
 * (action <= ceiling). The optional signed safety label is a CBOR map {1:risk, 2:scope}.
 */

declare(strict_types=1);

namespace Naalp;

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
}
