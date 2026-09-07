<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
/**
 * Manufacturing Add-ons Component F, the physical-hazard authorization extension
 * (design.md addendum; requirements F1-F5; wire authority
 * `spec/naalp-draft-01.cddl`), PHP port of
 * impl/rust/naalp-hazard/src/lib.rs (mirroring impl/csharp/Hazard.cs and
 * impl/java/.../Hazard.java).
 *
 * `effect` (Envelope field 7, Policy) describes DATA reversibility. `hazard` is a new,
 * ORTHOGONAL dimension describing PHYSICAL danger: a data-reversible action may still be a
 * high physical hazard. The two dimensions are never merged and neither derives the other.
 *
 * This module adds no new cryptography and no new CBOR codec of its own: every encode call
 * delegates to Cbor::encode / Cbor::contentId, exactly as the Rust reference crate adds no
 * crypto/encoding of its own over the graded `naalp` core.
 *
 * The fail-closed rules (F2, F3):
 *   - Hazard::classFromCode is the ONE fail-closed decode entry point: any missing or
 *     out-of-range raw value normalizes to Hazard::CLASS_MOTION_IN_SHARED_SPACE -- the highest
 *     class -- never to "absent" or any weaker class.
 *   - Hazard::hazardAuthorized requires an EXACT class match (not a <= ceiling the way the
 *     effect lattice's Policy::authorizes works) AND full containment of the claim's envelope
 *     inside the grant's on every axis, the speed bound, and the time window. Any single
 *     failing dimension denies the WHOLE claim -- there is no partial authorization.
 *   - Hazard::hazardAuthorizedOptional additionally covers the case where an action carries NO
 *     hazard claim at all: there is no envelope to check containment against, so it denies
 *     immediately with a distinct error (HazardUnknown) rather than fabricating a sentinel
 *     envelope and running the ordinary coverage check.
 */

declare(strict_types=1);

namespace Naalp;

class HazardMalformed extends \RuntimeException
{
    public string $kind = "HazardMalformed";

    public function __construct(string $msg = "hazard body is not the spec/naalp-draft-01.cddl shape, or an axis/frame is invalid")
    {
        parent::__construct($msg);
    }
}

class HazardNotCovered extends \RuntimeException
{
    public string $kind = "HazardNotCovered";

    public function __construct(string $msg = "declared hazard class or envelope is not fully covered by the authorization")
    {
        parent::__construct($msg);
    }
}

class HazardUnknown extends \RuntimeException
{
    public string $kind = "HazardUnknown";

    public function __construct(string $msg = "hazard value unrecognized or absent; no claim to check coverage against")
    {
        parent::__construct($msg);
    }
}

// ---- spatial-bounds ---------------------------------------------------------------------

/**
 * A named coordinate frame plus a signed axis-aligned bounding region in that frame, integer
 * millimeters (`spec/naalp-draft-01.cddl` `spatial-bounds`).
 *
 * @param list<array{0:int,1:int}> $axes per-axis (min, max), millimeters, signed. MUST be
 *   non-empty; every entry MUST satisfy min <= max.
 */
final class SpatialBounds
{
    public function __construct(
        public string $frame,
        public array $axes,
    ) {
    }

    /** Structural validity (`spec/naalp-draft-01.cddl`): non-empty axes, every min <= max, frame
     * non-empty and Unicode NFC. */
    public function isWellFormed(): bool
    {
        if (\count($this->axes) === 0) {
            return false;
        }
        foreach ($this->axes as $axis) {
            if ($axis[0] > $axis[1]) {
                return false;
            }
        }
        if ($this->frame === '') {
            return false;
        }
        try {
            Identity::requireNfc($this->frame);
        } catch (NonNFC $e) {
            return false;
        }
        return true;
    }

    public function toValue(): M
    {
        $axes = [];
        foreach ($this->axes as $axis) {
            $axes[] = new A([Hazard::intValue($axis[0]), Hazard::intValue($axis[1])]);
        }
        return new M([
            [new U(1), new T($this->frame)],
            [new U(2), new A($axes)],
        ]);
    }

    /** Deterministic-CBOR encoding of {1:frame,2:axes}. Malformed input still encodes (encoding
     * is not the validity gate); callers MUST check isWellFormed() before treating a
     * SpatialBounds as authoritative, exactly as fromValue() does on decode. */
    public function bytes(): string
    {
        return Cbor::encode($this->toValue());
    }

    /** Parse a `spatial-bounds` map. Rejects a non-map, an out-of-range/wrong-typed key or
     * value, a missing key, empty axes, an axis with min > max, or a non-NFC/empty frame --
     * fail-closed (HazardMalformed), never a partially-valid result. */
    public static function fromValue(mixed $v): self
    {
        if (!($v instanceof M)) {
            throw new HazardMalformed();
        }
        $frame = null;
        $axes = null;
        foreach ($v->pairs as $kv) {
            [$k, $val] = $kv;
            if (!($k instanceof U)) {
                throw new HazardMalformed();
            }
            switch ($k->v) {
                case 1:
                    if (!($val instanceof T)) {
                        throw new HazardMalformed();
                    }
                    $frame = $val->v;
                    break;
                case 2:
                    if (!($val instanceof A) || \count($val->items) === 0) {
                        throw new HazardMalformed();
                    }
                    $out = [];
                    foreach ($val->items as $it) {
                        if (!($it instanceof A) || \count($it->items) !== 2) {
                            throw new HazardMalformed();
                        }
                        $min = Hazard::intFromValue($it->items[0]);
                        $max = Hazard::intFromValue($it->items[1]);
                        if ($min > $max) {
                            throw new HazardMalformed();
                        }
                        $out[] = [$min, $max];
                    }
                    $axes = $out;
                    break;
                default:
                    throw new HazardMalformed();
            }
        }
        if ($frame === null || $axes === null) {
            throw new HazardMalformed();
        }
        $sb = new self($frame, $axes);
        if (!$sb->isWellFormed()) {
            throw new HazardMalformed();
        }
        return $sb;
    }
}

// ---- hazard-window ------------------------------------------------------------------------

/** A validity window, epoch ms, the same convention as `naalp-object` field 6 (created) and
 * `naalp-delegation-grant` fields 4/5. */
final class HazardWindow
{
    public function __construct(
        public int $notBefore,
        public int $notAfter,
    ) {
    }

    public function toValue(): M
    {
        return new M([
            [new U(1), new U($this->notBefore)],
            [new U(2), new U($this->notAfter)],
        ]);
    }

    public static function fromValue(mixed $v): self
    {
        if (!($v instanceof M)) {
            throw new HazardMalformed();
        }
        $notBefore = null;
        $notAfter = null;
        foreach ($v->pairs as $kv) {
            [$k, $val] = $kv;
            if (!($k instanceof U) || !($val instanceof U)) {
                throw new HazardMalformed();
            }
            switch ($k->v) {
                case 1:
                    $notBefore = $val->v;
                    break;
                case 2:
                    $notAfter = $val->v;
                    break;
                default:
                    throw new HazardMalformed();
            }
        }
        if ($notBefore === null || $notAfter === null) {
            throw new HazardMalformed();
        }
        return new self($notBefore, $notAfter);
    }
}

// ---- hazard-envelope -----------------------------------------------------------------------

/** The full physical envelope a claim or an authorization bounds itself by. All three fields
 * are MANDATORY on the wire (`spec/naalp-draft-01.cddl`) -- a silently-absent axis would be
 * fail-OPEN in a physical-safety context, so an issuer that means "unbounded" states so
 * explicitly with wide numeric bounds; the wire never infers permissiveness from silence here
 * (deliberate contrast with `naalp-delegation-grant`'s optional scope). */
final class HazardEnvelope
{
    public function __construct(
        public SpatialBounds $spatial,
        /** Max instantaneous speed, millimeters per second. */
        public int $speedBoundMmS,
        public HazardWindow $window,
    ) {
    }

    public function toValue(): M
    {
        return new M([
            [new U(1), $this->spatial->toValue()],
            [new U(2), new U($this->speedBoundMmS)],
            [new U(3), $this->window->toValue()],
        ]);
    }

    /** Deterministic-CBOR encoding of {1:spatial,2:speed_bound,3:window}. */
    public function bytes(): string
    {
        return Cbor::encode($this->toValue());
    }

    /** The envelope's content id (T1 framing): a pure function of the bytes above. */
    public function contentId(): string
    {
        return Cbor::contentId($this->toValue());
    }

    /** Parse a `hazard-envelope` map; fail-closed on any missing/malformed field. */
    public static function fromValue(mixed $v): self
    {
        if (!($v instanceof M)) {
            throw new HazardMalformed();
        }
        $spatial = null;
        $speed = null;
        $window = null;
        foreach ($v->pairs as $kv) {
            [$k, $val] = $kv;
            if (!($k instanceof U)) {
                throw new HazardMalformed();
            }
            switch ($k->v) {
                case 1:
                    $spatial = SpatialBounds::fromValue($val);
                    break;
                case 2:
                    if (!($val instanceof U)) {
                        throw new HazardMalformed();
                    }
                    $speed = $val->v;
                    break;
                case 3:
                    $window = HazardWindow::fromValue($val);
                    break;
                default:
                    throw new HazardMalformed();
            }
        }
        if ($spatial === null || $speed === null || $window === null) {
            throw new HazardMalformed();
        }
        return new self($spatial, $speed, $window);
    }
}

// ---- naalp-hazard-claim / naalp-hazard-authorization ----------------------------------------

/** A signed physical-hazard claim (`spec/naalp-draft-01.cddl` `naalp-hazard-claim`). Carriage
 * (the object it accompanies and how) is a wire-impact decision, not this module's concern. */
final class HazardClaim
{
    public function __construct(
        public int $class,
        public HazardEnvelope $envelope,
    ) {
    }

    public function toValue(): M
    {
        return Hazard::bodyToValue($this->class, $this->envelope);
    }

    /** Deterministic-CBOR encoding of {1:class,2:envelope}. */
    public function bytes(): string
    {
        return Cbor::encode($this->toValue());
    }

    /** The claim's content id (T1 framing). */
    public function contentId(): string
    {
        return Cbor::contentId($this->toValue());
    }

    /** Parse a `naalp-hazard-claim` body. Both class and envelope are mandatory -- a claim
     * declaring one and omitting the other is HazardMalformed, not partially valid. */
    public static function fromValue(mixed $v): self
    {
        [$class, $envelope] = Hazard::bodyFromValue($v);
        return new self($class, $envelope);
    }
}

/** A signed physical-hazard authorization ("a grant" in requirements F3's language;
 * `spec/naalp-draft-01.cddl` `naalp-hazard-authorization`). Same shape as HazardClaim
 * deliberately: one envelope shape for both sides keeps the containment check symmetric. */
final class HazardAuthorization
{
    public function __construct(
        public int $class,
        public HazardEnvelope $envelope,
    ) {
    }

    public function toValue(): M
    {
        return Hazard::bodyToValue($this->class, $this->envelope);
    }

    /** Deterministic-CBOR encoding of {1:class,2:envelope}. */
    public function bytes(): string
    {
        return Cbor::encode($this->toValue());
    }

    /** The authorization's content id (T1 framing). */
    public function contentId(): string
    {
        return Cbor::contentId($this->toValue());
    }

    /** Parse a `naalp-hazard-authorization` body. */
    public static function fromValue(mixed $v): self
    {
        [$class, $envelope] = Hazard::bodyFromValue($v);
        return new self($class, $envelope);
    }
}

// ---- Hazard: class vocabulary + F3 grant-coverage authorization ----------------------------

final class Hazard
{
    // ---- hazard-class (F2: closed, fail-closed to the highest class) ----------------------

    /** The closed five-value hazard-class vocabulary (`spec/naalp-draft-01.cddl`).
     * CLASS_MOTION_IN_SHARED_SPACE is BOTH a named class (4) and the fail-closed default for an
     * unrecognized or absent raw value (F2) -- the assumption that "the producer did not tell
     * us" is at least as dangerous as the worst named class. */
    public const CLASS_NONE = 0;
    public const CLASS_TOOL_ACTUATION = 1;
    public const CLASS_THERMAL = 2;
    public const CLASS_ENERGY_RELEASE = 3;
    public const CLASS_MOTION_IN_SHARED_SPACE = 4;

    /** Fail-closed decode (F2). `null` (the raw value was absent) or any value outside 0..4
     * (unrecognized) normalizes to CLASS_MOTION_IN_SHARED_SPACE -- never to a weaker class, and
     * never a decode failure (there is no "invalid hazard" outcome; there is only "the worst
     * case we must assume"). `$code` carries the raw uint64 wire value using the same
     * two's-complement bit-pattern convention as Cbor\U::$v (a value >= 2^63 is a negative PHP
     * int), so a malformed wire value outside even PHP's signed range still normalizes
     * correctly rather than throwing. */
    public static function classFromCode(?int $code): int
    {
        if ($code !== null && $code >= self::CLASS_NONE && $code <= self::CLASS_MOTION_IN_SHARED_SPACE) {
            return $code;
        }
        return self::CLASS_MOTION_IN_SHARED_SPACE; // F2: unknown/absent -> highest class
    }

    public static function classToValue(int $class): U
    {
        return new U($class);
    }

    /** @internal shared int<->CBOR-value helpers for SpatialBounds. */
    public static function intValue(int $v): U|N
    {
        return $v >= 0 ? new U($v) : new N($v);
    }

    /** @internal */
    public static function intFromValue(mixed $v): int
    {
        if ($v instanceof U) {
            return $v->v;
        }
        if ($v instanceof N) {
            return $v->v;
        }
        throw new HazardMalformed();
    }

    /** @internal shared {1:class,2:envelope} body codec for HazardClaim/HazardAuthorization. */
    public static function bodyToValue(int $class, HazardEnvelope $envelope): M
    {
        return new M([
            [new U(1), self::classToValue($class)],
            [new U(2), $envelope->toValue()],
        ]);
    }

    /**
     * @internal
     * @return array{0:int,1:HazardEnvelope}
     */
    public static function bodyFromValue(mixed $v): array
    {
        if (!($v instanceof M)) {
            throw new HazardMalformed();
        }
        $classCode = null;
        $envelope = null;
        foreach ($v->pairs as $kv) {
            [$k, $val] = $kv;
            if (!($k instanceof U)) {
                throw new HazardMalformed();
            }
            switch ($k->v) {
                case 1:
                    // An out-of-range class ON THE WIRE (not merely "absent") is a malformed
                    // body, not a normalize-to-4 input: F2's fail-closed normalization is for
                    // the DECODE step that produces a class from a less-structured source (see
                    // Hazard::classFromCode), not for a CDDL-invalid hazard-class value already
                    // claiming to be well-formed.
                    if (!($val instanceof U) || $val->v < self::CLASS_NONE || $val->v > self::CLASS_MOTION_IN_SHARED_SPACE) {
                        throw new HazardMalformed();
                    }
                    $classCode = $val->v;
                    break;
                case 2:
                    $envelope = HazardEnvelope::fromValue($val);
                    break;
                default:
                    throw new HazardMalformed();
            }
        }
        if ($classCode === null || $envelope === null) {
            throw new HazardMalformed();
        }
        return [self::classFromCode($classCode), $envelope];
    }

    // ---- containment (F3) -------------------------------------------------------------------

    /** Full containment (F3): same frame id (a bound in one frame says nothing about a bound in
     * a different, unrelated frame), the SAME axis count in the SAME order, and every claim
     * axis's [min,max] a subset of the matching grant axis's [min,max]. */
    public static function spatialContained(SpatialBounds $claim, SpatialBounds $grant): bool
    {
        if ($claim->frame !== $grant->frame) {
            return false;
        }
        if (\count($claim->axes) !== \count($grant->axes)) {
            return false;
        }
        foreach ($claim->axes as $i => $cAxis) {
            $gAxis = $grant->axes[$i];
            if (!($cAxis[0] >= $gAxis[0] && $cAxis[1] <= $gAxis[1])) {
                return false;
            }
        }
        return true;
    }

    /** Full containment (F3): spatialContained() AND claim.speedBoundMmS <=
     * grant.speedBoundMmS AND the claim's window is a sub-interval of the grant's
     * (grant.notBefore <= claim.notBefore and claim.notAfter <= grant.notAfter). */
    public static function envelopeContained(HazardEnvelope $claim, HazardEnvelope $grant): bool
    {
        return self::spatialContained($claim->spatial, $grant->spatial)
            && $claim->speedBoundMmS <= $grant->speedBoundMmS
            && $grant->window->notBefore <= $claim->window->notBefore
            && $claim->window->notAfter <= $grant->window->notAfter;
    }

    // ---- F3: grant-coverage authorization -----------------------------------------------------

    /** Authorize a well-formed, present claim against an authorization (F3): EXACT class match
     * (not a <= ceiling -- see the module doc) AND envelopeContained(). Any single failing
     * dimension denies the WHOLE claim (HazardNotCovered) -- there is no partial authorization
     * and no fail-open branch. */
    public static function hazardAuthorized(HazardClaim $claim, HazardAuthorization $grant): void
    {
        if ($claim->class !== $grant->class) {
            throw new HazardNotCovered();
        }
        if (!self::envelopeContained($claim->envelope, $grant->envelope)) {
            throw new HazardNotCovered();
        }
    }

    /** Authorize an OPTIONAL claim (F2's "absent" case at the object level, distinct from a
     * present-but-unrecognized class byte inside a claim). `null` -- no hazard-claim object
     * exists at all for an action that requires one -- denies immediately (HazardUnknown)
     * rather than fabricating a sentinel envelope and running the ordinary coverage check:
     * there is no envelope to check containment against, so the honest outcome is a distinct
     * error, not a coverage denial that implies an envelope was compared. */
    public static function hazardAuthorizedOptional(?HazardClaim $claim, HazardAuthorization $grant): void
    {
        if ($claim === null) {
            throw new HazardUnknown();
        }
        self::hazardAuthorized($claim, $grant);
    }
}
