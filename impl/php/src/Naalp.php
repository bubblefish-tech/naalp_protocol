<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
/**
 * Naalp — the ergonomic one-import front door to the PHP N-AALP SDK (draft-bubblefish-naalp-00).
 *
 * N-AALP makes the *object*, not the connection, the unit of security: every message is a
 * deterministically-encoded CBOR structure signed with COSE that carries, under one signature, its
 * content identity, its signer, a closed effect label, optional approval/audit bindings, and its
 * causal derivation — verifiable offline, over any transport.
 *
 * This facade gathers the common object-envelope surface behind a single class so a developer can
 * `use Naalp\Naalp;` and stay in one place; the byte-level primitives remain available directly as
 * their own classes:
 *
 *   Cbor      deterministic CBOR (RFC 8949 §4.2.1) + content id (§2.3)
 *   Cose      COSE_Sign1 (RFC 9052) ToBeSigned / assembly / parse + deterministic Ed25519
 *   Identity  self-certifying signer id (multiformats PeerHandle) + NFC rule
 *   Policy    the closed four-value effect set + the §6.1 authorization lattice + safety label
 *   Records   approval / ledger / receipt / delivery / stream / carriage bodies + transport boundary
 *   Graph     causal verify + deterministic federation reconcile + reconcile record
 *   Channels  the frozen 20-channel / 65-kind registry with declared effects
 *   Envelope  the full object envelope (NaalpObject + contentId/buildPayload/protectedHeader/
 *             toBeSigned/assembleSigned + structural verify)
 *
 * CRYPTO SCOPE (PURE-ONLY). PHP cannot deterministically sign or verify ML-DSA (FIPS 204); see
 * Envelope.php. The facade exposes the pure object construction + assembly (combine an
 * externally-produced ML-DSA signature via assembleSigned) and a full end-to-end Ed25519 round trip.
 *
 * Load order: require Cbor.php, Cose.php, Identity.php, Policy.php, Records.php, Graph.php,
 * Channels.php, Envelope.php, then this file (or use the Composer classmap autoloader).
 */

declare(strict_types=1);

namespace Naalp;

final class Naalp
{
    public const VERSION = "0.1.0";

    public const ALG_MLDSA65 = Cose::ALG_MLDSA65;
    public const ALG_MLDSA87 = Cose::ALG_MLDSA87;
    public const ALG_ED25519 = Cose::ALG_ED25519;

    public const PROFILE_PUBLIC = Cose::PROFILE_PUBLIC;
    public const PROFILE_ENTERPRISE = Cose::PROFILE_ENTERPRISE;
    public const PROFILE_SOVEREIGN = Cose::PROFILE_SOVEREIGN;

    /**
     * Build a NaalpObject. `signer` is the raw signer-id bytes; `body` is a cbor value.
     *
     * @param list<string> $causes
     */
    public static function object(
        int $kind,
        int $channel,
        string $signer,
        int $created,
        int $effect,
        mixed $body,
        int $tier = 0,
        int $profile = Cose::PROFILE_PUBLIC,
        array $causes = [],
        ?M $ext = null,
        ?M $cext = null,
    ): NaalpObject {
        return new NaalpObject(
            kind: $kind,
            channel: $channel,
            signer: $signer,
            created: $created,
            effect: $effect,
            body: $body,
            tier: $tier,
            profile: $profile,
            causes: $causes,
            ext: $ext,
            cext: $cext,
        );
    }

    /** The object content id (multihash SHA-384 over the body without field 1). */
    public static function contentId(NaalpObject $o): string
    {
        return Envelope::contentId($o);
    }

    /** Content-id-bind the object and return the serialized COSE_Sign1 payload (body with field 1). */
    public static function buildPayload(NaalpObject $o): string
    {
        return Envelope::buildPayload($o);
    }

    /** The COSE protected header for the given alg / signer / profile. */
    public static function protectedHeader(int $alg, string $signer, int $profile): string
    {
        return Envelope::protectedHeader($alg, $signer, $profile);
    }

    /** The RFC 9052 ToBeSigned bytes for (protected, payload). */
    public static function toBeSigned(string $protected, string $payload): string
    {
        return Envelope::toBeSigned($protected, $payload);
    }

    /** Assemble the tagged COSE_Sign1 by combining an externally-produced signature. */
    public static function assembleSigned(string $protected, string $payload, string $sig): string
    {
        return Envelope::assembleSigned($protected, $payload, $sig);
    }

    /** Full end-to-end Ed25519 sign of an object (build -> protected header -> sign -> assemble). */
    public static function signWithEd25519(NaalpObject $o, string $seed): string
    {
        return Envelope::signWithEd25519($o, $seed);
    }

    /**
     * Structurally verify a signed object (Ed25519 signatures are cryptographically checked; ML-DSA
     * objects pass structural verification without a signature check — PURE-ONLY).
     *
     * @param callable(int,int):bool|null $kindValidator
     * @param array<int,bool> $knownCext
     */
    public static function verify(
        int $profile,
        int $alg,
        string $pubkey,
        ?callable $kindValidator,
        string $objBytes,
        array $knownCext = []
    ): NaalpObject {
        return Envelope::verify($profile, $alg, $pubkey, $kindValidator, $objBytes, $knownCext);
    }

    /** The self-certifying signer id for an alg + raw public key. */
    public static function signerId(int $alg, string $pubkey): string
    {
        return Identity::signerId($alg, $pubkey);
    }
}
