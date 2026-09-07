<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
/**
 * N-AALP C2 signing layer for the PHP SDK: the COSE_Sign1 (RFC 9052) signing-input and
 * object assembly, plus deterministic Ed25519 (RFC 8032) via ext-sodium.
 *
 * ML-DSA (FIPS 204): deterministic (rnd=0) ML-DSA-65/87 keygen-from-seed, sign and verify are
 * provided by MlDsa.php (PHP-FFI to OpenSSL >= 3.5), byte-identical to the Go/Rust/Python consensus.
 * This file provides the COSE_Sign1 structure (toBeSignedRaw / assembleSign1Raw / parseSign1Raw)
 * that MlDsa signs over. Where OpenSSL >= 3.5 is not reachable (MlDsa::available() is false), the
 * adapter honestly skip-tracks the ML-DSA crypto ops rather than faking them.
 */

declare(strict_types=1);

namespace Naalp;

final class Cose
{
    public const ALG_MLDSA65 = -49;
    public const ALG_MLDSA87 = -50;
    public const ALG_ED25519 = -19;

    public const PROFILE_PUBLIC = 1;
    public const PROFILE_ENTERPRISE = 2;
    public const PROFILE_SOVEREIGN = 3;

    public const TAG_SIGN1 = 18;

    /**
     * NIST security level of a registered alg, and whether it is registered. Ed25519 is
     * classical (level 0), valid only as a hybrid leg.
     *
     * @return array{0:int,1:bool} [level, known]
     */
    public static function algLevel(int $alg): array
    {
        return match ($alg) {
            self::ALG_MLDSA87 => [5, true],
            self::ALG_MLDSA65 => [3, true],
            self::ALG_ED25519 => [0, true],
            default => [0, false],
        };
    }

    /** Minimum signature level a profile accepts (Sovereign floors at level 5; else 3). */
    public static function profileMinLevel(int $profile): int
    {
        return $profile === self::PROFILE_SOVEREIGN ? 5 : 3;
    }

    /** The RFC 9052 §4.4 Sig_structure for a COSE_Sign1 over an already-serialized header. */
    public static function toBeSignedRaw(string $protected, string $payload): string
    {
        return Cbor::encode(new A([
            new T("Signature1"),
            new B($protected),
            new B(""),
            new B($payload),
        ]));
    }

    /** The tagged COSE_Sign1 object: 18([protected, {}, payload, signature]). */
    public static function assembleSign1Raw(string $protected, string $payload, string $sig): string
    {
        return Cbor::encode(new Tag(self::TAG_SIGN1, new A([
            new B($protected),
            new M([]),
            new B($payload),
            new B($sig),
        ])));
    }

    /**
     * Recover [protected, payload, sig] from a tagged COSE_Sign1 object.
     *
     * @return array{0:string,1:string,2:string}
     */
    public static function parseSign1Raw(string $obj): array
    {
        $v = Cbor::decode($obj);
        if (!($v instanceof Tag) || $v->n !== self::TAG_SIGN1 || !($v->content instanceof A)) {
            throw new \RuntimeException("not a tagged COSE_Sign1");
        }
        $arr = $v->content->items;
        if (\count($arr) !== 4 || !($arr[0] instanceof B) || !($arr[2] instanceof B) || !($arr[3] instanceof B)) {
            throw new \RuntimeException("malformed COSE_Sign1 array");
        }
        return [$arr[0]->v, $arr[2]->v, $arr[3]->v];
    }

    // --- COSE_Sign (tag 98) multi-signature support: the §5.2 Rotation object co-signature ---

    public const TAG_SIGN = 98;

    /** One COSE_Signature protected header: {1: alg} (RFC 9052 §4). */
    public static function legProtected(int $alg): string
    {
        return Cbor::encode(new M([[new U(1), new N($alg)]]));
    }

    /**
     * The per-signer COSE_Signature signing input for a COSE_Sign (RFC 9052 §4.4):
     * det-CBOR(["Signature", body_protected, sign_protected, external_aad(empty), payload]). Note the
     * five-element "Signature" structure (with the per-leg sign_protected) vs the four-element
     * "Signature1" of a COSE_Sign1.
     */
    public static function signatureToBeSigned(string $bodyProt, int $signerAlg, string $payload): string
    {
        return Cbor::encode(new A([
            new T("Signature"),
            new B($bodyProt),
            new B(self::legProtected($signerAlg)),
            new B(""),
            new B($payload),
        ]));
    }

    /**
     * Build one COSE_Signature leg: [leg_protected_bytes, signature_bytes], the ML-DSA leg
     * deterministic (rnd=0) over the per-signer ToBeSigned with the key derived from $seed.
     *
     * @return array{0:string,1:string}
     */
    public static function signatureLeg(string $bodyProt, int $alg, string $seed, string $payload): array
    {
        $sprot = self::legProtected($alg);
        $sig = MlDsa::sign($seed, self::signatureToBeSigned($bodyProt, $alg, $payload), $alg);
        return [$sprot, $sig];
    }

    /**
     * The tagged COSE_Sign object: 98([body_prot, {}, payload, [[sprot, {}, sig], ...]]).
     *
     * @param list<array{0:string,1:string}> $legs
     */
    public static function assembleSignRaw(string $bodyProt, string $payload, array $legs): string
    {
        $sigArr = [];
        foreach ($legs as [$sprot, $sig]) {
            $sigArr[] = new A([new B($sprot), new M([]), new B($sig)]);
        }
        return Cbor::encode(new Tag(self::TAG_SIGN, new A([
            new B($bodyProt), new M([]), new B($payload), new A($sigArr),
        ])));
    }

    /**
     * Recover [body_prot, payload, [[sprot, sig], ...]] from a tagged COSE_Sign object.
     *
     * @return array{0:string,1:string,2:list<array{0:string,1:string}>}
     */
    public static function parseSignRaw(string $obj): array
    {
        $v = Cbor::decode($obj);
        if (!($v instanceof Tag) || $v->n !== self::TAG_SIGN || !($v->content instanceof A)) {
            throw new \RuntimeException("not a tagged COSE_Sign");
        }
        $arr = $v->content->items;
        if (\count($arr) !== 4 || !($arr[0] instanceof B) || !($arr[2] instanceof B) || !($arr[3] instanceof A)) {
            throw new \RuntimeException("malformed COSE_Sign array");
        }
        $legs = [];
        foreach ($arr[3]->items as $e) {
            if (!($e instanceof A) || \count($e->items) !== 3 || !($e->items[0] instanceof B) || !($e->items[2] instanceof B)) {
                throw new \RuntimeException("malformed COSE_Signature leg");
            }
            $legs[] = [$e->items[0]->v, $e->items[2]->v];
        }
        return [$arr[0]->v, $arr[2]->v, $legs];
    }

    /** Extract the alg (label 1) value from a serialized leg protected header {1: alg}. */
    public static function algFromProtected(string $prot): int
    {
        // §3.1.1 (R5): reject the redundant 0x41A0 encoding of an empty protected header (a bstr
        // wrapping an empty map; its unwrapped content is the single byte 0xA0) as NonCanonical,
        // before interpreting the header -- the empty protected header is pinned to 0x40.
        if (\strlen($prot) === 1 && \ord($prot[0]) === 0xA0) {
            throw new NonCanonical("empty protected header must be 0x40, not 0x41A0 (§3.1.1, R5)");
        }
        $v = Cbor::decode($prot);
        if (!($v instanceof M)) {
            throw new \RuntimeException("protected header not a map");
        }
        foreach ($v->pairs as [$k, $val]) {
            if ($k instanceof U && $k->v === 1 && $val instanceof N) {
                return $val->v;
            }
        }
        throw new \RuntimeException("no alg in protected header");
    }

    // --- Ed25519 (RFC 8032) via ext-sodium ---

    /** Deterministic Ed25519 signature over $msg with the key derived from a 32-byte seed. */
    public static function ed25519Sign(string $seed, string $msg): string
    {
        if (\strlen($seed) !== 32) {
            throw new \RuntimeException("ed25519 secret key must be a 32-byte seed");
        }
        $kp = \sodium_crypto_sign_seed_keypair($seed);
        $sk = \sodium_crypto_sign_secretkey($kp);
        return \sodium_crypto_sign_detached($msg, $sk);
    }

    public static function ed25519Verify(string $pk, string $msg, string $sig): bool
    {
        return \sodium_crypto_sign_verify_detached($sig, $msg, $pk);
    }

    // --- LAMPS opt-in composite signature (alg -65537, design.md §4.2) ---

    public const ALG_COMPOSITE_65_ED25519 = -65537; // COMPSIG-MLDSA65-Ed25519-SHA512
    public const ALG_COMPOSITE_44_ED25519 = -65538; // edge; RESERVED, not implemented
    private const COMPOSITE_PREFIX = "CompositeAlgorithmSignatures2025";
    private const COMPOSITE_LABEL_MLDSA65_ED25519 = "COMPSIG-MLDSA65-Ed25519-SHA512";
    private const MLDSA65_SIG_SIZE = 3309;         // FIPS 204 ML-DSA-65 signature size
    public const MLDSA65_PUB_SIZE = 1952;          // FIPS 204 ML-DSA-65 pubkey size (split point)

    /**
     * The LAMPS composite message representative M' = Prefix || Label || len(ctx) || ctx ||
     * SHA-512(M) (design.md §4.2). len(ctx) is a single length octet; the N-AALP composite context
     * is empty, so the octet is 0x00. Both legs sign this same M'.
     */
    public static function computeMprime(string $label, string $ctx, string $m): string
    {
        if (\strlen($ctx) > 255) { throw new \RuntimeException("composite context exceeds one length octet"); }
        return self::COMPOSITE_PREFIX . $label . \chr(\strlen($ctx)) . $ctx . \hash('sha512', $m, true);
    }

    /**
     * The LAMPS composite signature value over the COSE ToBeSigned $tbs: mldsaSig || tradSig
     * (ML-DSA-65 first, raw concatenation; §4.2). The ML-DSA leg is deterministic (rnd=0) with
     * context = the suite Label octets (OpenSSL context-string via FFI); the Ed25519 leg signs M'
     * with no context.
     */
    public static function compositeSign(string $mldsaSeed, string $edSeed, string $tbs): string
    {
        $mprime = self::computeMprime(self::COMPOSITE_LABEL_MLDSA65_ED25519, "", $tbs);
        $mldsaSig = MlDsa::sign($mldsaSeed, $mprime, self::ALG_MLDSA65, self::COMPOSITE_LABEL_MLDSA65_ED25519);
        $tradSig = self::ed25519Sign($edSeed, $mprime);
        return $mldsaSig . $tradSig; // ML-DSA first (LAMPS order)
    }

    /**
     * Valid IFF BOTH the ML-DSA-65 leg (context = Label) and the Ed25519 leg (no context) validate
     * over M'. A value of the wrong length is malformed and rejected. A stripped or re-interpreted
     * lone leg has no valid composite because M' binds both components (RFC 9955; §4.2/§4.5).
     */
    public static function compositeVerify(string $mldsaPk, string $edPk, string $m, string $sig): bool
    {
        if (\strlen($sig) !== self::MLDSA65_SIG_SIZE + 64) { return false; }
        $mprime = self::computeMprime(self::COMPOSITE_LABEL_MLDSA65_ED25519, "", $m);
        $mldsaOk = MlDsa::verify($mldsaPk, $mprime, \substr($sig, 0, self::MLDSA65_SIG_SIZE), self::ALG_MLDSA65,
                                 self::COMPOSITE_LABEL_MLDSA65_ED25519);
        $edOk = self::ed25519Verify($edPk, $mprime, \substr($sig, self::MLDSA65_SIG_SIZE));
        return $mldsaOk && $edOk;
    }
}
