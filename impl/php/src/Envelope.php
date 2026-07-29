<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
/**
 * N-AALP C3 object envelope for the PHP SDK — the full signed object surface and its offline
 * structural verify (design.md §2).
 *
 * This is the ergonomic surface a developer uses: build a NaalpObject (its channel/kind/effect/
 * body and the rest), bind its content id, serialize the signed payload + protected header, form
 * the COSE_Sign1 ToBeSigned, and assemble a tagged COSE_Sign1 object by combining an
 * externally-produced signature. The byte constructions are byte-identical to the Go, Rust,
 * Python, and TypeScript reference implementations (the worked example in
 * vectors/worked/example.json is the byte-level known-answer for this module).
 *
 * CRYPTO SCOPE (PURE-ONLY). PHP has no deterministic (rnd=0) ML-DSA sign/verify path (liboqs and
 * OpenSSL 3.5 ML-DSA are randomized-only, and no PHP binding exposes a deterministic seed->pk
 * keygen). Therefore this envelope does NOT sign or verify ML-DSA signatures. It provides the pure
 * object surface — contentId / buildPayload / protectedHeader / toBeSigned / assembleSigned — plus
 * a structural verify() that checks content-id, field ranges, header/body copies, version, critical
 * extensions, kind dispatch, and the profile floor. For the signature step, Ed25519 (RFC 8032)
 * objects ARE cryptographically verified via ext-sodium; ML-DSA objects pass structural
 * verification without a signature check (documented, honest — PHP cannot verify ML-DSA). A full
 * end-to-end Ed25519 sign->verify round trip IS available via signWithEd25519().
 *
 * This file relies on Cbor.php and Cose.php being loaded first (the same require-order convention
 * the adapter and the rest of the SDK use).
 */

declare(strict_types=1);

namespace Naalp;

/** A single named, fail-closed envelope failure; `kind` is the stable error code (§2.6). */
class EnvelopeError extends \RuntimeException
{
    public string $kind;

    public function __construct(string $kind, string $msg = '')
    {
        parent::__construct($kind . ': ' . $msg);
        $this->kind = $kind;
    }
}

/**
 * A decoded N-AALP object body. `id` is the content id (§2.3), set by buildPayload()/contentId().
 * Named "NaalpObject" because `Object` is a reserved type keyword in PHP.
 */
final class NaalpObject
{
    /** @param list<string> $causes list of raw content-id byte strings */
    public function __construct(
        public int $kind,
        public int $channel,
        public string $signer,          // raw bytes (the signer-id UTF-8 bytes)
        public int $created,
        public int $effect,
        public mixed $body,             // a cbor value (e.g. new M([...]))
        public int $tier = 0,
        public int $profile = Cose::PROFILE_PUBLIC,
        public array $causes = [],
        public ?M $ext = null,          // field 11, non-critical
        public ?M $cext = null,         // field 12, critical
        public ?string $id = null,      // field 1 (content id); set by buildPayload()
    ) {
    }

    /** Build the object body as a CBOR map. Encode emits canonical key order regardless of append order. */
    public function bodyMap(bool $includeId): M
    {
        $pairs = [];
        if ($includeId) {
            $pairs[] = [new U(Envelope::FIELD_ID), new B((string) $this->id)];
        }
        $causes = [];
        foreach ($this->causes as $c) {
            $causes[] = new B($c);
        }
        $pairs[] = [new U(Envelope::FIELD_KIND), new U($this->kind)];
        $pairs[] = [new U(Envelope::FIELD_CHANNEL), new U($this->channel)];
        $pairs[] = [new U(Envelope::FIELD_TIER), new U($this->tier)];
        $pairs[] = [new U(Envelope::FIELD_SIGNER), new B($this->signer)];
        $pairs[] = [new U(Envelope::FIELD_CREATED), new U($this->created)];
        $pairs[] = [new U(Envelope::FIELD_EFFECT), new U($this->effect)];
        $pairs[] = [new U(Envelope::FIELD_CAUSES), new A($causes)];
        $pairs[] = [new U(Envelope::FIELD_PROFILE), new U($this->profile)];
        $pairs[] = [new U(Envelope::FIELD_BODY), $this->body];
        if ($this->ext !== null) {
            $pairs[] = [new U(Envelope::FIELD_EXT), $this->ext];
        }
        if ($this->cext !== null) {
            $pairs[] = [new U(Envelope::FIELD_CEXT), $this->cext];
        }
        return new M($pairs);
    }

    /** The object content id over the body WITHOUT field 1 (§2.3). */
    public function contentId(): string
    {
        return Cbor::contentId($this->bodyMap(false));
    }
}

final class Envelope
{
    // object body field numbers (§2.1)
    public const FIELD_ID = 1;
    public const FIELD_KIND = 2;
    public const FIELD_CHANNEL = 3;
    public const FIELD_TIER = 4;
    public const FIELD_SIGNER = 5;
    public const FIELD_CREATED = 6;
    public const FIELD_EFFECT = 7;
    public const FIELD_CAUSES = 8;
    public const FIELD_PROFILE = 9;
    public const FIELD_BODY = 10;
    public const FIELD_EXT = 11;
    public const FIELD_CEXT = 12;

    public const NAALP_VERSION = 1;
    private const HEADER_LABEL = "naalp";

    /** The object content id over the body without field 1 (§2.3). */
    public static function contentId(NaalpObject $o): string
    {
        return $o->contentId();
    }

    /**
     * Content-id-bind the object and serialize the signed payload: sets $o->id to the content id
     * and returns the deterministic-CBOR bytes of the body WITH field 1 (the COSE_Sign1 payload).
     */
    public static function buildPayload(NaalpObject $o): string
    {
        $o->id = $o->contentId();
        return Cbor::encode($o->bodyMap(true));
    }

    /** The COSE protected header {1: nint(alg), "naalp": {1:signer, 2:profile, 3:version}} (§2.1, §2.5). */
    public static function protectedHeader(int $alg, string $signer, int $profile): string
    {
        $naalp = new M([
            [new U(1), new B($signer)],
            [new U(2), new U($profile)],
            [new U(3), new U(self::NAALP_VERSION)],
        ]);
        return Cbor::encode(new M([
            [new U(1), new N($alg)],
            [new T(self::HEADER_LABEL), $naalp],
        ]));
    }

    /** The RFC 9052 §4.4 Sig_structure ["Signature1", protected, "", payload]. */
    public static function toBeSigned(string $protected, string $payload): string
    {
        return Cose::toBeSignedRaw($protected, $payload);
    }

    /**
     * Assemble the tagged COSE_Sign1 object 18([protected, {}, payload, signature]) by combining an
     * externally-produced signature over toBeSigned(protected, payload). This is how a full N-AALP
     * object is finalized in PHP: the ML-DSA signature is produced by a deterministic FIPS 204
     * provider elsewhere, and PHP assembles the self-describing object bytes around it.
     */
    public static function assembleSigned(string $protected, string $payload, string $sig): string
    {
        return Cose::assembleSign1Raw($protected, $payload, $sig);
    }

    /**
     * Full end-to-end Ed25519 (RFC 8032) sign of an object: content-id-bind, serialize, form the
     * protected header for alg Ed25519, deterministically sign the ToBeSigned via ext-sodium, and
     * assemble the tagged COSE_Sign1. Ed25519 is a classical (level-0) leg — usable on the Public
     * profile floor for interop/demo; production Sovereign objects require ML-DSA (produced by a
     * FIPS 204 provider and assembled with assembleSigned()).
     */
    public static function signWithEd25519(NaalpObject $o, string $seed): string
    {
        $payload = self::buildPayload($o);
        $prot = self::protectedHeader(Cose::ALG_ED25519, $o->signer, $o->profile);
        $tbs = self::toBeSigned($prot, $payload);
        $sig = Cose::ed25519Sign($seed, $tbs);
        return self::assembleSigned($prot, $payload, $sig);
    }

    /**
     * Verify a signed N-AALP object structurally, offline (R-2.4). Returns the decoded NaalpObject
     * on success; throws EnvelopeError (or a Cbor NonCanonical) with a stable .kind on the first
     * named failure. Check order (fail-closed): decode -> content-id -> field ranges ->
     * header/body copies + version -> critical extensions -> kind dispatch -> profile floor ->
     * signature.
     *
     * SIGNATURE STEP (PURE-ONLY): for an Ed25519 object the signature IS cryptographically verified
     * via ext-sodium; for an ML-DSA object the structural checks above are complete and the
     * signature is NOT verified here (PHP has no deterministic ML-DSA verify). $pubkey is used only
     * for the Ed25519 leg.
     *
     * @param callable(int,int):bool|null $kindValidator (channel, kind) -> recognized?
     * @param array<int,bool> $knownCext recognized critical-extension keys
     */
    public static function verify(
        int $profile,
        int $alg,
        string $pubkey,
        ?callable $kindValidator,
        string $objBytes,
        array $knownCext = []
    ): NaalpObject {
        try {
            [$prot, $payload, $sig] = Cose::parseSign1Raw($objBytes);
        } catch (\Throwable $e) {
            throw new EnvelopeError("Malformed", "not a COSE_Sign1 object");
        }
        $bv = Cbor::decode($payload); // throws NonCanonical on a non-canonical body
        if (!($bv instanceof M)) {
            throw new EnvelopeError("Malformed", "body not a map");
        }

        // content-id: recompute over the body without field 1, compare to the claimed id.
        $claimed = null;
        $without = [];
        foreach ($bv->pairs as [$k, $v]) {
            if ($k instanceof U && $k->v === self::FIELD_ID) {
                if (!($v instanceof B)) {
                    throw new EnvelopeError("Malformed", "id not a bstr");
                }
                $claimed = $v->v;
                continue;
            }
            $without[] = [$k, $v];
        }
        if ($claimed === null) {
            throw new EnvelopeError("Malformed", "no content id");
        }
        if (!\hash_equals($claimed, Cbor::contentId(new M($without)))) {
            throw new EnvelopeError("ContentIdMismatch", "recomputed id differs");
        }

        $o = self::objectFromMap($bv);

        // field ranges (§3.3): channel 0..19, effect 0..3, profile 1..3.
        if ($o->channel > 19 || $o->effect > 3 || $o->profile < 1 || $o->profile > 3) {
            throw new EnvelopeError("RangeError", "field out of range");
        }

        // protected-header copies vs body (§2.1) + version.
        [$halg, $hsigner, $hprofile, $hversion] = self::parseProtected($prot);
        if ($hversion !== self::NAALP_VERSION) {
            throw new EnvelopeError("UnsupportedVersion", "bad naalp-version");
        }
        if ($hsigner !== $o->signer || $hprofile !== $o->profile) {
            throw new EnvelopeError("HeaderBodyMismatch", "protected header disagrees with body");
        }

        // critical extensions: any unrecognized key rejects (§2.5).
        if ($o->cext !== null) {
            foreach ($o->cext->pairs as [$k, $_v]) {
                if (!($k instanceof U) || !\array_key_exists($k->v, $knownCext) || $knownCext[$k->v] !== true) {
                    throw new EnvelopeError("UnknownCriticalExt", "unrecognized critical extension");
                }
            }
        }

        // kind/channel surface dispatch (§2.6).
        if ($kindValidator === null || !$kindValidator($o->channel, $o->kind)) {
            throw new EnvelopeError("UnknownKind", "kind/channel not a registered surface");
        }

        // profile floor + signature.
        [$level, $known] = Cose::algLevel($halg);
        if (!$known) {
            throw new EnvelopeError("UnknownAlg", "unregistered alg");
        }
        if ($level < Cose::profileMinLevel($profile)) {
            throw new EnvelopeError("ProfileDowngrade", "signature level below the profile minimum");
        }
        if ($halg === Cose::ALG_ED25519) {
            $tbs = self::toBeSigned($prot, $payload);
            if (!Cose::ed25519Verify($pubkey, $tbs, $sig)) {
                throw new EnvelopeError("BadSignature", "signature does not verify");
            }
        }
        // ML-DSA: structural verification complete; the signature is not verified in PHP (PURE-ONLY).
        return $o;
    }

    /**
     * Read the fixed body fields (1..12) into a NaalpObject. Unknown top-level field numbers or
     * wrong field types are Malformed; extension carriers are fields 11/12.
     */
    private static function objectFromMap(M $m): NaalpObject
    {
        $fields = [];
        foreach ($m->pairs as [$k, $v]) {
            if (!($k instanceof U)) {
                throw new EnvelopeError("Malformed", "non-uint body key");
            }
            $fields[$k->v] = $v;
        }

        $need = static function (int $fnum, array $types) use ($fields) {
            $v = $fields[$fnum] ?? null;
            foreach ($types as $t) {
                if ($v instanceof $t) {
                    return $v;
                }
            }
            throw new EnvelopeError("Malformed", "field " . $fnum . " wrong type/absent");
        };

        $causes = [];
        $causesV = $need(self::FIELD_CAUSES, [A::class]);
        foreach ($causesV->items as $c) {
            if (!($c instanceof B)) {
                throw new EnvelopeError("Malformed", "cause not a bstr");
            }
            $causes[] = $c->v;
        }
        $ext = $fields[self::FIELD_EXT] ?? null;
        $cext = $fields[self::FIELD_CEXT] ?? null;
        if ($ext !== null && !($ext instanceof M)) {
            throw new EnvelopeError("Malformed", "ext not a map");
        }
        if ($cext !== null && !($cext instanceof M)) {
            throw new EnvelopeError("Malformed", "cext not a map");
        }

        $bodyTypes = [U::class, N::class, B::class, T::class, A::class, M::class, Tag::class];
        $o = new NaalpObject(
            kind: $need(self::FIELD_KIND, [U::class])->v,
            channel: $need(self::FIELD_CHANNEL, [U::class])->v,
            signer: $need(self::FIELD_SIGNER, [B::class])->v,
            created: $need(self::FIELD_CREATED, [U::class])->v,
            effect: $need(self::FIELD_EFFECT, [U::class])->v,
            body: $need(self::FIELD_BODY, $bodyTypes),
            tier: $need(self::FIELD_TIER, [U::class])->v,
            profile: $need(self::FIELD_PROFILE, [U::class])->v,
            causes: $causes,
            ext: $ext,
            cext: $cext,
        );
        $idv = $fields[self::FIELD_ID] ?? null;
        $o->id = $idv instanceof B ? $idv->v : null;
        return $o;
    }

    /**
     * Read {1: nint(alg), "naalp": {1:signer, 2:profile, 3:version}} from a serialized protected
     * header.
     *
     * @return array{0:int,1:string,2:int,3:int} [alg, signer, profile, version]
     */
    private static function parseProtected(string $prot): array
    {
        $v = Cbor::decode($prot);
        if (!($v instanceof M)) {
            throw new EnvelopeError("Malformed", "protected header not a map");
        }
        $alg = $signer = $profile = $version = null;
        foreach ($v->pairs as [$k, $val]) {
            if ($k instanceof U && $k->v === 1 && $val instanceof N) {
                $alg = $val->v;
            } elseif ($k instanceof T && $k->v === self::HEADER_LABEL && $val instanceof M) {
                foreach ($val->pairs as [$kk, $vv]) {
                    if ($kk instanceof U && $kk->v === 1 && $vv instanceof B) {
                        $signer = $vv->v;
                    } elseif ($kk instanceof U && $kk->v === 2 && $vv instanceof U) {
                        $profile = $vv->v;
                    } elseif ($kk instanceof U && $kk->v === 3 && $vv instanceof U) {
                        $version = $vv->v;
                    }
                }
            }
        }
        if ($alg === null || $signer === null || $profile === null || $version === null) {
            throw new EnvelopeError("Malformed", "protected header missing routing fields");
        }
        return [$alg, $signer, $profile, $version];
    }
}
