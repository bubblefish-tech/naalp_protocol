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
 * CRYPTO SCOPE. Deterministic (rnd=0) ML-DSA-65/87 IS available in PHP via MlDsa (PHP-FFI to
 * OpenSSL >= 3.5: "deterministic=1" per-message + a seed->key path), byte-identical to the FIPS 204
 * consensus. So the opt-in LAMPS composite path (alg -65537, §4.2) is fully signed by signComposite()
 * AND cryptographically verified in verify() — both legs (ML-DSA-65 via MlDsa, Ed25519 via
 * ext-sodium). For a PURE (non-composite) object this envelope provides the object surface —
 * contentId / buildPayload / protectedHeader / toBeSigned / assembleSigned — plus a structural
 * verify() that checks content-id, field ranges, header/body copies, version, critical extensions,
 * kind dispatch, and the profile floor. In that pure path an Ed25519 (RFC 8032) object IS
 * cryptographically verified via ext-sodium; a pure ML-DSA object passes the structural checks here
 * and its signature leg is verified by the adapter's cose.verify1 op (which calls MlDsa directly),
 * not re-checked inside this structural verify(). A full end-to-end Ed25519 sign->verify round trip
 * is available via signWithEd25519(), and a full composite sign via signComposite(). Where OpenSSL
 * >= 3.5 is unreachable (MlDsa::available() false), the composite sign/verify legs raise honestly
 * rather than fabricating a result.
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
        // field 13 (§2.5.3): the single-use consume binding. Omit-when-empty -- a no-audience object
        // encodes byte-identically to a draft-00 object (additivity). Anchors version 2.
        public string $audience = '',
        // field 14 (§4.2): the signed suite declaration, present (value 1) iff a composite alg signs
        // this object; 0 = absent, so a pure object stays byte-identical to draft-00.
        public int $suite = 0,
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
        if ($this->audience !== '') {
            $pairs[] = [new U(Envelope::FIELD_AUDIENCE), new T($this->audience)];
        }
        if ($this->suite !== 0) {
            $pairs[] = [new U(Envelope::FIELD_SUITE), new U($this->suite)];
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
    // Field numbers (§2.1), the naalp-version (§2.5) and the header label are generated from
    // spec/wire-constants.csv into WireConstants; Envelope re-declares them as aliases so the value
    // is authored once and cannot be re-typed and drift (scripts/gen_wire_constants.py). php's 8.1
    // floor rules out const-in-trait, so this alias keeps all self::/Envelope:: usage sites unchanged.
    public const FIELD_ID = WireConstants::FIELD_ID;
    public const FIELD_KIND = WireConstants::FIELD_KIND;
    public const FIELD_CHANNEL = WireConstants::FIELD_CHANNEL;
    public const FIELD_TIER = WireConstants::FIELD_TIER;
    public const FIELD_SIGNER = WireConstants::FIELD_SIGNER;
    public const FIELD_CREATED = WireConstants::FIELD_CREATED;
    public const FIELD_EFFECT = WireConstants::FIELD_EFFECT;
    public const FIELD_CAUSES = WireConstants::FIELD_CAUSES;
    public const FIELD_PROFILE = WireConstants::FIELD_PROFILE;
    public const FIELD_BODY = WireConstants::FIELD_BODY;
    public const FIELD_EXT = WireConstants::FIELD_EXT;
    public const FIELD_CEXT = WireConstants::FIELD_CEXT;
    public const FIELD_AUDIENCE = WireConstants::FIELD_AUDIENCE;
    public const FIELD_SUITE = WireConstants::FIELD_SUITE;

    public const NAALP_VERSION = WireConstants::NAALP_VERSION;
    private const HEADER_LABEL = WireConstants::HEADER_LABEL;

    // The signed suite id carried in field 14 for the opt-in ML-DSA-65 + Ed25519 composite signature
    // (§4.2); present (value 1) iff a composite alg signs the object, so a pure object stays
    // byte-identical to a draft-00 object.
    public const SUITE_MLDSA65_ED25519 = 1;

    // The OPEN-DECISION toggle (design.md §4.4 profile floor applied to a rotation): a Sovereign/High
    // verifier gates the OLD (authorizing) leg by the profile floor too (DEFAULT, fail-closed) rather
    // than only the NEW leg. Ratified default = true (matches impl/go rotationOldLegFloorApplies).
    public const ROTATION_OLD_LEG_FLOOR_APPLIES = true;

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
     * (suite id, true) for a registered composite alg (field 14 present); (0, false) for any
     * non-composite alg, so field 14 stays absent for a pure object. Byte-identical to
     * impl/go/impl/rust compositeSuiteForAlg.
     *
     * @return array{0:int,1:bool}
     */
    private static function compositeSuiteForAlg(int $alg): array
    {
        if ($alg === Cose::ALG_COMPOSITE_65_ED25519) {
            return [self::SUITE_MLDSA65_ED25519, true];
        }
        return [0, false];
    }

    /**
     * Assembles, content-id-binds, and signs a full N-AALP object for the given signing alg
     * (ML-DSA-65, ML-DSA-87, Ed25519, or the opt-in composite). Detects whether $alg is a registered
     * composite and sets Object.suite/field-14 present iff so (0/absent for a pure object,
     * compositeSuiteForAlg), byte-identical to impl/go's generic Sign(o, signer). $seed is the
     * ML-DSA/Ed25519 signing seed; $edSeed is the SECOND (Ed25519) leg's seed and is REQUIRED for a
     * composite alg (ignored otherwise). Returns the tagged COSE_Sign1 object bytes, byte-identical
     * to the Go/Rust/Python reference for the same logical input.
     */
    public static function sign(NaalpObject $o, int $alg, string $seed, ?string $edSeed = null): string
    {
        [$suite, $isComposite] = self::compositeSuiteForAlg($alg);
        $o->suite = $suite;
        $payload = self::buildPayload($o); // sets id = contentId(), which now covers field 14
        $prot = self::protectedHeader($alg, $o->signer, $o->profile);
        $tbs = self::toBeSigned($prot, $payload);
        if ($isComposite) {
            if ($edSeed === null) {
                throw new EnvelopeError("Malformed", "composite alg requires an Ed25519 seed");
            }
            $sig = Cose::compositeSign($seed, $edSeed, $tbs);
        } elseif ($alg === Cose::ALG_ED25519) {
            $sig = Cose::ed25519Sign($seed, $tbs);
        } elseif ($alg === Cose::ALG_MLDSA65 || $alg === Cose::ALG_MLDSA87) {
            $sig = MlDsa::sign($seed, $tbs, $alg);
        } else {
            throw new EnvelopeError("UnknownAlg", "unregistered signing alg $alg");
        }
        return self::assembleSigned($prot, $payload, $sig);
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
     * Assemble, content-id-bind, and sign a full N-AALP object with the opt-in LAMPS composite
     * signature (alg -65537, §4.2). Sets the signed suite field (14) present (value 1) BEFORE the
     * content id so the id covers it; the composite value is deterministic in both legs (ML-DSA-65
     * with ctx = the suite Label, Ed25519 with no ctx). Returns the tagged COSE_Sign1 object bytes,
     * byte-identical to the Go/Rust/Python/TS/Java/Kotlin/Ruby composite object. Requires
     * deterministic ML-DSA (MlDsa / OpenSSL >= 3.5).
     */
    public static function signComposite(NaalpObject $o, string $mldsaSeed, string $edSeed): string
    {
        $o->suite = self::SUITE_MLDSA65_ED25519;
        $payload = self::buildPayload($o); // sets id = contentId(), which now covers field 14
        $prot = self::protectedHeader(Cose::ALG_COMPOSITE_65_ED25519, $o->signer, $o->profile);
        $tbs = self::toBeSigned($prot, $payload);
        $sig = Cose::compositeSign($mldsaSeed, $edSeed, $tbs);
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
        // Object octet-size bound (§3.4, R7): reject an oversized signed object on the raw bytes,
        // before any parse (RFC 8949 §10 decoder-memory guard).
        if (\strlen($objBytes) > WireConstants::MAX_OBJECT_SIZE) {
            throw new EnvelopeError("TooLarge", "object exceeds the maximum octet size (§3.4, R7)");
        }
        try {
            [$prot, $payload, $sig] = Cose::parseSign1Raw($objBytes);
        } catch (\Throwable $e) {
            throw new EnvelopeError("Malformed", "not a COSE_Sign1 object");
        }
        // non-canonical -> NonCanonical (§2.6); over-nested -> DepthExceeded (§3.4, R7).
        $bv = Cbor::decodeBounded($payload, WireConstants::MAX_NESTING_DEPTH);
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

        // A (channel 3, kind 0) Rotation object MUST be a tag-98 COSE_Sign co-signed by the old AND
        // new key (§5.2); a single-signature (tag-18) rotation is missing the old-key co-signature and
        // is rejected RotationUnauthorized (the single-Sign1 rotation-gap fix).
        if (self::isRotationObject($o->channel, $o->kind)) {
            throw new EnvelopeError("RotationUnauthorized", "single-signature rotation missing the old-key co-signature");
        }

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

        // critical extensions: any unrecognized key rejects (§2.5). RECHECK_KEY (13) is an
        // envelope-recognized critical key: a critical recheck naming an UNKNOWN procedure id is
        // rejected fail-closed (the critical-extension rule reaching the procedure it names, T1.3);
        // a known procedure id is recognized regardless of the caller's $knownCext. A NON-critical
        // recheck (ext, field 11) is never rejected here — an unknown non-critical procedure is
        // ignored per the may-ignore rule.
        if ($o->cext !== null) {
            foreach ($o->cext->pairs as [$k, $v]) {
                if (!($k instanceof U)) {
                    throw new EnvelopeError("UnknownCriticalExt", "unrecognized critical extension");
                }
                if ($k->v === self::RECHECK_KEY) {
                    if (!($v instanceof U)) {
                        throw new EnvelopeError("Malformed", "recheck procedure id not a uint");
                    }
                    if (!self::isKnownRecheckProcedure($v->v)) {
                        throw new EnvelopeError("UnknownCriticalExt", "unrecognized critical extension");
                    }
                    continue;
                }
                if (!\array_key_exists($k->v, $knownCext) || $knownCext[$k->v] !== true) {
                    throw new EnvelopeError("UnknownCriticalExt", "unrecognized critical extension");
                }
            }
        }

        // kind/channel surface dispatch (§2.6).
        if ($kindValidator === null || !$kindValidator($o->channel, $o->kind)) {
            throw new EnvelopeError("UnknownKind", "kind/channel not a registered surface");
        }

        $tbs = self::toBeSigned($prot, $payload);

        // Opt-in composite path (§4.2/§4.4/§4.5), handled BEFORE the pure algLevel gate because the
        // composite alg (-65537) is not a registered pure alg. Check order: CompositeRefused
        // (Sovereign floors at level 5; the composite ML-DSA-65 leg is level 3) -> SuiteMismatch
        // (field 14 must declare the matching suite) -> both-legs signature. Verifying key =
        // mldsaPub || ed25519Pub. This path IS cryptographically verified in full (ML-DSA-65 via
        // MlDsa, Ed25519 via ext-sodium).
        if ($halg === Cose::ALG_COMPOSITE_65_ED25519) {
            if ($profile === Cose::PROFILE_SOVEREIGN) {
                throw new EnvelopeError("CompositeRefused", "composite refused on the Sovereign profile");
            }
            if ($o->suite !== self::SUITE_MLDSA65_ED25519) {
                throw new EnvelopeError("SuiteMismatch", "field 14 does not declare the composite suite");
            }
            $mldsaPub = \substr($pubkey, 0, Cose::MLDSA65_PUB_SIZE);
            $edPub = \substr($pubkey, Cose::MLDSA65_PUB_SIZE);
            if (\strlen($edPub) !== 32 || !Cose::compositeVerify($mldsaPub, $edPub, $tbs, $sig)) {
                throw new EnvelopeError("BadSignature", "composite signature does not verify");
            }
            return $o;
        }

        // pure path: a non-composite alg MUST NOT carry the signed suite field (§4.2).
        if ($o->suite !== 0) {
            throw new EnvelopeError("SuiteMismatch", "pure object carries a composite suite field");
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
            if (!Cose::ed25519Verify($pubkey, $tbs, $sig)) {
                throw new EnvelopeError("BadSignature", "signature does not verify");
            }
        }
        // ML-DSA (pure): structural verification complete; the pure ML-DSA signature leg is verified
        // by the adapter's cose.verify1 op (MlDsa), not re-checked inside this structural verify().
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
        if (\count($causesV->items) > WireConstants::MAX_CAUSES) { // causal fan-in bound (§3.4, R7)
            throw new EnvelopeError("TooManyCauses", "causes[] exceeds the maximum count (§3.4, R7)");
        }
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
        if ($ext !== null && \count($ext->pairs) > WireConstants::MAX_EXT) { // ext cardinality bound (§3.4, R7)
            throw new EnvelopeError("TooManyExtensions", "ext/cext exceeds the maximum cardinality (§3.4, R7)");
        }
        if ($cext !== null && !($cext instanceof M)) {
            throw new EnvelopeError("Malformed", "cext not a map");
        }
        if ($cext !== null && \count($cext->pairs) > WireConstants::MAX_CEXT) { // cext cardinality bound (§3.4, R7)
            throw new EnvelopeError("TooManyExtensions", "ext/cext exceeds the maximum cardinality (§3.4, R7)");
        }
        $aud = $fields[self::FIELD_AUDIENCE] ?? null;
        if ($aud !== null && !($aud instanceof T)) {
            throw new EnvelopeError("Malformed", "audience not a tstr");
        }
        $suiteV = $fields[self::FIELD_SUITE] ?? null;
        if ($suiteV !== null && !($suiteV instanceof U)) {
            throw new EnvelopeError("Malformed", "suite not a uint");
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
            audience: $aud !== null ? $aud->v : '',
            suite: $suiteV !== null ? $suiteV->v : 0,
        );
        $idv = $fields[self::FIELD_ID] ?? null;
        $o->id = $idv instanceof B ? $idv->v : null;
        return $o;
    }

    /**
     * The single-use consume binding gate (§2.5.3), checked at the point of use -- before the consume
     * logic (the CAS append) -- NEVER inside verify(). An in-transit relay, ordering authority, or
     * auditor legitimately verifies objects addressed to some OTHER authority; only the authority about
     * to CONSUME an object enforces that the object is addressed to it. Three branches: (a) absent
     * audience on a consume-once object -> WrongAudience; (b) an audience present but not this authority
     * -> WrongAudience; (c) a non-consume-once object with no audience -> pass. Throws
     * EnvelopeError("WrongAudience") on rejection.
     */
    public static function checkAudience(NaalpObject $o, string $selfAuthority, bool $consumeOnce): void
    {
        if ($o->audience === '') {
            if ($consumeOnce) {
                throw new EnvelopeError("WrongAudience", "consume-once object has no audience");
            }
            return;
        }
        if ($o->audience !== $selfAuthority) {
            throw new EnvelopeError("WrongAudience", "object audience is not this consuming authority");
        }
    }

    /**
     * Read {1: nint(alg), "naalp": {1:signer, 2:profile, 3:version}} from a serialized protected
     * header.
     *
     * @return array{0:int,1:string,2:int,3:int} [alg, signer, profile, version]
     */
    private static function parseProtected(string $prot): array
    {
        // §3.1.1 (R5): the empty protected header is pinned to 0x40; a byte string wrapping an
        // empty CBOR map (the 0x41A0 form -- its unwrapped content is the single byte 0xA0) MUST
        // be rejected as NonCanonical before the header is interpreted as a map.
        if (\strlen($prot) === 1 && \ord($prot[0]) === 0xA0) {
            throw new EnvelopeError("NonCanonical", "empty protected header must be 0x40, not 0x41A0 (§3.1.1, R5)");
        }
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

    // --- §5.2 Rotation object (tag-98 COSE_Sign, old+new co-signature) ---

    private static function isRotationObject(int $channel, int $kind): bool
    {
        return $channel === 3 && $kind === 0;
    }

    private static function isCompositeAlg(int $alg): bool
    {
        return $alg === Cose::ALG_COMPOSITE_65_ED25519 || $alg === Cose::ALG_COMPOSITE_44_ED25519;
    }

    /**
     * Build a §5.2 Rotation object as a tag-98 COSE_Sign co-signed by the OLD then the NEW key in
     * fixed order; the body protected header names the NEW (go-forward) key. Permitted ONLY for the
     * Identity Rotation object (channel 3, kind 0); a composite leg is rejected fail-closed. Bytes are
     * byte-identical to the Go/Rust/Python/TS/Ruby reference implementations. Requires deterministic
     * ML-DSA (MlDsa / OpenSSL >= 3.5).
     */
    public static function signRotationObject(NaalpObject $o, int $oldAlg, string $oldSeed, int $newAlg, string $newSeed): string
    {
        if (!self::isRotationObject($o->channel, $o->kind)) {
            throw new EnvelopeError("UnknownKind", "tag-98 permitted only for the Identity Rotation object");
        }
        if (self::isCompositeAlg($oldAlg) || self::isCompositeAlg($newAlg)) {
            throw new EnvelopeError("Malformed", "composite-inside-rotation is undecided");
        }
        $o->suite = 0; // a rotation object is never composite
        $payload = self::buildPayload($o); // sets id = contentId()
        $bodyProt = self::protectedHeader($newAlg, $o->signer, $o->profile);
        $oldLeg = Cose::signatureLeg($bodyProt, $oldAlg, $oldSeed, $payload);
        $newLeg = Cose::signatureLeg($bodyProt, $newAlg, $newSeed, $payload);
        return Cose::assembleSignRaw($bodyProt, $payload, [$oldLeg, $newLeg]);
    }

    /**
     * Verify a tag-98 Rotation object (§5.2): the same object-body checks as verify(), then EXACTLY
     * two legs in fixed order (old-key then new-key) BOTH verifying via MlDsa. Any missing/wrong/bad
     * old leg is RotationUnauthorized. Permitted ONLY for (channel 3, kind 0). Requires MlDsa.
     *
     * @param callable(int,int):bool|null $kindValidator
     * @param array<int,bool> $knownCext
     */
    public static function verifyRotationObject(
        int $profile,
        int $oldAlg,
        string $oldPk,
        int $newAlg,
        string $newPk,
        ?callable $kindValidator,
        string $objBytes,
        array $knownCext = []
    ): NaalpObject {
        // Object octet-size bound (§3.4, R7): the tag-98 rotation object is a top-level signed
        // object too, so it is size-checked on raw bytes before any parse.
        if (\strlen($objBytes) > WireConstants::MAX_OBJECT_SIZE) {
            throw new EnvelopeError("TooLarge", "object exceeds the maximum octet size (§3.4, R7)");
        }
        try {
            [$bodyProt, $payload, $legs] = Cose::parseSignRaw($objBytes);
        } catch (\Throwable $e) {
            throw new EnvelopeError("Malformed", "not a COSE_Sign object");
        }
        // non-canonical -> NonCanonical; over-nested -> DepthExceeded (§3.4, R7).
        $bv = Cbor::decodeBounded($payload, WireConstants::MAX_NESTING_DEPTH);
        if (!($bv instanceof M)) {
            throw new EnvelopeError("Malformed", "body not a map");
        }

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
        if ($o->channel > 19 || $o->effect > 3 || $o->profile < 1 || $o->profile > 3) {
            throw new EnvelopeError("RangeError", "field out of range");
        }

        [$halg, $hsigner, $hprofile, $hversion] = self::parseProtected($bodyProt);
        if ($hversion !== self::NAALP_VERSION) {
            throw new EnvelopeError("UnsupportedVersion", "bad naalp-version");
        }
        if ($hsigner !== $o->signer || $hprofile !== $o->profile) {
            throw new EnvelopeError("HeaderBodyMismatch", "protected header disagrees with body");
        }
        // RECHECK_KEY (13) is envelope-recognized regardless of $knownCext, same as verify(); see the
        // comment there for the full rationale.
        if ($o->cext !== null) {
            foreach ($o->cext->pairs as [$k, $v]) {
                if (!($k instanceof U)) {
                    throw new EnvelopeError("UnknownCriticalExt", "unrecognized critical extension");
                }
                if ($k->v === self::RECHECK_KEY) {
                    if (!($v instanceof U)) {
                        throw new EnvelopeError("Malformed", "recheck procedure id not a uint");
                    }
                    if (!self::isKnownRecheckProcedure($v->v)) {
                        throw new EnvelopeError("UnknownCriticalExt", "unrecognized critical extension");
                    }
                    continue;
                }
                if (!\array_key_exists($k->v, $knownCext) || $knownCext[$k->v] !== true) {
                    throw new EnvelopeError("UnknownCriticalExt", "unrecognized critical extension");
                }
            }
        }

        // tag-98 is permitted ONLY for the Identity-channel Rotation object (channel 3, kind 0).
        if (!self::isRotationObject($o->channel, $o->kind)) {
            throw new EnvelopeError("UnknownKind", "tag-98 permitted only for the Identity Rotation object");
        }
        if ($kindValidator === null || !$kindValidator($o->channel, $o->kind)) {
            throw new EnvelopeError("UnknownKind", "kind/channel not a registered surface");
        }
        if (self::isCompositeAlg($halg)) {
            throw new EnvelopeError("Malformed", "composite-inside-rotation is undecided");
        }
        if ($halg !== $newAlg) {
            throw new EnvelopeError("KeyAlgMismatch", "body header alg is not the new key alg");
        }

        // EXACTLY two legs, fixed order (old, new). A missing/lone leg IS "old leg dropped".
        if (\count($legs) !== 2) {
            throw new EnvelopeError("RotationUnauthorized", "rotation must carry exactly two legs");
        }
        $oldLegAlg = Cose::algFromProtected($legs[0][0]);
        $newLegAlg = Cose::algFromProtected($legs[1][0]);
        if (self::isCompositeAlg($oldLegAlg) || self::isCompositeAlg($newLegAlg)) {
            throw new EnvelopeError("Malformed", "composite leg in a rotation");
        }
        if ($oldLegAlg !== $oldAlg || $newLegAlg !== $newAlg) {
            throw new EnvelopeError("RotationUnauthorized", "legs not in (old, new) order");
        }

        // profile floor: the NEW (go-forward) leg always; the OLD leg iff the fail-closed toggle applies.
        [$newLevel, $nknown] = Cose::algLevel($newLegAlg);
        if (!$nknown) {
            throw new EnvelopeError("UnknownAlg", "unregistered alg");
        }
        if ($newLevel < Cose::profileMinLevel($profile)) {
            throw new EnvelopeError("ProfileDowngrade", "new-leg level below the profile minimum");
        }
        if (self::ROTATION_OLD_LEG_FLOOR_APPLIES) {
            [$oldLevel, $oknown] = Cose::algLevel($oldLegAlg);
            if (!$oknown) {
                throw new EnvelopeError("UnknownAlg", "unregistered alg");
            }
            if ($oldLevel < Cose::profileMinLevel($profile)) {
                throw new EnvelopeError("ProfileDowngrade", "old-leg level below the profile minimum");
            }
        }

        // both legs MUST verify over their per-signer ToBeSigned (deterministic ML-DSA via MlDsa).
        $oldTbs = Cose::signatureToBeSigned($bodyProt, $oldLegAlg, $payload);
        if (!MlDsa::verify($oldPk, $oldTbs, $legs[0][1], $oldLegAlg)) {
            throw new EnvelopeError("RotationUnauthorized", "old leg does not verify");
        }
        $newTbs = Cose::signatureToBeSigned($bodyProt, $newLegAlg, $payload);
        if (!MlDsa::verify($newPk, $newTbs, $legs[1][1], $newLegAlg)) {
            throw new EnvelopeError("RotationUnauthorized", "new leg does not verify");
        }
        return $o;
    }

    // --- T1.3 recheck (the checkable-minimum field, NAALP-REQ-110/111, §2.5) ---

    // The ext/cext extension key under which an object NAMES the re-check procedure for the claim in
    // its body (§2.5, NAALP-REQ-111(c) -- the "checkable minimum"). The value is a procedure id into
    // the closed registry below. In the non-critical ext map (field 11) it is may-ignore; in the
    // critical cext map (field 12) it is must-understand and an unknown procedure id is rejected
    // fail-closed (UnknownCriticalExt), the same critical-extension rule reaching the procedure it
    // names. 13 does not collide with the safety-label ext key 1 (§6.4) or the signer-counter ext key
    // 14 (§2.5.2). Byte-identical to impl/go and impl/rust.
    public const RECHECK_KEY = 13;

    // The closed re-check procedure registry (design.md §2.5; T1.3).
    public const RECHECK_RECOMPUTE_CONTENT_ID = 1; // recompute the content id from the body and compare (§2.3)
    public const RECHECK_VERIFY_COSE_SIGN1 = 2;    // verify the COSE_Sign1 signature under the signer key (§4)
    public const RECHECK_WALK_CAUSES = 3;          // walk the signed causal partial order offline (§8.2)
    public const RECHECK_REPLAY_CONSUME_CHECK = 4; // replay the single-use consume ledger for the approval (§7.2)

    /**
     * Reports whether $id is a recognized re-check procedure. The registry is CLOSED: an id outside
     * it is unknown, and an unknown id under the critical map is rejected (§2.5).
     */
    public static function isKnownRecheckProcedure(int $id): bool
    {
        return $id >= self::RECHECK_RECOMPUTE_CONTENT_ID && $id <= self::RECHECK_REPLAY_CONSUME_CHECK;
    }

    /**
     * Returns [id, present, critical] -- the re-check procedure $o names (RECHECK_KEY, §2.5): present
     * is true when a procedure is named, and critical is true iff it is named in the cext map (field
     * 12, must-understand) rather than the ext map (field 11, may-ignore). cext takes precedence when
     * BOTH carry the key. When no procedure is named the claim is attributable-only (NAALP-REQ-111).
     *
     * @return array{0:int,1:bool,2:bool}
     */
    public static function recheck(NaalpObject $o): array
    {
        [$v, $ok] = self::extGetUint($o->cext, self::RECHECK_KEY);
        if ($ok) {
            return [$v, true, true];
        }
        [$v, $ok] = self::extGetUint($o->ext, self::RECHECK_KEY);
        if ($ok) {
            return [$v, true, false];
        }
        return [0, false, false];
    }

    /**
     * Names $procId as $o's body claim's re-check procedure. $critical places it in the cext map
     * (field 12, must-understand); otherwise the ext map (field 11, may-ignore). Creates the carrier
     * if absent and leaves any other extension entries intact.
     */
    public static function setRecheck(NaalpObject $o, int $procId, bool $critical): void
    {
        $entry = [new U(self::RECHECK_KEY), new U($procId)];
        if ($critical) {
            $o->cext = self::replaceOrAppendEntry($o->cext, self::RECHECK_KEY, $entry);
        } else {
            $o->ext = self::replaceOrAppendEntry($o->ext, self::RECHECK_KEY, $entry);
        }
    }

    // --- T1.6 per-signer forward-only counter + duplication detection (NAALP-REQ-120, §2.5.2) ---

    // The ext extension key under which an object OPTIONALLY carries a forward-only per-signer
    // counter (design.md §2.5.2, NAALP-REQ-120 -- the per-signer counter). The value is a
    // forward-only position (a uint) the signer increments on each object. It lives in the
    // NON-CRITICAL ext map (field 11): a verifier that does not perform duplication-detection ignores
    // it and the object still verifies (may-ignore). Because ext (field 11) is part of the signed
    // body/payload, the counter is covered by the SIGNER's own COSE_Sign1 signature -- the deliberate
    // contrast with the consume-receipt position, which is signed by the LEDGER key. 14 does not
    // collide with the safety-label ext key 1 (§6.4) or the recheck ext/cext key 13. Byte-identical
    // to impl/go and impl/rust.
    //
    // The counter is DETECTION, not prevention (NAALP-REQ-120): a single self-authored sequence
    // proves nothing. It is a NON-CRITICAL field only -- placing it in the critical cext map (field
    // 12) is an unrecognized critical extension and is rejected fail-closed (UnknownCriticalExt),
    // because a detection aid is never a must-understand verification gate.
    public const SIGNER_COUNTER_KEY = 14;

    /**
     * Returns [seq, present] -- the forward-only per-signer position $o names (SIGNER_COUNTER_KEY,
     * §2.5.2): present is true iff a counter is named in the non-critical ext map (field 11) as a
     * uint. The field is OPTIONAL -- absent (present == false) is valid. present is keyed on the KEY
     * being present, not on the value: a present counter of value 0 returns [0, true].
     *
     * @return array{0:int,1:bool}
     */
    public static function signerCounter(NaalpObject $o): array
    {
        return self::extGetUint($o->ext, self::SIGNER_COUNTER_KEY);
    }

    /**
     * Names $seq as $o's forward-only per-signer position in the NON-CRITICAL ext map (field 11),
     * covered by the signer's COSE_Sign1 signature. Creates the ext carrier if absent and leaves any
     * other extension entries intact. The counter is deliberately never placed in the critical cext
     * map (it is detection, not a verification gate).
     */
    public static function setSignerCounter(NaalpObject $o, int $seq): void
    {
        $entry = [new U(self::SIGNER_COUNTER_KEY), new U($seq)];
        $o->ext = self::replaceOrAppendEntry($o->ext, self::SIGNER_COUNTER_KEY, $entry);
    }

    /**
     * Reads a uint value under $key in a CBOR map (ext or cext). Returns [value, present]; present is
     * true only when the key exists AND its value is a uint.
     *
     * @return array{0:int,1:bool}
     */
    private static function extGetUint(?M $m, int $key): array
    {
        if ($m === null) {
            return [0, false];
        }
        foreach ($m->pairs as [$k, $v]) {
            if ($k instanceof U && $k->v === $key) {
                if ($v instanceof U) {
                    return [$v->v, true];
                }
                return [0, false];
            }
        }
        return [0, false];
    }

    /**
     * Replaces $key's entry in $m with $entry if present, otherwise appends it; creates the map if
     * $m is null. Leaves every other entry intact; the return value is always a NEW map (the caller
     * assigns it back to $o->ext / $o->cext).
     *
     * @param array{0:mixed,1:mixed} $entry
     */
    private static function replaceOrAppendEntry(?M $m, int $key, array $entry): M
    {
        if ($m === null) {
            return new M([$entry]);
        }
        $pairs = [];
        $replaced = false;
        foreach ($m->pairs as [$k, $v]) {
            if ($k instanceof U && $k->v === $key) {
                $pairs[] = $entry;
                $replaced = true;
            } else {
                $pairs[] = [$k, $v];
            }
        }
        if (!$replaced) {
            $pairs[] = $entry;
        }
        return new M($pairs);
    }

    /**
     * Compares two forward-only counter values as UNSIGNED 64-bit integers (a value >= 2^63 is
     * carried as a negative PHP int bit-pattern, per Cbor::encode's U handling, §2.3): a negative
     * value always compares GREATER than a non-negative one, and within one sign group plain signed
     * comparison already matches unsigned order.
     */
    private static function u64Cmp(int $a, int $b): int
    {
        $an = $a < 0;
        $bn = $b < 0;
        if ($an !== $bn) {
            return $an ? 1 : -1;
        }
        return $a <=> $b;
    }

    /**
     * Scans a SET of PRESENTED objects for per-signer counter reuse (NAALP-REQ-120). This is the
     * whole point of the field, and it is DETECTION, not prevention: it flags a signer id ONLY when
     * two conflicting sequences from that signer physically MEET in the presented set -- a counter
     * value bound to >= 2 distinct content ids by one signer. Given only ONE object per value it
     * returns no findings; the second conflicting object must be present, unsuppressed, for the
     * duplication to become provable. Objects with no counter do not participate. Output is
     * deterministic (findings ordered by signer id then counter; ids within a finding ascending by
     * bytes). Byte-identical logic to impl/go/impl/rust DetectSignerDuplication.
     *
     * It operates over the SET, never per object: a per-object boolean could never express "these two
     * distinct objects reuse one position," and a single self-authored counter proves nothing on its
     * own.
     *
     * @param list<NaalpObject> $objs
     * @return list<DuplicationFinding>
     */
    public static function detectSignerDuplication(array $objs): array
    {
        // signerKey -> counter -> (contentIdKey -> contentIdBytes), a set that de-dups a
        // byte-identical re-presentation (one content id twice) so it is NOT a conflict.
        $groups = [];
        $signerBytes = [];
        foreach ($objs as $o) {
            [$seq, $present] = self::signerCounter($o);
            if (!$present) {
                continue; // a counter-less object does not participate in detection
            }
            try {
                $id = $o->contentId();
            } catch (\Throwable $e) {
                continue; // a body that cannot be canonically encoded cannot be a presented object
            }
            $sk = 'x' . \bin2hex($o->signer); // 'x'-prefixed hex: never a numeric-looking PHP array key
            $signerBytes[$sk] = $o->signer;
            if (!isset($groups[$sk])) {
                $groups[$sk] = [];
            }
            if (!isset($groups[$sk][$seq])) {
                $groups[$sk][$seq] = [];
            }
            $idKey = 'x' . \bin2hex($id);
            $groups[$sk][$seq][$idKey] = $id;
        }

        $signerKeys = \array_keys($groups);
        \usort($signerKeys, static fn($a, $b) => \strcmp($signerBytes[$a], $signerBytes[$b]));

        $findings = [];
        foreach ($signerKeys as $sk) {
            $byCounter = $groups[$sk];
            $counters = \array_keys($byCounter);
            \usort($counters, [self::class, 'u64Cmp']);
            foreach ($counters as $c) {
                $idset = $byCounter[$c];
                // A (signer, counter) that binds two-or-more DISTINCT content ids is a detected
                // duplication. The >= 2 requirement is the detection-requires-both invariant: relax
                // it to >= 1 and a single sequence would flag (prevention theatre).
                if (\count($idset) < 2) {
                    continue;
                }
                $ids = \array_values($idset);
                \usort($ids, 'strcmp');
                $findings[] = new DuplicationFinding($signerBytes[$sk], $c, $ids);
            }
        }
        return $findings;
    }

    // --- NA-IETF-1 producing-boundary disclosure (OPTIONAL, self-asserted ext key 15, §2.5.4) ---

    // The ext extension key under which an object OPTIONALLY carries a per-object producing-boundary
    // disclosure (design.md §2.5.4, NA-IETF-1): the trust boundary that emitted the object and whether
    // that boundary OBSERVED the event it describes first-hand or is RELAYING a report of it. It rides
    // the NON-CRITICAL ext map (field 11): a verifier that does not understand it, or that reads a
    // malformed value, IGNORES the entry and the object still verifies (may-ignore). Because ext is
    // part of the signed body/payload, the disclosure is covered by the SIGNER's own COSE_Sign1
    // signature -- a SELF-ASSERTED claim. 15 collides with neither the safety-label ext key 1 (§6.4),
    // the recheck ext/cext key 13 (§2.5.1), nor the signer-counter ext key 14 (§2.5.2). Byte-identical
    // to impl/go and impl/python.
    public const PRODUCING_BOUNDARY_KEY = 15;

    // The producing-boundary kind (§2.5.4): a closed enum naming whether the emitting boundary
    // witnessed the event directly or is relaying a report of it.
    public const PRODUCING_BOUNDARY_OBSERVED = 1; // this boundary witnessed the event directly (first-hand)
    public const PRODUCING_BOUNDARY_REPORTED = 2; // this boundary is relaying a report it did not witness

    // The producing-boundary value sub-map keys (§2.5.4).
    private const PB_FIELD_BOUNDARY = 1;  // bstr -- the emitting trust boundary (party id)
    private const PB_FIELD_KIND = 2;      // 1 observed / 2 reported
    private const PB_FIELD_REPORTING = 3; // bstr -- report origin; present iff kind == reported

    /**
     * Return [ProducingBoundary|null, present] -- present is true iff `o` carries a WELL-FORMED
     * producing-boundary disclosure in the non-critical ext map (field 11, PRODUCING_BOUNDARY_KEY): a
     * non-empty boundary (key 1), a kind (key 2) in {observed, reported}, and a reporting-boundary
     * (key 3) absent unless the kind is reported. A malformed value is IGNORED -- returns
     * [null, false], NEVER throwing (may-ignore). An absent disclosure returns [null, false]. An
     * unrecognized sub-key is ignored and does not by itself make an otherwise well-formed value
     * malformed.
     *
     * @return array{0:?ProducingBoundary,1:bool}
     */
    public static function producingBoundary(NaalpObject $o): array
    {
        if ($o->ext === null) {
            return [null, false];
        }
        $val = null;
        $found = false;
        foreach ($o->ext->pairs as [$k, $v]) {
            if ($k instanceof U && $k->v === self::PRODUCING_BOUNDARY_KEY) {
                $val = $v;
                $found = true;
                break;
            }
        }
        if (!$found || !($val instanceof M)) {
            return [null, false];
        }
        $boundary = null;
        $kind = null;
        $reporting = null;
        $haveReporting = false;
        foreach ($val->pairs as [$k, $v]) {
            if (!($k instanceof U)) {
                return [null, false];
            }
            if ($k->v === self::PB_FIELD_BOUNDARY) {
                if (!($v instanceof B)) {
                    return [null, false];
                }
                $boundary = $v->v;
            } elseif ($k->v === self::PB_FIELD_KIND) {
                if (!($v instanceof U)) {
                    return [null, false];
                }
                $kind = $v->v;
            } elseif ($k->v === self::PB_FIELD_REPORTING) {
                if (!($v instanceof B)) {
                    return [null, false];
                }
                $reporting = $v->v;
                $haveReporting = true;
            }
            // else: an unrecognized sub-key -- may-ignore.
        }
        // well-formedness (§2.5.4). Any failure returns [null, false] (may-ignore), never an error.
        if ($boundary === null || $boundary === '') {
            return [null, false]; // no boundary named
        }
        if ($kind !== self::PRODUCING_BOUNDARY_OBSERVED && $kind !== self::PRODUCING_BOUNDARY_REPORTED) {
            return [null, false]; // absent or out-of-enum kind
        }
        if ($haveReporting && $kind !== self::PRODUCING_BOUNDARY_REPORTED) {
            return [null, false]; // a reporting-boundary under observed: an observer relays from no one
        }
        return [new ProducingBoundary($boundary, $kind, $haveReporting ? $reporting : null), true];
    }

    /**
     * Name `pb` as `o`'s producing-boundary disclosure in the NON-CRITICAL ext map (field 11),
     * covered by the signer's COSE_Sign1 signature. Creates the ext carrier if absent and leaves any
     * other extension entries intact. The reporting-boundary is emitted ONLY when non-null AND the
     * kind is reported, so a caller cannot accidentally emit a malformed observed-with-reporting
     * disclosure (an observer relays from no one). Sub-map keys are appended in ascending order;
     * encode emits canonical CBOR regardless, so the object stays deterministic.
     */
    public static function setProducingBoundary(NaalpObject $o, ProducingBoundary $pb): void
    {
        $sub = [
            [new U(self::PB_FIELD_BOUNDARY), new B($pb->boundary)],
            [new U(self::PB_FIELD_KIND), new U($pb->kind)],
        ];
        if ($pb->reporting !== null && $pb->kind === self::PRODUCING_BOUNDARY_REPORTED) {
            $sub[] = [new U(self::PB_FIELD_REPORTING), new B($pb->reporting)];
        }
        $entry = [new U(self::PRODUCING_BOUNDARY_KEY), new M($sub)];
        if ($o->ext === null) {
            $o->ext = new M([$entry]);
            return;
        }
        $newPairs = [];
        $replaced = false;
        foreach ($o->ext->pairs as [$k, $v]) {
            if ($k instanceof U && $k->v === self::PRODUCING_BOUNDARY_KEY) {
                $newPairs[] = $entry;
                $replaced = true;
            } else {
                $newPairs[] = [$k, $v];
            }
        }
        if (!$replaced) {
            $newPairs[] = $entry;
        }
        $o->ext = new M($newPairs);
    }
}

/**
 * A decoded producing-boundary disclosure (Envelope::PRODUCING_BOUNDARY_KEY, §2.5.4). `boundary` is
 * the emitting trust boundary (the same raw bstr party-id form as NaalpObject::$signer). `kind` is
 * Envelope::PRODUCING_BOUNDARY_OBSERVED or Envelope::PRODUCING_BOUNDARY_REPORTED. `reporting` names
 * the report origin and is non-null ONLY when kind is PRODUCING_BOUNDARY_REPORTED (an observer relays
 * from no one).
 */
final class ProducingBoundary
{
    public function __construct(
        public string $boundary,
        public int $kind,
        public ?string $reporting = null,
    ) {
    }
}

/**
 * One detected per-signer counter conflict (Envelope::detectSignerDuplication, §2.5.2): two or more
 * DISTINCT objects (distinct content ids) from the SAME signer id that carry the SAME forward-only
 * counter value. A forward-only counter binds each value to at most one object, so a value bound to
 * >= 2 distinct objects is the observable fingerprint of the key incrementing in two places (key
 * duplication). The finding surfaces BOTH sides of the contradiction: the reused `counter` value and
 * every conflicting content id (`ids`, ascending by bytes) -- never a single flag with the evidence
 * hidden.
 */
final class DuplicationFinding
{
    /** @param list<string> $ids raw content-id byte strings of the >= 2 conflicting objects, ascending by bytes */
    public function __construct(
        public string $signer,
        public int $counter,
        public array $ids,
    ) {
    }
}
