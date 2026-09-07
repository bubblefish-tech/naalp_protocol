<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
/**
 * N-AALP C18 signed description / directory / import primitive for the PHP SDK (design.md §21;
 * R-DESC-1..8).
 *
 * C18 is a signed, OFFLINE-VERIFIABLE description and discovery layer carried on N-AALP's own signed
 * object. Its load-bearing property is that authority lives in the SIGNED BYTES, never in the connection
 * or the host that served them: the same signed Description re-verifies byte-identically when an
 * unrelated host serves it, because the signature (not a TLS-fetch origin) is the authority. It
 * introduces NO new envelope, encoding, signature, identity, or audit mechanism (R-11.3): each object is
 * an ordinary signed N-AALP body (COSE_Sign1, §4), reusing the closed C5 effect lattice (Policy) and the
 * T1 content-id framing (§2.3) unchanged.
 *
 * Three wire objects:
 *   - Description {1: service, 2: operations[]} lists a service's operations, each Operation
 *     {1: name, 2: effect, 3: requires_approval} carrying its C5 effect and an approval declaration.
 *     Desc::parseDescription reconstructs the whole operation table from the bytes ALONE.
 *   - Directory {1: directory, 2: version, 3: members[]} is a signed collection whose members are
 *     content ids. Two conflicting versions from ONE signer — same directory and version, different
 *     members — are a FORK, detected at the FIRST-DIFFERING member POSITION (as the §8.5 audit
 *     fork-proof reports the position of an equivocation).
 *   - Import {1: importer, 2: format, 3: foreign, 4: operations[]} carries a foreign description format
 *     (an A2A Agent Card, an ANP Agent Description, an AGNTCY Agent Badge) octet-for-octet (carriage,
 *     not adoption) as a signed N-AALP attestation binding the foreign bytes' content id AND an N-AALP
 *     effect mapping. The IMPORTER (the wrapping signer, recomputed self-certifyingly from the verifying
 *     key) is the SOLE authorization identity; a foreign identity embedded in `foreign` never becomes an
 *     N-AALP authorization identity — the confused-deputy rule, enforced normatively here (R-14.6).
 *
 * An independent transcription of impl/go/description (cross-read against impl/python/naalp/description.py),
 * graded against the shared vectors/description/cases.json. The bodies, heads, content ids, the
 * foreign-id binding, the fork first-differing position, and the closed foreign-format rejection are
 * signature-independent and pure.
 *
 * CRYPTO SCOPE (PURE-ONLY / STRUCTURAL-ML-DSA): the byte surfaces above are pure and corpus-graded. PHP
 * has no deterministic ML-DSA (FIPS 204) signer, so — exactly as the delegation port — the signed-object
 * sign/verify paths (signDescription / signDirectory / signImport pairing with verifyDescription /
 * verifyDirectory / verifyImport / DirectoryForkProof::verify) produce/accept a structural ML-DSA-65
 * object (bare {1: alg} header + placeholder signature) that clears the level-3 profile floor; the
 * ML-DSA signature itself is not cryptographically signed/verified in PHP (documented, not faked). A
 * real Ed25519 (RFC 8032) leg is also demonstrated (signBody's Ed25519 branch), but it is a level-0
 * signature that never clears the level-3 profile floor, so it round-trips its RAW signature in
 * isolation rather than through verifyDescription/verifyDirectory/verifyImport. The signer id the
 * confused-deputy check binds is a REAL Identity::signerId(ML-DSA-65, pubkey), so the R-14.6 binding is
 * genuinely exercised, and a level-0 Ed25519 object is correctly rejected ProfileDowngrade. The corpus
 * carries no signed vector, so all signed paths are isolation-only.
 *
 * DEVIATION (honest F4, as the Python port documents): Go's verifyImport carries a VerifierKeyMismatch
 * guard because it takes BOTH an (alg, pubkey) pair AND a separate verifier and must bind them before
 * deriving the authority id. This port (like Gateway/Delegation) verifies with a SINGLE (alg, pubkey), so
 * the authority id is ALWAYS derived from exactly the verifying key — the mismatch that guard prevents is
 * structurally impossible, so there is no VerifierKeyMismatch surface. It is absent, not silently dropped.
 *
 * Every check is fail-closed (§15): a failing object is rejected whole, returns its named error, and
 * causes no state change.
 */

declare(strict_types=1);

namespace Naalp;

// Named, fail-closed errors; $kind mirrors the Go/Rust/Python error kinds. The crypto kinds UnknownAlg
// (Identity.php), ProfileDowngrade / KeyAlgMismatch / BadSignature (Gateway.php) are reused unchanged.
class DescError extends \RuntimeException
{
    public string $kind;

    public function __construct(string $kind, string $msg = "")
    {
        $this->kind = $kind;
        parent::__construct($msg === "" ? $kind : "$kind: $msg");
    }
}

/**
 * One entry of a Description or an Import mapping: a named operation, its C5 effect class, and whether it
 * requires an approval. `requiresApproval` is the uint 1 (yes) / 0 (no) — the N-AALP spine carries no
 * CBOR boolean (design §3.1).
 */
final class Operation
{
    public string $name;         // operation name (advisory routing key)
    public int $effect;          // the operation's effect class (C5 lattice)
    public int $requiresApproval; // 1 if this operation requires an approval, 0 otherwise

    public function __construct(string $name, int $effect, int $requiresApproval)
    {
        $this->name = $name;
        $this->effect = $effect;
        $this->requiresApproval = $requiresApproval;
    }

    /** The operation as its CBOR map {1: name, 2: effect, 3: requires_approval}. */
    public function toMap(): M
    {
        return new M([
            [new U(1), new T($this->name)],
            [new U(2), new U($this->effect)],
            [new U(3), new U($this->requiresApproval)],
        ]);
    }

    /** Deterministic-CBOR encoding of the operation body. */
    public function bytes(): string
    {
        return Cbor::encode($this->toMap());
    }

    /** The per-operation effect, normalized fail-closed: an unrecognized value is destructive (R-6.2). */
    public function effectClass(): int
    {
        return Policy::normalizeEffect($this->effect);
    }

    /** True iff the operation declares that it requires an approval. */
    public function requiresApprovalFlag(): bool
    {
        return $this->requiresApproval === 1;
    }
}

/**
 * A signed N-AALP object listing a service's operations. Its authority is in the signed bytes:
 * Desc::parseDescription reconstructs the whole operation table from the bytes alone, so an unrelated
 * host serving the same bytes yields a byte-identical verification (offline-verifiable).
 */
final class Description
{
    public string $service;      // opaque service id
    /** @var array<int,Operation> */
    public array $operations;

    /** @param array<int,Operation> $operations */
    public function __construct(string $service, array $operations)
    {
        $this->service = $service;
        $this->operations = \array_values($operations);
    }

    /** Deterministic-CBOR encoding {1: service, 2: operations[]}. */
    public function bytes(): string
    {
        return Cbor::encode(new M([
            [new U(1), new B($this->service)],
            [new U(2), Desc::operationsValue($this->operations)],
        ]));
    }

    /** The Description's SHA-384 head (48 octets). */
    public function head(): string
    {
        return \hash('sha384', $this->bytes(), true);
    }

    /** The Description's T1 content id (50 octets). */
    public function id(): string
    {
        return Cbor::contentId($this->bytes());
    }

    /**
     * The named operation and whether it is listed.
     * @return array{0:?Operation,1:bool}
     */
    public function operation(string $name): array
    {
        return Desc::findOperation($this->operations, $name);
    }
}

/**
 * A signed collection object whose members are content ids (the same shape the §8.2 causal partial order
 * uses for `causes`). It carries a monotonic per-signer version so two versions can be compared for
 * equivocation.
 */
final class Directory
{
    public string $directory;    // opaque directory id
    public int $version;         // monotonic per-signer version
    /** @var array<int,string> content ids of the member objects */
    public array $members;

    /** @param array<int,string> $members */
    public function __construct(string $directory, int $version, array $members)
    {
        $this->directory = $directory;
        $this->version = $version;
        $this->members = \array_values($members);
    }

    /** Deterministic-CBOR encoding {1: directory, 2: version, 3: members[]}. */
    public function bytes(): string
    {
        $arr = [];
        foreach ($this->members as $m) {
            $arr[] = new B($m);
        }
        return Cbor::encode(new M([
            [new U(1), new B($this->directory)],
            [new U(2), new U($this->version)],
            [new U(3), new A($arr)],
        ]));
    }

    /** The Directory's SHA-384 head (48 octets). */
    public function head(): string
    {
        return \hash('sha384', $this->bytes(), true);
    }

    /** The Directory's T1 content id (50 octets). */
    public function id(): string
    {
        return Cbor::contentId($this->bytes());
    }
}

/**
 * Carries a foreign description format octet-for-octet (carriage, not adoption) as a signed N-AALP
 * attestation. `importer` is the wrapping signer id (the sole authorization identity); `foreign` is the
 * foreign bytes verbatim; `operations` is the N-AALP effect mapping the importer attests. The foreign
 * bytes' content id is bound by foreignId().
 */
final class Import
{
    public string $importer;     // the importing (wrapping) signer id — the SOLE authorization identity (R-14.6)
    public int $format;          // the foreign description format code
    public string $foreign;      // the foreign description bytes, carried octet-for-octet
    /** @var array<int,Operation> the N-AALP effect mapping the importer attests */
    public array $operations;

    /** @param array<int,Operation> $operations */
    public function __construct(string $importer, int $format, string $foreign, array $operations)
    {
        $this->importer = $importer;
        $this->format = $format;
        $this->foreign = $foreign;
        $this->operations = \array_values($operations);
    }

    /** Deterministic-CBOR encoding {1: importer, 2: format, 3: foreign, 4: operations[]}. */
    public function bytes(): string
    {
        return Cbor::encode(new M([
            [new U(1), new B($this->importer)],
            [new U(2), new U($this->format)],
            [new U(3), new B($this->foreign)],
            [new U(4), Desc::operationsValue($this->operations)],
        ]));
    }

    /** The Import's SHA-384 head (48 octets). */
    public function head(): string
    {
        return \hash('sha384', $this->bytes(), true);
    }

    /** The Import attestation's own T1 content id (50 octets). */
    public function id(): string
    {
        return Cbor::contentId($this->bytes());
    }

    /** The T1 content id of the carried foreign bytes — the hash the attestation binds. A changed
     * foreign document yields a different foreignId, so an attestation binds the exact bytes. */
    public function foreignId(): string
    {
        return Cbor::contentId($this->foreign);
    }

    /**
     * The named operation from the attested mapping and whether it is listed.
     * @return array{0:?Operation,1:bool}
     */
    public function operation(string $name): array
    {
        return Desc::findOperation($this->operations, $name);
    }
}

/**
 * An Import that has passed signature verification and the confused-deputy check. authorityId is the
 * self-certifying signer id RECOMPUTED from the verifying key — the wrapping signer, and the only
 * authorization identity. It is never any identity parsed from the foreign bytes.
 */
final class ResolvedImport
{
    public string $authorityId;  // the wrapping signer id, recomputed from the key (the sole authority)
    public int $format;
    public string $foreignId;    // the content id the attestation binds
    /** @var array<int,Operation> */
    public array $operations;

    /** @param array<int,Operation> $operations */
    public function __construct(string $authorityId, int $format, string $foreignId, array $operations)
    {
        $this->authorityId = $authorityId;
        $this->format = $format;
        $this->foreignId = $foreignId;
        $this->operations = \array_values($operations);
    }
}

/**
 * Non-repudiable evidence of a directory fork: two validly-signed Directory objects by ONE signer at the
 * SAME (directory, version) listing DIFFERENT members, carried as the accused signer's OWN two signed
 * objects (the tagged COSE_Sign1 bytes). Because a single verifier checks BOTH signed objects, the proof
 * is self-contained.
 */
final class DirectoryForkProof
{
    public string $signer;   // accused signer id (both signed objects verify under its key)
    public string $signedA;  // the accused's first signed Directory (tagged COSE_Sign1)
    public string $signedB;  // the accused's second signed Directory at the same (directory, version)

    public function __construct(string $signer, string $signedA, string $signedB)
    {
        $this->signer = $signer;
        $this->signedA = $signedA;
        $this->signedB = $signedB;
    }

    /**
     * Check that this is a genuine directory fork by the signer whose key is (alg, pubkey), and return
     * the FIRST-DIFFERING member POSITION. Accepts iff ALL hold: (1) the signer id is present; (2) BOTH
     * signed objects verify under the key (which, because a single verifier checks both, proves one
     * signer); (3) the two directories share one directory id and version; and (4) their member lists
     * differ. Any failure rejects the whole proof (fail-closed): an unnamed signer, a different
     * directory/version, or identical members is DirForkProofInvalid; a signature that does not verify
     * propagates its named error.
     */
    public function verify(int $profile, int $alg, string $pubkey): int
    {
        if ($this->signer === "") {
            throw new DescError("DirForkProofInvalid", "an unnamed accused is not evidence");
        }
        $a = Desc::verifyDirectory($this->signedA, $profile, $alg, $pubkey);
        $b = Desc::verifyDirectory($this->signedB, $profile, $alg, $pubkey);
        [$pos, $fork] = Desc::detectFork($a, $b);
        if (!$fork) {
            throw new DescError("DirForkProofInvalid", "same directory+version identical members, or not the same versioned directory");
        }
        return $pos;
    }
}

final class Desc
{
    /** The width of a head / content-id digest (SHA-384 = 48 bytes), matching the C7 audit chain. */
    public const HEAD_SIZE = 48;

    // Foreign description format codes (the closed naalp-description-format registry, §21).
    public const FORMAT_A2A_CARD = 1;        // A2A Agent Card
    public const FORMAT_ANP_DESCRIPTION = 2; // ANP Agent Description
    public const FORMAT_AGNTCY_BADGE = 3;    // AGNTCY Agent Badge

    /** Whether $fmt is a registered foreign-description format (the closed set {1,2,3}). */
    public static function isKnownFormat(int $fmt): bool
    {
        return $fmt === self::FORMAT_A2A_CARD || $fmt === self::FORMAT_ANP_DESCRIPTION || $fmt === self::FORMAT_AGNTCY_BADGE;
    }

    /** Encode an operations slice as a CBOR array of operation maps. */
    public static function operationsValue(array $ops): A
    {
        $arr = [];
        foreach ($ops as $op) {
            $arr[] = $op->toMap();
        }
        return new A($arr);
    }

    /**
     * The first operation with the given name.
     * @param array<int,Operation> $ops
     * @return array{0:?Operation,1:bool}
     */
    public static function findOperation(array $ops, string $name): array
    {
        foreach ($ops as $op) {
            if ($op->name === $name) {
                return [$op, true];
            }
        }
        return [null, false];
    }

    /**
     * Parse one operation map, rejecting a malformed shape (DescMalformed) or an approval flag outside
     * {0,1} (MalformedApprovalFlag). Fail-closed.
     */
    public static function operationFromValue(mixed $v): Operation
    {
        if (!($v instanceof M)) {
            throw new DescError("DescMalformed", "operation is not a map");
        }
        $name = $effect = $req = null;
        foreach ($v->pairs as [$k, $val]) {
            if (!($k instanceof U)) {
                throw new DescError("DescMalformed", "non-uint operation key");
            }
            if ($k->v === 1 && $val instanceof T) {
                $name = $val->v;
            } elseif ($k->v === 2 && $val instanceof U) {
                $effect = $val->v;
            } elseif ($k->v === 3 && $val instanceof U) {
                $req = $val->v;
            }
        }
        if ($name === null || $effect === null || $req === null) {
            throw new DescError("DescMalformed", "operation missing a mandatory field");
        }
        if ($req > 1) {
            throw new DescError("MalformedApprovalFlag", "requires_approval is outside {0,1}: the spine carries no CBOR boolean, so it is rejected, never defaulted");
        }
        return new Operation($name, $effect, $req);
    }

    /**
     * Parse the operations array.
     * @return array<int,Operation>
     */
    public static function operationsFromValue(mixed $v): array
    {
        if (!($v instanceof A)) {
            throw new DescError("DescMalformed", "operations is not an array");
        }
        $ops = [];
        foreach ($v->items as $e) {
            $ops[] = self::operationFromValue($e);
        }
        return $ops;
    }

    /** Reconstruct a Description from its body bytes ALONE — the offline-verifiable property. */
    public static function parseDescription(string $b): Description
    {
        $m = self::decodeMap($b);
        $svc = self::bstrField($m, 1);
        $opsV = self::field($m, 2);
        if ($svc === null || $opsV === null) {
            throw new DescError("DescMalformed", "description missing service or operations");
        }
        return new Description($svc, self::operationsFromValue($opsV));
    }

    /**
     * Produce the tagged COSE_Sign1 object over the Description body (Go impl/go/description/
     * description.go:231 SignDescription). Pairs with verifyDescription (round-trip). See signBody
     * (below verifyImport) for the alg dispatch: Ed25519 is signed with real crypto; ML-DSA is signed
     * STRUCTURALLY (a placeholder, not cryptographically verified in PHP), exactly as verifySign1
     * accepts on the verify side.
     */
    public static function signDescription(Description $d, int $alg, string $seed): string
    {
        return self::signBody($d->bytes(), $alg, $seed);
    }

    /**
     * Verify a Description's signed object under the profile (structural ML-DSA in the pure tier), then
     * reconstruct the operation table from the signed body bytes. Because the authority is the signature
     * over the bytes, this returns the identical Description regardless of which host served $obj (the
     * offline-verification property, R-DESC-1). Fail-closed.
     */
    public static function verifyDescription(string $obj, int $profile, int $alg, string $pubkey): Description
    {
        $payload = self::verifySign1($obj, $profile, $alg, $pubkey);
        return self::parseDescription($payload);
    }

    /** Reconstruct a Directory from its body bytes alone. */
    public static function parseDirectory(string $b): Directory
    {
        $m = self::decodeMap($b);
        $did = self::bstrField($m, 1);
        $ver = self::uintField($m, 2);
        $memV = self::field($m, 3);
        if ($did === null || $ver === null || !($memV instanceof A)) {
            throw new DescError("DescMalformed", "directory missing or malformed field");
        }
        $members = [];
        foreach ($memV->items as $e) {
            if (!($e instanceof B)) {
                throw new DescError("DescMalformed", "member is not a bstr");
            }
            $members[] = $e->v;
        }
        return new Directory($did, $ver, $members);
    }

    /**
     * Produce the tagged COSE_Sign1 object over the Directory body (Go impl/go/description/
     * description.go:307 SignDirectory). Pairs with verifyDirectory (round-trip).
     */
    public static function signDirectory(Directory $d, int $alg, string $seed): string
    {
        return self::signBody($d->bytes(), $alg, $seed);
    }

    /** Verify a Directory's signed object under the profile, then reconstruct it. Fail-closed. */
    public static function verifyDirectory(string $obj, int $profile, int $alg, string $pubkey): Directory
    {
        $payload = self::verifySign1($obj, $profile, $alg, $pubkey);
        return self::parseDirectory($payload);
    }

    /**
     * The first index at which two member lists differ, and whether they differ at all. If the lists
     * share a common prefix and one is longer, the difference is reported at the length of the shorter
     * list. Identical lists return [0, false].
     *
     * @param array<int,string> $a
     * @param array<int,string> $b
     * @return array{0:int,1:bool}
     */
    public static function firstMemberDifference(array $a, array $b): array
    {
        $n = \min(\count($a), \count($b));
        for ($i = 0; $i < $n; $i++) {
            if ($a[$i] !== $b[$i]) {
                return [$i, true];
            }
        }
        if (\count($a) !== \count($b)) {
            return [$n, true];
        }
        return [0, false];
    }

    /**
     * Compare two directory versions from ONE signer and report whether they equivocate — the SAME
     * directory id and version but DIFFERENT members — and, if so, the FIRST-DIFFERING member POSITION.
     * A different directory id or version is a legitimate distinct object/succession, not a fork;
     * identical members are a benign duplicate. In both non-fork cases returns [0, false]. The caller
     * establishes the "one signer" precondition by verifying both objects under the same key.
     *
     * @return array{0:int,1:bool}
     */
    public static function detectFork(Directory $a, Directory $b): array
    {
        if ($a->directory !== $b->directory || $a->version !== $b->version) {
            return [0, false]; // different directory or version — not a conflicting pair
        }
        return self::firstMemberDifference($a->members, $b->members);
    }

    /**
     * Reconstruct an Import from its body bytes alone. A format code outside the closed
     * naalp-description-format set {1,2,3} is rejected on decode (UnknownDescriptionFormat), never
     * carried as an unknown format. Fail-closed.
     */
    public static function parseImport(string $b): Import
    {
        $m = self::decodeMap($b);
        $imp = self::bstrField($m, 1);
        $fmt = self::uintField($m, 2);
        $foreign = self::bstrField($m, 3);
        $opsV = self::field($m, 4);
        if ($imp === null || $fmt === null || $foreign === null || $opsV === null) {
            throw new DescError("DescMalformed", "import missing a mandatory field");
        }
        // The CDDL types field 2 as the closed enum {1,2,3}; a code outside the set is rejected on decode.
        if (!self::isKnownFormat($fmt)) {
            throw new DescError("UnknownDescriptionFormat", "import format $fmt is outside the closed set {1,2,3}");
        }
        return new Import($imp, $fmt, $foreign, self::operationsFromValue($opsV));
    }

    /**
     * Produce the tagged COSE_Sign1 object over the Import body (Go impl/go/description/
     * description.go:457 SignImport). Pairs with verifyImport (round-trip).
     */
    public static function signImport(Import $im, int $alg, string $seed): string
    {
        return self::signBody($im->bytes(), $alg, $seed);
    }

    /**
     * Verify a foreign-description import end-to-end and enforce the confused-deputy rule normatively. It
     * (1) verifies the signed object under the profile (structural ML-DSA in the pure tier); (2)
     * recomputes the wrapping signer's SELF-CERTIFYING id from the verifying key (Identity::signerId);
     * and (3) requires the attestation's `importer` field to equal that recomputed id (ImporterMismatch
     * otherwise). The returned authorityId is that recomputed key id — the wrapping signer — so no field
     * inside the carried foreign bytes, including any foreign identity claim, can ever become the N-AALP
     * authorization identity (R-14.6). Any failure returns its named error and authorizes nothing.
     */
    public static function verifyImport(string $obj, int $profile, int $alg, string $pubkey): ResolvedImport
    {
        $payload = self::verifySign1($obj, $profile, $alg, $pubkey);
        $im = self::parseImport($payload);
        $keyId = Identity::signerId($alg, $pubkey);
        // The authorization identity is the wrapping key's own id. The attestation's declared importer
        // MUST match it: a signer can only ever import AS ITSELF, never as a foreign identity it names.
        if ($im->importer !== $keyId) {
            throw new DescError("ImporterMismatch", "the attested importer is not the verifying key's signer id — a foreign identity never authorizes");
        }
        return new ResolvedImport($keyId, $im->format, $im->foreignId(), $im->operations);
    }

    // ---- signed-object verification (bare {1: alg} COSE_Sign1; structural ML-DSA in the pure tier) ----

    /** The bare {1: alg} COSE_Sign1 protected header (§4), matching the reference cose.Sign1. */
    public static function protectedHeader(int $alg): string
    {
        return Cbor::encode(new M([[new U(1), new N($alg)]]));
    }

    /** Read the alg (label 1) value from an encoded protected header. */
    public static function algFromProtected(string $prot): int
    {
        $v = Cbor::decode($prot);
        if ($v instanceof M) {
            foreach ($v->pairs as [$k, $val]) {
                if ($k instanceof U && $k->v === 1 && ($val instanceof N || $val instanceof U)) {
                    return $val->v;
                }
            }
        }
        throw new DescError("DescMalformed", "protected header has no alg");
    }

    /**
     * Verify a tagged COSE_Sign1 object under the profile floor and return the payload. Faithful
     * transcription: alg registry (UnknownAlg) -> profile floor (ProfileDowngrade) -> key-alg match
     * (KeyAlgMismatch) -> signature. PURE-ONLY PHP: Ed25519 is verified with real crypto (but a level-0
     * Ed25519 object never clears a profile floor, so it is rejected ProfileDowngrade first); ML-DSA is
     * accepted structurally — its signature is NOT cryptographically verified in PHP (documented, not
     * faked). Fail-closed with a named error.
     */
    public static function verifySign1(string $obj, int $profile, int $alg, string $pubkey): string
    {
        [$prot, $payload, $sig] = Cose::parseSign1Raw($obj);
        $halg = self::algFromProtected($prot);
        [$level, $known] = Cose::algLevel($halg);
        if (!$known) {
            throw new UnknownAlg("unregistered alg $halg");
        }
        if ($level < Cose::profileMinLevel($profile)) {
            throw new ProfileDowngrade("signature level below the profile minimum");
        }
        if ($halg !== $alg) {
            throw new KeyAlgMismatch("alg $halg does not match the verifier key alg $alg");
        }
        if ($halg === Cose::ALG_ED25519) {
            if (!Cose::ed25519Verify($pubkey, Cose::toBeSignedRaw($prot, $payload), $sig)) {
                throw new BadSignature("signature does not verify");
            }
        }
        // ML-DSA: structural verification complete; the signature is not verified in PHP (PURE-ONLY).
        return $payload;
    }

    /**
     * Produce a signed COSE_Sign1 object over $payload for signing alg $alg — the sign-side counterpart
     * of verifySign1, shared by signDescription/signDirectory/signImport. PURE-ONLY PHP, mirroring the
     * established php sign pattern (Negotiation::signMessage, Payment::signPaymentImport, Envelope::sign):
     * Ed25519 is signed with REAL crypto (Cose::ed25519Sign); ML-DSA (or any other alg) is signed
     * STRUCTURALLY — a 64-octet zero placeholder signature that verifySign1 accepts without
     * cryptographic verification (documented, not faked), exactly as the ML-DSA-65 signed objects this
     * port's tests assemble by hand for isolation testing. The header always carries the real $alg, so a
     * signed object round-trips through verifyDescription/verifyDirectory/verifyImport under either
     * branch.
     */
    private static function signBody(string $payload, int $alg, string $seed): string
    {
        $prot = self::protectedHeader($alg);
        if ($alg === Cose::ALG_ED25519) {
            $sig = Cose::ed25519Sign($seed, Cose::toBeSignedRaw($prot, $payload));
        } else {
            // ML-DSA (or any other alg): structural placeholder, not cryptographically verified in PHP.
            $sig = \str_repeat("\x00", 64);
        }
        return Cose::assembleSign1Raw($prot, $payload, $sig);
    }

    // ---- small deterministic-CBOR field accessors ----------------------------------------------

    /** Decode $b to a canonical CBOR map; a non-canonical body or a non-map is DescMalformed. */
    private static function decodeMap(string $b): M
    {
        try {
            $v = Cbor::decode($b);
        } catch (\Throwable $e) {
            throw new DescError("DescMalformed", "body is not well-formed deterministic CBOR");
        }
        if (!($v instanceof M)) {
            throw new DescError("DescMalformed", "body is not a map");
        }
        return $v;
    }

    /** The value at uint key $k, or null. */
    private static function field(M $m, int $k): mixed
    {
        foreach ($m->pairs as [$key, $val]) {
            if ($key instanceof U && $key->v === $k) {
                return $val;
            }
        }
        return null;
    }

    private static function bstrField(M $m, int $k): ?string
    {
        $v = self::field($m, $k);
        return $v instanceof B ? $v->v : null;
    }

    private static function uintField(M $m, int $k): ?int
    {
        $v = self::field($m, $k);
        return $v instanceof U ? $v->v : null;
    }
}
