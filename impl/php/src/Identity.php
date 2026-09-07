<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
/**
 * N-AALP C4 identity for the PHP SDK: the self-certifying signer id (§5.1) and the NFC rule.
 *
 * signer id = multibase(base32, multihash(0x12 sha2-256, SHA-256(multicodec(mc) || pubkey))),
 * identical in form to the N-PAMP PeerHandle. Multicodec codes are from the multiformats
 * registry: ed25519-pub 0xed, mldsa-65-pub 0x1211, mldsa-87-pub 0x1212; multihash sha2-256 0x12.
 * base32 is RFC 4648 lowercase, no padding, with the multibase 'b' prefix.
 */

declare(strict_types=1);

namespace Naalp;

class UnknownAlg extends \RuntimeException
{
    public string $kind = "UnknownAlg";
}

class SignerMismatch extends \RuntimeException
{
    public string $kind = "SignerMismatch";
}

class NonNFC extends \RuntimeException
{
    public string $kind = "NonNFC";
}

final class Identity
{
    private const MULTICODEC = [
        Cose::ALG_ED25519 => 0xED,
        Cose::ALG_MLDSA65 => 0x1211,
        Cose::ALG_MLDSA87 => 0x1212,
    ];
    private const MH_SHA256 = 0x12;

    /** LEB128 unsigned varint (multiformats). */
    private static function uvarint(int $n): string
    {
        $out = "";
        while (true) {
            $b = $n & 0x7F;
            $n >>= 7;
            if ($n) {
                $out .= \chr($b | 0x80);
            } else {
                $out .= \chr($b);
                return $out;
            }
        }
    }

    /** RFC 4648 base32 lowercase, no padding. */
    private static function base32LowerNoPad(string $data): string
    {
        $alphabet = "abcdefghijklmnopqrstuvwxyz234567";
        $out = "";
        $buffer = 0;
        $bits = 0;
        $len = \strlen($data);
        for ($i = 0; $i < $len; $i++) {
            $buffer = ($buffer << 8) | \ord($data[$i]);
            $bits += 8;
            while ($bits >= 5) {
                $bits -= 5;
                $out .= $alphabet[($buffer >> $bits) & 0x1F];
            }
        }
        if ($bits > 0) {
            $out .= $alphabet[($buffer << (5 - $bits)) & 0x1F];
        }
        return $out;
    }

    /** Compute the signer id (multiformats PeerHandle form) for an alg + raw public key. */
    public static function signerId(int $alg, string $pubkey): string
    {
        if (!\array_key_exists($alg, self::MULTICODEC)) {
            throw new UnknownAlg("no multicodec for alg " . $alg);
        }
        $tagged = self::uvarint(self::MULTICODEC[$alg]) . $pubkey;
        $digest = \hash('sha256', $tagged, true);
        $mh = self::uvarint(self::MH_SHA256) . self::uvarint(\strlen($digest)) . $digest;
        return "b" . self::base32LowerNoPad($mh);
    }

    /**
     * The self-certifying signer id for a composite key pair (§5.1). The SHA-256 preimage is the
     * multicodec-tagged ML-DSA public key concatenated with the multicodec-tagged Ed25519 public
     * key -- using only existing official multicodecs (no minted code) -- so stripping or
     * substituting either leg changes the id (=> SignerMismatch before verify). Downgrade-resistant,
     * byte-identical to impl/ruby composite_signer_id and the other ports.
     */
    public static function compositeSignerId(int $mldsaAlg, string $mldsaPub, string $edPub): string
    {
        if ($mldsaAlg !== Cose::ALG_MLDSA65 && $mldsaAlg !== Cose::ALG_MLDSA87) {
            throw new UnknownAlg("composite signer id requires an ML-DSA alg, got " . $mldsaAlg);
        }
        $preimage = self::uvarint(self::MULTICODEC[$mldsaAlg]) . $mldsaPub
                  . self::uvarint(self::MULTICODEC[Cose::ALG_ED25519]) . $edPub;
        $digest = \hash('sha256', $preimage, true);
        $mh = self::uvarint(self::MH_SHA256) . self::uvarint(\strlen($digest)) . $digest;
        return "b" . self::base32LowerNoPad($mh);
    }

    public static function checkSigner(string $claimed, int $alg, string $pubkey): void
    {
        if (self::signerId($alg, $pubkey) !== $claimed) {
            throw new SignerMismatch("signer id does not recompute from the key");
        }
    }

    /** Reject an identity/scope string that is not Unicode NFC (§3.1, R-3.3). */
    public static function requireNfc(string $s): void
    {
        $nfc = \Normalizer::normalize($s, \Normalizer::FORM_C);
        if ($nfc !== $s) {
            throw new NonNFC("string is not Unicode NFC");
        }
    }

    // ---- key rotation (design §5.2): the co-signed old->new link -----------------------------
    // ADDED ADDITIVELY (Wave D, rooms port): the self-certifying signer id survives a key rotation.
    // A RotationRecord binds the old id to the new id from a not_before position, co-signed by BOTH
    // keys, so attribution to the durable identity is preserved across rotation (R-1.4). This is the
    // C4 primitive the Delivery-Model-B principal registry (Naalp\PrincipalRegistry) composes on for
    // a rotation-authorised rebind — placed in the identity spine exactly as impl/go/identity and
    // impl/python/naalp/identity place it, NOT inside Rooms. New methods/types only; no existing
    // Identity code is changed.

    /**
     * Co-sign a rotation with BOTH the old and new keys (§5.2). PURE-ONLY PHP: each leg is a real
     * deterministic Ed25519 (RFC 8032) signature over the rotation body (the pure-tier stand-in for
     * the reference's deterministic ML-DSA co-signature). Returns [oldSig, newSig].
     *
     * @return array{0:string,1:string}
     */
    public static function signRotation(RotationRecord $r, string $oldSeed, string $newSeed): array
    {
        $m = $r->bytes();
        return [Cose::ed25519Sign($oldSeed, $m), Cose::ed25519Sign($newSeed, $m)];
    }

    /**
     * Confirm a rotation is authorized (§5.2, §5.5): BOTH keys derive the ids in the record AND BOTH
     * signatures verify over the rotation body. Any failure — an id that does not recompute from its
     * key, or a signature that does not verify — is RotationUnauthorized (fail-closed). A
     * substitution not co-signed by the old key cannot pass, so the durable id cannot be hijacked to
     * an unrelated key. PURE-ONLY PHP: only Ed25519 is a real verify path; a non-Ed25519 leg has no
     * deterministic PHP verifier and is refused fail-closed (documented pure-tier behaviour).
     */
    public static function verifyRotation(RotationRecord $r, int $oldAlg, string $oldPub, int $newAlg, string $newPub, string $oldSig, string $newSig): void
    {
        try {
            self::checkSigner($r->old, $oldAlg, $oldPub);
            self::checkSigner($r->new, $newAlg, $newPub);
        } catch (\Throwable $e) {
            throw new RotationUnauthorized("a rotation key does not derive its recorded signer id");
        }
        $m = $r->bytes();
        if (!self::rotationLegVerifies($oldAlg, $oldPub, $m, $oldSig) || !self::rotationLegVerifies($newAlg, $newPub, $m, $newSig)) {
            throw new RotationUnauthorized("a rotation signature does not verify under its key");
        }
    }

    /** One rotation-leg signature check. PURE-ONLY: Ed25519 is verified; any other alg is refused. */
    private static function rotationLegVerifies(int $alg, string $pub, string $msg, string $sig): bool
    {
        if ($alg === Cose::ALG_ED25519) {
            return Cose::ed25519Verify($pub, $msg, $sig);
        }
        return false; // PURE-ONLY: PHP has no deterministic ML-DSA verify (fail-closed, honest)
    }

    // ---- key revocation (design §5.3): distinct from rotation, dead not superseded ---------------
    // ADDED ADDITIVELY (identity-records wave): the eleven RECORD + THREAD surfaces (RevocationRecord,
    // VerifyRevocation, RevokedAt, ForeignLinkRecord, VerifyForeignLink, RotationEvidence, Thread,
    // Thread::attributable, ResolveThread) previously had NO PHP port and NO independent oracle
    // coverage in this SDK; see tools/identity_records_oracle.py -> vectors/identity_records/cases.json
    // (F3). Mirrors impl/go/identity/identity.go and impl/rust/src/identity.rs exactly: same CBOR
    // field numbers, same fail-closed error kinds, same membership-before-signature order in
    // VerifyRevocation.

    /**
     * One raw signature verification dispatched by alg, for the record+thread surfaces below: real
     * Ed25519 (ext-sodium) and real deterministic ML-DSA-65/87 (MlDsa.php, PHP-FFI to OpenSSL >= 3.5)
     * -- distinct from the PURE-ONLY rotationLegVerifies() above, which predates the ML-DSA FFI
     * landing and is left untouched for its existing Rooms.php callers. An alg with no verifier, or
     * an unavailable ML-DSA runtime, is fail-closed false (never verified). Plain (empty) context,
     * matching the reference's bare-record signature (not the LAMPS composite's Label context).
     */
    private static function verifyRawByAlg(int $alg, string $pub, string $msg, string $sig): bool
    {
        if ($alg === Cose::ALG_ED25519) {
            return Cose::ed25519Verify($pub, $msg, $sig);
        }
        if ($alg === Cose::ALG_MLDSA65 || $alg === Cose::ALG_MLDSA87) {
            return MlDsa::available() && MlDsa::verify($pub, $msg, $sig, $alg);
        }
        return false;
    }

    /**
     * Confirm a revocation is validly signed (§5.3): by the key it revokes, or by a deployer-
     * configured recovery key. $recoveryIds is the deployer's set of authorized recovery-key signer
     * ids; a revocation whose signer is neither $r->key nor a member of $recoveryIds is rejected
     * SignerMismatch (§5.5), fail-closed -- an empty $recoveryIds admits only the revoked key itself.
     * The signer id is recomputed from the presented key and checked BEFORE the signature.
     *
     * @param string[] $recoveryIds
     */
    public static function verifyRevocation(RevocationRecord $r, int $alg, string $pub, string $sig, array $recoveryIds): void
    {
        $id = self::signerId($alg, $pub); // UnknownAlg propagates unchanged
        $authorized = $id === $r->key;
        if (!$authorized) {
            foreach ($recoveryIds as $rid) {
                if ($rid === $id) {
                    $authorized = true;
                    break;
                }
            }
        }
        if (!$authorized) {
            throw new SignerMismatch("signer is neither the revoked key nor an authorized recovery key");
        }
        if (!self::verifyRawByAlg($alg, $pub, $r->bytes(), $sig)) {
            throw new BadSignature("revocation signature does not verify");
        }
    }

    /**
     * Whether an object fixed at authoritative position $posTime is after the revocation; objects
     * fixed at or before not_after stay valid (§5.3).
     */
    public static function revokedAt(RevocationRecord $r, int $posTime): bool
    {
        return $posTime > $r->notAfter;
    }

    // ---- foreign-identity linkage (design §5.4) ----------------------------------------------------

    /**
     * Whether a foreign-identity link confers linkage at time $now (§5.4). A non-NFC foreign_id is
     * rejected (NonNFC). An expired link or a bad cross-signature confers NO linkage but is not
     * itself an error -- it simply does not link (the object remains valid on its own signature,
     * §5.4/§5.5). It NEVER overrides the key-derived id.
     */
    public static function verifyForeignLink(ForeignLinkRecord $r, int $foreignAlg, string $foreignPub, string $sig, int $now): bool
    {
        self::requireNfc($r->foreignId); // throws NonNFC
        if ($now > $r->notAfter) {
            return false; // expired: confers no authority (ignored)
        }
        if (!self::verifyRawByAlg($foreignAlg, $foreignPub, $r->bytes(), $sig)) {
            return false; // bad/absent cross-signature: no linkage
        }
        return true;
    }

    // ---- durable identity thread (rotation-surviving attribution, R-1.4) ---------------------------

    /**
     * Verify an ordered rotation chain and return the durable identity thread (§5.2, R-1.4). Each
     * rotation must be authorized (co-signed) and link the previous `new` to the next `old`; a break
     * yields RotationUnauthorized. A receipt signed under any id in the returned Thread's chain is
     * attributable to the root, so it stays attributable after rotation.
     *
     * @param RotationEvidence[] $evs
     */
    public static function resolveThread(array $evs): Thread
    {
        if (\count($evs) === 0) {
            throw new RotationUnauthorized("empty rotation chain");
        }
        $root = $evs[0]->record->old;
        $chain = [$root];
        $prevNew = $root;
        foreach ($evs as $e) {
            if ($e->record->old !== $prevNew) {
                throw new RotationUnauthorized("chain not contiguous");
            }
            self::verifyRotationEvidence($e);
            $chain[] = $e->record->new;
            $prevNew = $e->record->new;
        }
        return new Thread($root, $prevNew, $chain);
    }

    /**
     * Verify one RotationEvidence's co-signature (§5.2): both keys derive the record's ids and both
     * signatures verify, via the general alg-dispatch verifyRawByAlg (ML-DSA and Ed25519) so
     * ResolveThread matches the Go/Rust reference, which verifies any registered alg generically via
     * the Verifier interface.
     */
    private static function verifyRotationEvidence(RotationEvidence $e): void
    {
        try {
            self::checkSigner($e->record->old, $e->oldAlg, $e->oldPub);
            self::checkSigner($e->record->new, $e->newAlg, $e->newPub);
        } catch (\Throwable $ex) {
            throw new RotationUnauthorized("a rotation key does not derive its recorded signer id");
        }
        $m = $e->record->bytes();
        if (!self::verifyRawByAlg($e->oldAlg, $e->oldPub, $m, $e->oldSig)
            || !self::verifyRawByAlg($e->newAlg, $e->newPub, $m, $e->newSig)) {
            throw new RotationUnauthorized("a rotation signature does not verify under its key");
        }
    }
}

/**
 * Raised when a rotation is not authorized by both keys (§5.2, §5.5). Added additively for the rooms
 * Delivery-Model-B rebind; `$kind` mirrors the Go/Python "RotationUnauthorized" error kind.
 */
class RotationUnauthorized extends \RuntimeException
{
    public string $kind = "RotationUnauthorized";
}

/**
 * Links an old signer id to a new one from `notBefore` (§5.2). Its signed bytes are the
 * deterministic-CBOR map {1: old, 2: new, 3: not_before}. Added additively (rooms port); the wire
 * body is byte-identical to impl/go/identity RotationRecord and impl/python/naalp/identity.
 */
final class RotationRecord
{
    public string $old;
    public string $new;
    public int $notBefore;

    public function __construct(string $old, string $new, int $notBefore)
    {
        $this->old = $old;
        $this->new = $new;
        $this->notBefore = $notBefore;
    }

    /** Deterministic-CBOR encoding of the rotation body {1: old, 2: new, 3: not_before}. */
    public function bytes(): string
    {
        return Cbor::encode(new M([
            [new U(1), new T($this->old)],
            [new U(2), new T($this->new)],
            [new U(3), new U($this->notBefore)],
        ]));
    }
}

/**
 * Marks a key dead from `notAfter` (§5.3). Its signed bytes are the deterministic-CBOR map
 * {1: key, 2: not_after} -- byte-identical to impl/go/identity RevocationRecord and
 * impl/rust/src/identity.rs RevocationRecord.
 */
final class RevocationRecord
{
    public string $key;
    public int $notAfter;

    public function __construct(string $key, int $notAfter)
    {
        $this->key = $key;
        $this->notAfter = $notAfter;
    }

    /** Deterministic-CBOR encoding of the revocation body {1: key, 2: not_after}. */
    public function bytes(): string
    {
        return Cbor::encode(new M([
            [new U(1), new T($this->key)],
            [new U(2), new U($this->notAfter)],
        ]));
    }
}

/**
 * Cross-signs a foreign identity to a signer id (§5.4). Its signed bytes are the deterministic-CBOR
 * map {1: controls, 2: foreign_id, 3: not_after} -- byte-identical to impl/go/identity
 * ForeignLinkRecord and impl/rust/src/identity.rs ForeignLinkRecord. It is signed by the FOREIGN
 * identity's key.
 */
final class ForeignLinkRecord
{
    public string $controls;
    public string $foreignId;
    public int $notAfter;

    public function __construct(string $controls, string $foreignId, int $notAfter)
    {
        $this->controls = $controls;
        $this->foreignId = $foreignId;
        $this->notAfter = $notAfter;
    }

    /** Deterministic-CBOR encoding of the foreign-link body {1: controls, 2: foreign_id, 3: not_after}. */
    public function bytes(): string
    {
        return Cbor::encode(new M([
            [new U(1), new T($this->controls)],
            [new U(2), new T($this->foreignId)],
            [new U(3), new U($this->notAfter)],
        ]));
    }
}

/**
 * One verified rotation step: the record plus the two keys (alg + raw public key) and their
 * co-signatures (§5.2). Mirrors impl/go/identity RotationEvidence and impl/rust/src/identity.rs
 * RotationEvidence, except the alg+pubkey pair stands in for the Go/Rust cose.Verifier interface --
 * PHP's Identity module has no such abstraction elsewhere (checkSigner/verifyRotation already take
 * alg+pubkey directly).
 */
final class RotationEvidence
{
    public RotationRecord $record;
    public int $oldAlg;
    public string $oldPub;
    public int $newAlg;
    public string $newPub;
    public string $oldSig;
    public string $newSig;

    public function __construct(
        RotationRecord $record,
        int $oldAlg,
        string $oldPub,
        int $newAlg,
        string $newPub,
        string $oldSig,
        string $newSig
    ) {
        $this->record = $record;
        $this->oldAlg = $oldAlg;
        $this->oldPub = $oldPub;
        $this->newAlg = $newAlg;
        $this->newPub = $newPub;
        $this->oldSig = $oldSig;
        $this->newSig = $newSig;
    }
}

/**
 * A durable identity: a root signer id continued by a chain of rotations (R-1.4). Mirrors
 * impl/go/identity Thread and impl/rust/src/identity.rs Thread.
 */
final class Thread
{
    public string $root;    // the id the thread is named by (the first key)
    public string $current; // the id after the latest rotation
    /** @var string[] */
    public array $chain;    // root, then each rotated-to id in order

    /** @param string[] $chain */
    public function __construct(string $root, string $current, array $chain)
    {
        $this->root = $root;
        $this->current = $current;
        $this->chain = $chain;
    }

    /**
     * Whether an object whose body signer id is $signer belongs to this durable thread (any id in
     * the chain, including a pre-rotation key, R-1.4).
     */
    public function attributable(string $signer): bool
    {
        foreach ($this->chain as $id) {
            if ($id === $signer) {
                return true;
            }
        }
        return false;
    }
}
